//
// Copyright (C) 2011 Martin Becke
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.

#ifdef PRIVATE

#include "TCPMultipathFlow.h"


#if defined(__APPLE__)
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#define SHA1 CC_SHA1
#else
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <inttypes.h>
#endif

#include "TCP.h"


// some defines for maximum sizes
#define COMMON_MPTCP_OPTION_HEADER_SIZE 16
#define SENDER_KEY_SIZE                 64
#define RECEIVER_KEY_SIZE               64

// Some defines for MP_CAPABLE
#define MP_CAPABLE_SIZE_SYN    ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + SENDER_KEY_SIZE) >> 3)
#define MP_CAPABLE_SIZE_SYNACK ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + RECEIVER_KEY_SIZE) >> 3)
#define MP_CAPABLE_SIZE_ACK    ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + SENDER_KEY_SIZE + RECEIVER_KEY_SIZE) >> 3)

// Some defines for MP_JOIN
#define MP_JOIN_SIZE_SYN                12
#define MP_JOIN_SIZE_SYNACK             16
#define MP_JOIN_SIZE_ACK                24

// Version of MPTCP
#define VERSION 0x0


/**
 * Constructor
 * @param int ID for each Flow
 * @param int aAppGateIndex Application Gate Index for Flow
 * @param int MPTCP_PCB Protocol Control Block for Flow
 */
MPTCP_Flow::MPTCP_Flow(int connID, int aAppGateIndex,TCPConnection* subflow, MPTCP_PCB* aPCB) :
    state(IDLE), local_key(0),
            remote_key(0) {


    // For easy PCB Lookup set ID and Application Index
    appID = connID;
    appGateIndex = aAppGateIndex;
    pcb = aPCB;
    seq = 0;
    // Identifier
    local_token = 0;
    remote_token = 0;
    // Sending side
    snd_una = 0;
    snd_nxt = 0;
    snd_wnd = 0;
    // Receiver Side
    rcv_nxt = 0;
    rcv_wnd = 0;
    isPassive = false;
    // Init the flow
    if(subflow->localPort > 0)
        _initFlow(subflow->localPort);
    queue_mgr = new TCPMultipathQueueMngmt();
}

/**
 * Destructor
 */
MPTCP_Flow::~MPTCP_Flow() {
    // TODO(MBe) -> De-Constructor of Flow
}

/**
 * Initialization of an Multipath Flow
 * A Flow is equal to one connection
 * A Flow contains different subflows
 */
void MPTCP_Flow::_initFlow(int port) {
    // 1) lookup for all available IP addresses
    // 2) setup a list of local addresses
    // We need cross layer information of available interfaces

    IInterfaceTable *ift = interfaceTableAccess.get();

    // Setup a list of available addresses
    if (!list_laddrtuple.size()) {
        for (int32 i = 0; i < ift->getNumInterfaces(); ++i) {
            AddrTupple_t* addr = new AddrTupple_t();
            addr->port = -1;
            if (ift->getInterface(i)->ipv4Data() != NULL) {
                tcpEV<<"[MPTCP FLOW] add IPv4: " << ift->getInterface(i)->ipv4Data()->getIPAddress() << "\0";
                addr->addr = ift->getInterface(i)->ipv4Data()->getIPAddress();
                addr->port = port;
            }
            else if (ift->getInterface(i)->ipv6Data()!=NULL)
            {
                for (int32 j=0; j<ift->getInterface(i)->ipv6Data()->getNumAddresses(); j++)
                {
                    tcpEV<<"[MPTCP FLOW] add IPv6: " << ift->getInterface(i)->ipv6Data()->getAddress(j) << "\0";
                    addr->addr = ift->getInterface(i)->ipv6Data()->getAddress(j);
                    addr->port = port;
                }
            }
            else {
                ASSERT(false);
            }

            // ############################
            // List of local address tuples
            if( addr->port != -1 )
                list_laddrtuple.push_back(addr);
        }
    }
    else
    {
        // Should never happen...
        tcpEV<<"[MPTCP FLOW][ERROR] Problems by adding all known IP adresses\n";
    }
    return;
}

/**
 * Add a subflow to a MPTCP connection
 * @param int Id of subflow - still not used
 * @param TCPConnection* To add subflow
 * */
int MPTCP_Flow::addSubflow(int id, TCPConnection* subflow) {
    // 1) Add the given subflow to the flow/connections
    // 2) Check if further subflows are possible
    // 3) Initiate possible new subflows by a selfmessage (add to join queue)

    // Create a subflow entry in the list, a entry is stateful
    TCP_subflow_t *t = new TCP_subflow_t();
    subflow->isSubflow = true;

    // FIXME perhaps it is a good idea to add the PCB to the subflow !!!!
    // subflow-multi_pcb = pcb

    // If we know this subflow already something goes wrong
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i
            != subflow_list.end(); i++) {
        TCP_subflow_t* entry = (*i);
            if ((entry->subflow->remoteAddr == subflow->remoteAddr)
                && (entry->subflow->remotePort == subflow->remotePort)
                && (entry->subflow->localAddr == subflow->localAddr)
                && (entry->subflow->localPort == subflow->localPort))

            return 0;
    }

    // set subflow as active
    t->active = true;
    t->subflow = subflow;

    // add to list
    subflow_list.push_back(t);

    // ###################################
    // Check for further possible subflows
    // add the adresses of this subflow to the known address list for a MP_JOIN or add
    bool found = false;
    TCP_AddressVector_t::const_iterator it_r;
    for (it_r = list_raddrtuple.begin(); it_r != list_raddrtuple.end(); it_r++) {
        AddrTupple_t* tmp_r = (AddrTupple_t*) *it_r;
        if ((tmp_r->addr.equals(subflow->remoteAddr)) && (tmp_r->port
                == subflow->remotePort)) {
            found = true;
        }
    }

    // add this address because it is unknown
    if (!found) {
        AddrTupple_t *a = new AddrTupple_t();
        a->addr = subflow->remoteAddr;
        a->port = subflow->remotePort;
        list_raddrtuple.push_back(a);
    }

    // ############################################################
    // we have to trigger the new handshakes of the other subflows
    // sender side; we have to check if there are more possibles

    for (it_r = list_raddrtuple.begin(); it_r != list_raddrtuple.end(); it_r++) {
        AddrTupple_t* tmp_r = (AddrTupple_t*) *it_r;

        TCP_AddressVector_t::const_iterator it_l;
        for (it_l = list_laddrtuple.begin(); it_l != list_laddrtuple.end(); it_l++) {
            AddrTupple_t* tmp_l = (AddrTupple_t*) *it_l;
            tcpEV<< "[MPTCP][PREPARE ADD SUBFLOW] Base Addr:" << subflow->localAddr << "\0";
            // collect data for possible new connections
            if (!tmp_l->addr.equals(subflow->localAddr)) {
                AddrCombi_t* to_join = new AddrCombi_t();
                to_join->local.addr  = tmp_l->addr;
                to_join->remote.addr = tmp_r->addr;
                to_join->local.port  = tmp_l->port;
                to_join->remote.port = tmp_r->port;

                DEBUGPRINT("\nAdd Possible MPTCP Subflow: %s:%d to %s:%d\n", to_join->local.addr.str().c_str(), to_join->local.port,  to_join->remote.addr.str().c_str(), to_join->remote.port);

                // add to join queue () - joinConnection() will work for this queue
                join_queue.push_back(to_join);

            }
        }
    }
    list_raddrtuple.clear();

    return 1;
}

/**
 * Check if a specific subflow belogs to this flow/connection
 * @param TCPConnection* To check subflow
 */
bool MPTCP_Flow::isSubflowOf(TCPConnection* subflow) {
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i
            != subflow_list.end(); ++i) {
        TCP_subflow_t* entry = (*i);
        if ((entry->subflow->remoteAddr == subflow->remoteAddr)
                && (entry->subflow->remotePort == subflow->remotePort)
                && (entry->subflow->localAddr == subflow->localAddr)
                && (entry->subflow->localPort == subflow->localPort))
            return true; // Yes this subflow belongs to this flow
    }
    // Sorry, this subflow is handled on this flow
    return false;
}

/**
 * TODO ???
 */
int MPTCP_Flow::sendByteStream(TCPConnection* subflow) {
    ASSERT(false);
    return 0;
}

/**
 * Main Entry Point for outgoing MPTCP segments.
 * - here we add MPTCP Options
 * - take care about SQN of MPTCP (Sender Side)
 * @param uint Count of options
 * @param TCPStateVariables* The State of the subflow
 * @param TCPSegment* The TCP segment to work for
 * @param TCPConnection* The connection itself
 */
int MPTCP_Flow::writeMPTCPHeaderOptions(uint t,
        TCPStateVariables* subflow_state, TCPSegment *tcpseg,
        TCPConnection* subflow) {

    // 1) Depending on state and segment type add multipath tcp options
    // TODO Split segment, if there is not enough space for the options
    // TODO Better error handling
    // TODO Generate a extra message e.g. an duplicate ACK (see draft section 2)
    // TODO CHECK FLOW FLAGS, eg. report or delete address


    // Initiate some helper
    uint options_len = 0;
    TCPOption option;
    DEBUGPRINT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Prepare Outgoing Packet%s","\0");
    // First check if is it allowed to add further options
    for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
        options_len = options_len + tcpseg->getOptions(i).getLength();

    // Check on not increasing the TCP Option
    ASSERT(options_len <= 40);

    // Only work on MPTCP Options!!
    // (Note: If this is a design problem to do it here, we could move this to TCP...)
    option.setKind(TCPOPTION_MPTCP); // FIXME depending on IANA request
    DEBUGPRINT("[FLOW][OUT][SEND A MPTCP PACKET] STATE (%i)",state);
    DEBUGPRINT("[FLOW][OUT][SEND A MPTCP PACKET] Support of MPTCP Kind: %u",TCPOPTION_MPTCP);

    // If SYN remark this combination as tried
    if ((tcpseg->getSynBit()) && (!tcpseg->getAckBit())) {
        AddrCombi_t* c = new AddrCombi_t();
        AddrTupple_t* l = new AddrTupple_t();
        AddrTupple_t* r = new AddrTupple_t();

        l->addr = subflow->localAddr;
        r->addr = subflow->remoteAddr;
        c->local.addr = l->addr;
        c->remote.addr = r->addr;
        c->local.port = l->port;
        c->remote.port = r->port;
        tried_join.push_back(c);
    }

    /**********************************************************************************
     *  we have to send different TCP Options for handshake, depending on the states
     *  SYN(A->B):      A's KEY             -> MPTCP STATE IDLE/PRE_ESTABLISHED
     *  SYN/ACK(B->A)   B's key             -> MPTCP STATE IDLE/PRE_ESTABLISHED
     *  ACK(A->B):      A's KEY & B's key   -> MPTCP STATE PRE_ESTABLISHED/ESTABLISHED
     *
     *  Main/common traffic is during the ESTABLISHED state
     */


    /* General overview about the msg exchange
            Host A                               Host B
        ------------------------             ------------------------
        Address A1    Address A2             Address B1    Address B2
        ----------    ----------             ----------    ----------
        |             |                      |             |
        |     (initial connection setup)     |             |
        |----------------------------------->|             |
        |<-----------------------------------|             |
        |             |                      |             |
        |            (additional subflow setup)            |
        |             |--------------------->|             |
        |             |<---------------------|             |
        |             |                      |             |
        |             |                      |             |
     */

    // FIXME What is with a RST from our system
    if(tcpseg->getRstBit())
        return t;

    switch (this->state) {
        case ESTABLISHED: {
            DEBUGPRINT("[FLOW][OUT][SEND A MPTCP PACKET] ESTABLISHED (%i)",state);
            // complete additional subflow setup
            // If we in ESTABLISHED state and there comes up a syn we have to add a join for MPTCP transfer
            if ( ((subflow->isSubflow) &&   (tcpseg->getSynBit()))  || subflow->joinToAck || subflow->joinToSynAck) {
                t = _writeJoinHandshakeHeader(t, subflow_state, tcpseg, subflow, &option);
                subflow->joinToAck      = false;
                subflow->joinToSynAck   = false;
            }else{
                DEBUGPRINT("[FLOW][OUT][SEND A MPTCP PACKET] DATA OUT Do SQN for subflow (%u) by utilizing DSS",subflow->isSubflow);
                _writeDSSHeaderandProcessSQN(t, subflow_state, tcpseg, subflow, &option);
            }
            break;
        }
        case SHUTDOWN:
            DEBUGPRINT("[FLOW][OUT] SHUTDOWN  (%i)",state);
            break;
        case PRE_ESTABLISHED:
            DEBUGPRINT("[FLOW][OUT] PRE ESTABLISHED (%i)",state);
            t = _writeInitialHandshakeHeader(t, subflow_state, tcpseg, subflow,  &option);
            break;
        case IDLE:
            DEBUGPRINT("[FLOW][OUT] Work on state %i - Figure out what to do",state);
            if ((tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
                DEBUGPRINT("[FLOW][OUT] Not ESTABLISHED here we go %i",state);
                // If we send the SYN ACK, we are the passive side, please note this
                isPassive = true;
            }
            t = _writeInitialHandshakeHeader(t, subflow_state, tcpseg, subflow,  &option);
            break;

        default: ASSERT(false); break;
    }
    if(this->state == ESTABLISHED && (!tcpseg->getSynBit())  ){
        // FIXME Perhaps we need a switch for also handshake from passive side
        //
#define BOTH_SIDE_HANDSHAKE true
        if(BOTH_SIDE_HANDSHAKE || !isPassive){
            // 3.2. Starting a New Subflow
            // It is permitted for
            // either host in a connection to initiate the creation of a new
            // subflow, but it is expected that this will normally be the original
            // connection initiator
            _prepareJoinConnection(); // FIXME -> Perhaps there is a better place, but in first try we check if there are new data received
        }
    }
    DEBUGPRINT("End Preparing Outgoing Segment <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<%s","\n");
    return t;
}

/*
 * Do the MP_CAPABLE Handshake
 */
int MPTCP_Flow::_writeInitialHandshakeHeader(uint t, TCPStateVariables* subflow_state,
    TCPSegment *tcpseg, TCPConnection* subflow, TCPOption* option) {

    /* General overview MP_CAPABLE
        ------------------------                       ----------
         Address A1    Address A2                       Address B1
         ----------    ----------                       ----------
             |             |                                |
             |            SYN + MP_CAPABLE(Key-A)           |
             |--------------------------------------------->|
             |<---------------------------------------------|
             |          SYN/ACK + MP_CAPABLE(Key-B)         |
             |             |                                |
             |        ACK + MP_CAPABLE(Key-A, Key-B)        |
             |--------------------------------------------->|
    */

    // Initiate some helper
    uint32_t first_bits = 0x0;
    uint32_t version = 0x0;
    DEBUGPRINT("Multipath FSM: Enter Initial Handshake%s","\0");

    first_bits = (first_bits | ((uint16_t) MP_CAPABLE)); //12
    first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);

    version = (version | ((uint16_t) VERSION << MP_VERSION_POS));
    version = version << (MP_VERSION_POS + MP_SIGNAL_FIRST_VALUE_TYPE);
    first_bits |= version;

    switch (state) {
        // Connection initiation SYN; SYN/ACK; ACK of the whole flow it must contain the MP_CAPABLE Option
        // MPTCP IDLE
        case IDLE: { // whether a SYN or ACK for a SYN ACK is send -> new MPTCP Flow

            if (!tcpseg->getSynBit()) {
                DEBUGPRINT("[FLOW][OUT] ERROR MPTCP Connection state: %u", getState());
                ASSERT(false);
                return t;
            }


// SYN MP_CAPABLE
            // Check if it is whether a SYN or SYN/ACK
            if (tcpseg->getSynBit() && (!tcpseg->getAckBit())) { // SYN
                DEBUGPRINT("[MPTCP][HANDSHAKE][MP_CAPABLE] IDLE working for sending a SYN%s","\0");
                addSubflow(0,subflow); // OK this is the first subflow and should be add
                // Prepare
                option->setLength(MP_CAPABLE_SIZE_SYN);
                option->setValuesArraySize(3);
                option->setValues(0, first_bits);

                // generate local_key(!!) Section 3.1 => only time the key will send in clear

                _generateLocalKey();
                ASSERT(local_key != 0);
                // set 64 bit value
                uint32_t value = (uint32_t) _getLocalKey();
                option->setValues(1, value);
                value = _getLocalKey() >> 32;
                option->setValues(2, value);
                this->MPTCP_FSM(PRE_ESTABLISHED);
                DEBUGPRINT("[FLOW][OUT] Generate Sender Key in IDLE for SYN: %ld",_getLocalKey());








// SYN-ACK MP_CAPABLE
            } else if (tcpseg->getSynBit() && tcpseg->getAckBit()) { // SYN/ACK
                DEBUGPRINT("[MPTCP][HANDSHAKE][MP_CAPABLE] IDLE working for sending a SYN-ACK%s","\0");

                // Prepare
                option->setLength(MP_CAPABLE_SIZE_SYNACK);
                option->setValuesArraySize(3);
                option->setValues(0, first_bits);

                // generate receiver_key -> important is key of ACK
                _generateLocalKey();
                ASSERT(local_key != 0);
                // set 64 bit value
                uint32_t value = (uint32_t) _getLocalKey();
                option->setValues(1, value);
                value = _getLocalKey() >> 32;
                option->setValues(2, value);

                DEBUGPRINT("[FLOW][OUT] Generate Receiver Key in IDLE for SYN-ACK: %ld",_getLocalKey());
                this->MPTCP_FSM(ESTABLISHED);//TEST
                tcpEV << "[MPTCP][HANDSHAKE][MP_CAPABLE] PRE_ESTABLISHED after send SYN-ACK\n";

            } else
                ASSERT(false); // FIXME Just for Testing

            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
            tcpseg->setOptions(t, *option);
            t++;
            break;
        }

        // MPTCP PRE_ESTABLISHED
        case PRE_ESTABLISHED: { // whether ACK for a SYN ACK is send -> new MPTCP Flow



// ACK MP_CAPABLE
            // OK we are stateful, however the handshake is not complete
            if (tcpseg->getAckBit()) { // ACK
                DEBUGPRINT("[MPTCP][HANDSHAKE][MP_CAPABLE] PRE_ESTABLISHED working for sending  a ACK%s","\0");

                // Prepare
                option->setLength(MP_CAPABLE_SIZE_ACK);
                option->setValuesArraySize(5);
                option->setValues(0, first_bits);

                // set 64 bit value
                uint32_t value = (uint32_t) _getLocalKey();
                option->setValues(1, value);
                value = _getLocalKey() >> 32;
                option->setValues(2, value);

                // set 64 bit value
                value = (uint32_t) _getRemoteKey();
                option->setValues(3, value);
                value = _getRemoteKey() >> 32;
                option->setValues(4, value);

                tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
                tcpseg->setOptions(t, *option);
                t++;



                // FIXME - NOT SURE IF BEST PLACE HERE
                // If we allow a server side syn we have to set the Client in listen modus for incoming SYNs
                // For this we utilize a TCPOpencommand
/*                std::string sendQueueClass;
                std::string receiveQueueClass;
                std::string tcpAlgorithmClass;
                TCPConnection *newConn = new TCPConnection(subflow->getTcpMain(), subflow->appGateIndex, subflow->appGateIndex);
                TCPOpenCommand *openCmd = new TCPOpenCommand();
                openCmd->setLocalAddr(subflow->localAddr);
                openCmd->setLocalPort(tcpseg->getSrcPort());
                openCmd->setConnId(subflow->connId);
                openCmd->setFork(fork);

                openCmd->setSendQueueClass(sendQueueClass.c_str());
                openCmd->setReceiveQueueClass(receiveQueueClass.c_str());
                openCmd->setTcpAlgorithmClass(tcpAlgorithmClass.c_str());
                newConn->initMPTCPConnection(openCmd);
*/

                TCPConnection* newSubflow = subflow->cloneMPTCPConnection(false);
                cMessage *msg = new cMessage("PassiveOPEN", TCP_E_OPEN_PASSIVE);    // Passive Server Side

                TCPOpenCommand *openCmd = new TCPOpenCommand();
//                openCmd->setLocalAddr(subflow->localAddr);
                openCmd->setLocalAddr(IPvXAddress("0.0.0.0"));
                openCmd->setLocalPort(subflow->localPort);
                openCmd->setConnId(subflow->connId);
                openCmd->setFork(true);
                openCmd->setSendQueueClass(subflow->getTcpMain()->par("sendQueueClass"));
                openCmd->setReceiveQueueClass(subflow->getTcpMain()->par("receiveQueueClass"));
                openCmd->setTcpAlgorithmClass(subflow->getTcpMain()->par("tcpAlgorithmClass"));
                openCmd->setSubFlowNumber(getLocalToken());

                openCmd->setIsMptcpSubflow(true);
                msg->setControlInfo(openCmd);
                msg->setContextPointer(newSubflow);
// TODO: What is better to schedule this as selfmessage or to hande it as call
               //
//                newSubflow->processAppCommand(msg);
                newSubflow->getTcpMain()->scheduleAt(simTime() + 0.00001, msg);
                DEBUGPRINT("[MPTCP][HANDSHAKE][MP_CAPABLE] ESTABLISHED after enqueue a ACK%s","\0");
                MPTCP_FSM(ESTABLISHED);
            } else {
                ASSERT(false); // FIXME Just for Testing
            }
            break;
        }
        // MPTCP ESTABLISHED

        default:
            DEBUGPRINT("[MPTCP][HANDSHAKE][MP_CAPABLE][ERROR] Options length exceeded! Segment will be sent without options%s","\0");
            ASSERT(false); // FIXME Just for Testing
        break;
    }
    return t;
}

/**
 * Do the MP_JOIN Handshake
 */
int MPTCP_Flow::_writeJoinHandshakeHeader(uint t, TCPStateVariables* subflow_state,
        TCPSegment *tcpseg, TCPConnection* subflow, TCPOption* option) {
    /*
        ------------------------                       ----------
         Address A1    Address A2                       Address B1
         ----------    ----------                       ----------
             |             |                                |
             |             |                                |
             |             |   SYN + MP_JOIN(Token-B, R-A)  |
             |             |------------------------------->|
             |             |<-------------------------------|
             |             |  SYN/ACK + MP_JOIN(MAC-B, R-B) |
             |             |                                |
             |             |      ACK + MP_JOIN(MAC-A)      |
             |             |------------------------------->|
             |             |<-------------------------------|
             |             |             ACK                |

       MAC-A = MAC(Key=(Key-A+Key-B), Msg=(R-A+R-B))
       MAC-B = MAC(Key=(Key-B+Key-A), Msg=(R-B+R-A))
    */
    // NOTE The key material (Token-B and Mac is generated earlier in processMPTCPSegment

    // Initiate some helper
    uint32_t first_bits = 0x0;

    // the state is still established for another subflow, but here we need to initiate the handshake
    // whether a SYN or ACK for a SYN ACK is send -> new MPTCP Flow

    // 1) Handle new adresses and/or connections MP_JOIN
    // FIXME ADD_ADDR/ REMOVE ADDR
    // FIXME DSS

    DEBUGPRINT("[MPTCP][HANDSHAKE][MP_JOIN] ESTABLISHED should use MP_JOIN%s","\0");

    first_bits = (first_bits | ((uint16_t) MP_JOIN)); //12
    first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);

// SYN MP_JOIN
    // Add MP_JOIN on a SYN of a established MULTIPATH Connection
    if (tcpseg->getSynBit() && (!tcpseg->getAckBit())) {
        // OK, we are still established so, this must be a JOIN or ADD.
        // ADD is not handled here (FIXME ADD), so it must be a MP_JOIN
        // this is triggert by a self message, called by joinConnection()
        DEBUGPRINT("[MPTCP][HANDSHAKE][MP_JOIN] SYN with MP_JOIN%s","\0");

        // Prepare
        assert(MP_JOIN_SIZE_SYN==12); // In the draft it is defined as 12
        option->setLength(MP_JOIN_SIZE_SYN);
        option->setValuesArraySize(3);
        option->setValues(0, first_bits);

        // FIXME Missing Address ID (!!!!)
        option->setValues(1,getRemoteToken());

        subflow->randomA = 0; // FIXME (uint32)generateKey();
        option->setValues(2, subflow->randomA); // FIXME Sender's random number (Generator perhaps other one??)

        addSubflow(subflow->connId,subflow); // connection becomes stateful on SYN because we have to remember all values -> not needed for real implemenation

        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
        tcpseg->setOptions(t, *option);
        t++;

    }

// SYN-ACK MP_JOIN
    // Add MP_JOIN on a SYN/ACK of a etablished MULTIPATH Connection
    else if (tcpseg->getSynBit() && (tcpseg->getAckBit())) {
        DEBUGPRINT("[MPTCP][HANDSHAKE][MP_JOIN] SYN ACK with MP_JOIN <Not filled yet>%s","\0");

        // Prepare
        assert(MP_JOIN_SIZE_SYNACK==16); // In the draft it is defined as 12
        option->setLength(MP_JOIN_SIZE_SYNACK);
        option->setValuesArraySize(3);
        option->setValues(0, first_bits);
        // FIXME B
        // FIXME Adress ID


        // generate the tuncated MAC (64) and the random Number of the Receiver (Sender of the Packet)
        // FIXME For second Parameter
        option->setValues(1, 0); // FIXME truncated MAC 64
        option->setValues(2, 0); // FIXME Random Number

        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
        tcpseg->setOptions(t, *option);
        t++;
        DEBUGPRINT("[MPTCP][HANDSHAKE][MP_JOIN] Pre-Established after enqueue of SYN-ACK%s","\0");

// ACK MP_JOIN
    } else if ((!tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
        // MPTCP OUT MP_JOIN ACK
        DEBUGPRINT("[MPTCP][HANDSHAKE][MP_JOIN] ACK with MP_JOIN <Not filled yet>%s","\0");

        // Prepare
        assert(MP_JOIN_SIZE_ACK==24); // In the draft it is defined as 12
        option->setLength(MP_JOIN_SIZE_ACK);
        option->setValuesArraySize(3);
        option->setValues(0, first_bits);


        // generate the tuncated MAC (64) and the random Number of the Receiver (Sender of the Packet)
        // FIXME FIXME FIXME
        option->setValues(1, 0); // FIXME truncated MAC 64
        option->setValues(2, 0); // FIXME Random Number

        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
        tcpseg->setOptions(t, *option);
        t++;

       DEBUGPRINT("[MPTCP][HANDSHAKE][MP_JOIN] Established after enqueue of SYN%s","\0");

    }
    else {
        DEBUGPRINT("[MPTCP][HANDSHAKE][ERRROR]%s","\0");;
    }
    return t;
}

    /**
     * Initiation of a new subflow of a multipath TCP connection
     */
bool MPTCP_Flow::_prepareJoinConnection() {
    // 1) Check for valid adresses and combinations
    // 2) Setup selfmessages
    // 3) Delete combination from join queue
    static bool working = false;
    int cnt = 0;

    if((!working) && (join_queue.size() > 0)){
        bool skip = false;
        working = true;
        if(this->getState() != ESTABLISHED) return false;

        // In case we know new address pairs...

        TCP_JoinVector_t::const_iterator it;

        for (it = join_queue.begin(); it != join_queue.end(); it++,cnt++) {
            AddrCombi_t* c = (AddrCombi_t *)(*it);
            DEBUGPRINT("Work on possible Join: %s:%d to %s:%d\n", c->local.addr.str().c_str(), c->local.port,  c->remote.addr.str().c_str(), c->remote.port);

            ASSERT(subflow_list.size() != 0);
            TCP_subflow_t* entry = NULL;
            for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i
                       != subflow_list.end(); i++) {
                       entry = (*i);
                       if ((entry->subflow->remoteAddr ==  c->remote.addr)
                           && (entry->subflow->remotePort ==  c->remote.port)
                           && (entry->subflow->localAddr == c->local.addr)
                           && (entry->subflow->localPort == c->local.port)){
                           DEBUGPRINT("We know: %s:%d to %s:%d\n", c->local.addr.str().c_str(), c->local.port,  c->remote.addr.str().c_str(), c->remote.port);
                           skip = true;
                           break;
                       }
               }
            if(skip){
                skip = false;
                continue;
            }
            if(entry==NULL) // it doesn't matter which enty we use, we need only one subflow
                continue;   // if there is no known subflow, we have nothing todo
            TCPConnection* tmp = entry->subflow;
            ASSERT(tmp->getTcpMain()!=NULL);

           DEBUGPRINT("Check if new MPTCP Subflow: %s:%d to %s:%d\n", c->local.addr.str().c_str(), c->local.port,  c->remote.addr.str().c_str(), c->remote.port);

            // ignore local addresses
            if(IPvXAddress("127.0.0.1").equals(c->local.addr)){
                tcpEV<< "[MPTCP][PREPARE JOIN] skip 127.0.0.1\n";
                continue;
            }
            if(IPvXAddress("0.0.0.0").equals(c->local.addr)){
                tcpEV<< "[MPTCP][PREPARE JOIN] skip 0.0.0.0\n";
                continue;
            }

            // ignore still etablished subflows
            TCP_JoinVector_t::const_iterator it_tj;
            for (it_tj = tried_join.begin(); it_tj != tried_join.end(); it_tj++) {
                AddrCombi_t* tmp = (AddrCombi_t*) *it_tj;
                if ((c->local.addr.equals(tmp->local.addr)) && (c->remote.addr.equals(tmp->remote.addr))) {

                   DEBUGPRINT("[MPTCP][PREPARE JOIN] Connection still known%s","\0");
                    skip = true;
                    break;
                }
            }

            // #############################################
            // Create selfmessage for new subflow initiation

            // Is this a possible new subflow?
            if(!skip) {

 //               if(tmp->getTcpMain()->isKnownConn(c->local.addr,tmp->localPort,c->remote.addr,tmp->remotePort))
 //                       continue; // OK TCP still knows this subflow, do nothing
                DEBUGPRINT("\nTry to add Subflow: %s:%d to %s:%d\n", c->local.addr.str().c_str(), c->local.port,  c->remote.addr.str().c_str(), c->remote.port);

                // create a internal message for another active open connection
                TCPConnection* newSubflow = tmp->cloneMPTCPConnection(true);
                cMessage *msg = new cMessage("ActiveOPEN", TCP_C_OPEN_ACTIVE);  // Client Side Connection

                // setup the subflow
                TCPOpenCommand *openCmd = new TCPOpenCommand();
                openCmd->setConnId(tmp->connId);
                openCmd->setLocalAddr(c->local.addr);
                openCmd->setLocalPort(tmp->localPort);
                openCmd->setRemoteAddr(c->remote.addr);
                openCmd->setRemotePort(tmp->remotePort);
                openCmd->setSendQueueClass(tmp->getTcpMain()->par("sendQueueClass"));
                openCmd->setReceiveQueueClass(tmp->getTcpMain()->par("receiveQueueClass"));
                openCmd->setTcpAlgorithmClass(tmp->getTcpMain()->par("tcpAlgorithmClass"));
                openCmd->setSubFlowNumber(getLocalToken());

                // initiate handshake for subflow
                openCmd->setIsMptcpSubflow(true);
                msg->setControlInfo(openCmd);
                msg->setContextPointer(newSubflow);
     //           newSubflow->processAppCommand(msg);
                tmp->getTcpMain()->scheduleAt(simTime() + 0.00001, msg);
                goto freeAndfinish;
            }
        }
        // I go true the list and nothing was usefull....clear it
        join_queue.clear();

        goto finish;
    }
    else{

        return false;
    }

    ASSERT(false); // should never reached

freeAndfinish:
    join_queue.erase(join_queue.begin()+cnt);
finish:
    working = false;
    return true;
}

/**
 * Do the SQN Number Work for to send packet. DSS context
 * @param uint TCP Option Count
 * @param TCPStateVariables* State of the subflow
 * @param TCPSegment* The Segment to work on
 * @param TCPConnection* the subflow itself
 * @param TCPOption* A prepared TCP Option object
 */
int MPTCP_Flow::_writeDSSHeaderandProcessSQN(uint t,
            TCPStateVariables* subflow_state, TCPSegment *tcpseg,
            TCPConnection* subflow, TCPOption* option){

    /*
       The Data Sequence Mapping and the Data ACK are signalled in the Data
       Sequence Signal (DSS) option.  Either or both can be signalled in one
       DSS, dependent on the flags set.  The Data Sequence Mapping defines
       how the sequence space on the subflow maps to the connection level,
       and the Data ACK acknowledges receipt of data at the connection
       level.
    */

    /*
    DSS packet format:
    1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +---------------+---------------+-------+----------------------+
    |     Kind      |    Length     |Subtype| (reserved) |F|m|M|a|A|    // Flags defined in Header
    +---------------+---------------+-------+----------------------+
    |           Data ACK (4 or 8 octets, depending on flags)       |    // Data Acknowledgements
    +--------------------------------------------------------------+
    |   Data Sequence Number (4 or 8 octets, depending on flags)   |    // Data Sequence Mapping
    +--------------------------------------------------------------+
    |              Subflow Sequence Number (4 octets)              |    // Data Sequence Mapping
    +-------------------------------+------------------------------+
    |  Data-level Length (2 octets) |      Checksum (2 octets)     |    // Data Sequence Mapping
    +-------------------------------+------------------------------+
    */

    // Initiate some helper
    uint32 first_bits = 0x0;
    DEBUGPRINT("[MPTCP][PROCESS SQN] start%s","\0");
    first_bits = (first_bits | ((uint16_t) MP_DSS));
    first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);


// Data Sequence Mapping [Section 3.3.1] ==> OUT
    // Note: if ACK is available we have to set the flag
    first_bits |= DSS_FLAG_M;
    // Switch: NED Parameter multipath_DSSSeqNo8
    if(subflow->getTcpMain()->multipath_DSSSeqNo8)
    {
        first_bits |= DSS_FLAG_m; // 8 or 4 Octets
    }
    // Note:
    // Fill Data Sequence Number with complete 64bit number or lowest 32
    // Subflow SQN is relativ to the SYN
    // Data-Level length Payload
    // Checksum if flag in MP_CAPABLE was set


// Data Acknowledgments [Section 3.3.2] ==> OUT
    // Note: if ACK is available we have to set the flag
    first_bits |= DSS_FLAG_A;
    // Switch: NED Parameter multipath_DSSDataACK8
    if(subflow->getTcpMain()->multipath_DSSDataACK8)
    {
        first_bits |= DSS_FLAG_a;// 8 or 4 Octets
    }
    // Note:
    // Data ACK fill with cum SQN
    // TODO getNewCumSQN

    //uint64_t cumSQN = queue_mgr->getCumSQN();   // First Step: Report every time a new cum SQN
    // Switch: NED Parameter multipath_DSSDataACK8

    // DSS size is variable ... 8...20
    option->setLength(8);
    option->setValuesArraySize(1);
    option->setValues(0, first_bits);
    // generate the tuncated MAC (64) and the random Number of the Receiver (Sender of the Packet)
    // FIXME For second Parameter
//  option->setValues(1, 0); // FIXME truncated MAC 64
//  option->setValues(2, 0); // FIXME Random Number

    tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
    tcpseg->setOptions(t, *option);
    t++;

    return 0;
}


TCPConnection* MPTCP_Flow::schedule(TCPConnection* save, cMessage* msg){
    // easy scheduler
    static int scheduler = 0;
    int cnt=0;

    TCP_subflow_t* entry = NULL;
    cPacket* pkt = PK(msg);
    int64 len =pkt->getByteLength();
    char message_name[255];
    int msg_nr = 0;
    // We split every data for scheduling, if there bigger than connection MMS
    for(int64 offset = 0; offset <len;){

        scheduler++;
        for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i
                  != subflow_list.end(); i++) {
                  entry = (*i);
                  scheduler++;
                  DEBUGPRINT("Scheulder %d==%d %d==%d",scheduler,subflow_list.size(),(scheduler%subflow_list.size()),0);

                  if(((scheduler%(subflow_list.size())))==0){

                      // get the mms
                      uint32 mss = entry->subflow->getState()->snd_mss;
                      sprintf(message_name,"MPTCP%i",scheduler);
                      cPacket *part_msg = new cPacket(message_name);
                      offset += mss;
                      if(offset < len){
                          part_msg->setByteLength(mss);
                      }
                      else{
                          part_msg->setBitLength(mss-(len-offset));
                          delete msg;
                      }

                      DEBUGPRINT("[FLOW][SUBFLOW][%i][STATUS] Send via  %s:%d to %s:%d", cnt, entry->subflow->localAddr.str().c_str(), entry->subflow->localPort, entry->subflow->remoteAddr.str().c_str(), entry->subflow->remotePort);
                      _createMSGforProcess(part_msg,entry->subflow);


                  }
        }

    }
    return save;
}

void MPTCP_Flow::_createMSGforProcess(cMessage *msg, TCPConnection* sc){
   msg->setKind(TCP_C_MPTCP_SEND);
   TCPSendCommand *cmd = new TCPSendCommand();
   cmd->setConnId(sc->connId);
   msg->setControlInfo(cmd);
   sc->processAppCommand(msg);
   //sc->getTcpMain()->scheduleAt(simTime() + 0.1, msg);
}

void MPTCP_Flow::initKeyMaterial(TCPConnection* subflow){
    _generateSYNACK_HMAC(_getLocalKey(), _getRemoteKey(), subflow->randomA, subflow->randomB, subflow->MAC64);
    _generateACK_HMAC(_getLocalKey(), _getRemoteKey(), subflow->randomA, subflow->randomB, subflow->MAC160);
}

bool MPTCP_Flow::keysAreEqual(uint64_t rk, uint64_t lk ){
    if((rk == this->_getRemoteKey()) && (lk == this->_getLocalKey())){
        return true;
    }
    return false;
}

// ########################################### KEY HELPER STUFF #########################################
/**
 * Generate a 64 Byte Key
 * @return unit64 The Key
 */
uint64_t MPTCP_Flow::_generateLocalKey() {

    // FIXME be sure it is unique
    uint64_t key = intrand((long)UINT64_MAX);

    setLocalKey(key); // use setter helper to set in object
    return key;
}



/**
 * generate
 * - Start SQN
 * - Token ID
 */
int MPTCP_Flow::_generateToken(uint64_t key, bool type) {

// FIXME: irgendwas ist faul
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#error  "SHA NOT SUPPORTED."
#endif

    SHA_CTX ctx;
    unsigned char dm[SHA_DIGEST_LENGTH]; // SHA_DIGEST_LENGTH = 20 Bytes


    uint32_t *out32 = { 0 };
    uint64_t *out64 = { 0 };

    SHA1_Init(&ctx);
    // generate SHA-1 for token
    SHA1_Update(&ctx,(const void*) &key, sizeof(uint64_t));
    SHA1_Final((unsigned char*) dm, &ctx);

    out64 = (uint64*) dm; // Should be a different one, but for simulation it is enough
    out32 = (uint32*) dm; // most significant 32 bits [Section 3.2]
    DEBUGPRINT("[FLOW][OUT] Generate TOKEN: %u:  ",*out32);
    DEBUGPRINT("[FLOW][OUT] Generate SQN: %ld:  ",*out64);
    switch(type){
    case MPTCP_LOCAL:  setLocalToken(*out32);
        break;
    case MPTCP_REMOTE: setRemoteToken(*out32);
        break;
    default: ASSERT(false); break;
    }
    if(type==MPTCP_LOCAL)
        setBaseSQN(*out64);
    return 0;
}

/**
 * generate body of SYN/ACK HMAC
 */
unsigned char* MPTCP_Flow::_generateSYNACK_HMAC(uint64 ka, uint64 kb, uint32 ra,
        uint32 rb, unsigned char* digist) {
    // On Host B - Not Initiator
    char key[38];
    char msg[20];

    // Need MAC-B
    // MAC(KEY=(Key-B + Key-A)), Msg=(R-B + R-A))
    sprintf(key, "%19ld%19ld", kb, ka);
    sprintf(msg, "%10u%10u", rb, ra);
    _hmac_md5((unsigned char*) msg, strlen(msg), (unsigned char*) key, strlen(
            key), digist);
    return digist;
}
/**
 * generate body of ACK HMAC
 */
unsigned char* MPTCP_Flow::_generateACK_HMAC(uint64 ka, uint64 kb, uint32 ra,
        uint32 rb, unsigned char* digist) {
    // On Host A - The Initiator
    char key[38];
    char msg[20];

    // Need MAC-A
    // MAC(KEY=(Key-A + Key-B)), Msg=(R-A + R-B))
    sprintf(key, "%19ld%19ld", ka, kb);
    sprintf(msg, "%10u%10u", ra, rb);
    _hmac_md5((unsigned char*) msg, strlen(msg), (unsigned char*) key, strlen(
            key), digist);
    return digist;
}

/*
 ** Function: hmac_md5 by RFC 2104
 * @param text;          pointer to data stream
 * @param text_len;      length of data stream
 * @param key;           pointer to authentication key
 * @param key_len;       length of authentication key
 * @param digest;        caller digest to be filled in
 */
void MPTCP_Flow::_hmac_md5(unsigned char* text, int text_len,
        unsigned char* key, int key_len, unsigned char* digest)

{
    MD5_CTX context;
    unsigned char k_ipad[65]; /* inner padding -
     * key XORd with ipad
     */
    unsigned char k_opad[65]; /* outer padding -
     * key XORd with opad
     */
    unsigned char tk[16];
    int i;
    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    if (key_len > 64) {

        MD5_CTX tctx;

        MD5_Init(&tctx);
        MD5_Update(&tctx, (const void*)  key, (size_t) key_len);
        MD5_Final(tk, &tctx);

        key = tk;
        key_len = 16;
    }

    /*
     * the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

    /* start out by storing key in pads */
    bzero((void*) k_ipad, sizeof(k_ipad));
    bzero((void*) k_opad, sizeof(k_opad));
    bcopy((const void*) key, (void*) k_ipad, key_len);
    bcopy((const void*) key, (void*) k_opad, key_len);

    /* XOR key with ipad and opad values */
    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    /*
     * perform inner MD5
     */
    MD5_Init(&context); /* init context for 1st
     * pass */
    MD5_Update(&context, (const void*) k_ipad, (size_t) 64); /* start with inner pad */
    MD5_Update(&context, (const void*) text, (size_t) text_len); /* then text of datagram */
    MD5_Final(digest, &context); /* finish up 1st pass */
    /*
     * perform outer MD5
     */
    MD5_Init(&context); /* init context for 2nd
     * pass */
    MD5_Update(&context, k_opad, 64); /* start with outer pad */
    MD5_Update(&context, digest, 16); /* then results of 1st
     * hash */
    MD5_Final(digest, &context); /* finish up 2nd pass */
}

// ########################################### Getter Setter #########################################

/**
 * getter function sender_key
 */
uint64_t MPTCP_Flow::_getLocalKey() {
    return local_key;
}

/**
 * getter function receiver_key
 */
uint64_t MPTCP_Flow::_getRemoteKey() {
    return remote_key;
}

/**
 * getter function for state
 */
MPTCP_State MPTCP_Flow::getState() {
    return state;
}

const TCP_SubFlowVector_t* MPTCP_Flow::getSubflows(){
    return &subflow_list;
}

MPTCP_PCB* MPTCP_Flow::getPCB(){
    return pcb;
}

uint64_t MPTCP_Flow::getHighestCumSQN(){
    return queue_mgr->getHighestReceivedSQN();
}

uint64_t MPTCP_Flow::getBaseSQN(){
    return getSQN();
}
/**
 * setter for sender_key
 */
void MPTCP_Flow::setRemoteKey(uint64_t key) {
    if(remote_key){
        DEBUGPRINT("[FLOW][OUT] Reset TOKEN: NEW REMOTE %ld:  ",key);
        DEBUGPRINT("[FLOW][OUT] Reset TOKEN: OLD LOCAL  %ld:  ",local_key);
        DEBUGPRINT("[FLOW][OUT] Reset TOKEN: OLD REMOTE %ld:  ",remote_key);
        ASSERT(remote_key == key);
        return;
    }
    _generateToken(key, MPTCP_REMOTE);
    remote_key = key;
}
/**
 * setter for sender_key
 */
void MPTCP_Flow::setLocalKey(uint64_t key) {
    if(local_key){ // For Testing
        DEBUGPRINT("[FLOW][OUT] Reset TOKEN: NEW LOCAL %ld:  ",key);
        DEBUGPRINT("[FLOW][OUT] Reset TOKEN: OLD LOCAL  %ld:  ",local_key);
        DEBUGPRINT("[FLOW][OUT] Reset TOKEN: OLD REMOTE %ld:  ",remote_key);
        ASSERT(key==local_key);
        return;
    }
    _generateToken(key, MPTCP_LOCAL);
    local_key = key;
}


uint64_t MPTCP_Flow::getSQN(){
    return seq;
}
void MPTCP_Flow::setBaseSQN(uint64_t s){
    DEBUGPRINT("[FLOW][INFO] INIT SQN from %ld to %ld",seq,s);
    ASSERT(seq == 0);
    seq = s;
}

void MPTCP_Flow::setRemoteToken(uint32_t t){
    remote_token = t;
}
void MPTCP_Flow::setLocalToken(uint32_t t){
    local_token = t;
}

uint32_t MPTCP_Flow::getRemoteToken(){
    return remote_token;
}
uint32_t MPTCP_Flow::getLocalToken(){
    return local_token;
}
/**
 * helper set function
 */
int MPTCP_Flow::setState(MPTCP_State s) {
    if(state == s){
        ASSERT(state != s);
    }
    if(s == ESTABLISHED){
        DEBUGPRINT("[FLOW][OUT]IS ESTABLISHED Remote Token %u:  ",getRemoteToken());
        DEBUGPRINT("[FLOW][OUT]IS ESTABLISHED Local Token %u:  ", getLocalToken());
    }
    state = s;
    return state;
}

int MPTCP_Flow::getAppID(){
    return appID;
}
int MPTCP_Flow::getappGateIndex(){
    return appGateIndex;
}

void MPTCP_Flow::DEBUGprintMPTCPFlowStatus(){
#ifdef PRIVATE_DEBUG
    DEBUGprintStatus();
#endif
}
void MPTCP_Flow::DEBUGprintStatus(){
#ifdef PRIVATE_DEBUG

    DEBUGPRINT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FLOW %lu >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>",this->getRemoteToken());
    DEBUGPRINT("[FLOW][STATUS] Sequence Number: %ld",seq);
    DEBUGPRINT("[FLOW][STATUS] snd_una: %ld",snd_una);
    DEBUGPRINT("[FLOW][STATUS] snd_nxt: %ld",snd_nxt);
    DEBUGPRINT("[FLOW][STATUS] snd_wnd: %d", snd_wnd);
    DEBUGPRINT("[FLOW][STATUS] rcv_nxt: %ld",rcv_nxt);
    DEBUGPRINT("[FLOW][STATUS] rcv_wnd: %ld",rcv_wnd);

    int cnt = 0;
    TCP_subflow_t* entry = NULL;
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i
               != subflow_list.end(); i++,cnt) {
               entry = (*i);
               DEBUGPRINT("[FLOW][SUBFLOW][%i][STATUS] Connections  %s:%d to %s:%d", cnt, entry->subflow->localAddr.str().c_str(), entry->subflow->localPort, entry->subflow->remoteAddr.str().c_str(), entry->subflow->remotePort);
               DEBUGPRINT("[FLOW][SUBFLOW][%i][STATUS] rcv_nxt: %i\t snd_nxt: %i",cnt, entry->subflow->getState()->rcv_nxt,entry->subflow->getState()->snd_nxt);
       }


    DEBUGPRINT("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< FLOW %lu <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<",this->getRemoteToken());
#endif
}

// end MPTCP_Flow

#endif // Private
