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

#include "TCP.h"
#include "TCPConnection.h"
#include "TCPMultipathFlow.h"
#include "TCPSACKRexmitQueue.h"
#include "TCPSchedulerManager.h"
#include "TCPAlgorithm.h"
#include "TCPSendQueue.h"

#include "TCPTahoeRenoFamily.h"

#include <map>
#if defined(__APPLE__)
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#define SHA1 CC_SHA1
#else
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <inttypes.h>
#endif

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

#define MP_ADD_ADDR_SIZE ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE) >> 3)

// Version of MPTCP
#define VERSION 0x0

int MPTCP_Flow::CNT = 0;
/**
 * Constructor
 * @param int ID for each Flow
 * @param int aAppGateIndex Application Gate Index for Flow
 * @param int MPTCP_PCB Protocol Control Block for Flow
 */
MPTCP_Flow::MPTCP_Flow(int connID, int aAppGateIndex, TCPConnection* subflow,
        MPTCP_PCB* aPCB) :
        state(IDLE), local_key(0), remote_key(0) {
    ID = CNT++;
    // For easy PCB Lookup set ID and Application Index
    appID = connID;
    appGateIndex = aAppGateIndex;
    pcb = aPCB;
    seq = 0;
    // Identifier
    local_token = 0;
    remote_token = 0;

    // Sending side
    mptcp_snd_una = subflow->getState()->snd_una;
    mptcp_snd_nxt = subflow->getState()->getSndNxt();
    mptcp_snd_wnd = subflow->getState()->snd_wnd;
    // Receiver Side
    mptcp_rcv_nxt = subflow->getState()->rcv_nxt;
    mptcp_rcv_wnd = subflow->getState()->rcv_wnd;
    mptcp_rcv_adv = subflow->getState()->rcv_adv;
    maxBuffer = subflow->getState()->maxRcvBuffer;

    isPassive = false;
    isFIN = false;
    // Init the flow
    if (subflow->localPort > 0)
        _initFlow(subflow->localPort);

    sendEstablished = false;
    _readParameter(subflow);
    char name[255]; // opp_dup will be called
    sprintf(name, "[FLOW-%d][RCV-QUEUE] size", ID);
    mptcpRcvBufferSize = new cOutVector(name);
    lastscheduled = NULL;
    lastenqueued = NULL;
    commonSendQueueLimit = 0;

    // init for MPTCP CC
    utilizedCMTCwnd = 0;
    totalCMTCwnd = 0;
    totalCMTSsthresh = 0;
//    maxCwndBasedBandwidth = 0;
//    totalCwndBasedBandwidth = 0;
    cmtCC_alpha = 0;
    tmp_msg_buf = subflow->tmp_msg_buf;
    mptcp_highestRTX = 0;
    old_mptcp_highestRTX = 0;
    isMPTCP_RTX = false;
    buffer_blocked = false;
    inConSNBlock = false;
}

void MPTCP_Flow::_readParameter(TCPConnection *subflow) {
    // initial Receive Queue
    mptcp_receiveQueue = check_and_cast<TCPMultipathReceiveQueue*>(
            createOne(
                    subflow->getTcpMain()->par("multipath_receiveQueueClass")));
    mptcp_receiveQueue->setFlow(this);

    ordered = subflow->getTcpMain()->par("multipath_ordered");

    // Check kind of link utilisat
    if (strcmp(
            (const char*) subflow->getTcpMain()->par(
                    "multipath_link_uitlization"), "cross") == 0) {
        path_utilization = CROSS;
    } else if (strcmp(
            (const char*) subflow->getTcpMain()->par(
                    "multipath_link_uitlization"), "linear") == 0) {
        path_utilization = LINEAR;
    } else {
        throw cRuntimeError("Bad setting for multipath_path_scheduler: %s\n",
                (const char*) subflow->getTcpMain()->par(
                        "multipath_path_scheduler"));
    }

    // Opportunistic retransmission
    if (strcmp(
            (const char*) subflow->getTcpMain()->par(
                    "multipath_opportunistic_retransmission"), "on") == 0) {
        opportunisticRetransmission = true;
    } else if (strcmp(
            (const char*) subflow->getTcpMain()->par(
                    "multipath_opportunistic_retransmission"), "off") == 0) {
        opportunisticRetransmission = false;
    } else {
        throw cRuntimeError(
                "Bad setting for multipath_path_opportunistic_retranmssion: %s\n",
                (const char*) subflow->getTcpMain()->par(
                        "multipath_path_opportunistic_retranmission"));
    }

    // multipath penalizing
    if (strcmp((const char*) subflow->getTcpMain()->par("multipath_penalizing"),
            "on") == 0) {
        multipath_penalizing = true;
    } else if (strcmp(
            (const char*) subflow->getTcpMain()->par("multipath_penalizing"),
            "off") == 0) {
        multipath_penalizing = false;
    } else {
        throw cRuntimeError("Bad setting for multipath_penalizing: %s\n",
                (const char*) subflow->getTcpMain()->par(
                        "multipath_penalizing"));
    }
    // multipath ConSN
    if (strcmp(
            (const char*) subflow->getTcpMain()->par(
                    "multipath_consn"), "on") == 0) {
        consn = true;
    } else if (strcmp(
            (const char*) subflow->getTcpMain()->par(
                    "multipath_consn"), "off") == 0) {
        consn = false;
    } else {
        throw cRuntimeError(
                "Bad setting for multipath_consn: %s\n",
                (const char*) subflow->getTcpMain()->par(
                        "multipath_consn"));
    }
}

/**
 * Destructor
 */
MPTCP_Flow::~MPTCP_Flow() {

    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); i++) {
        TCPConnection *conn = (*i)->subflow;
        // I want everything off
        if (conn != NULL && (conn->getState() != NULL))
            delete conn;
        conn = NULL;
    }

    subflow_list.clear();
    TCPSchedulerManager::destroyMPTCPScheduler();

    if (mptcp_receiveQueue) {
        mptcp_receiveQueue->clear();
        delete mptcp_receiveQueue;
        mptcp_receiveQueue = NULL;
    }
    if (mptcpRcvBufferSize) {
        delete mptcpRcvBufferSize;
        mptcpRcvBufferSize = NULL;
    }
    lastscheduled = NULL;
    lastenqueued = NULL;
}

void MPTCP_Flow::removeSubflow(TCPConnection* subflow) {
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); i++) {
        TCP_subflow_t* entry = (*i);
        if ((entry->subflow == subflow)) {
            subflow_list.erase(i);
            delete entry;
            break;
        }
    }
    // clean for non used entry
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); i++) {
        if ((*i) == NULL)
            i = subflow_list.erase(i);
    }
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
                tcpEV << "[MPTCP FLOW] add IPv4: "
                             << ift->getInterface(i)->ipv4Data()->getIPAddress()
                             << "\0";
                addr->addr = ift->getInterface(i)->ipv4Data()->getIPAddress();
                addr->port = port;
            } else if (ift->getInterface(i)->ipv6Data() != NULL) {
                for (int32 j = 0;
                        j < ift->getInterface(i)->ipv6Data()->getNumAddresses();
                        j++) {
                    tcpEV << "[MPTCP FLOW] add IPv6: "
                                 << ift->getInterface(i)->ipv6Data()->getAddress(
                                         j) << "\0";
                    addr->addr = ift->getInterface(i)->ipv6Data()->getAddress(
                            j);
                    addr->port = port;
                }
            } else {
                ASSERT(false && "What kind of address is this?");
            }

            // ############################
            // List of local address tuples
            if (addr->port != -1)
                list_laddrtuple.push_back(addr);
        }
    } else {
        // Should never happen...
        tcpEV << "[MPTCP FLOW][ERROR] Problems by adding all known IP adresses";
    }
    return;
}

#ifdef ADD_ADDR
int MPTCP_Flow::addADDR(AddrTupple_t* raddr) {

    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i != subflow_list.end(); i++) {
        TCP_subflow_t* entry = (*i);
        if ((entry->subflow->remoteAddr == raddr->addr) && (entry->subflow->remotePort == raddr->port)) {
            return 0;
        }
    }

    TCP_AddressVector_t::const_iterator it_r;
    for (it_r = list_raddrtuple.begin(); it_r != list_raddrtuple.end();
            it_r++) {
        AddrTupple_t* tmp_r = (AddrTupple_t*) *it_r;
        if ((tmp_r->addr.equals(raddr->addr))
                && (tmp_r->port == raddr->port)) {
            break;
        }
    }

    // add this address because it is unknown
    if (it_r == list_raddrtuple.end()) {
        list_raddrtuple.push_back(raddr);
    }

    bool found = false;
    AddrTupple_t* tmp_l;
    TCP_AddressVector_t::const_iterator it_l;
    for (it_l = list_laddrtuple.begin(); it_l != list_laddrtuple.end(); it_l++) {
        tmp_l = (AddrTupple_t*) *it_l;
        if (IPvXAddress("127.0.0.1").equals(tmp_l->addr)) {
            continue;
        }
        if (IPvXAddress("0.0.0.0").equals(tmp_l->addr)) {
            continue;
        }
        for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i != subflow_list.end(); i++) {
            TCP_subflow_t* entry = (*i);
            if ((entry->subflow->localAddr == tmp_l->addr) && (entry->subflow->localPort == tmp_l->port)) {
                found = true;
                break;
            }
        }
        if (found) {
            found = false;
            continue;
        } else {
            break;
        }
    }

    if (it_l != list_laddrtuple.end()) {
        TCPConnection* tmp = subflow_list.front()->subflow;

        int old = tmp->remotePort;
        tmp->remotePort = raddr->port;
        TCPConnection *conn_tmp = tmp->cloneMPTCPConnection(true,
                getLocalToken(), IPvXAddress(tmp_l->addr),
                IPvXAddress(raddr->addr));
        tmp->getTcpMain()->addNewMPTCPConnection(tmp, conn_tmp);
        tmp->isSubflow = true;
        tmp->remotePort = old;
    }

    return 1;
}
#endif // ADD_ADDR
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

    if ((subflow->localPort == -1) || (subflow->remotePort == -1))
        return 0;

    // If we know this subflow already something goes wrong
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); i++) {
        TCP_subflow_t* entry = (*i);
        if (((entry->subflow->remoteAddr == subflow->remoteAddr)
                && (entry->subflow->remotePort == subflow->remotePort)
                && (entry->subflow->localAddr == subflow->localAddr)
                && (entry->subflow->localPort == subflow->localPort)))

            return 0;
    }

    // set subflow as active
    subflow->getState()->sendQueueLimit = commonSendQueueLimit;
    t->active = true;
    t->subflow = subflow;
    t->subflow->flow = this;
    static int sub_cnt = 0; // TODO DEBUG
    sub_cnt++;              // TODO DEBUG
    t->cnt = sub_cnt;       // TODO DEBUG
    DEBUGPRINT("[FLOW][SUBFLOW][STATUS] add subflow from  %s:%d to %s:%d",
            subflow->localAddr.str().c_str(), subflow->localPort,
            subflow->remoteAddr.str().c_str(), subflow->remotePort);
    // add to list
    if (!t->subflow->inlist) {
        t->subflow->inlist = true;
        if (t->subflow->connId != this->appID) {
            DEBUGPRINT("FLOW connID %i ", this->appID);
            //return 0;
        }DEBUGPRINT("SUBFLOW connID %i ", t->subflow->connId);

        if (t->subflow->tmp_msg_buf != tmp_msg_buf) {
            while (!t->subflow->tmp_msg_buf->empty()) {
                tmp_msg_buf->push(t->subflow->tmp_msg_buf->front());
                t->subflow->tmp_msg_buf->pop();
            }
            delete t->subflow->tmp_msg_buf;
            t->subflow->tmp_msg_buf = tmp_msg_buf;
        }
        subflow_list.push_back(t);
        subflow->orderBytesForQueue(commonSendQueueLimit, true);
    }

    // ###################################
    // Check for further possible subflows
    // add the adresses of this subflow to the known address list for a MP_JOIN or add
    bool found = false;
    TCP_AddressVector_t::const_iterator it_r;
    for (it_r = list_raddrtuple.begin(); it_r != list_raddrtuple.end();
            it_r++) {
        AddrTupple_t* tmp_r = (AddrTupple_t*) *it_r;
        if ((tmp_r->addr.equals(subflow->remoteAddr))
                && (tmp_r->port == subflow->remotePort)) {
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

    for (it_r = list_raddrtuple.begin(); it_r != list_raddrtuple.end();
            it_r++) {
        AddrTupple_t* tmp_r = (AddrTupple_t*) *it_r;

        TCP_AddressVector_t::const_iterator it_l;
        for (it_l = list_laddrtuple.begin(); it_l != list_laddrtuple.end();
                it_l++) {
            AddrTupple_t* tmp_l = (AddrTupple_t*) *it_l;
            tcpEV << "[MPTCP][PREPARE ADD SUBFLOW] Base Addr:"
                         << subflow->localAddr << "\0";
            // collect data for possible new connections
            if (!tmp_l->addr.equals(subflow->localAddr)) {
                AddrCombi_t* to_join = new AddrCombi_t();
                to_join->local.addr = tmp_l->addr;
                to_join->remote.addr = tmp_r->addr;
                to_join->local.port = tmp_l->port;
                to_join->remote.port = tmp_r->port;

                DEBUGPRINT("Add Possible MPTCP Subflow: %s:%d to %s:%d",
                        to_join->local.addr.str().c_str(), to_join->local.port,
                        to_join->remote.addr.str().c_str(),
                        to_join->remote.port);

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
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); ++i) {
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
 * Main Entry Point for outgoing MPTCP segments.
 * - here we add MPTCP Options
 * - take care about SQN of MPTCP (Sender Side)
 * @param uint Count of options
 * @param TCPStateVariables* The State of the subflow
 * @param TCPSegment* The TCP segment to work for
 * @param TCPConnection* The connection itself
 */
int MPTCP_Flow::writeMPTCPHeaderOptions(uint t,
        TCPStateVariables* subflow_state, TCPSegment *tcpseg, uint32 bytes,
        TCPConnection* subflow) {

    // 1) Depending on state and segment type add multipath tcp options
    // TODO Split segment, if there is not enough space for the options
    // TODO Better error handling
    // TODO Generate a extra message e.g. an duplicate ACK (see draft section 2)
    // TODO CHECK FLOW FLAGS, eg. report or delete address
    // Initiate some helper

    // check if we should send more SACKS
//    if(buffer_blocked){
//        buffer_blocked = false;
//        for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
//                    i != subflow_list.end(); i++) {
//                TCPConnection *sub = (*i)->subflow;
//                if(subflow != sub)
//                    sub->sendAck();
//        }
//    }

    uint options_len = 0;
    TCPOption option;
    DEBUGPRINT(
            ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Prepare Outgoing Packet%s",
            "\0");
    // First check if is it allowed to add further options
    for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
        options_len = options_len + tcpseg->getOptions(i).getLength();

    // Check on not increasing the TCP Option
    ASSERT(options_len <= 40 && "Options > 40 not allowed");

    // Only work on MPTCP Options!!
    // (Note: If this is a design problem to do it here, we could move this to TCP...)
    option.setKind(TCPOPTION_MPTCP); // FIXME depending on IANA request
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
    if (this->isFIN) {
        tcpseg->setFinBit(true);
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
    if (tcpseg->getRstBit())
        return t;

    switch (this->state) {
    case ESTABLISHED: {
        DEBUGPRINT("[FLOW][OUT][SEND A MPTCP PACKET] ESTABLISHED (%i)", state);
        // complete additional subflow setup
        // If we in ESTABLISHED state and there comes up a syn we have to add a join for MPTCP transfer
        if (((subflow->isSubflow) && (tcpseg->getSynBit()))
                || subflow->joinToAck || subflow->joinToSynAck) {
            t = _writeJoinHandshakeHeader(t, subflow_state, tcpseg, subflow,
                    option);
            subflow->joinToAck = false;
            subflow->joinToSynAck = false;
        } else {
            DEBUGPRINT(
                    "[FLOW][OUT][SEND A MPTCP PACKET] DATA OUT Do SQN for subflow (%u) by utilizing DSS",
                    subflow->isSubflow);
            t = _writeDSSHeaderandProcessSQN(t, subflow_state, tcpseg, bytes,
                    subflow, option);
            if(t < 0) return t;
#ifdef ADD_ADDR
            if (subflow->add_addr) {
                TCPOption option2;
                option2.setKind(TCPOPTION_MPTCP);
                _writeADDADDRHeader(t, subflow_state, tcpseg, bytes, subflow,
                        &option2);
                subflow->add_addr = false;
            }
#endif // ADD_ADDR
        }
        break;
    }
    case SHUTDOWN:
        DEBUGPRINT("[FLOW][OUT] SHUTDOWN  (%i)", state)
        ;
        break;
    case PRE_ESTABLISHED:
        DEBUGPRINT("[FLOW][OUT] PRE ESTABLISHED (%i)", state)
        ;
        t = _writeInitialHandshakeHeader(t, subflow_state, tcpseg, subflow,
                option);
        break;
    case IDLE:
        DEBUGPRINT("[FLOW][OUT] Work on state %i - Figure out what to do",
                state)
        ;
        if ((tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
            DEBUGPRINT("[FLOW][OUT] Not ESTABLISHED here we go %i", state);
            // If we send the SYN ACK, we are the passive side, please note this
            isPassive = true;
        }
        t = _writeInitialHandshakeHeader(t, subflow_state, tcpseg, subflow,
                option);
        break;

    default:
        ASSERT(false && "State not supported");
        break;
    }
#ifndef ADD_ADDR
    if (this->state == ESTABLISHED && (!tcpseg->getSynBit())
            && (tcpseg->getAckBit())) {
        // FIXME Perhaps we need a switch for also handshake from passive side
        //
#define BOTH_SIDE_HANDSHAKE true

        if (BOTH_SIDE_HANDSHAKE || (!isPassive)) {
            // 3.2. Starting a New Subflow
            // It is permitted for
            // either host in a connection to initiate the creation of a new
            // subflow, but it is expected that this will normally be the original
            // connection initiator
            _prepareJoinConnection(); // FIXME -> Perhaps there is a better place, but in first try we check if there are new data received
        }
    }
#endif // ADD_ADDR
    DEBUGPRINT(
            "End Preparing Outgoing Segment <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<%c",
            '\0');
    return t;
}

bool MPTCP_Flow::close() {
    isFIN = true;
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); ++i) {
        TCP_subflow_t* entry = (*i);
        if (!entry->subflow->getState()->send_fin) {
            entry->subflow->process_CLOSE();
            entry->subflow->sendRst(entry->subflow->getState()->getSndNxt()); // FIXME RSt should not used here,... but we have to tear down the connextion

        }
    }
    return true;
}

bool MPTCP_Flow::sendData(bool fullSegmentsOnly) {
    //fullSegmentsOnly = true; // FIXME
    std::map<std::string, int> (ad_queue);
    weak_link = false;

    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); i++) {
        TCPConnection* conn = (*i)->subflow;
        TCPTahoeRenoFamilyStateVariables* another_state = check_and_cast<
                TCPTahoeRenoFamilyStateVariables*>(
                conn->getTcpAlgorithm()->getStateVariables());

        if (!conn->isSendQueueEmpty())  // have we any data to send?
        {
            if ((simTime() - another_state->time_last_data_sent)
                    > another_state->rexmit_timeout) {
                // RFC 5681, page 11: "For the purposes of this standard, we define RW = min(IW,cwnd)."
                if (another_state->increased_IW_enabled)
                    another_state->snd_cwnd = std::min(
                            std::min(4 * another_state->snd_mss,
                                    std::max(2 * another_state->snd_mss,
                                            (uint32) 4380)),
                            another_state->snd_cwnd);
                else
                    another_state->snd_cwnd = another_state->snd_mss;

                TCPBaseAlg* base = check_and_cast<TCPBaseAlg*>(
                        conn->getTcpAlgorithm());
                if (base->cwndVector)
                    base->cwndVector->record(another_state->snd_cwnd);
                if (base->ssthreshVector)
                    base->ssthreshVector->record(another_state->ssthresh);
            }
        }
    }

    switch (path_utilization) {
    case LINEAR:
        for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
                i != subflow_list.end(); i++) {
            TCP_subflow_t* entry = (*i);
            if (entry->subflow->isQueueAble) {
                if (ad_queue.end()
                        == ad_queue.find(entry->subflow->remoteAddr.str())) {
                    ad_queue.insert(
                            std::make_pair(entry->subflow->remoteAddr.str(),
                                    0));
                } else {
                    entry->subflow->isQueueAble = false;
                    removeSubflow(entry->subflow); // FIXME to add in list of unused subflows!!!
                    ad_queue.clear();
                    i = subflow_list.begin();
                }
            }
        }
        break;
    default:
        // cross ...nothing to do
        break;
    }
    ad_queue.clear();
    // Here is the System Scheduler
    // To rephrase it, here we decide how to schedule over the paths.
    if (subflow_list.empty())
        return false;
    MPTCP_PATH_SCHEDULER scheduler =
            (*(subflow_list.begin()))->subflow->getTcpMain()->multipath_path_scheduler;

    // First alternative: we fill the window depending on the RTT - TCP like

    switch (scheduler) {
    case Linux_like: {
        // start always with the path with the smallest RTT
        // map should insert in order
        std::map<double, int> path_order;
        int c = 0;

        for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
                i != subflow_list.end(); i++, c++) {
            TCPConnection* tmp = (*i)->subflow;
            if (tmp->isQueueAble) {
                TCPTahoeRenoFamilyStateVariables* another_state =
                        check_and_cast<TCPTahoeRenoFamilyStateVariables*>(
                                tmp->getTcpAlgorithm()->getStateVariables());
                    double sRTT = GET_SRTT(another_state->srtt.dbl());
                    for (;;) {
                        if (path_order.end() == path_order.find(sRTT)) {
                            path_order.insert(std::make_pair(sRTT, c));
                            break;
                        } else
                            sRTT += 0.001;
                    }
            }
        }
        // Steps to do
        // get first path of the list (e.g. best RTT path)
        // try to send
        //  - if ok     -> done
        //  - if not ok
        //      -> try optimizing
        //      -> next path
        for (std::map<double, int>::iterator o = path_order.begin();
                o != path_order.end(); o++) {
            TCPConnection* tmp = (*(subflow_list.begin() + o->second))->subflow;
            refreshSendMPTCPWindow();
            if (tmp->isQueueAble) {
                TCPTahoeRenoFamilyStateVariables* another_state =
                        check_and_cast<TCPTahoeRenoFamilyStateVariables*>(
                                tmp->getTcpAlgorithm()->getStateVariables());

               tmp->sendData(fullSegmentsOnly, another_state->snd_cwnd);

                 // if we are blocked -> correct behavior
                if ((another_state->snd_cwnd > (4*another_state->snd_mss))
                    && (mptcp_snd_wnd  < (mptcp_snd_nxt- mptcp_snd_una))
                    && (mptcp_snd_nxt != mptcp_snd_una) ) {

                    // The window is too small,
                    // if we not in an initial state do
                    // penalizing and opportunistic retransmission

                    // Penalize the flow with the smallest DSS
                    if (multipath_penalizing)
                        penalize(tmp, mptcp_snd_una);
                    if (opportunisticRetransmission) {
                        _opportunisticRetransmission(tmp);
                    }
                    //break;
                }
            }
        }
        path_order.clear();
    }
        break;
    default: {
        for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
                i != subflow_list.end(); i++) {
            TCP_subflow_t* entry = (*i);
            if (entry->subflow->isQueueAble) {
                TCPTahoeRenoFamilyStateVariables* another_state =
                        check_and_cast<TCPTahoeRenoFamilyStateVariables*>(
                                entry->subflow->getTcpAlgorithm()->getStateVariables());
                entry->subflow->sendData(fullSegmentsOnly,
                        another_state->snd_cwnd);
            }
            this->refreshSendMPTCPWindow();
        }
        break;
    }
    }

    return true;
}

void MPTCP_Flow::_opportunisticRetransmission(TCPConnection* sub) {

    // idea opportunistic retransmission
    // Send smallest DSS of alternative to free buffer blocking

    // update highest retransmitted...work in correct range
    if(sub->highestRTX_path < mptcp_snd_una){
        sub->highestRTX_path = mptcp_snd_una;
    }

    mptcp_highestRTX = sub->highestRTX_path;

    // save current state,
    // - to compare for max range
    // - to set back
    uint64 old_mptcp_snd_nxt = mptcp_snd_nxt;
    Scheduler_list::iterator s_itr = slist.begin();
    // count bytes sent by opportunistic rtx
    uint32 sent_by_opp = 0;

    // send until there are no more data, or window is closed
    for(;;){
        // search for the smallest DSS
        if(sub->highestRTX_path > mptcp_snd_nxt){
            return;
        }

        s_itr = slist.begin();
        // go through list
        while((s_itr != slist.end())){
          if((s_itr->first > sub->highestRTX_path)){
              if(sub != s_itr->second){
                  // found
                  mptcp_highestRTX = s_itr->first;
                  break;
              }
              else{
                  return;
              }
          }
          s_itr++;
        }

        // break condition is end of list
        if(s_itr == slist.end() || (mptcp_highestRTX >= old_mptcp_snd_nxt)){
            return;
        }

        // prepare
        TCPTahoeRenoFamilyStateVariables* another_state = check_and_cast<
                TCPTahoeRenoFamilyStateVariables*>(
                sub->getTcpAlgorithm()->getStateVariables());
        isMPTCP_RTX = true;
        mptcp_snd_nxt = mptcp_highestRTX;

        // send

        if((another_state->snd_cwnd > sent_by_opp + (another_state->snd_max - another_state->snd_una))){
            sub->orderBytesForQueue(another_state->snd_mss);

            sub->sendOneNewSegment(true, another_state->snd_cwnd);
        }

        // set back
        isMPTCP_RTX = false;


        // check if send successfull
        if (mptcp_snd_nxt != mptcp_highestRTX) {
            // new successful highest rtx

            // count sent data
            sent_by_opp += (mptcp_snd_nxt - mptcp_highestRTX - 1);
           // sub->orderBytesForQueue((mptcp_snd_nxt - mptcp_highestRTX - 1),true);
            // store new highestRTX
            mptcp_highestRTX = mptcp_snd_nxt;
            // set back mptcp next
            mptcp_snd_nxt = old_mptcp_snd_nxt;
            sub->highestRTX_path = mptcp_highestRTX;
        }else{
            mptcp_snd_nxt = old_mptcp_snd_nxt;
            return;
        }
    }
    return;
}

uint64 MPTCP_Flow::penalize(TCPConnection *sub, uint64 last) {

    Scheduler_list::iterator s_itr = slist.begin();
    while(s_itr != slist.end()){
        if(sub != s_itr->second){
            _penalize(s_itr->second);
            break;
        }
        s_itr++;
    }
    return s_itr->first;
}

void MPTCP_Flow::_penalize(TCPConnection *conn) {
    if (!multipath_penalizing)
        return;

    TCPTahoeRenoFamilyStateVariables* another_state = check_and_cast<
            TCPTahoeRenoFamilyStateVariables*>(
            conn->getTcpAlgorithm()->getStateVariables());
    if(another_state->lossRecovery || another_state->isRTX){
        return;
    }
    if (simTime() - conn->getState()->time_last_penalized
            > another_state->srtt) {
        another_state->ssthresh = std::max(another_state->snd_cwnd / 2,
                another_state->snd_mss);
        another_state->snd_cwnd = another_state->ssthresh;
        TCPBaseAlg* base = check_and_cast<TCPBaseAlg*>(conn->getTcpAlgorithm());
        if (base->cwndVector)
            base->cwndVector->record(another_state->snd_cwnd);
        if (base->ssthreshVector)
            base->ssthreshVector->record(another_state->ssthresh);
        // mark last penalized
        conn->getState()->time_last_penalized = simTime();
    }
}
/*
 * Do the MP_CAPABLE Handshake
 */
int MPTCP_Flow::_writeInitialHandshakeHeader(uint t,
        TCPStateVariables* subflow_state, TCPSegment *tcpseg,
        TCPConnection* subflow, TCPOption option) {

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
    DEBUGPRINT("Multipath FSM: Enter Initial Handshake%s", "\0");

    first_bits = (first_bits | ((uint16_t) MP_CAPABLE)); //12
    first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);

    version = (version | ((uint16_t) VERSION << MP_VERSION_POS));
    version = version << (MP_VERSION_POS + MP_SIGNAL_FIRST_VALUE_TYPE);
    first_bits |= version;

    switch (state) {
    // Connection initiation SYN; SYN/ACK; ACK of the whole flow it must contoain the MP_CAPABLE Option
    // MPTCP IDLE
    case IDLE: { // whether a SYN or ACK for a SYN ACK is send -> new MPTCP Flow

        if (!tcpseg->getSynBit()) {
            DEBUGPRINT("[FLOW][OUT] ERROR MPTCP Connection state: %u",
                    getState());
            // ASSERT(false && "Not a SYN -> in IDLE not allowed"); FIXME

            return t;
        }

// SYN MP_CAPABLE
        // Check if it is whether a SYN or SYN/ACK
        if (tcpseg->getSynBit() && (!tcpseg->getAckBit())) { // SYN
            DEBUGPRINT(
                    "[MPTCP][HANDSHAKE][MP_CAPABLE] IDLE working for sending a SYN%s",
                    "\0");

            // Prepare
            option.setLength(MP_CAPABLE_SIZE_SYN);
            option.setValuesArraySize(3);
            option.setValues(0, first_bits);

            // generate local_key(!!) Section 3.1 => only time the key will send in clear

            _generateLocalKey();

            ASSERT(local_key != 0 && "Something is wrong with the local key");
            // set 64 bit value
            uint32_t value = (uint32_t) _getLocalKey();
            option.setValues(1, value);
            value = _getLocalKey() >> 32;
            option.setValues(2, value);
            addSubflow(0, subflow); // OK this is the first subflow and should be add
            this->MPTCP_FSM(PRE_ESTABLISHED)
            ;DEBUGPRINT("[FLOW][OUT] Generate Sender Key in IDLE for SYN: %ld",
                    _getLocalKey());

// SYN-ACK MP_CAPABLE
        } else if (tcpseg->getSynBit() && tcpseg->getAckBit()) { // SYN/ACK
            DEBUGPRINT(
                    "[MPTCP][HANDSHAKE][MP_CAPABLE] IDLE working for sending a SYN-ACK%s",
                    "\0");

            // Prepare
            option.setLength(MP_CAPABLE_SIZE_SYNACK);
            option.setValuesArraySize(3);
            option.setValues(0, first_bits);

            // generate receiver_key -> important is key of ACK
            _generateLocalKey();

            ASSERT(local_key != 0 && "Something is wrong with the local key");
            // set 64 bit value
            uint32_t value = (uint32_t) _getLocalKey();
            option.setValues(1, value);
            value = _getLocalKey() >> 32;
            option.setValues(2, value);

            DEBUGPRINT(
                    "[FLOW][OUT] Generate Receiver Key in IDLE for SYN-ACK: %ld",
                    _getLocalKey());
            this->MPTCP_FSM(ESTABLISHED)
            ; //TEST
            tcpEV
                         << "[MPTCP][HANDSHAKE][MP_CAPABLE] PRE_ESTABLISHED after send SYN-ACK";

        } else
            ASSERT(false);
        // FIXME Just for Testing

        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
        tcpseg->setOptions(t, option);
        t++;
        break;
    }

        // MPTCP PRE_ESTABLISHED
    case PRE_ESTABLISHED: { // whether ACK for a SYN ACK is send -> new MPTCP Flow

// ACK MP_CAPABLE
        // OK we are stateful, however the handshake is not complete
        if (tcpseg->getAckBit()) { // ACK
            DEBUGPRINT(
                    "[MPTCP][HANDSHAKE][MP_CAPABLE] PRE_ESTABLISHED working for sending  a ACK%s",
                    "\0");

            // Prepare
            option.setLength(MP_CAPABLE_SIZE_ACK);
            option.setValuesArraySize(5);
            option.setValues(0, first_bits);

            // set 64 bit value
            uint32_t value = (uint32_t) _getLocalKey();
            option.setValues(1, value);
            value = _getLocalKey() >> 32;
            option.setValues(2, value);

            // set 64 bit value
            value = (uint32_t) _getRemoteKey();
            option.setValues(3, value);
            value = _getRemoteKey() >> 32;
            option.setValues(4, value);

            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
            tcpseg->setOptions(t, option);
            t++;

            // OK,if we want accept server side joints we have to open a socket wor incoming connection
            DEBUGPRINT("[MPTCP] send an ACK MP_CAPABLE by local %s:%d to %s:%d",
                    subflow->localAddr.str().c_str(), subflow->localPort,
                    subflow->remoteAddr.str().c_str(), subflow->remotePort);
            bool skip = false;
            for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
                    i != subflow_list.end(); i++) {
                TCP_subflow_t* entry = (*i);
                if ((IPvXAddress("0.0.0.0").equals(entry->subflow->localAddr))) {
                    tcpEV
                                 << "Listen on 0.0.0.0 so skip setting in server mode\n";
                    skip = true;
                }
            }

            if (!skip) { // we don have to set it in general server mode (passiv = false)

                TCPConnection *conn_tmp = subflow->cloneMPTCPConnection(false,
                        getLocalToken(), subflow->localAddr,
                        subflow->remoteAddr);
                subflow->getTcpMain()->addNewMPTCPConnection(subflow, conn_tmp);
                subflow->isSubflow = true;
                subflow->isQueueAble = true;
                TCP_subflow_t *t = new TCP_subflow_t();
                t->active = true;
                t->subflow = conn_tmp;
                t->subflow->flow = this;

                // subflow_list.push_back(t);

            }DEBUGPRINT(
                    "[MPTCP][HANDSHAKE][MP_CAPABLE] ESTABLISHED after enqueue a ACK%s",
                    "\0");
            MPTCP_FSM(ESTABLISHED);
        } else {
#warning "Sometimes we enter this"
            // ASSERT(false && "This message type is not allowed in this state");
            // FIXME Just for Testing
        }
        break;
    }
        // MPTCP ESTABLISHED

    default:
        DEBUGPRINT(
                "[MPTCP][HANDSHAKE][MP_CAPABLE][ERROR] Options length exceeded! Segment will be sent without options%s",
                "\0")
        ;
        ASSERT(false && "No options ?");
        // FIXME Just for Testing
        break;
    }
    return t;
}

/**
 * Do the MP_JOIN Handshake
 */
int MPTCP_Flow::_writeJoinHandshakeHeader(uint t,
        TCPStateVariables* subflow_state, TCPSegment *tcpseg,
        TCPConnection* subflow, TCPOption option) {

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

    DEBUGPRINT("[MPTCP][HANDSHAKE][MP_JOIN] ESTABLISHED should use MP_JOIN%s",
            "\0");

    first_bits = (first_bits | ((uint16_t) MP_JOIN)); //12
    first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);

// SYN MP_JOIN
    // Add MP_JOIN on a SYN of a established MULTIPATH Connection
    if (tcpseg->getSynBit() && (!tcpseg->getAckBit())) {
        // OK, we are still established so, this must be a JOIN or ADD.
        // ADD is not handled here (FIXME ADD), so it must be a MP_JOIN
        // this is triggert by a self message, called by joinConnection()

        DEBUGPRINT("[MPTCP][HANDSHAKE][MP_JOIN] SYN with MP_JOIN%s", "\0");

        // Prepare
        assert(
                MP_JOIN_SIZE_SYN==12 && "Did somone a change on the MP_JOIN_SIZE_SYN");
        // In the draft it is defined as 12
        option.setLength(MP_JOIN_SIZE_SYN);
        option.setValuesArraySize(3);
        option.setValues(0, first_bits);

        // FIXME Missing Address ID (!!!!)
        option.setValues(1, getRemoteToken());

        subflow->randomA = 0; // FIXME (uint32)generateKey();
        option.setValues(2, subflow->randomA); // FIXME Sender's random number (Generator perhaps other one??)

        addSubflow(subflow->connId, subflow); // connection becomes stateful on SYN because we have to remember all values -> not needed for real implemenation

        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
        tcpseg->setOptions(t, option);
        t++;

    }

// SYN-ACK MP_JOIN
    // Add MP_JOIN on a SYN/ACK of a etablished MULTIPATH Connection
    else if (tcpseg->getSynBit() && (tcpseg->getAckBit())) {
        DEBUGPRINT(
                "[MPTCP][HANDSHAKE][MP_JOIN] SYN ACK with MP_JOIN <Not filled yet>%s",
                "\0");
        subflow->isQueueAble = true;
        subflow->updateWndInfo(tcpseg, true);
        // Prepare
        assert(
                MP_JOIN_SIZE_SYNACK==16 && "Did someone a change on MP_JOIN_SIZE_SYNACK?");
        // In the draft it is defined as 12
        option.setLength(MP_JOIN_SIZE_SYNACK);
        option.setValuesArraySize(3);
        option.setValues(0, first_bits);
        // FIXME B
        // FIXME Adress ID

        // generate the tuncated MAC (64) and the random Number of the Receiver (Sender of the Packet)
        // FIXME For second Parameter
        option.setValues(1, 0); // FIXME truncated MAC 64
        option.setValues(2, 0); // FIXME Random Number

        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
        tcpseg->setOptions(t, option);
        t++;
        DEBUGPRINT(
                "[MPTCP][HANDSHAKE][MP_JOIN] Pre-Established after enqueue of SYN-ACK%s",
                "\0");

// ACK MP_JOIN
    } else if ((!tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
        // MPTCP OUT MP_JOIN ACK
        subflow->isQueueAble = true;
        subflow->updateWndInfo(tcpseg, true);
        DEBUGPRINT(
                "[MPTCP][HANDSHAKE][MP_JOIN] ACK with MP_JOIN <Not filled yet>%s",
                "\0");

        // Prepare
        assert(
                MP_JOIN_SIZE_ACK==24 && "Did someone a change on MP_JOIN_SIZE_ACK");
        // In the draft it is defined as 12
        option.setLength(MP_JOIN_SIZE_ACK);
        option.setValuesArraySize(3);
        option.setValues(0, first_bits);

        // generate the tuncated MAC (64) and the random Number of the Receiver (Sender of the Packet)
        // FIXME FIXME FIXME
        option.setValues(1, 0); // FIXME truncated MAC 64
        option.setValues(2, 0); // FIXME Random Number

        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
        tcpseg->setOptions(t, option);
        t++;

        //  subflow->startMPTCPACKRexmitTimer();

        DEBUGPRINT(
                "[MPTCP][HANDSHAKE][MP_JOIN] Established after enqueue of SYN%s",
                "\0");

    } else {
        DEBUGPRINT("[MPTCP][HANDSHAKE][ERRROR]%s", "\0");;
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

    if ((!working) && (join_queue.size() > 0)) {
        bool skip = false;
        working = true;
        if (this->getState() != ESTABLISHED)
            return false;

        // In case we know new address pairs...

        TCP_JoinVector_t::const_iterator it;

        for (it = join_queue.begin(); it != join_queue.end(); it++, cnt++) {
            AddrCombi_t* c = (AddrCombi_t *) (*it);
            DEBUGPRINT("Work on possible Join: %s:%d to %s:%d",
                    c->local.addr.str().c_str(), c->local.port,
                    c->remote.addr.str().c_str(), c->remote.port);

            ASSERT(
                    subflow_list.size() != 0
                            && "Ups...why is the subflow_list empty");
            TCP_subflow_t* entry = NULL;
            for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
                    i != subflow_list.end(); i++) {
                entry = (*i);
                if ((entry->subflow->remoteAddr == c->remote.addr)
                        && (entry->subflow->remotePort == c->remote.port)
                        && (entry->subflow->localAddr == c->local.addr)
                        && (entry->subflow->localPort == c->local.port)) {
                    DEBUGPRINT("We know: %s:%d to %s:%d",
                            c->local.addr.str().c_str(), c->local.port,
                            c->remote.addr.str().c_str(), c->remote.port);
                    skip = true;
                    break;
                }
            }
            if (skip) {
                skip = false;
                continue;
            }
            if (entry == NULL) // it doesn't matter which enty we use, we need only one subflow
                continue; // if there is no known subflow, we have nothing todo
            TCPConnection* tmp = entry->subflow;
            ASSERT(
                    tmp->getTcpMain()!=NULL && "There should allways a TCP MAIN");

            DEBUGPRINT("Check if new MPTCP Subflow: %s:%d to %s:%d",
                    c->local.addr.str().c_str(), c->local.port,
                    c->remote.addr.str().c_str(), c->remote.port);

            // ignore local addresses
            if (IPvXAddress("127.0.0.1").equals(c->local.addr)) {
                tcpEV << "[MPTCP][PREPARE JOIN] skip 127.0.0.1\n";
                continue;
            }
            if (IPvXAddress("0.0.0.0").equals(c->local.addr)) {
                tcpEV << "[MPTCP][PREPARE JOIN] skip 0.0.0.0\n";
                continue;
            }

            // ignore still etablished subflows
            TCP_JoinVector_t::const_iterator it_tj;
            for (it_tj = tried_join.begin(); it_tj != tried_join.end();
                    it_tj++) {
                AddrCombi_t* tmp = (AddrCombi_t*) *it_tj;
                if ((c->local.addr.equals(tmp->local.addr))
                        && (c->remote.addr.equals(tmp->remote.addr))) {

                    DEBUGPRINT("[MPTCP][PREPARE JOIN] Connection still known%s",
                            "\0");
                    skip = true;
                    break;
                }
            }

            // #############################################
            // Create selfmessage for new subflow initiation

            // Is this a possible new subflow?
            if (!skip) {

                //               if(tmp->getTcpMain()->isKnownConn(c->local.addr,tmp->localPort,c->remote.addr,tmp->remotePort))
                //                       continue; // OK TCP still knows this subflow, do nothing
                DEBUGPRINT("Try to add Subflow: %s:%d to %s:%d",
                        c->local.addr.str().c_str(), c->local.port,
                        c->remote.addr.str().c_str(), c->remote.port);
                // create a new active connection
                int old = tmp->remotePort;
                tmp->remotePort = c->remote.port;
                TCPConnection *conn_tmp = tmp->cloneMPTCPConnection(true,
                        getLocalToken(), IPvXAddress(c->local.addr),
                        IPvXAddress(c->remote.addr)); //    new TCPConnection(tmp->getTcpMain(),tmp->appGateIndex, tmp->connId); //
                tmp->getTcpMain()->addNewMPTCPConnection(tmp, conn_tmp);
                tmp->isSubflow = true;
                tmp->remotePort = old;
                TCP_subflow_t *t = new TCP_subflow_t();
                t->active = true;
                t->subflow = conn_tmp;

                t->subflow->flow = this;
                //subflow_list.push_back(t);

                goto freeAndfinish;
            }
        }
        // I go true the list and nothing was usefull....clear it
        join_queue.clear();

        goto finish;
    } else {

        return false;
    }

    ASSERT(false && "Should never reached");
    // should never reached

    freeAndfinish: join_queue.erase(join_queue.begin() + cnt);
    finish: working = false;
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
        TCPStateVariables* subflow_state, TCPSegment *tcpseg, uint32 bytes,
        TCPConnection* subflow, TCPOption option) {

    /*
     The Data Sequence Mapping and the Data ACK are signalled in the Data
     Sequence Signal (DSS) option.  Either or both can be signalled in one
     DSS, dependent on the flags set.  The Data Sequence Mapping defines
     how the sequence space on the subflow maps to the connection level,
     and the Data ACK acknowledges receipt of data at the connection
     level.
     */

    DEBUGprintDSSInfo();
    // check if we need to add DSS
    uint64 dss_end = 0;
    // Special cases: Retranmission
    bool isRetranmission = false;
    uint64 rtx_snd_seq = 0;
    uint32 rtx_msg_length = 0;
    // First calculate possible message size
    uint options_len = 0;
    if(!subflow->isQueueAble) return 0;
    for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
        options_len = options_len + tcpseg->getOptions(i).getLength();

    uint32 dss_option_offset = MP_DSS_OPTIONLENGTH_4BYTE;
    if (subflow->getTcpMain()->multipath_DSSSeqNo8)
        dss_option_offset += 4;
    if (subflow->getTcpMain()->multipath_DSSDataACK8)
        dss_option_offset += 4;

    options_len += dss_option_offset; // Option for Multipath

    if (subflow->getState()->sack_enabled) {
#warning "TODO SACK"
        //uint32 offset =  subflow->rexmitQueue->getEndOfRegion(subflow->getState()->snd_una);
        //if(offset > 0) // we know this segment.... send only segment size
        //    bytes = offset - subflow->getState()->snd_una; // FIXME: In this case we overwrite for a retransmission the sending window
    }
/////    if(bytes == 0)
/////        return t;
    while (bytes + options_len > subflow->getState()->snd_mss)
        bytes--;

    // FIXME
    uint32 old_bytes = bytes;
    if ((old_bytes > 0) && (bytes < 1)) {
        ASSERT(
                "Uih...sending window is just less 8 bytes... if we want send, we have to fix this");
    }

    // get Start DSS
    uint64 dss_start = this->mptcp_snd_una;
    subflow->base_una_dss_info.dss_seq = this->mptcp_snd_una;

    // fill the dss seq nr map
    // FIXME -> Perhaps it is enough to hold list like on SACK
    uint32 snd_nxt_tmp = subflow->getState()->getSndNxt();
    uint32 bytes_tmp = bytes;
    uint32 to_report_sqn = this->mptcp_snd_nxt;



    if (bytes_tmp > subflow->getState()->snd_mss)
        ASSERT(false && "Expect only segments with size less that path mss");

    for (uint64 cnt = 0; cnt <= bytes; cnt++) {
        // check if there is any in the list
        ASSERT(cnt < 1 && "if we do more than one round we have a problem");
        // FIXME Check if it is still in the queue, overflow
        TCPMultipathDSSStatus::const_iterator it =
                subflow->dss_dataMapofSubflow.find(snd_nxt_tmp);




        // check for special cases
        if(!subflow->dss_dataMapofSubflow.empty())
        if((subflow->getState()->snd_max) > snd_nxt_tmp && (it == subflow->dss_dataMapofSubflow.end())) {
                if ((subflow->dss_dataMapofSubflow.begin()->first <= snd_nxt_tmp)
                        && (snd_nxt_tmp
                                < ((--subflow->dss_dataMapofSubflow.end())->first
                                        + (--subflow->dss_dataMapofSubflow.end())->second->seq_offset))) {
#warning "Real problem - Why we are not in sync -See issue #29 in github"
                    uint32 old = snd_nxt_tmp;
                    // FIXME - This is just a hotfix/workaround ...it don t solve the problem
                    TCPMultipathDSSStatus::iterator i =
                            subflow->dss_dataMapofSubflow.begin();
                    while (i != subflow->dss_dataMapofSubflow.end()) {
                        //std::cerr << "sqn: " << i->first << " DSS "
                        //        << i->second->dss_seq << std::endl;
                        if (i->first < old)
                            snd_nxt_tmp = i->first;
                        else
                            break;
                        i++;
                    }
                    it = subflow->dss_dataMapofSubflow.find(snd_nxt_tmp);
                    if (it == subflow->dss_dataMapofSubflow.end()) {
                        std::cerr << "not in sync of full packets" << std::endl;
                        ASSERT(false && "Workaround not functional");;
                    }

                }
            }



            if (it != subflow->dss_dataMapofSubflow.end()) {
                // this is a retransmission
                isRetranmission = true;
                DSS_INFO* dss_info = it->second;
                rtx_msg_length = dss_info->seq_offset;
                rtx_snd_seq = dss_info->dss_seq;
                to_report_sqn = dss_info->dss_seq;
                // FIXME check if only one message
                break;
            } else {
                if((subflow->getState()->snd_max > snd_nxt_tmp) && (it == subflow->dss_dataMapofSubflow.end())){
                    std::cerr
                            << "this is a retransmission of still delivered MPTCP data "
                            << subflow->dss_dataMapofSubflow.begin()->first << " > " << snd_nxt_tmp << std::endl;
                    return t;
                }
                // create Block
                uint32 queueAbleFlows = 0;
                bool blocked_block = false;
                for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
                                                    i != subflow_list.end(); i++) {
                     TCPConnection* sub = (*i)->subflow;
                     if(!sub->isQueueAble) continue;
                     queueAbleFlows++;
                }
                if(consn && (!this->inConSNBlock) && (queueAbleFlows > 1)){
                    // OK block is complete ... recalculate new block
                    refreshSendMPTCPWindow();
                    // First we need arwnd
                    TCPTahoeRenoFamilyStateVariables* state =
                    check_and_cast<TCPTahoeRenoFamilyStateVariables*>(
                            subflow->getTcpAlgorithm()->getStateVariables());

                    uint32 max_block = this->mptcp_snd_wnd - state->snd_mss;
                    consn_snd_una = this->mptcp_snd_una;
                    consn_snd_wnd = max_block;

                    // static block size calculation
                    uint32 block_size = max_block / queueAbleFlows;

                    // fill structures static
                    uint32 _consn_order = 1;
                    uint32 offset = 0;
                    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
                                   i != subflow_list.end(); i++, _consn_order++) {
                        TCPConnection* sub = (*i)->subflow;
                        if(!sub->isQueueAble) continue;
                        sub->getState()->consn_order = _consn_order;
                        sub->getState()->consn_status.block_id = sub->getState()->consn_order;
                        sub->getState()->consn_status.finished = false;

                        if(_consn_order != 1){
                            sub->getState()->consn_status.snd_max = this->mptcp_snd_una + offset - sub->getState()->snd_mss; // one MMS Overlapping;
                            offset += block_size;
                            sub->getState()->consn_status.snd_una = this->mptcp_snd_una + offset;
                            sub->getState()->consn_status.start_block = sub->getState()->consn_status.snd_una;
                            sub->getState()->consn_status.snd_nxt =  this->mptcp_snd_nxt + offset;
                            sub->getState()->consn_status.count_direction = backward;
                        }
                        else{

                            sub->getState()->consn_status.snd_una = this->mptcp_snd_una + offset;
                            sub->getState()->consn_status.start_block = sub->getState()->consn_status.snd_una;
                            offset += block_size;
                            sub->getState()->consn_status.snd_max = sub->getState()->consn_status.snd_una + offset + sub->getState()->snd_mss; // one MMS Overlapping
                            sub->getState()->consn_status.snd_nxt = this->mptcp_snd_nxt;
                            sub->getState()->consn_status.count_direction = forward;
                        }

                        sub->getState()->consn_status.sqn_map.clear();
                    }

                    // max Block size is current arwnd
                    this->inConSNBlock = true;
                }


                DSS_INFO* dss_info = new DSS_INFO;// (DSS_INFO*) malloc(sizeof(DSS_INFO));
                if((!consn) || (queueAbleFlows < 2)){
                    dss_info->dss_seq = this->mptcp_snd_nxt;
                    dss_info->seq_offset = bytes;
                    mptcp_snd_nxt += (bytes + 1);
                    dss_end = mptcp_snd_nxt -1;
                }
                else if(consn){
                    if(!subflow->getState()->consn_status.finished){
                        if(subflow->getState()->consn_status.count_direction == backward){
                            // mptcp_snd_nxt = subflow->getState()->consn_status.snd_nxt;
                            dss_info->dss_seq = (subflow->getState()->consn_status.snd_nxt - bytes);
                            dss_info->seq_offset = bytes;
                            subflow->getState()->consn_status.snd_nxt -= (bytes + 1);
                            dss_end = subflow->getState()->consn_status.snd_nxt;
                            if(subflow->getState()->consn_status.snd_nxt <= subflow->getState()->consn_status.snd_max)
                                subflow->getState()->consn_status.finished = true;
                        }
                        else if(subflow->getState()->consn_status.count_direction == forward){
                            dss_info->dss_seq = subflow->getState()->consn_status.snd_nxt;
                            dss_info->seq_offset = bytes;
                            subflow->getState()->consn_status.snd_nxt += (bytes + 1);
                            dss_end = subflow->getState()->consn_status.snd_nxt - 1;
                            //mptcp_snd_nxt += bytes;
                            if(subflow->getState()->consn_status.snd_nxt >= subflow->getState()->consn_status.snd_max)
                                subflow->getState()->consn_status.finished = true;
                        }
                        else ASSERT(false && "This should not happen");
                        mptcp_snd_nxt = mptcp_snd_una;
                    }
                    else{
                            blocked_block = true;
                        }

                        // ok ... the block is finished, which block should I support of complete ConSN Block
                        //fprintf(stderr,"ConSN Block is finished for %d \t snd_una %llu \t %llu \n",subflow->getState()->consn_status.block_id, this->mptcp_snd_una, consn_snd_una + consn_snd_wnd);
                        if(this->mptcp_snd_una >= (consn_snd_una + consn_snd_wnd)){
                           //fprintf(stderr,"Create New Block");
                           this->mptcp_snd_nxt = this->mptcp_snd_una;
                           this->inConSNBlock = false;
                        }

                        if(blocked_block){

                            //default:
                            return -1;

                        }
                        // check if all blocks finished



                }
                else
                    ASSERT(false && "This should not happen");

               // if(to_report_sqn >= 212514543)

               //     fprintf(stderr,"ConSN %d \t Send DSS %llu with len %d\n",subflow->getState()->consn_status.block_id, dss_info->dss_seq,dss_info->seq_offset);
                to_report_sqn = dss_info->dss_seq;
                dss_info->section_end = false;
                // we work wit an offset parameter - if we have numbers in sequence
                // I think it is more easy to handle this in mss sections
                slist.insert(std::make_pair(dss_info->dss_seq, subflow));
                // information stuff
                dss_info->re_scheduled = 0;
                dss_info->delivered = false;
                subflow->dss_dataMapofSubflow[snd_nxt_tmp] = dss_info;   //dss_info;
                // recalc the offset
                snd_nxt_tmp += bytes_tmp;
                cnt += bytes_tmp;
            }

//		}
//		else ASSERT (false);
    }

    // this->mptcp_snd_nxt += bytesToSend;


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
    // Some Debug
    // !!!!!!!!!!!!!!!!!!!! FIXME -> I have a shift of 16 bit during use of  option.setValues
    // Initiate some helper
    uint32_t first_bits = 0x0;
    DEBUGPRINT("[MPTCP][PROCESS SQN] start%s", "\0");
    first_bits = (first_bits | ((uint16_t) MP_DSS));
    first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);

    if (dss_end == dss_start){
        option.setLength(MP_DSS_OPTIONLENGTH_ACK);
        option.setValuesArraySize(3);
    }else{
        option.setLength(dss_option_offset);
        option.setValuesArraySize(4);
    }
    uint32_t array_cnt = 0;
    uint32_t flags = 0;

    uint64 ack_seq = 0;
    uint64 snd_seq = 0;
    uint32 flow_seq = 0;
    uint16 data_len = 0;

    flags |= DSS_FLAG_M;
    // Switch: NED Parameter multipath_DSSSeqNo8
    if (subflow->getTcpMain()->multipath_DSSSeqNo8) {
        flags |= DSS_FLAG_m; // 8 or 4 Octets
        option.setValuesArraySize(option.getValuesArraySize() + 1);
    }

    // Note:
    // Fill Data Sequence Number with complete 64bit number or lowest 32
    // Subflow SQN is relativ to the SYN
    // Data-Level length Payload
    // Checksum if flag in MP_CAPABLE was set

    // Data Acknowledgments [Section 3.3.2] ==> OUT
    // Note: if ACK is available we have to set the flag
    flags |= DSS_FLAG_A;
    // Switch: NED Parameter multipath_DSSDataACK8
    if (subflow->getTcpMain()->multipath_DSSDataACK8) {
        flags |= DSS_FLAG_a; // 8 or 4 Octets
        option.setValuesArraySize(option.getValuesArraySize() + 1);
    }
    if (dss_end == dss_start){
        // No other flags, there is only an ack
        flags = 0x01;
    }
    first_bits |= flags << 16;

    uint32 l_seq = 0;
    // FIXME We send the DSSSeqNo every time, is this ok?
    if (subflow->getTcpMain()->multipath_DSSSeqNo8) {
        // FIXME
        ASSERT(false && "Not implemented yet");
    }
    // Ack Seq number
    l_seq = ack_seq = this->mptcp_rcv_nxt;

    first_bits |= l_seq >> 16;
    option.setValues(array_cnt++, first_bits);
    first_bits = 0;
    first_bits |= l_seq << 16;

    // // Data Sequence Mapping [Section 3.3.1] ==> OUT
    // Note: if ACK is available we have to set the flag
    // FIXME We send always an ACK, now -> is this  ok?

    if (subflow->getTcpMain()->multipath_DSSDataACK8) {
        // FIXME
        ASSERT(false && "Not implemented yet");
    }

    if (dss_end == dss_start){
        // Data seq no.
        l_seq  = 0;

        first_bits |= l_seq >> 16;
        option.setValues(array_cnt++, first_bits);
        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
        tcpseg->setOptions(t++, option);
        return t;
    }

    // Data seq no.
    l_seq = snd_seq = to_report_sqn;

    first_bits |= l_seq >> 16;
    option.setValues(array_cnt++, first_bits);

    first_bits = 0;

    first_bits |= l_seq << 16;

    // Offset of sequence number
    l_seq = flow_seq = subflow->getState()->getSndNxt()
            - subflow->getState()->iss;
    first_bits |= l_seq >> 16;

    option.setValues(array_cnt++, first_bits);
    first_bits = 0;
    first_bits |= l_seq << 16;

    if (isRetranmission)
        first_bits |= data_len = rtx_msg_length;
    else
        first_bits |= data_len = bytes;
    option.setValues(array_cnt++, first_bits);

    // FIXME Checksum is missing

    tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
    tcpseg->setOptions(t++, option);


    DEBUGPRINT(
            "[FLOW][DSS][INFO][SND] Ack Seq: %ld \t SND Seq: %ld \t Subflow Seq: %d \t Data length: %d",
            ack_seq, snd_seq, flow_seq, data_len);

    return t;
}

#ifdef ADD_ADDR
int MPTCP_Flow::_writeADDADDRHeader(uint t, TCPStateVariables* subflow_state,
        TCPSegment *tcpseg, uint32 bytes, TCPConnection* subflow,
        TCPOption option) {
    AddrTupple_t* laddr;
    TCP_AddressVector_t::const_iterator it;
    bool skip = false;
    const TCP_SubFlowVector_t* sf_list = subflow->flow->getSubflows();
    for (it = list_laddrtuple.begin(); it != list_laddrtuple.end(); it++) {
        laddr = (AddrTupple_t*) (*it);
        TCP_SubFlowVector_t::const_iterator mptcp_flow;
        for (mptcp_flow = sf_list->begin();
                mptcp_flow != sf_list->end(); mptcp_flow++) {
            TCP_subflow_t* entry = (*mptcp_flow);
            if (entry->subflow->localAddr == laddr->addr
                    && entry->subflow->localPort == laddr->port) {
                skip = true;
                break;
            }
        }
        if (skip) {
            skip = false;
            continue;
        }
        if (IPvXAddress("127.0.0.1").equals(laddr->addr)) {
            continue;
        }
        if (IPvXAddress("0.0.0.0").equals(laddr->addr)) {
            continue;
        }
        if (!skip)
        break;
    }

    if (it != list_laddrtuple.end()) {
        DEBUGPRINT("[MPTCP][ADD_ADDR] start%s", "\0");
        uint32_t first_bits = 0x0;
        first_bits = (first_bits | ((uint16_t) MP_ADD_ADDR));
        first_bits = first_bits
        << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);
        option.setValuesArraySize(3);
        option.setValues(0, first_bits);
        if (laddr->addr.isIPv6()) {
            option.setLength(MP_ADD_ADDR_SIZE + 20);
            option.setValuesArraySize(option.getValuesArraySize()+3);
            option.setValues(1, laddr->addr.get6().words()[0]);
            option.setValues(2, laddr->addr.get6().words()[1]);
            option.setValues(3, laddr->addr.get6().words()[2]);
            option.setValues(4, laddr->addr.get6().words()[3]);
            option.setValues(5, laddr->port);
        } else {
            option.setLength(MP_ADD_ADDR_SIZE + 8);
            option.setValues(1, laddr->addr.get4().getInt());
            option.setValues(2, laddr->port);
        }
        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
        tcpseg->setOptions(t, option);
        t++;
    }
    return t;

}
#endif // ADD_ADDR
void MPTCP_Flow::DEBUGprintDSSInfo() {
#ifdef _PRIVATE
    TCP_subflow_t* entry = NULL;
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); i++) {
        entry = (*i);
        TCPMultipathDSSStatus::const_iterator it;
        DEBUGPRINT("[FLOW][STATUS][DSS] DSS MAP SIZE %d",entry->subflow->dss_dataMapofSubflow.size());
        for (it = entry->subflow->dss_dataMapofSubflow.begin(); it != entry->subflow->dss_dataMapofSubflow.end(); ++it) {
            uint32 subflow_seq = it->first;
            DSS_INFO* dss_info = it->second;
            DEBUGPRINT("[FLOW][STATUS][DSS] Subflow SEQ: %d -> DSS SEQ %ld", subflow_seq, dss_info->dss_seq);
        }
    }
#endif
}
void MPTCP_Flow::refreshSendMPTCPWindow() {
    // we try to organize the DSS List in a Map with offsets of in order sequence of DSS
    TCP_subflow_t* entry = NULL;

    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); i++) {
        entry = (*i);

        if (entry->subflow->dss_dataMapofSubflow.empty())
            continue;   // Nothing to do

        // Clear sending memory (DSS MAP)
        TCPStateVariables* subflow_state = entry->subflow->getState();
        TCPConnection* conn = entry->subflow;
        //uint32 offset = 0;

        for (TCPMultipathDSSStatus::const_iterator it =
                conn->dss_dataMapofSubflow.begin();
                it != conn->dss_dataMapofSubflow.end(); it++) {

            if (subflow_state->snd_una > (it->first)) {
                // complete delivered
                it->second->delivered = true;
            }

            if ( it->second->dss_seq < mptcp_snd_una - 1) {
                slist.erase(it->second->dss_seq);
                dlist.insert(std::make_pair(it->second->dss_seq,it->second->seq_offset));
                if(it->second->delivered){
                    conn->dss_dataMapofSubflow.erase(it->first);
                }
                // FIXME To split
            }
        }
        // Delete the entries marked as delivered
    }

    if(maxBuffer > mptcp_receiveQueue->getOccupiedMemory())
        mptcp_rcv_wnd = maxBuffer - mptcp_receiveQueue->getOccupiedMemory();
    else
        mptcp_rcv_wnd = 0;
}

void MPTCP_Flow::sendToApp() {

    // some checks
    if (subflow_list.empty())
        return;
    TCP_SubFlowVector_t::iterator it = subflow_list.begin();
    TCPConnection *conn = (*it)->subflow;

    cMessage* tmp = NULL;
    // Correction parameter
    while ((tmp = mptcp_receiveQueue->extractBytesUpTo(mptcp_rcv_nxt)) != NULL) {
        // 4) Send Data to Connection
        tmp->setKind(TCP_I_DATA);
        TCPCommand *cmd = new TCPCommand();
        cmd->setConnId((*(subflow_list.begin()))->subflow->connId);
        tmp->setControlInfo(cmd);
        conn->getTcpMain()->send(tmp, "appOut", conn->appGateIndex);

    }

    if (maxBuffer >= mptcp_receiveQueue->getOccupiedMemory()) {
        mptcp_rcv_wnd = maxBuffer - mptcp_receiveQueue->getOccupiedMemory();
    } else {
        mptcp_receiveQueue->printInfo();
        mptcp_rcv_wnd = 0;
        buffer_blocked = true;
    }
    return;
}

void MPTCP_Flow::enqueueMPTCPData(uint64 dss_start_seq, uint32 data_len) {
    uint32 old_mptcp_rcv_adv = mptcp_rcv_adv;
    mptcp_rcv_nxt = mptcp_receiveQueue->insertBytesFromSegment(dss_start_seq,
            data_len);
    uint32 queueAbleFlows = 0;
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
                                       i != subflow_list.end(); i++) {
        TCPConnection* sub = (*i)->subflow;
        if(!sub->isQueueAble) continue;
        queueAbleFlows++;
    }
    // ConSN Block on Receiver Side
    if(consn && (queueAbleFlows > 2) ){
        // recalculate structure for ConSN
        bool found = false;

        for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
                 i != subflow_list.end(); i++) {
            if(!found){
                uint64 min_block = 0;
                uint64 max_block = 0;
                TCPConnection* sub = (*i)->subflow;
                if(sub->getState()->consn_status.count_direction == forward){
                    min_block = sub->getState()->consn_status.start_block;
                    max_block = sub->getState()->consn_status.snd_max;
                }
                else{
                    min_block = sub->getState()->consn_status.snd_max;
                    max_block = sub->getState()->consn_status.start_block;
                }
                if((min_block <= dss_start_seq) &&  (dss_start_seq + data_len <= max_block)){
                    sub->getState()->consn_status.finished = false;
                    found = true;

                    // Check list for Forward
                    if(sub->getState()->consn_status.count_direction == forward){
                        sub->getState()->consn_status.sqn_map.insert(std::make_pair(dss_start_seq,data_len));
                        ConSN_SQN_MAP::iterator consn_sqn_list = sub->getState()->consn_status.sqn_map.find(min_block);
                        uint64 nxt_sqn = min_block;
                        while(consn_sqn_list != sub->getState()->consn_status.sqn_map.end()){
                            sub->getState()->consn_status.snd_una = nxt_sqn;

                            nxt_sqn = consn_sqn_list->first + consn_sqn_list->second;
                            if(nxt_sqn >= max_block){
                                sub->getState()->consn_status.finished = true;
                                break;
                            }
                            consn_sqn_list = sub->getState()->consn_status.sqn_map.find(nxt_sqn);
                        }
                    }
                    else{
                        sub->getState()->consn_status.sqn_map.insert(std::make_pair(dss_start_seq + data_len,data_len));
                        ConSN_SQN_MAP::iterator consn_sqn_list = sub->getState()->consn_status.sqn_map.find(max_block);
                        uint64 nxt_sqn = max_block;
                        while(consn_sqn_list != sub->getState()->consn_status.sqn_map.end()){
                          sub->getState()->consn_status.snd_una = nxt_sqn;

                          nxt_sqn = consn_sqn_list->first - consn_sqn_list->second;
                          if(nxt_sqn <= min_block){
                              sub->getState()->consn_status.finished = true;
                              break;
                          }
                          consn_sqn_list = sub->getState()->consn_status.sqn_map.find(nxt_sqn);
                        }
                    }
                }
                this->inConSNBlock &= sub->getState()->consn_status.finished;
            }
        }
    }
    // End ConSN Receiver Side

    if (maxBuffer < mptcp_receiveQueue->getOccupiedMemory()) {
        mptcp_receiveQueue->printInfo();
        std::cerr << "RECEIVER occupied more than allowed: "
                << mptcp_receiveQueue->getOccupiedMemory() << " - Allowed are: "
                << maxBuffer << std::endl;
        // ASSERT(false && "What is wrong here");
    }
    //if (maxBuffer < mptcp_receiveQueue->getOccupiedMemory() + 1500)
    //    std::cerr << "RECEIVER waiting for " << mptcp_rcv_nxt << std::endl;
    //mptcp_receiveQueue->printInfo();
    mptcp_rcv_adv = mptcp_rcv_nxt + mptcp_rcv_wnd;
    if (mptcp_rcv_adv < old_mptcp_rcv_adv) {
    //    ASSERT(false && "What is wrong here");
    }
}

TCPConnection* MPTCP_Flow::schedule(TCPConnection* save, cMessage* msg) {
    // easy scheduler

    /**
     * TODO TEST
     */

    MPTCP_SchedulerI* scheduler = TCPSchedulerManager::getMPTCPScheduler(
            save->getTcpMain(), this);
    scheduler->schedule(save, msg);
    return save;
}

void MPTCP_Flow::initKeyMaterial(TCPConnection* subflow) {
    _generateSYNACK_HMAC(_getLocalKey(), _getRemoteKey(), subflow->randomA,
            subflow->randomB, subflow->MAC64);
    _generateACK_HMAC(_getLocalKey(), _getRemoteKey(), subflow->randomA,
            subflow->randomB, subflow->MAC160);
}

bool MPTCP_Flow::keysAreEqual(uint64_t rk, uint64_t lk) {
    if ((rk == this->_getRemoteKey()) && (lk == this->_getLocalKey())) {
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
    uint64_t key = intrand((long) UINT64_MAX);

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
    SHA1_Update(&ctx, (const void*) &key, sizeof(uint64_t));
    SHA1_Final((unsigned char*) dm, &ctx);

    out64 = (uint64*) dm; // Should be a different one, but for simulation it is enough
    out32 = (uint32*) dm; // most significant 32 bits [Section 3.2]
    DEBUGPRINT("[FLOW][OUT] Generate TOKEN: %u:  ", *out32);DEBUGPRINT(
            "[FLOW][OUT] Generate SQN: %ld:  ", *out64);
    switch (type) {
    case MPTCP_LOCAL:
        setLocalToken(*out32);
        break;
    case MPTCP_REMOTE:
        setRemoteToken(*out32);
        break;
    default:
        ASSERT(false && "What type is this?");
        break;
    }
    //if (type == MPTCP_LOCAL)
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
    sprintf(key, "%19lld%19lld", kb, ka);
    sprintf(msg, "%10u%10u", rb, ra);
    _hmac_md5((unsigned char*) msg, strlen(msg), (unsigned char*) key,
            strlen(key), digist);
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
    sprintf(key, "%19lld%19lld", ka, kb);
    sprintf(msg, "%10u%10u", ra, rb);
    _hmac_md5((unsigned char*) msg, strlen(msg), (unsigned char*) key,
            strlen(key), digist);
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
        MD5_Update(&tctx, (const void*) key, (size_t) key_len);
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
     */MD5_Init(&context); /* init context for 1st
     * pass */
    MD5_Update(&context, (const void*) k_ipad, (size_t) 64); /* start with inner pad */
    MD5_Update(&context, (const void*) text, (size_t) text_len); /* then text of datagram */
    MD5_Final(digest, &context); /* finish up 1st pass */
    /*
     * perform outer MD5
     */MD5_Init(&context); /* init context for 2nd
     * pass */
    MD5_Update(&context, k_opad, 64); /* start with outer pad */
    MD5_Update(&context, digest, 16); /* then results of 1st
     * hash */
    MD5_Final(digest, &context); /* finish up 2nd pass */
}

// ########################################### Getter Setter #########################################

uint64_t MPTCP_Flow::getAmountOfFreeBytesInReceiveQueue(uint64 maxRcvBuffer) {
    return this->mptcp_receiveQueue->getAmountOfFreeBytes(maxRcvBuffer);
}

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

const TCP_SubFlowVector_t* MPTCP_Flow::getSubflows() {
    // clean for non used entry
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); i++) {
        if ((*i) == NULL)
            i = subflow_list.erase(i);
    }
    return &subflow_list;
}

MPTCP_PCB* MPTCP_Flow::getPCB() {
    return pcb;
}

uint64_t MPTCP_Flow::getHighestCumSQN() {
    ASSERT(false && "Not implemented yet");
    return 0;
}

uint64_t MPTCP_Flow::getBaseSQN() {
    return getSQN();
}
/**
 * setter for sender_key
 */
void MPTCP_Flow::setRemoteKey(uint64_t key) {
    if (remote_key) {
        DEBUGPRINT("[FLOW][OUT] Reset TOKEN: NEW REMOTE %ld:  ", key);DEBUGPRINT(
                "[FLOW][OUT] Reset TOKEN: OLD LOCAL  %ld:  ", local_key);DEBUGPRINT(
                "[FLOW][OUT] Reset TOKEN: OLD REMOTE %ld:  ", remote_key);
        ASSERT(remote_key == key && "that should be not allowed");
        return;
    }
    _generateToken(key, MPTCP_REMOTE);
    remote_key = key;
}
/**
 * setter for sender_key
 */
void MPTCP_Flow::setLocalKey(uint64_t key) {
    if (local_key) { // For Testing
        DEBUGPRINT("[FLOW][OUT] Reset TOKEN: NEW LOCAL %ld:  ", key);DEBUGPRINT(
                "[FLOW][OUT] Reset TOKEN: OLD LOCAL  %ld:  ", local_key);DEBUGPRINT(
                "[FLOW][OUT] Reset TOKEN: OLD REMOTE %ld:  ", remote_key);
#warning "Why we enter this sometimes"
#ifdef PROBLEM
        ASSERT(key==local_key && "that should be not allowed");
        return;
#endif
        fprintf(stderr, "WOW the local key will be overwritten\n");
    }
    _generateToken(key, MPTCP_LOCAL);
    local_key = key;
}

uint64_t MPTCP_Flow::getSQN() {
    return seq;
}
void MPTCP_Flow::setBaseSQN(uint64_t s) {
    DEBUGPRINT("[FLOW][INFO] INIT SQN from %ld to %ld", seq, s);
    start_seq = (s%20); // FIXME Overflow
    seq = (s%20); // FIXME Overflow
    mptcp_receiveQueue->init(seq);
    mptcp_snd_una = seq;
    mptcp_snd_nxt = seq + 1;

    mptcp_rcv_nxt = seq;
    mptcp_rcv_adv = mptcp_rcv_nxt + maxBuffer;
    slist.clear();
    mptcp_receiveQueue->init(seq);
}

void MPTCP_Flow::setRemoteToken(uint32_t t) {
    remote_token = t;
}
void MPTCP_Flow::setLocalToken(uint32_t t) {
    local_token = t;
}

uint32_t MPTCP_Flow::getRemoteToken() {
    return remote_token;
}
uint32_t MPTCP_Flow::getLocalToken() {
    return local_token;
}
/**
 * helper set function
 */
int MPTCP_Flow::setState(MPTCP_State s) {
    if (s == ESTABLISHED) {
        DEBUGPRINT("[FLOW][OUT]IS ESTABLISHED Remote Token %u:  ",
                getRemoteToken());DEBUGPRINT(
                "[FLOW][OUT]IS ESTABLISHED Local Token %u:  ", getLocalToken());
    }
    state = s;
    return state;
}

int MPTCP_Flow::getAppID() {
    return appID;
}
int MPTCP_Flow::getappGateIndex() {
    return appGateIndex;
}

void MPTCP_Flow::DEBUGprintMPTCPFlowStatus() {
#ifdef PRIVATE_DEBUG
    DEBUGprintStatus();
#endif
}
void MPTCP_Flow::DEBUGprintStatus() {
#ifdef PRIVATE

    DEBUGPRINT(
            ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FLOW %u >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>",
            this->getRemoteToken());DEBUGPRINT(
            "[FLOW][STATUS] Sequence Number: %ld", seq);DEBUGPRINT(
            "[FLOW][STATUS] snd_una: %ld", mptcp_snd_una);DEBUGPRINT(
            "[FLOW][STATUS] snd_nxt: %ld", mptcp_snd_nxt);DEBUGPRINT(
            "[FLOW][STATUS] snd_wnd: %d", mptcp_snd_wnd);DEBUGPRINT(
            "[FLOW][STATUS] rcv_nxt: %ld", mptcp_rcv_nxt);DEBUGPRINT(
            "[FLOW][STATUS] rcv_wnd: %ld", mptcp_rcv_wnd);

    int cnt = 0;
    TCP_subflow_t* entry = NULL;
    for (TCP_SubFlowVector_t::iterator i = subflow_list.begin();
            i != subflow_list.end(); i++, cnt++) {
        entry = (*i);
        DEBUGPRINT("[FLOW][SUBFLOW][%i][STATUS] Connections  %s:%d to %s:%d",
                cnt, entry->subflow->localAddr.str().c_str(),
                entry->subflow->localPort,
                entry->subflow->remoteAddr.str().c_str(),
                entry->subflow->remotePort);DEBUGPRINT(
                "[FLOW][SUBFLOW][%i][STATUS][SEND] rcv_nxt: %i\t snd_nxt: %i\t snd_una: %i snd_max: %i",
                cnt, entry->subflow->getState()->rcv_nxt,
                entry->subflow->getState()->snd_nxt,
                entry->subflow->getState()->snd_una,
                entry->subflow->getState()->snd_max);

    }

    DEBUGPRINT(
            "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< FLOW %u <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<",
            this->getRemoteToken());
#endif
}

// end MPTCP_Flow

#endif // Private
