/*
 * TCPMultipathPCB.cc
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */
#ifdef PRIVATE

#include "TCPMultipathPCB.h"


//##################################################################################################
//#
//# THE MULTIPATH TCP PROTOCOL CONTROL BLOCK
//#
//#################################################################################################


AllMultipathSubflowsVector_t MPTCP_PCB::subflows_vector; // TODO This is the first shot of hold all system wide subflows.
// Note: Alternative implementation. Setup PCB as Singleton implementation and create list in PCB


/**
 * Constructor
 */
MPTCP_PCB::MPTCP_PCB(){
    ASSERT(false);
}

/**
 * Constructor for an PCB
 *
 * Includes also the persistent in the static subflow_vector
 */
MPTCP_PCB::MPTCP_PCB(int connId, int appGateIndex, TCPConnection* subflow) {

    // Setup PCB and make first subflow persistent
    TuppleWithStatus_t*  t = new TuppleWithStatus_t();
    t->flow = new MPTCP_Flow(connId, appGateIndex, this);
    t->flow->addSubflow(0,subflow);

    flow = t->flow;
    subflows_vector.push_back(t);
// For Debug
    this->_printFlowOverview(-1);
}
/**
 * De-Constructor
 */
MPTCP_PCB::~MPTCP_PCB() {
    // FIXME delete flow
    DEBUGPRINT("[PCB][Destroy] Currently %u MPTCP Protocol Control Blocks used",subflows_vector.size());
}

/**
 * Important External Static Function
 * 1) Find mPCB
 * 2) Process Segment
 * 3) If needed become stateful
 */
int MPTCP_PCB::processMPTCPSegment(int connId, int aAppGateIndex,
    TCPConnection* subflow, TCPSegment *tcpseg) {

    // First look for a Multipath Protocol Control Block
    MPTCP_PCB* tmp = MPTCP_PCB::lookupMPTCP_PCB(connId, aAppGateIndex,tcpseg, subflow);

    if (tmp == NULL){
        tcpEV<< "[MPTCP][PROCESS][INCOMING] DID my best, but found no Flow for this subflow" << "\n";
        tmp = new MPTCP_PCB(connId, aAppGateIndex,subflow);
    }else{
        tcpEV<< "[MPTCP][PROCESS][INCOMING] Existing flow" << "\n";
        tcpEV<< "[MPTCP][PROCESS][INCOMING] Flow State ";

        switch(tmp->getFlow()->getState()){
        case IDLE:
            tcpEV<< "IDLE";
            break;
        case PRE_ESTABLISHED:
            tcpEV<< "PRE_ESTABLISHED";
            break;
        case SHUTDOWN:
            tcpEV<< "SHUTDOWN";
            break;
        case ESTABLISHED:
            tcpEV<< "ESTABLISHED";
            break;
        default:
            ASSERT(false);
            break;
        }
        tcpEV<< "\n";
    }
    int ret = tmp->_processSegment(connId, subflow, tcpseg);
    return ret;
}



/**
* Internal helper to process packet for a flow
* FIXME Something goes wrong (TCP RST)
*/
int MPTCP_PCB::_processSegment(int connId, TCPConnection* subflow,
    TCPSegment *tcpseg) {
    _printFlowOverview(0);
    // We are here; so it must be Multipath TCP Stack
    if (!subflow->getTcpMain()->multipath) {
        ASSERT(true); // FIXME Only for testing
        return 0;
    }

    /**
     * CASE "NEW MPTCP FLOW" or "NO MPTCP FLOW"
     */
    // Check if this is still a Multipath Connection with an existing Flow
    if (flow == NULL || (flow->getState() == IDLE) || (flow->getState() == PRE_ESTABLISHED)) {

        // There exist no MPTCP Flow so we are in the first handshake phase or this is not a MPTCP Flow
        // We don't care about the SYN, because it is stateless. But during getting SYN/ACK and ACK we become stateful
        if (!tcpseg->getAckBit()) { // There is no ACK Bit set, so we are still stateless
            if (!tcpseg->getSynBit()) {
                return 0; // NOT SYN  SYN/ACK or ACK
            }

        }
        // In every case we expect a MP_CAPABEL Option
        // FIXME check Option, if not exist return
        if (tcpseg->getHeaderLength() <= TCP_HEADER_OCTETS) {
            ASSERT(true);
            return 0; // No MPTCP Options
        }
        // lets parse the options
        for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++) {
            const TCPOption& option = tcpseg->getOptions(i);
            short kind = option.getKind();
            //          short length = option.getLength();

            if (kind == TCPOPTION_MPTCP) {
                if(option.getLength() < 4) {
                    ASSERT(true); //should never be happen
                    return 0;
                }

                uint32_t first = option.getValues(0);
                uint16_t sub = (first >> (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE));


                // OK, it is a MPTCP Option, so lets figure out which subtype
                switch(sub){
                    case MP_CAPABLE:
                        tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] MP_CAPABLE" << "\n";
                        _processMP_CAPABLE(connId, subflow, tcpseg, &option);
                        break;
                    case MP_JOIN:
                        tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] MP_JOIN" << "\n";
                        _processMP_JOIN_IDLE(connId, subflow, tcpseg, &option);
                        break;
                    case MP_DSS:
                        tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] MP_DSS" << "\n";
                        //FIXME ASSERT(false);
                        break;
                    default:
                        tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] Not supported" << "\n";
                        ASSERT(false);
                        break;
                }
                break;
            } // MPTCP Options
        } // end for each option
    } // Check if this is still a Multipath Connection with an existing Flow
    else { // This is an established MPTCP Flow -lets parse the options
        for (uint i=0; i<tcpseg->getOptionsArraySize(); i++)
        {
            const TCPOption& option = tcpseg->getOptions(i);
            short kind = option.getKind();
            //          short length = option.getLength();


            if(kind == TCPOPTION_MPTCP)
            {
                tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] process" << "\n";
                if(option.getLength() < 4) {
                    ASSERT(true); //should never be happen
                    return 0;
                }

                uint32_t value = option.getValues(0);
                uint16_t sub = (value >> (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE));

                switch(sub){
                case MP_CAPABLE:
                    tcpEV << "[MPTCP][ESTABLISHED][MPTCP OPTION][IN] MP_CAPABLE" << "\n";
                    ASSERT(false);
                    break;
                case MP_JOIN:
                    // Subtype MP_JOIN
                    /**
                     * Be carfull, the server is in listen mode
                     * this could be a valid connection, but not a multipath
                     *
                     * However, in case of SUB = JOIN, it should be a multipath
                     * That means, we have to stop communication and must respond with an TCP RST
                     * FIXME add RST in error state
                     **/
                    tcpEV << "[MPTCP][ESTABLISHED][MPTCP OPTION][IN] MP_JOIN" << "\n";
                    _processMP_JOIN_ESTABLISHED(connId, subflow, tcpseg, &option);
                    break;
                case MP_DSS:
                    tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] MP_DSS" << "\n";
                    _processMP_DSS(connId, subflow, tcpseg, &option);
                    break;
                default:
                    tcpEV << "[MPTCP][ESTABLISHED][MPTCP OPTION][IN] Not supported" << "\n";
                    ASSERT(false);
                    break;
                }

            }
        }
    }
    return 1;
}

/*
 *  Process the MPTCP MP CAPABLE Flag
 *
 */
int MPTCP_PCB::_processMP_CAPABLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option) {

    if (option->getValuesArraySize() < 3) {
        ASSERT(true);
        return 0; //should never be happen
    }
    // In every case we expect a sender key
    if ((tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
        // SYN/ACK: We aspect the sender key in the MP_CAPABLE Option

        // read 64 bit keys
        uint64 key = option->getValues(2);
        key = (key << 32) | option->getValues(1);
        flow->setRemoteKey(key); // Could be generated every time -> important is key of ACK


        DEBUGPRINT("[PRE_ESTABLISHED][CAPABLE][IN] Got SYN/ACK with sender key %llu",
                flow->getLocalKey());
        DEBUGPRINT("[PRE_ESTABLISHED][CAPABLE][IN Got SYN/ACK with receiver key %llu",
                flow->getRemoteKey());

        // We set state Established, when we send the ACK
        return MPTCP_STATEFULL;
    } else if (tcpseg->getAckBit()) {
        // ACK: We aspect the sender key in the MP_CAPABLE Option
        if (option->getValuesArraySize() < 5) {
            ASSERT(false);
            return 0; //should never be happen
        }

        // read 64 bit keys
        uint64 key = option->getValues(2);
        key = (key << 32) | option->getValues(1);
        flow->setRemoteKey(key);
        key = option->getValues(4);
        key = (key << 32) | option->getValues(3);
        flow->setLocalKey(key); // Only for check

        DEBUGPRINT("[IDLE][CAPABLE][IN] Got ACK with Sender Key %llu", flow->getLocalKey());
        DEBUGPRINT("[IDLE][CAPABLE][IN] Got ACK with Receiver Key %llu",flow->getRemoteKey());

        // Status: Check MPTCP FLOW
        // - this is a MULTIPATH Stack:             OK
        // - This is a New MPTCP Flow:              OK
        // - The needed MP_CAPABLE Option exits:    OK
        // - Valid keys:                            OK
        // ==> Create a stateful Flow: generate token and SQN and Buffer

        if (flow == NULL) {
            // we have to be ESTABLISHED and is has to be an ACK
            if (tcpseg->getAckBit())
                flow = new MPTCP_Flow(connId, subflow->appGateIndex,this);
        }
        ASSERT(flow!=NULL);

        // OK new stateful MPTCP flow, calculate the token and Start-SQN

        // Add (First) Subflow of the connection
        flow->addSubflow(connId, subflow);
        flow->MPTCP_FSM(ESTABLISHED);
    } else {
        // SYN
        // read 64 bit keys
        uint64 key = option->getValues(2);
        key = (key << 32) | option->getValues(1);
        flow->setRemoteKey(key);
        DEBUGPRINT("[IDLE][CAPABLE][IN] Got SYN with sender key %llu", flow->getRemoteKey());
    }

    return MPTCP_STATELESS; // OK we got a MP_CAPABLE in a SYN, we are still stateless
}

/*
 *  Process the MPTCP MP Koin in idle state
 */
int MPTCP_PCB::_processMP_JOIN_IDLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const TCPOption* option) {
    // Only SYN is important in IDLE
    if((tcpseg->getSynBit()) && (!tcpseg->getAckBit()) ) {
        _processMP_JOIN_ESTABLISHED(connId, subflow, tcpseg, option);
    }
    return 0;
}

/*
 * Process the MPTCP MP Koin in established state
 */
int MPTCP_PCB::_processMP_JOIN_ESTABLISHED(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const TCPOption* option){
    // Now it is time to start a new SUBFLOW
    // We have to do the normal staff, but we have also look on the still existing flow
    // - procees SYN    -> Error in Established
    // - process SYN/ACK
    // - process ACK

// process SYN
    if((tcpseg->getSynBit()) && (!tcpseg->getAckBit()) ) {
        tcpEV << "[MPTCP][IDLE][JOIN] process SYN" << "\n";
            // First the main flow should be find in the list of flows

            // OK if we are here there exist
            // - a valid Multipath TCP Control Block
            // - next step is to send SYN/ACK
            // ==> add subflow to connection/ multipath flow (For first -> FIXME, handle TCP RST)

            flow->addSubflow(connId,subflow);

            // process the security part

            // get important information of the segment
            subflow->randomA = option->getValues(2);
            // It is also a got time to generate Random of B
            subflow->randomB = 0; // FIXME (uint32) flow->generateKey();

            // Generate truncated
            flow->generateSYNACK_HMAC(flow->getLocalKey(), flow->getRemoteKey(), subflow->randomA, subflow->randomB, subflow->MAC64);
            flow->generateACK_HMAC(flow->getLocalKey(), flow->getRemoteKey(), subflow->randomA, subflow->randomB, subflow->MAC160);

            subflow->joinToAck = true;

    }
// process SYN/ACK
    else if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
        tcpEV << "[MPTCP][ESTABLISHED][JOIN] process SYN ACK" << "\n";
        // FIXME - Check if this is the correct subflow - we added the flow still on the MPTCP SYN - I'm not sure if this is OK

        // Read the truncated MAC
        option->getValues(1);
        option->getValues(2);

        // However, we need the Host-B random number
// FIXME        subflow->randomA = option->getValues(3);

        // Here we should check the HMAC
        // FIXME int err isValidTruncatedHMAC();
        // if(err)
        // TCP RST FIXME

        // if everything is fine, we can go to established
//      flow->FSM(PRE_ESTABLISHED);
        subflow->joinToAck = true;
    }
// process ACK
    else if((!tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
        tcpEV << "[MPTCP][ESTABLISHED][JOIN] process ACK" << "\n";
//      unsigned char mac160[160];
//      int offset = 0;
        // FIXME Interprete MP_JOIN ACK
        //for(int i = 1; i <= 5; i++) { // 20 Octets/ 160 Bits
        //  uint32 value = option->getValues(i);
        //  memcpy(&mac160[offset],&value,sizeof(uint32));
        //  offset = 2 << i;
        //}
        // Here we should check the HMAC
        // Idea, compute the input bevor sending the packet
        // FIXME int err isValidHMAC();
        // if(err)
        // TCP RST FIXME

        // if everything is fine, we can go to established

        subflow->joinToAck = true;
    }

    return 0;
}

/*
 * Process default package with MP DSS
 */
int MPTCP_PCB::_processMP_DSS(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option){
        tcpEV << "[MPTCP][ESTABLISHED][DSS] process MPTCP Option DSS" << "\n";
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

        // Data Sequence Mapping [Section 3.3.1] ==> IN
        // TODO check for Flag M
        {
        // Note:
        // Fill Data Sequence Number with complete 64bit number or lowest 32
        // Subflow SQN is relativ to the SYN
        // Data-Level length Payload
        // Checksum if flag in MP_CAPABLE was set
        }
        // Data Acknowledgements [Section 3.3.2] ==> IN
        // TODO check for Flag A
        {
        // Data ACK = cum SQN
        // TODO Read Option and
        // compare with old...  flow->getHighestCumSQN(); // can we free memory

        }
        return 0;
}

/**
 * FIXME Scheduler
 */
TCPConnection* MPTCP_PCB::lookupMPTCPConnection(int connId, int aAppGateIndex,
        TCPConnection* subflow, TCPSegment *tcpseg) {

    //FIXME OK, now we have to choose by the scheduler which flow we should use next....
    //FIXME Scheduler
    ASSERT(false);
    return subflow;
}

/**
 * PCB lookup by ID
 */
MPTCP_PCB* MPTCP_PCB::_lookupMPTCP_PCB(int connId, int aAppGateIndex) {

    /* lookup is not easy, the best case for omnet is by connID and AppGateIndex */
    AllMultipathSubflowsVector_t::const_iterator it;
    for (it = subflows_vector.begin(); it != subflows_vector.end(); it++) {
        TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
        TCP_SubFlowVector_t::const_iterator it_subflows;

        for (it_subflows = t->flow->getSubflows()->begin(); it_subflows != t->flow->getSubflows()->end(); it_subflows++) {
            TCP_subflow_t* sub = (TCP_subflow_t*) (*it_subflows);
            if((sub->subflow->connId == connId) && (sub->subflow->appGateIndex == aAppGateIndex)){
                if(t->flow->getLocalToken()!=0 && t->flow->getRemoteToken()!=0)
                    return t->flow->getPCB();
            }
        }
    }
    return NULL;
}

/**
 * Internal helper to find the Multipath PCB by the MP_JOIN Potion
 */
MPTCP_PCB* MPTCP_PCB::_lookupMPTCP_PCBbyMP_JOIN_Option(TCPSegment* tcpseg,
        TCPConnection* subflow) {
    if (!subflow->getTcpMain()->multipath) {
        return NULL;
    }

    // We are here; so it must be Multipath TCP Stack
    // let check the options if there is a join request
    for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++) {
        const TCPOption& option = tcpseg->getOptions(i);
        short kind = option.getKind();

        // Check for Multipath Options
        if (kind == TCPOPTION_MPTCP) {
            if(option.getLength() < 4) {
                return NULL;
            }
            // Get Subtype and check for MP_JOIN
            uint32_t value = option.getValues(0);
            uint16_t sub = (value >> (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE));
            if(sub == MP_JOIN) {
                // OK, it is a MP_JOIN
                if (option.getValuesArraySize() < 2) {
                    return NULL;
                }

                // Check MPCB for MP_JOIN SYN
                if( (tcpseg->getSynBit()) && (!tcpseg->getAckBit()) ) {
                    uint64_t send_local_token = option.getValues(1);
                    AllMultipathSubflowsVector_t::const_iterator it;
                    // FIXME Check if the comparison is correct here
                    for (it = subflows_vector.begin(); it != subflows_vector.end(); it++) {
                            TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
                            // FIXME -> Of course only one is correct, but I don t wont to differ for the first step
                            ASSERT(t->flow->getLocalToken() != 0);
                            if(t->flow->getLocalToken() == send_local_token) {
                                return t->flow->getPCB();
                            }
                    }
                }
                // Check MPCB for MP_JOIN
                else if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
                    // Sender's Truncated MAC (64) MAC-B
                    // Sender's Random Number (32)
                    // FIXME missing comparison
                }
                // Check MPCB for MP_JOIN
                else if((!tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
                    // Sender's MAC (MAC-A)
                    // FIXME missing comparison
                }
            }
        } // MPTCP Options
    }
    return NULL; // No PCB found
}

/**
 * PCB lookup by subflow
 */
MPTCP_PCB* MPTCP_PCB::_lookupMPTCPbySubflow_PCB(TCPSegment *tcpseg,
        TCPConnection* subflow) {

    // Perhaps we know this flow by IP and Port
    AllMultipathSubflowsVector_t::const_iterator it;
    for (it = subflows_vector.begin(); it != subflows_vector.end(); it++) {
        TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
        if (t->flow->isSubflowOf(subflow)) {
            // So here we are, this subflow belongs to this flow,
            // this flow is controlled by this PCB
            return t->flow->getPCB();
        }
    }
    return NULL;
}

/*
 *
 */
MPTCP_PCB* MPTCP_PCB::lookupMPTCP_PCB(int connId, int aAppGateIndex,TCPSegment *tcpseg,  TCPConnection* subflow){
    MPTCP_PCB* tmp = NULL;
    if(tmp == NULL){
        // the best is we have the flow id
            if((uint32)subflow->getTcpMain()->multipath_subflow_id!=0){
                AllMultipathSubflowsVector_t::const_iterator it;
                for (it = subflows_vector.begin(); it != subflows_vector.end(); it++) {
                    TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
                    if (((uint32)subflow->getTcpMain()->multipath_subflow_id) == t->flow->getLocalToken()){
                        /* keep for debug */
                        // DEBUGPRINT("[MPTCP][OVERVIEW][PCB][LOOKUP] SEARCHED FOR LOCAL TOKEN %u ",(uint32)subflow->getTcpMain()->multipath_subflow_id);
                        // DEBUGPRINT("[MPTCP][OVERVIEW][PCB][LOOKUP] FOUND Flow ID TOKEN Local  %u ",t->flow->local_token);
                        // DEBUGPRINT("[MPTCP][OVERVIEW][PCB][LOOKUP] FOUND Flow ID TOKEN REMOTE %u ",t->flow->remote_token);
                        return t->flow->getPCB();
                    }
                }
            }
        }

    if(tmp == NULL)
        tmp = _lookupMPTCP_PCBbyMP_JOIN_Option(tcpseg, subflow);
    if(tmp == NULL)
        tmp = _lookupMPTCP_PCB(connId, aAppGateIndex);
    if(tmp == NULL)
        tmp = _lookupMPTCPbySubflow_PCB(tcpseg, subflow);
    if(tmp == NULL)
        DEBUGPRINT("[IDLE][lookupMPTCP_PCB] found no PCB for %i and %i",connId,aAppGateIndex);
    return tmp;
}

/**
 *  Debug Information
 */
void MPTCP_PCB::_printFlowOverview(int type){
#ifdef PRIVATE_DEBUG
    tcpEV<< "[MPTCP][OVERVIEW][PCB] =======================================" << "\n";
    static uint64_t rcv_cnt = 0;

    AllMultipathSubflowsVector_t::const_iterator it;

    DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] >>>>>>>>>>>>>>>>>>>>>>>>>>>>>   SYSTEM SUBFLOWS DURING RECEIVE %llu  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<",rcv_cnt++);

    for (it = subflows_vector.begin(); it != subflows_vector.end(); it++) {
        TuppleWithStatus_t* tmp = (TuppleWithStatus_t *)(*it);

        switch(tmp->flow->getState()){
        case IDLE:
            tcpEV<< "[MPTCP][OVERVIEW][PCB] IDLE \n";
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN Local  %u IDLE",tmp->flow->getLocalToken());
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN REMOTE  %u IDLE",tmp->flow->getRemoteToken());
            break;
        case PRE_ESTABLISHED:
            tcpEV<< "[MPTCP][OVERVIEW][PCB] PRE_ESTABLISHED \n";
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN Local  %u PRE_ESTABLISHED",tmp->flow->getLocalToken());
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN REMOTE  %u PRE_ESTABLISHED",tmp->flow->getRemoteToken());
            break;
        case SHUTDOWN:
            tcpEV<< "[MPTCP][OVERVIEW][PCB] SHUTDOWN \n";
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN Local  %u SHUTDOWN",tmp->flow->getLocalToken());
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN REMOTE  %u SHUTDOWN",tmp->flow->getRemoteToken());
            break;
        case ESTABLISHED:
            tcpEV<< "[MPTCP][OVERVIEW][PCB] ESTABLISHED \n";
            {
                switch(tmp->flow->appID){
                case 0:
                    DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] SERVER INSTANCE Flow ID TOKEN Local  %u <--> REMOTE %u ESTABLISHED - Flow Token %u", tmp->flow->getLocalToken(),tmp->flow->getRemoteToken(), tmp->flow->getPCB()->id);
                    break;
                default:
                    DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] CLIENT APP %u   Flow ID TOKEN Local  %u <--> REMOTE %u ESTABLISHED - Flow Token %u",tmp->flow->appID, tmp->flow->getLocalToken(),tmp->flow->getRemoteToken(), tmp->flow->getPCB()->id);
                }
            }
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Base Sequence Number:        %llu",tmp->flow->getBaseSQN());
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Highest Cum Sequence number: %llu",tmp->flow->getHighestCumSQN());
            break;
        default:
            ASSERT(false);
            break;
        }

        // TODO
        TCP_SubFlowVector_t::const_iterator it_subflows;
        int subflow_cnt = 0;
        for (it_subflows = tmp->flow->getSubflows()->begin(); it_subflows != tmp->flow->getSubflows()->end(); it_subflows++,subflow_cnt++) {
            TCP_subflow_t* sub = (TCP_subflow_t*) (*it_subflows);
            tcpEV<< "[MPTCP][OVERVIEW][PCB][SUBFLOW]["<< subflow_cnt <<"] ConnID: " << sub->subflow->connId << "\n";
            tcpEV<< "[MPTCP][OVERVIEW][PCB][SUBFLOW]["<< subflow_cnt <<"] AppGate: " << sub->subflow->appGateIndex << "\n";
            tcpEV<< "[MPTCP][OVERVIEW][PCB][SUBFLOW]["<< subflow_cnt <<"] Local Adress:" << sub->subflow->localAddr << "\n";
            tcpEV<< "[MPTCP][OVERVIEW][PCB][SUBFLOW]["<< subflow_cnt <<"] Local Port:  " << sub->subflow->localPort << "\n";
            tcpEV<< "[MPTCP][OVERVIEW][PCB][SUBFLOW]["<< subflow_cnt <<"] Remote Adress:" << sub->subflow->remoteAddr << "\n";
            tcpEV<< "[MPTCP][OVERVIEW][PCB][SUBFLOW]["<< subflow_cnt <<"] Remote Port:  " << sub->subflow->remotePort << "\n";
        }

    }
#endif
}

/**
 * FIXME Check Function
 */
int MPTCP_PCB::_clearAll() {
    // FIXME shutdown
    if (flow != NULL) {
        delete flow;
        flow = NULL;
    }
    return 0;
}

/**
 * helper to get the flow
 */
MPTCP_Flow* MPTCP_PCB::getFlow() {
    return flow;
}

#endif // Private
