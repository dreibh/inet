/*
 * TCPMultipathPCB.cc
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */
#ifdef PRIVATE
#include "TCPConnection.h"
#include "TCPMultipathPCB.h"
#include "TCPSegment.h"

//##################################################################################################
//#
//# THE MULTIPATH TCP PROTOCOL CONTROL BLOCK
//#
//#################################################################################################



// Note: Alternative implementation. Setup PCB as Singleton implementation and create list in PCB
AllMultipathTCPVector_t MPTCP_PCB::mptcp_flow_vector; // TODO This is the first shot of hold all system wide subflows.


/**
 * Constructor
 */
MPTCP_PCB::MPTCP_PCB(){
    ASSERT(false && "EMPTY CONSTRUCTOR NOT ALLOWED");
}

/**
 * Constructor for an PCB
 *
 * Includes also the persistent in the static subflow_vector
 */
MPTCP_PCB::MPTCP_PCB(int connId, int appGateIndex, TCPConnection* subflow) {

    subflow->flow = NULL;
    // Static helper elements for organization
    AllMultipathTCPVector_t::const_iterator it;
    for (it = mptcp_flow_vector.begin(); it != mptcp_flow_vector.end(); it++) {
       t = (TuppleWithStatus_t *)(*it);
       if(t->active){   // this flow is active
           if(t->flow->isSubflowOf(subflow)){
               // This is a known multipath subflow
               subflow->flow = t->flow;
           }
       }
    }

    if(subflow->flow==NULL){
        // Setup PCB and make first subflow persistent
        t = new TuppleWithStatus_t();
        subflow->flow = new MPTCP_Flow(connId, appGateIndex, subflow, this);
        t->active = true;
        t->flow = subflow->flow;
        t->appGateIndex = appGateIndex;
        t->connID = connId;
        addMPTCPFlow(t);
        subflow->getTcpMain()->flow = subflow->flow;
    }
    ASSERT(subflow->flow!=NULL && "SUBFLOW SHOULD NEVER BE NULL HERE");
}
/**
 * De-Constructor
 */
MPTCP_PCB::~MPTCP_PCB() {
    // By default no flows should be in the list
    AllMultipathTCPVector_t::iterator i = mptcp_flow_vector.begin();
    while (i != mptcp_flow_vector.end())
    {
        TuppleWithStatus_t* entry = (*i);
        if(entry->flow!=NULL)
            delete entry->flow;
        mptcp_flow_vector.erase(i);
        delete entry;
        i = mptcp_flow_vector.begin();
    }
    mptcp_flow_vector.clear();
}

/**
 * Important External Static Function
 * 1) Find mPCB
 * 2) Process Segment
 * 3) If needed become stateful
 */
MPTCP_PCB* MPTCP_PCB::processMPTCPSegment(int connId, int aAppGateIndex,
    TCPConnection* subflow, TCPSegment *tcpseg) {
    DEBUGPRINT("Process Segment >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>%s","\0");
    // First look for a Multipath Protocol Control Block
    MPTCP_PCB* tmp = MPTCP_PCB::lookupMPTCP_PCB(connId, aAppGateIndex,tcpseg, subflow);

    tmp->DEBUGprintFlowOverview(0);
    if (tmp == NULL){
        DEBUGPRINT("[MPTCP][PROCESS][INCOMING] DID my best, but found no Flow for this subflow %s","\0");
        tmp = new MPTCP_PCB(connId, aAppGateIndex,subflow);

    }else{
        DEBUGPRINT("[MPTCP][PROCESS][INCOMING] Existing flow use exiting PCB%s","\0");
        subflow->flow->DEBUGprintStatus();

        switch(subflow->flow->getState()){
        case IDLE:
            DEBUGPRINT("IDLE%s","\0");
            break;
        case PRE_ESTABLISHED:
            DEBUGPRINT("PRE_ESTABLISHED%s","\0");
            break;
        case SHUTDOWN:
            DEBUGPRINT("SHUTDOWN%s","\0");
            break;
        case ESTABLISHED:
            DEBUGPRINT("ESTABLISHED%s","\0");
            break;
        default:
            ASSERT(false && "STATE IS NOT DEFINED");
            break;
        }

    }
    ASSERT(tmp->_processSegment(connId, subflow, tcpseg) && "SOMETHING WENT WRONG IN PROCEEDING THE SEGMENT");

    DEBUGPRINT("End Process Segment <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<%s","\0");
    return tmp;
}

void MPTCP_PCB::addMPTCPFlow(TuppleWithStatus_t* t){
        MPTCP_PCB::mptcp_flow_vector.push_back(t);
}


/**
* Internal helper to process packet for a flow
* FIXME Something goes wrong (TCP RST)
*/
int MPTCP_PCB::_processSegment(int connId, TCPConnection* subflow,
    TCPSegment *tcpseg) {
    // We are here; so it must be Multipath TCP Stack
    if (!subflow->getTcpMain()->multipath) {
        ASSERT(false && "UPS...We are not in Multipath -> What is wrong here...?"); // FIXME Only for testing
        return 0;
    }
    if ((!tcpseg->getSynBit()) && (tcpseg->getAckBit())){
        DEBUGPRINT("TCP ACK%s","\0");
    }
    if ((tcpseg->getSynBit()) && (!tcpseg->getAckBit())){
        DEBUGPRINT("TCP SYN%s","\0");
    }
    if ((tcpseg->getSynBit()) && (tcpseg->getAckBit())){
        DEBUGPRINT("TCP SYN ACK%s","\0");
    }

    if (tcpseg->getFinBit()){
        DEBUGPRINT("TCP FIN SEND%s","\0");
        subflow->flow->close();
    }
    if (tcpseg->getRstBit()){
        DEBUGPRINT("TCP RST SEND%s","\0")
    }
    /**
     * CASE "NEW MPTCP FLOW" or "NO MPTCP FLOW"
     */
    // Check if this is still a Multipath Connection with an existing Flow
    if (subflow->flow == NULL || (subflow->flow->getState() == IDLE) || (subflow->flow->getState() == PRE_ESTABLISHED)) {

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
            return 0; // No MPTCP Options
        }
        // lets parse the options
        for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++) {
            const TCPOption& option = tcpseg->getOptions(i);
            short kind = option.getKind();
            //          short length = option.getLength();

            if (kind == TCPOPTION_MPTCP) {
                if(option.getLength() < 4) {
                    ASSERT(false && "We need some more options for multipath"); //should never be happen
                    return 0;
                }

                uint32_t first = option.getValues(0);
                uint16_t sub = (first >> (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE));

                // OK, it is a MPTCP Option, so lets figure out which subtype
                switch(sub){
                    case MP_CAPABLE:
                        DEBUGPRINT("[MPTCP][IDLE][MPTCP OPTION][IN] MP_CAPABLE%s","\0");
                        _processMP_CAPABLE(connId, subflow, tcpseg, &option);
                        break;
                    case MP_JOIN:
                        DEBUGPRINT("[MPTCP][IDLE][MPTCP OPTION][IN] MP_JOIN%s","\0");
                        _processMP_JOIN_IDLE(connId, subflow, tcpseg, &option);
                        break;
                    case MP_DSS:
                        DEBUGPRINT("[MPTCP][IDLE][MPTCP OPTION][IN] MP_DSS%s","\0");
                        break;
                    default:
                        DEBUGPRINT("[MPTCP][IDLE][MPTCP OPTION][IN] Not supported%s","\0");
                        ASSERT(false && "MPTCP State not supported");
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
                DEBUGPRINT("[MPTCP][IDLE][MPTCP OPTION][IN] process%s","\0");
                if(option.getLength() < 4) {
                    ASSERT(false && "We need some more options..."); //should never be happen
                    return 0;
                }

                uint32_t value = option.getValues(0);
                uint16_t sub = (value >> (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE));

                switch(sub){
                case MP_CAPABLE:
                    DEBUGPRINT("[MPTCP][ESTABLISHED][MPTCP OPTION][IN] MP_CAPABLE%s","\0");
                    if ((!tcpseg->getSynBit()) && (tcpseg->getAckBit())){
                        _processMP_CAPABLE(connId, subflow, tcpseg, &option);
                    }
                    else
                        ASSERT(false && "This state is currently not allowed");
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
                    DEBUGPRINT("[MPTCP][ESTABLISHED][MPTCP OPTION][IN] MP_JOIN%s","\0");
                    _processMP_JOIN_ESTABLISHED(connId, subflow, tcpseg, &option);
                    break;
                case MP_DSS:
                    DEBUGPRINT("[MPTCP][IDLE][MPTCP OPTION][IN] MP_DSS%s","\0");
                    _processMP_DSS(connId, subflow, tcpseg, &option);
                    break;
                default:
                    DEBUGPRINT("[MPTCP][ESTABLISHED][MPTCP OPTION][IN] Not supported%s","\0");
                    ASSERT(false && "This MPTCP Message Type is not supported");
                    break;
                }
            }
            subflow->flow->refreshSendMPTCPWindow();
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
        ASSERT(false && "We need some more options...");
        return 0; //should never be happen
    }
    // In every case we expect a sender key
    if ((tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
        // SYN/ACK: We aspect the sender key in the MP_CAPABLE Option

        // read 64 bit keys
        uint64 key = option->getValues(2);
        key = (key << 32) | option->getValues(1);
        subflow->flow->setRemoteKey(key); // Could be generated every time -> important is key of ACK
        // We set state Established, when we send the ACK
        subflow->flow->addSubflow(connId, subflow);
        return MPTCP_STATEFULL;
    } else if (tcpseg->getAckBit()) {
        // ACK: We aspect the sender key in the MP_CAPABLE Option
        if (option->getValuesArraySize() < 5) {
            ASSERT(false && "we need some more options..." );
            return 0; //should never be happen
        }

        // read 64 bit keys
        uint64 key = option->getValues(2);
        key = (key << 32) | option->getValues(1);
        subflow->flow->setRemoteKey(key);
        key = option->getValues(4);
        key = (key << 32) | option->getValues(3);
        subflow->flow->setLocalKey(key); // Only for check


        // Status: Check MPTCP FLOW
        // - this is a MULTIPATH Stack:             OK
        // - This is a New MPTCP Flow:              OK
        // - The needed MP_CAPABLE Option exits:    OK
        // - Valid keys:                            OK
        // ==> Create a stateful Flow: generate token and SQN and Buffer

        /* We got a SYN-ACK
         * That means we know this flow
         * If not, we have a Problem
         *
         * 1) Search for the existing Multipath Flow
         * 2) Remove this Working Flow from List
         */

        ASSERT(subflow->flow!=NULL && "Why is the subflow NULL?");

        // OK new stateful MPTCP flow, calculate the token and Start-SQN

        // Add (First) Subflow of the connection
        subflow->flow->addSubflow(connId, subflow);

    } else {
        // SYN
        // read 64 bit keys
        uint64 key = option->getValues(2);
        key = (key << 32) | option->getValues(1);
        subflow->flow->setRemoteKey(key);
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
        DEBUGPRINT("[MPTCP][IDLE][JOIN] process SYN%s","\0");
        // First the main flow should be find in the list of flows

        // OK if we are here there exist
        // - a valid Multipath TCP Control Block
        // - next step is to send SYN/ACK
        // ==> add subflow to connection/ multipath flow (For first -> FIXME, handle TCP RST)
        uint32_t remoteToken = option->getValues(1);
        DEBUGPRINT("[MPTCP] got Token = %i", remoteToken);
        // First we should find the flow for this subflow. We must sure that we know it
        AllMultipathTCPVector_t::const_iterator it;
        for (it = mptcp_flow_vector.begin(); it != mptcp_flow_vector.end(); it++) {
           TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
           TCP_SubFlowVector_t::const_iterator it_mpflows;
           if(t->flow!=NULL){
               DEBUGPRINT("[MPTCP] Token = %i", t->flow->getLocalToken());
               subflow->flow = t->flow;
               if(t->flow->getLocalToken() == remoteToken){
                   subflow->flow = t->flow;
                   t->flow->addSubflow(connId,subflow);
                   break;
               }
           }
        }
    }
// process SYN/ACK
    else if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
        DEBUGPRINT("[MPTCP][ESTABLISHED][JOIN] process SYN ACK%s","\0");
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

//        subflow->sendAck();
    }
// process ACK
    else if((!tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
        DEBUGPRINT("[MPTCP][ESTABLISHED][JOIN] process ACK%s","\0");
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

//        subflow->joinToAck = true;
    }

    return 0;
}

/*
 * Process default package with MP DSS
 */
int MPTCP_PCB::_processMP_DSS(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option){
        DEBUGPRINT("[MPTCP][ESTABLISHED][DSS] process MPTCP Option DSS%s","\0");
        // Note: it does not matter on which flow the data comes in.... we have the flow, so proceed...
        /*
        DSS packet format:
        1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +---------------+---------------+-------+----------------------+
        |     Kind      |    Length     |Subtype| (reserved) |F|m|M|a|A|    // Flags defined in Header
        +---------------+---------------+-------+----------------------+
        |           Data ACK (4 or 8 octets, depending on flags)       |    // Data Acknowledgments
        +--------------------------------------------------------------+
        |   Data Sequence Number (4 or 8 octets, depending on flags)   |    // Data Sequence Mapping
        +--------------------------------------------------------------+
        |              Subflow Sequence Number (4 octets)              |    // Data Sequence Mapping
        +-------------------------------+------------------------------+
        |  Data-level Length (2 octets) |      Checksum (2 octets)     |    // Data Sequence Mapping
        +-------------------------------+------------------------------+
        */
        //
        DEBUGPRINT("[FLOW][RCV][DSS][STATUS] snd_una: %ld", subflow->flow->mptcp_snd_una);
        DEBUGPRINT("[FLOW][RCV][DSS][STATUS] snd_nxt: %ld", subflow->flow->mptcp_snd_nxt);
        DEBUGPRINT("[FLOW][RCV][DSS][STATUS] snd_wnd: %d",  subflow->flow->mptcp_snd_wnd);
        DEBUGPRINT("[FLOW][RCV][DSS][STATUS] rcv_nxt: %ld", subflow->flow->mptcp_rcv_nxt);
        DEBUGPRINT("[FLOW][RCV][DSS][STATUS] rcv_wnd: %ld", subflow->flow->mptcp_rcv_wnd);

        // The data itself will be pushed to the application later during -> Flow sendtoapp
        // 1) read data of packet
        // 2) enqueue data to receive queue
        // 3) proceed data in sendtoapp (we don t have to check, if still the subflow is not in sync)

        // some checks
        ASSERT((option->getValuesArraySize() > 3) && "We need some more options...");

        // First get the flags so we know what to do
        uint32 option_cnt = 0;
        uint32_t option_v[6] = {0};

        uint64 ack_seq  = 0;
        uint64 snd_seq  = 0;
        uint32 flow_seq = 0;
        uint16 data_len = 0;

        for(option_cnt = 0;option_cnt < option->getValuesArraySize() ;option_cnt++){
            option_v[option_cnt] = option->getValues(option_cnt);
        }
        option_cnt = 0;
        // Currently the flags are at the first bits of the Option 0
        uint8_t flags = option_v[option_cnt] >> 16;
        bool isDSS_FLAG_A = (flags&DSS_FLAG_A)?true:false; // DSS_FLAG_A (0x01) Data ACK present
        bool isDSS_FLAG_a = (flags&DSS_FLAG_a)?true:false; // DSS_FLAG_a (0x02) Data ACK is 8 octets
        bool isDSS_FLAG_M = (flags&DSS_FLAG_M)?true:false; // DSS_FLAG_M (0x04) Data Sequence Number, Subflow Sequence Number, Data-level  Length, and Checksum present
        bool isDSS_FLAG_m = (flags&DSS_FLAG_m)?true:false; // DSS_FLAG_m (0x08) Data SQN is 8 Octets

        if(isDSS_FLAG_A){
            // Data Ack
            uint16_t first16  = option_v[option_cnt];
            uint16_t second16 = option_v[++option_cnt] >> 16;
            ack_seq |= (uint32_t) first16 << 16;
            ack_seq |= (uint32_t) second16;
            if(isDSS_FLAG_a){
                // 8 octets
                // TODO
                ASSERT(false && "NOT Implemented yet");
            }else{
                // we have to guess the rest... it should have the same offset like flow->mptcp_snd_una
                // FIXME overflow border
                uint64_t first32_bits = subflow->flow->mptcp_snd_una >> 32;
                ack_seq |= first32_bits << 32;
            }
        }
        if(isDSS_FLAG_M){
            // seq no

            uint16_t first16  = option_v[option_cnt];
            uint16_t second16 = option_v[++option_cnt] >> 16;
            snd_seq |= (uint32_t) first16 << 16;
            snd_seq |= (uint32_t) second16;
            if(isDSS_FLAG_m){
                // 8 octets
                // TODO
                ASSERT(false && "NOT Implemented yet");
            }else{
                // we have to guess the rest... it should have the same offset like flow->mptcp_rcv_nxt
                // FIXME overflow border
                uint64_t first32_bits = subflow->flow->mptcp_rcv_nxt >> 32;
                snd_seq |= first32_bits << 32;
            }

            flow_seq  = option_v[option_cnt] << 16;
            flow_seq |= option_v[++option_cnt] >> 16;

            data_len =  option_v[option_cnt];
        }

        // we know everything ...lets queue in if data > 0
        if(data_len > 0){
        	//TCPSegment *mptcp_tcpseg =  new TCPSegment(*tcpseg);
        	subflow->flow->enqueueMPTCPData(tcpseg, snd_seq, data_len);
        }

        DEBUGPRINT("[FLOW][DSS][INFO][RCV] Ack Seq: %ld \t SND Seq: %ld \t Subflow Seq: %d \t Data length: %d", ack_seq, snd_seq, flow_seq, data_len);
        return 0;
}

/**
 * FIXME Scheduler
 */
TCPConnection* MPTCP_PCB::lookupMPTCPConnection(int connId, int aAppGateIndex,
        TCPConnection* subflow, TCPSegment *tcpseg) {

    //FIXME OK, now we have to choose by the scheduler which flow we should use next....
    //FIXME Scheduler
    ASSERT(false && "This is just a test function....don t use");
    return subflow;
}

/**
 * PCB lookup by ID
 */
MPTCP_PCB* MPTCP_PCB::_lookupMPTCP_PCB(int connId, int aAppGateIndex, TCPConnection *subflow) {

    /* lookup is not easy, the best case for omnet is by connID and AppGateIndex */
    AllMultipathTCPVector_t::const_iterator it;
    for (it = mptcp_flow_vector.begin(); it != mptcp_flow_vector.end(); it++) {
        TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
        TCP_SubFlowVector_t::const_iterator it_mpflows;
        if(t->flow!=NULL){
            for (it_mpflows = t->flow->getSubflows()->begin(); it_mpflows != t->flow->getSubflows()->end(); it_mpflows++) {
                TCP_subflow_t* sub = (TCP_subflow_t*) (*it_mpflows);
                if((sub->subflow->connId == connId) && (sub->subflow->appGateIndex == aAppGateIndex)){
                    if(t->flow->getLocalToken()!=0 && t->flow->getRemoteToken()!=0)
                        if(subflow->flow != t->flow)
                            subflow->flow = t->flow;
                        return t->flow->getPCB();
                }
            }
        }
    }

    return NULL;

}

/**
 * Internal helper to find the Multipath PCB by the MP_JOIN Potion
 */
MPTCP_PCB* MPTCP_PCB::_lookupMPTCP_PCBbyMP_Option(TCPSegment* tcpseg,
        TCPConnection* subflow) {
    if((tcpseg->getAckBit()) && (!tcpseg->getSynBit())){
        DEBUGPRINT("We got an ACK, we should find Flow by Token,%s","\0");
    }
    if (!subflow->getTcpMain()->multipath) {
        subflow->flow = NULL;
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
            if(sub == MP_CAPABLE) {
                if((!tcpseg->getSynBit()) && (tcpseg->getAckBit())) {   // It is an ACK we have to know this
                    // ACK: We aspect the sender key in the MP_CAPABLE Option
                    if (option.getValuesArraySize() < 5) {
                        ASSERT(false && "We need some more options");
                        return 0; //should never be happen
                    }

                    // read 64 bit keys
                    uint64_t remote_key = option.getValues(2);
                    remote_key = (remote_key << 32) | option.getValues(1);

                    uint64_t local_key = option.getValues(4);
                    local_key = (local_key << 32) | option.getValues(3);

                    AllMultipathTCPVector_t::const_iterator it;
                    for (it = mptcp_flow_vector.begin(); it != mptcp_flow_vector.end(); it++) {
                           TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
                           if(t->flow->keysAreEqual(remote_key,local_key)){
                               subflow->flow = t->flow;
                               return t->flow->getPCB();
                           }
                    }
                }
            }
            if(sub == MP_JOIN) {
                // OK, it is a MP_JOIN
                if (option.getValuesArraySize() < 2) {
                    return NULL;
                }

                // Check MPCB for MP_JOIN SYN
                if( (tcpseg->getSynBit()) && (!tcpseg->getAckBit()) ) {
                    uint64_t send_local_token = option.getValues(1);
                    AllMultipathTCPVector_t::const_iterator it;
                    // FIXME Check if the comparison is correct here
                    for (it = mptcp_flow_vector.begin(); it != mptcp_flow_vector.end(); it++) {
                            TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);

                            // FIXME -> Of course only one is correct, but I don t wont to differ for the first step
                            // Later we have time for error handling

                            if(t->flow->getLocalToken() == send_local_token) {
                                subflow->flow = t->flow;
                                return t->flow->getPCB();
                            }
                    }
                }
                // Check MPCB for MP_JOIN
                else if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
                    // Sender's Truncated MAC (64) MAC-B
                    // Sender's Random Number (32)
                    // FIXME missing comparison
                    AllMultipathTCPVector_t::const_iterator it;
                    // FIXME Check if the comparison is correct here



                }
                // Check MPCB for MP_JOIN
                else if((!tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
                    // Sender's MAC (MAC-A)
                    // FIXME missing comparison

                    AllMultipathTCPVector_t::const_iterator it;
                    // FIXME Check if the comparison is correct here
                    // FIXME FIXME -> only for a fest test
                   // ASSERT(false);
                }
            }
        } // MPTCP Options
    }
    return NULL; // No PCB found
}

/**
 * PCB lookup by subflow
 */
MPTCP_PCB* MPTCP_PCB::_lookupMPTCPbySubflow_PCB(int connId, int aAppGateIndex, TCPSegment *tcpseg,
        TCPConnection* subflow) {

    // Perhaps we know this flow by IP and Port
    AllMultipathTCPVector_t::const_iterator it;
    for (it = mptcp_flow_vector.begin(); it != mptcp_flow_vector.end(); it++) {
        TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
           if((t->appGateIndex == aAppGateIndex) && (t->connID == connId)){
                DEBUGPRINT("APP GATE UND ConnID sind gleich %i==%i %i==%i",t->appGateIndex ,aAppGateIndex,t->connID, connId);
                if (t->flow->isSubflowOf(subflow)) {
                    subflow->flow = t->flow;
                    return t->flow->getPCB();
                }
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
                AllMultipathTCPVector_t::const_iterator it;
                for (it = mptcp_flow_vector.begin(); it != mptcp_flow_vector.end(); it++) {
                    TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
                    if(t->flow != NULL){
                        if (((uint32)subflow->getTcpMain()->multipath_subflow_id) == t->flow->getLocalToken()){
                            subflow->flow = t->flow;    // Fixme Should be the same -> TODO add an ASSERT
                            return t->flow->getPCB();
                        }
                    }
                }
            }
        }

    if(tmp == NULL){
        DEBUGPRINT("[MPTCP][PROCESS][INCOMING]_lookupMPTCP_PCBbyMP_JOIN_Option%s","\0");
        tmp = _lookupMPTCP_PCBbyMP_Option(tcpseg, subflow);
    }
/*    if(tmp == NULL){
        DEBUGPRINT("[MPTCP][PROCESS][INCOMING]_lookupMPTCP_PCB by APP ID %s","\0");
        tmp = _lookupMPTCP_PCB(connId, aAppGateIndex);
    }
*/
    if(tmp == NULL){    // FIXME ... This is a fast workaround, as log the securtiy stuff is not complete installed
        DEBUGPRINT("_lookupMPTCP_PCBbyMP_JOIN_Option%s","\0");
        tmp = _lookupMPTCPbySubflow_PCB(connId , aAppGateIndex,tcpseg, subflow);
    }
    if(tmp == NULL)
        DEBUGPRINT("[IDLE][lookupMPTCP_PCB] found no PCB for %i and %i",connId,aAppGateIndex);

    return tmp;

}

/**
 * FIXME Check Function
 */
int MPTCP_PCB::_clearAll() {
	AllMultipathTCPVector_t::const_iterator it;
	for (it = mptcp_flow_vector.begin(); it != mptcp_flow_vector.end(); it++) {
		TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
		if(t->flow != NULL){
			delete t->flow;
			t->flow = NULL;
		}
	}
	mptcp_flow_vector.clear();
    return 0;
}

/**
 * helper to get the flow
 */
//MPTCP_Flow* MPTCP_PCB::getFlow() {
//    return flow;
//}



/**
 *  Debug Information
 */
void MPTCP_PCB::DEBUGprintFlowOverview(int type){
#ifdef PRIVATE
   DEBUGPRINT("[MPTCP][OVERVIEW][PCB] =======================================%s","\0");
   // static uint64_t rcv_cnt = 0;

    AllMultipathTCPVector_t::const_iterator it;

    for (it = mptcp_flow_vector.begin(); it != mptcp_flow_vector.end(); it++) {
        TuppleWithStatus_t* tmp = (TuppleWithStatus_t *)(*it);

        switch(tmp->flow->getState()){
        case IDLE:
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB] IDLE%s","\0");
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN Local  %u IDLE",tmp->flow->getLocalToken());
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN REMOTE  %u IDLE",tmp->flow->getRemoteToken());
            break;
        case PRE_ESTABLISHED:
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN Local  %u PRE_ESTABLISHED",tmp->flow->getLocalToken());
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN REMOTE  %u PRE_ESTABLISHED",tmp->flow->getRemoteToken());
            break;
        case SHUTDOWN:
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN Local  %u SHUTDOWN",tmp->flow->getLocalToken());
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID TOKEN REMOTE  %u SHUTDOWN",tmp->flow->getRemoteToken());
            break;
        case ESTABLISHED:
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB] ESTABLISHED%s","\0");
            {
                switch(tmp->flow->getAppID()){
                case 0:
                    DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] SERVER INSTANCE Flow ID TOKEN Local  %u <--> REMOTE %u ESTABLISHED - Flow Token %u", tmp->flow->getLocalToken(),tmp->flow->getRemoteToken(), tmp->flow->getPCB()->id);
                    break;
                default:
                    DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] CLIENT APP %u   Flow ID TOKEN Local  %u <--> REMOTE %u ESTABLISHED - Flow Token %u",tmp->flow->getAppID(), tmp->flow->getLocalToken(),tmp->flow->getRemoteToken(), tmp->flow->getPCB()->id);
                }
            }
            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Base Sequence Number:        %ld",tmp->flow->getBaseSQN());
//            DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Highest Cum Sequence number: %ld",tmp->flow->getHighestCumSQN());
            break;
        default:
            ASSERT(false && "State not supported");
            break;
        }
    }

#endif
}



#endif // Private
