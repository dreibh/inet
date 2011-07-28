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
//
//

#include "TCP.h"
#include "TCPMultipath.h"
#include "TCPConnection.h"
#include "TCPSegment.h"
#include <ASSERT.h>
#include <openssl/sha.h>
#include <inttypes.h>


// For some debug output
/* defines for debuging */
#define WHERESTR  "\n[MPTCP][file %s, line %d]: "
#define WHEREARG  __FILE__, __LINE__
#define DEBUGPRINT2(...)  fprintf(stderr, __VA_ARGS__)
//#define DEBUGPRINT(_fmt, ...)  DEBUGPRINT2(WHERESTR _fmt, WHEREARG, __VA_ARGS__)

//#ifndef PRIVATE_DEBUG
#define DEBUGPRINT(_fmt, ...)  DEBUGPRINT2(WHERESTR _fmt, WHEREARG, __VA_ARGS__)
//#else
//#define	DEBUGPRINT(_fmt, ...) ;
//#endif

const unsigned int MP_SIGNAL_FIRST_VALUE_TYPE = 16;
const unsigned int MP_SUBTYPE_POS = MP_SIGNAL_FIRST_VALUE_TYPE - 4;
const unsigned int MP_VERSION_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - 4;
const unsigned int MP_C_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - MP_VERSION_POS - 1;
const unsigned int MP_RESERVED_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - MP_VERSION_POS - MP_C_POS - 4;
const unsigned int MP_S_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - MP_VERSION_POS - MP_C_POS - MP_RESERVED_POS - 1;

#define COMMON_MPTCP_OPTION_HEADER_SIZE 16
#define SENDER_KEY_SIZE 				64
#define RECEIVER_KEY_SIZE 				64

#define MP_CAPABLE_SIZE_SYN    ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + SENDER_KEY_SIZE) >> 3)
#define MP_CAPABLE_SIZE_SYNACK ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + RECEIVER_KEY_SIZE) >> 3)
#define MP_CAPABLE_SIZE_ACK    ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + SENDER_KEY_SIZE + RECEIVER_KEY_SIZE) >> 3)

#define MP_JOIN_SIZE_SYN 				12
#define MP_JOIN_SIZE_SYNACK 			16
#define MP_JOIN_SIZE_ACK 				24

#define VERSION 0x0


/**
 * Constructor
 * @param ID ID for each Flow
 */
MPTCP_Flow::MPTCP_Flow(int ID, int aAppGateIndex) :
	cnt_subflows(0), state(IDLE), initiator(false), sender_key(0), receiver_key(0) {

	// Set same basics
	appID = ID;
	state = IDLE;
	appGateIndex = aAppGateIndex;
	// init the flow
	initFlow();
}

/**
 * Destructor
 */
MPTCP_Flow::~MPTCP_Flow() {
	// TODO
}

/**
 * Initialization of an Multipath Flow
 * A Flow is equal to one connection
 * A Flow contains different subflows
 */
void MPTCP_Flow::initFlow() {
	// We need cross layer information of available interfaces
	IInterfaceTable *ift = interfaceTableAccess.get();
	// Some debug staff
	tcpEV<<"[MPTCP FLOW] Add local address...\n";
	// Setup a list of available addresses
	if (!list_laddrtuple.size())
	{
		for (int32 i=0; i<ift->getNumInterfaces(); ++i)
		{
			AddrTupple_t* addr = new AddrTupple_t();

			if (ift->getInterface(i)->ipv4Data()!=NULL)
			{
				tcpEV<<"[MPTCP FLOW] add IPv4: " << ift->getInterface(i)->ipv4Data()->getIPAddress() << "\n";
				addr->addr = ift->getInterface(i)->ipv4Data()->getIPAddress();
			}
			else if (ift->getInterface(i)->ipv6Data()!=NULL)
			{
				for (int32 j=0; j<ift->getInterface(i)->ipv6Data()->getNumAddresses(); j++)
				{
					tcpEV<<"[MPTCP FLOW] add IPv6: " << ift->getInterface(i)->ipv6Data()->getAddress(j) << "\n";
					addr->addr =  ift->getInterface(i)->ipv6Data()->getAddress(j);
				}
			}
			else{
				ASSERT(false);
			}
			// List of local adress tuples
			list_laddrtuple.push_back(addr);
		}
	}
	else
	{
		// Should never happen...
		tcpEV<<"Problems by adding all known IP adresses\n";
	}

	DEBUGPRINT("[INIT] Found local Adresse: %i",(int)list_laddrtuple.size());
	return;
}

/**
 * Add a subflow to a MPTCP connection
 * */
int MPTCP_Flow::addSubflow(int id, TCPConnection* subflow) {
	// Create a subflow entry in the list, a entry is stateful
	TCP_SUBFLOW_T *t = new TCP_SUBFLOW_T();

	// If we know this subflow allread something goes wrong
	for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i
			!= subflow_list.end(); ++i) {
		TCP_SUBFLOW_T* entry = (*i);
		if ((entry->flow->remoteAddr == subflow->remoteAddr)
				&& (entry->flow->remotePort == subflow->remotePort)
				&& (entry->flow->localAddr == subflow->localAddr)
				&& (entry->flow->localPort == subflow->localPort))
			ASSERT(false);
	}

	// set subflow as active
	t->active = true;
	t->flow = subflow;
	// add to list
	subflow_list.push_back(t);
	cnt_subflows++;

	// add the adresses of this subflow to the known address list for a MP_JOIN or add
	bool found = false;
	TCP_AddressVector_t::const_iterator it_r;
	for (it_r = list_raddrtuple.begin(); it_r != list_raddrtuple.end(); it_r++) {
		AddrTupple_t* tmp_r = (AddrTupple_t*) *it_r;
		if ((tmp_r->addr.equals(subflow->remoteAddr)) && (tmp_r->port == subflow->remotePort)) {
			found = true;
		}
	}
	// add this address because it is unkown
	if (!found) {
		AddrTupple_t *a = new AddrTupple_t();
		a->addr = subflow->remoteAddr;
		a->port = subflow->remotePort;
		list_raddrtuple.push_back(a);
	}

	/**
	 * Someware we have to trigger the new handshakes of the other subflows
	 */

	// sender side; we have to check if there are more possibles
	if (initiator) {	// draft 03 -> It is permitted for either host in a connection, but it is expected only the initiator
		for (it_r = list_raddrtuple.begin(); it_r != list_raddrtuple.end(); it_r++) {
			AddrTupple_t* tmp_r = (AddrTupple_t*) *it_r;

			TCP_AddressVector_t::const_iterator it_l;
			for (it_l = list_laddrtuple.begin(); it_l != list_laddrtuple.end(); it_l++) {
				AddrTupple_t* tmp_l = (AddrTupple_t*) *it_l;

				// collect data for possible new connections
				if (!tmp_l->addr.equals(subflow->localAddr)){
					AddrCombi_t* to_join = new AddrCombi_t();
					to_join->local = tmp_l;
					to_join->remote = tmp_r;
					tcpEV<< "ADD Possible new Subflow " << tmp_l->addr << "<-->" <<tmp_r->addr <<"\n";
					join_queue.push_back(to_join);
				}
			}
		}
	}

	// TODO we have to check if there are any new MP_JOIN possible
	// if this remote address is new, we have to add all possible combinations
	// check if address is new
	// if yes put into remote address vector
	// if yes put all possible combinations with all local addresses to the JOIN queue


	return 1;
}

/**
 * Check if a specific subflow belogs to this flow/connection
 */
bool MPTCP_Flow::isSubflowOf(TCPConnection* subflow) {
	for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i
				!= subflow_list.end(); ++i) {
		TCP_SUBFLOW_T* entry = (*i);
		if ((entry->flow->remoteAddr == subflow->remoteAddr)
				&& (entry->flow->remotePort == subflow->remotePort)
				&& (entry->flow->localAddr == subflow->localAddr)
				&& (entry->flow->localPort == subflow->localPort))
			return true;	// Yes this subflow belongs to this flow
	}
	// Sorry, this subflow is handled on this flow
	return false;
}


/**
 * TODO
 */
int MPTCP_Flow::sendByteStream(TCPConnection* subflow) {
	return 0;
}

/**
 * Main Entry Point for outgoing MPTCP segments.
 * - here we add MPTCP Options
 * - take care about SQN of MPTCP (Sender Side)
 */
int MPTCP_Flow::writeMPTCPHeaderOptions(uint t,
		TCPStateVariables* subflow_state, TCPSegment *tcpseg,
		TCPConnection* subflow) {

	// initiate some helper
	uint options_len  = 0;
	uint16 first_bits = 0x00;
	TCPOption option;

	// First check if is it allowed to add further options
	for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
		options_len = options_len + tcpseg->getOptions(i).getLength();

	// Check on not increasing the TCP Option
	ASSERT(options_len <= 40);
	// TODO, here we have to generate a extra message e.g. an duplicate ACK (see draft section 2)

	// Here we only work on MPTCP Options!! (Note: If this is a design problem to do it here, we could move this...)
	option.setKind(TCPOPTION_MPTCP); // TODO depending on IANA request
	DEBUGPRINT("[OUT] Support of MPTCP Kind: %d",TCPOPTION_MPTCP);

	// if SYN remark this combi as tried
	if ((tcpseg->getSynBit()) && (!tcpseg->getAckBit())) {
		AddrCombi_t* c = new AddrCombi_t();
		AddrTupple_t* l = new AddrTupple_t();
		AddrTupple_t* r = new AddrTupple_t();

		l->addr = subflow->localAddr;
		r->addr = subflow->remoteAddr;
		c->local = l;
		c->remote = r;
		tried_join.push_back(c);
	}

	/**
	 *  we have to send different TCP Options for handshake, depending on the states
	 *  SYN(A->B): 		A's KEY				-> MPTCP STATE IDLE/PRE_ESTABLISHED
	 *  SYN/ACK(B->A)	B's key				-> MPTCP STATE IDLE/PRE_ESTABLISHED
	 *  ACK(A->B): 		A's KEY & B's key	-> MPTCP STATE PRE_ESTABLISHED/ESTABLISHED
	 *
	 *  Main/common traffic is during the ESTABLISHED state
	 */

	DEBUGPRINT("[OUT] Check Substate for a MPTCP Kind: %d",TCPOPTION_MPTCP);
	// Work on MTCP State
	switch (state) {
	// FIRST Connection initiation SYN; SYN/ACK; ACK of the whole flow it must contain the MP_CAPABLE Option
	case IDLE: { // whether a SYN or ACK for a SYN ACK is send -> new MPTCP Flow
		if (!tcpseg->getSynBit()) {
			DEBUGPRINT("[OUT] ERROR MPTCP Connection state: %d", getState());
			ASSERT(false);
			return t;
		}
		DEBUGPRINT("[OUT] Enter IDLE for connection Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());
		first_bits = first_bits | ((uint16) MP_CAPABLE << MP_SUBTYPE_POS);
		first_bits = first_bits | ((uint16) VERSION << MP_VERSION_POS);

		// Check if it is whether a SYN or SYN/ACK
		if (tcpseg->getSynBit() && (!tcpseg->getAckBit())) { // SYN
			initiator = true;
			option.setLength(MP_CAPABLE_SIZE_SYN);
			option.setValuesArraySize(2);
			option.setValues(0, first_bits);
			sender_key = generateKey();
			option.setValues(1, sender_key);
			state = PRE_ESTABLISHED;

		} else if (tcpseg->getSynBit() && tcpseg->getAckBit()) { // SYN/ACK
			option.setLength(MP_CAPABLE_SIZE_SYNACK);
			option.setValuesArraySize(2);
			option.setValues(0, first_bits);
			receiver_key = generateKey(); // Could be generated every time -> important is key of ACK
			ASSERT(receiver_key != 0);
			option.setValues(1, receiver_key);

			state = PRE_ESTABLISHED;
		} else
			ASSERT(false); // Just for Testing

		tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
		tcpseg->setOptions(t, option);
		t++;
		DEBUGPRINT("[OUT] Leave IDLE for connection Src-Port %u -  Dest-Port %u PRE-ESTABLISHED",tcpseg->getSrcPort(),tcpseg->getDestPort());
		break;
	}
	case PRE_ESTABLISHED: { // whether ACK for a SYN ACK is send -> new MPTCP Flow
		DEBUGPRINT("[OUT] Enter PRE_ESTABLISHED for connection Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());

		first_bits = first_bits | ((uint16) MP_CAPABLE << MP_SUBTYPE_POS);
		first_bits = first_bits | ((uint16) VERSION << MP_VERSION_POS);

		// OK we are stateful, however the handshake is not complete
		if (tcpseg->getAckBit()) { // ACK
			option.setLength(MP_CAPABLE_SIZE_ACK);
			option.setValuesArraySize(3);

			// ACK include both keys
			option.setValues(0, first_bits);
			option.setValues(1, sender_key);
			option.setValues(2, receiver_key);

			tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
			tcpseg->setOptions(t, option);
			t++;
			this->state = ESTABLISHED;
		} else {
			DEBUGPRINT("[OUT] Enter PRE_ESTABLISHED for connection Src-Port %u -  Dest-Port %u - BUT THIS IS NOT WANTED",tcpseg->getSrcPort(),tcpseg->getDestPort());
		}

		DEBUGPRINT("[OUT] Leave PRE_ESTABLISHED for connection Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());
		break;
	}
	case ESTABLISHED: { // whether a SYN or ACK for a SYN ACK is send -> new MPTCP Flow
		// Work on new adresses and/or connections MP_JOIN
		// ADD_ADDR/ REMOVE ADDR
		// DSS

		// ADD MP_JOIN on a SYN of a etablished MULTIPATH Connection
		if (tcpseg->getSynBit() && (!tcpseg->getAckBit())) {
			// OK, we are still etablished so, this must be a JOIN or ADD.
			// ADD is not handled here (TODO ADD), so it must be a MP_JOIN
			// this is triggert by a self message, called by joinConnection()
			DEBUGPRINT("[OUT] In state ESTABLISHED, starting SYN with MP_JOIN Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());
			first_bits = first_bits | ((uint16) MP_JOIN << MP_SUBTYPE_POS);
			// TODO B
			// TODO Adress ID

			assert(MP_JOIN_SIZE_SYN==12); // In the draft it is defined as 12
			option.setLength(MP_JOIN_SIZE_SYN);
			option.setValuesArraySize(3);

			option.setValues(0, first_bits);
			option.setValues(1, receiver_key); // TODO Receivers Token
			option.setValues(2, 0); // TODO Sender's random number
			tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
			tcpseg->setOptions(t, option);
			t++;

		}
		// ADD MP_JOIN on a SYN/ACK of a etablished MULTIPATH Connection
		else if (tcpseg->getSynBit() && (tcpseg->getAckBit())) {
				DEBUGPRINT("[OUT] In state ESTABLISHED, starting SYN with MP_JOIN Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());

				first_bits = first_bits | ((uint16) MP_JOIN << MP_SUBTYPE_POS);
				// TODO B
				// TODO Adress ID

				assert(MP_JOIN_SIZE_SYNACK==16); // In the draft it is defined as 12
				option.setLength(MP_JOIN_SIZE_SYNACK);
				option.setValuesArraySize(3);

				option.setValues(0, first_bits);
				option.setValues(1, 0); // TODO Receivers Token
				option.setValues(2, 0); // TODO Senders Token
				tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
				tcpseg->setOptions(t, option);
				t++;
				// TODO for the last ACK we should etablish a connection
		}else if ((!tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
				// TODO - Im not sure how to detect the kind of acks who have to transport the MP_JOIN
		}
		else{

			DEBUGPRINT("[OUT] In state ESTABLISHED, Check for a new join - Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());

		}
		// TODO -> Perhaps there is a better place, but in first try we check if there are new data received
		joinConnection(); // TODO
		DEBUGPRINT("[OUT] Leave ESTABLISHED for connection Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());
		break;
	}
	default:
		DEBUGPRINT("[OUT] Enter default for connection Src-Port %u -  Dest-Port %u - BUT THIS IS NOT WANTED",tcpseg->getSrcPort(),tcpseg->getDestPort());
		tcpEV<<"ERROR: Options length exceeded! Segment will be sent without options" << "\n";
		ASSERT(false);
		break;
		// TODO CHECK FLOW FLAGS, eg. report or delete address
	}
	DEBUGPRINT("[OUT] Leave function with %d header Src-Port %u -  Dest-Port %u",t, tcpseg->getSrcPort(),tcpseg->getDestPort());
	return t;
}


/**
 * Initiate a new subflow of a multipath TCP connection
 */
bool MPTCP_Flow::joinConnection() {

	// In case we know new address pairs...
	while (join_queue.size() > 0) {
		ASSERT(subflow_list.size() != 0);
		bool skip = false;;
		TCP_SUBFLOW_T* subflow = (TCP_SUBFLOW_T *) (*(subflow_list.begin()));
		TCPConnection* tmp = subflow->flow;
		ASSERT(tmp->getTcpMain()!=NULL);

		// OK, there is a possible new subflow, so there should a connection exist with all required info

		AddrCombi_t* c = (AddrCombi_t*) *(join_queue.begin());
		tcpEV<< "New subflow join: " << c->local->addr << "<->" << c->remote->addr << "\n";

		// ignore local addresses
		if(IPvXAddress("127.0.0.1").equals(c->local->addr))
			skip = true;
		if(IPvXAddress("0.0.0.0").equals(c->local->addr))
			skip = true;

		// ignore still etablished subflows
		TCP_JoinVector_t::const_iterator it_tj;
		for (it_tj = tried_join.begin(); it_tj != tried_join.end(); it_tj++) {
			AddrCombi_t* tmp = (AddrCombi_t*) *it_tj;
			tcpEV<< "Check if new subflow join ok: " << tmp->local->addr << "<->" << tmp->remote->addr << "\n";
			if ((c->local->addr.equals(tmp->local->addr)) && (c->remote->addr.equals(tmp->remote->addr))) {

				tcpEV<< "Connection still known\n";
				skip = true;
				break;
			}
		}

		// Is this a possible new subflow?
		if(!skip){
			// create a internal message for another active open connection
			cMessage *msg = new cMessage("ActiveOPEN", TCP_C_OPEN_ACTIVE);

			// setup the subflow
			TCPOpenCommand *openCmd = new TCPOpenCommand();
			openCmd->setConnId(tmp->connId);
			openCmd->setLocalAddr(c->local->addr);
			openCmd->setLocalPort(tmp->localPort);
			openCmd->setRemoteAddr(c->remote->addr);
			openCmd->setRemotePort(tmp->remotePort);
			openCmd->setSendQueueClass(tmp->getTcpMain()->par("sendQueueClass"));
			openCmd->setReceiveQueueClass(tmp->getTcpMain()->par("receiveQueueClass"));
			openCmd->setTcpAlgorithmClass(tmp->getTcpMain()->par("tcpAlgorithmClass"));
			openCmd->setSubFlowNumber(cnt_subflows);

			// initiate handshake for subflow
			openCmd->setIsMptcpSubflow(true);
			msg->setControlInfo(openCmd);
			msg->setContextPointer(tmp);
			tmp->getTcpMain()->scheduleAt(simTime() + 0.001, msg);
			tcpEV<< "Schedule join of new Subflow " << c->local->addr << "<-->" << c->remote->addr <<"\n";
		}
		// clean up the staff
		join_queue.erase(join_queue.begin());
		delete c;
	}
	return true;
}

// KEY AND ID GENERATING

/**
 * helper functions
 */
uint64 MPTCP_Flow::generateKey() {
	// TODO SHOULD be changed to something we could check
	return intrand(INT64_MAX);
}

/**
 * helper set function
 */
int MPTCP_Flow::setState(MPTCP_State s) {
	state = s;
	return state;
}

/**
 * helper get function
 */
MPTCP_State MPTCP_Flow::getState() {
	return state;
}

/**
 * helper get function
 */
uint64 MPTCP_Flow::getSenderKey() {
	return sender_key;
}

/**
 * generate
 * - Start SQN
 * - Token ID
 */
int MPTCP_Flow::generateTokenAndSQN(uint64 s, uint64 r) {

	// TODO: irgendwas ist faul

	//    SHA_CTX       ctx;
	//    unsigned char s1[64];
	//    unsigned char s2[64];
	//	unsigned char out32[32] = {0};
	//	unsigned char out64[64] = {0};
	sender_key = s;
	receiver_key = r;
	// sender_key and receiver_key are not allowed to be 0
	ASSERT(sender_key != 0);
	ASSERT(receiver_key != 0);
	//	sprintf((char*)s1,"%ju",sender_key);
	//	sprintf((char*)s2,"%ju",receiver_key);
	//	SHA1_Init(&ctx);
	// generate SHA-1 for token
	//	SHA1_Update(&ctx,(unsigned char*)s1, strlen((char*)s1));
	//	SHA1_Update(&ctx,(unsigned char*) s2, strlen((char*)s2));
	//	SHA1_Final((unsigned char*) out32, &ctx);
	//	SHA1_Final((unsigned char*) out64, &ctx);


	//	DEBUGPRINT("[OUT] Generate token: %u:  ",32);
	//	  for (int i = 0; i < 32; i++) {
	//	        printf("%02x ", out32[i]);
	//	    }
	//	  printf("\n");
	//	  DEBUGPRINT("[OUT] Generate token: %u:  ",64);
	//	  	  for (int i = 0; i < 64; i++) {
	//	  	        printf("%02x ", out64[i]);
	//	  	    }
	//	  	  printf("\n");
	//	flow_token = *((uint32*) out32);
	//	seq = *((uint64*) out64);
	//	DEBUGPRINT("[OUT] Generate token (Readable): %ju  ",flow_token);

	return 0;
}

//##################################################################################################
//#
//#	THE MULTIPATH TCP PROTOCOL CONTROL BLOCK
//#
//#################################################################################################


int MPTCP_PCB::count;

MPTCP_PCB* MPTCP_PCB::first = NULL;

/**
 * Constructor
 */
MPTCP_PCB::MPTCP_PCB() :
	flow(NULL) {

	// selforg. by a simple list
	id = count++;
	MPTCP_PCB* tmp = first;
	MPTCP_PCB* last = NULL;
	this->next = NULL;
	while(tmp != NULL){
		last = tmp;
		tmp = tmp->next;
	}
	if(last == NULL){
		first = this;
	}
	else{
		last->next = this;
	}
	DEBUGPRINT("[Create] New MPTCP Protocol Control Block: %d  ",count);
}


MPTCP_PCB::MPTCP_PCB(int connId, int appGateIndex, TCPConnection* subflow){
	// selforg. by a simple list
	id = count++;
	MPTCP_PCB* tmp = first;
	MPTCP_PCB* last = NULL;
	this->next = NULL;
	while(tmp != NULL){
		last = tmp;
		tmp = tmp->next;
	}
	if(last == NULL){
		first = this;
	}
	else{
		last->next = this;
	}
	DEBUGPRINT("[Create] New MPTCP Protocol Control Block: %d  ",count);

	flow = new MPTCP_Flow(connId,appGateIndex);
}
/**
 * De-Constructor
 */
MPTCP_PCB::~MPTCP_PCB() {
	// TODO delete flow
	count--;
	MPTCP_PCB* tmp = first;
	MPTCP_PCB* last = NULL;
	while(tmp != NULL){
		if(id == tmp->id){
			if(last!=NULL){
				last->next = tmp->next;
			}
			else{
				first = tmp->next;
			}
			break;
		}
		last = tmp;
		tmp = tmp->next;
	}
	DEBUGPRINT("[Destroy] Currently %d MPTCP Protocol Control Blocks used",count);
}

/**
 * Important External Static Function
 * 1) Find mPCB
 * 2) Process Segment
 * 3) If needed become stateful
 */
int MPTCP_PCB::processMPTCPSegment(int connId, int aAppGateIndex, TCPConnection* subflow, TCPSegment *tcpseg) {
	// First look for a Multipath Protocol Control Block
	MPTCP_PCB* tmp = MPTCP_PCB::lookupMPTCP_PCB(connId, aAppGateIndex);
	// In case there is no, we have to check for MP_JOIN or we have to create
	// check for MP_JOIN
	if(tmp==NULL)
		tmp = MPTCP_PCB::lookupMPTCP_PCBbyMP_JOIN_Option(tcpseg,subflow);
	if(tmp==NULL)
		tmp = new MPTCP_PCB(connId,aAppGateIndex,subflow);
	// Proc
	int ret = tmp->processSegment(connId, subflow, tcpseg);
	return ret;
}

/**
 * Internal helper to find the Multipath PCB by the MP_JOIN Potion
 */
MPTCP_PCB* MPTCP_PCB::lookupMPTCP_PCBbyMP_JOIN_Option(TCPSegment* tcpseg, TCPConnection* subflow){
	// We are here; so it must be Multipath TCP Stack
	if (!subflow->getTcpMain()->multipath) {
		return NULL;
	}
	// let check the options
	for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++) {
		const TCPOption& option = tcpseg->getOptions(i);
		short kind = option.getKind();

		// Check for Muultipath Options
		if (kind == TCPOPTION_MPTCP) {
			tcpEV<< "MPTCP Option" << "\n";
			if(option.getLength() < 4) {
				return NULL;
			}
			// Get Subtype
			uint16 value = option.getValues(0);
			uint16 sub = (value >> MP_SUBTYPE_POS);
			if(sub == MP_JOIN) {
				// OK, it is a MP_JOIN
				if (option.getValuesArraySize() < 2) {
					return NULL;
				}

				// Check MPCB for MP_JOIN SYN
				if( (tcpseg->getSynBit()) && (!tcpseg->getAckBit()) ) {
					// Check for receiver token (32)
					// It is easy to identify the subflow by the receiver token
					MPTCP_PCB* tmp = first;
					uint64 receiver_key = option.getValues(1);
					while(tmp != NULL){
						MPTCP_Flow* flow = tmp->getFlow();

						if((flow->receiver_key == receiver_key)){
							return tmp;	// OK we know a flow with this Receiver key, let's work with this one
						}
						tmp = tmp->next;
					}
				}
				// Check MPCB for MP_JOIN
				else if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
					// Sender's Truncated MAC (64) MAC-B
					// Sender's Random Number (32)
				}
				// Check MPCB for MP_JOIN
				else if((!tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
					// Sender's MAC (MAC-A)
				}
			}
		} // MPTCP Options
	}
	return NULL;	// No PCB found
}


/**
 * Internal helper to process packet for a flow
 * TODO Something goes wrong (TCP RST)
 */
int MPTCP_PCB::processSegment(int connId, TCPConnection* subflow,
		TCPSegment *tcpseg) {

	// We are here; so it must be Multipath TCP Stack
	if (!subflow->getTcpMain()->multipath) {
		ASSERT(true); // TODO Only for testing
		return 0;
	}

	/**
	 * CASE "NEW MPTCP FLOW" or "NO MPTCP FLOW"
	 */
	// Check if this is still a Multipath Connection with an existing Flow
	if (flow == NULL || (flow->getState() == IDLE) || (flow->getState()
			== PRE_ESTABLISHED)) {

		// each new flow need a:
		uint64 sender_key = 0;
		uint64 receiver_key = 0;

		// There exist no MPTCP Flow so we are in the first handshake phase or this is not a MPTCP Flow
		// We don't care about the SYN, because it is stateless. But during getting SYN/ACK and ACK we become stateful
		if (!tcpseg->getAckBit()) { // There is no ACK Bit set, so we are still stateless
			if (!tcpseg->getSynBit()) {
				return 0; // NOT SYN  SYN/ACK or ACK
			}

		}
		// In every case we expect a MP_CAPABEL Option
		// TODO check Option, if not exist return
		if (tcpseg->getHeaderLength() <= TCP_HEADER_OCTETS) {
			ASSERT(true);
			return 0; // No MPTCP Options
		}


		for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++) {
			const TCPOption& option = tcpseg->getOptions(i);
			short kind = option.getKind();
			//			short length = option.getLength();

			if (kind == TCPOPTION_MPTCP) {
				tcpEV<< "MPTCP Option" << "\n";
				if(option.getLength() < 4) {
					ASSERT(true); //should never be happen
					return 0;
				}

				uint16 first = option.getValues(0);
				uint16 sub = (first >> MP_SUBTYPE_POS);

// Subtype MP_CAPABLE
				if(sub == MP_CAPABLE) {


					if (option.getValuesArraySize() < 2) {
						ASSERT(true);
						return 0; //should never be happen
					}
					// In every case we expect a sender key
					if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
						// SYN/ACK: We aspect the sender key in the MP_CAPABLE Option
						sender_key = flow->getSenderKey();
						receiver_key = option.getValues(1); // Could be generated every time -> important is key of ACK
						DEBUGPRINT("[IN] Got SYN/ACK Src-Port %u -  Dest-Port %u: Sender Key %ju",tcpseg->getSrcPort(),tcpseg->getDestPort(),sender_key);
						DEBUGPRINT("[IN] Got SYN/ACK Src-Port %u -  Dest-Port %u: Receiver Key %ju",tcpseg->getSrcPort(),tcpseg->getDestPort(),receiver_key);
						DEBUGPRINT("[IN] Got SYN/ACK Src-Port %d -  Dest-Port %d: > MPTCP CONNECTION ESTABLISHED",tcpseg->getSrcPort(),tcpseg->getDestPort());
						// OK new stateful MPTCP flow, calculate the token and Start-SQN
						flow->generateTokenAndSQN(sender_key, receiver_key);
						// add (First) Subflow of the connection

						flow->addSubflow(connId,subflow);

						return 1;
					}
					else if(tcpseg->getAckBit()) {
						// ACK: We aspect the sender key in the MP_CAPABLE Option
						if (option.getValuesArraySize() < 3) {
							ASSERT(false);
							return 0; //should never be happen
						}
						uint64 sender_key = option.getValues(1);
						uint64 receiver_key = option.getValues(2);
						DEBUGPRINT("[IN] Got ACK Src-Port %d -  Dest-Port %d: Sender Key %ju",tcpseg->getSrcPort(),tcpseg->getDestPort(),sender_key);
						DEBUGPRINT("[IN] Got ACK Src-Port %d -  Dest-Port %d: Receiver Key %ju",tcpseg->getSrcPort(),tcpseg->getDestPort(),receiver_key);
						DEBUGPRINT("[IN] Got ACK Src-Port %d -  Dest-Port %d: > MPTCP CONNECTION ESTABLISHED",tcpseg->getSrcPort(),tcpseg->getDestPort());
						// Status: Check MPTCP FLOW
						// - this is a MULTIPATH Stack: 			OK
						// - This is a New MPTCP Flow: 				OK
						// - The needed MP_CAPABLE Option exits: 	OK
						// - Valid keys:							OK
						// ==> Create a stateful Flow: generate token and SQN and Buffer

						if(flow == NULL) {
							// we have to be ESTABLISHED and is has to be an ACK
							if(tcpseg->getAckBit())
							flow = new MPTCP_Flow(connId, subflow->appGateIndex);
						}
						ASSERT(flow!=NULL);

						// OK new stateful MPTCP flow, calculate the token and Start-SQN
						flow->generateTokenAndSQN(sender_key, receiver_key);

						// Add (First) Subflow of the connection
						flow->addSubflow(connId,subflow);
						flow->setState(ESTABLISHED);

					} else {
						// SYN
						flow->sender_key = option.getValues(1);
						DEBUGPRINT("[IN] Got SYN Src-Port %u -  Dest-Port %u: Sender Key %ju",tcpseg->getSrcPort(),tcpseg->getDestPort(),flow->sender_key);
						DEBUGPRINT("[IN] Got SYN Src-Port %d -  Dest-Port %d: > MPTCP CONNECTION PRE ESTABLISHED",tcpseg->getSrcPort(),tcpseg->getDestPort());
						return 0; // OK we got a MP_CAPABLE in a SYN, we a steless anymore
					}

					break; // OK we got a MP_CAPABLE, lets become stateful
				}
				// OK, it is a MPTCP Option, so lets figure out which subtype
				tcpEV << "MPTCP Option\n";
			} // MPTCP Options
		} // end for each option
	} // Check if this is still a Multipath Connection with an existing Flow
	else { // This is a etablished MPTCP Flow
		DEBUGPRINT("[IN] MPTCP CONNECTION ESTABLISHED: Got a Segment...lets proceed -> SRC-Port: %d DST-Port: %d",tcpseg->getSrcPort(),tcpseg->getDestPort());

		for (uint i=0; i<tcpseg->getOptionsArraySize(); i++)
		{
			const TCPOption& option = tcpseg->getOptions(i);
			short kind = option.getKind();
			//			short length = option.getLength();


			if(kind == TCPOPTION_MPTCP)
			{
				tcpEV << "MPTCP Option" << "\n";
				if(option.getLength() < 4) {
					ASSERT(true); //should never be happen
					return 0;
				}

				uint16 value = option.getValues(0);
				uint16 sub = (value >> MP_SUBTYPE_POS);

				if(sub == MP_CAPABLE) {
					tcpEV << "MPTCP Option MP_CAPABLE" << "\n";
					ASSERT(false);
				} // Connection etablished ?? TODO ERROR

// Subtype MP_JOIN
				/**
				 * Be carfull, the server is in listen mode
				 * this could be a valid connection, but not a multipath
				 *
				 * However, in case of SUB = JOIN, it should be a multipath
				 * That means, we have to stop communication and must respond with an TCP RST
				 * TODO add RST in error state
				 **/
// IN MP_JOIN
				else if(sub == MP_JOIN) {
					bool tcp_rst = false;
					if (option.getValuesArraySize() < 2) {
						ASSERT(true);
						return 0; //should never be happen
					}

					// Now it is time to start a new SUBFLOW
					// We have to do the normal staff, but we have also look on the still existing flow
					// - procees SYN
					// - process SYN/ACK
					// - process ACK

					// process SYN
					if((tcpseg->getSynBit()) && (!tcpseg->getAckBit()) ) {
						DEBUGPRINT("[IN] Got SYN Src-Port %d -  Dest-Port %d: > MPTCP MP_JOIN",tcpseg->getSrcPort(),tcpseg->getDestPort());
						// First the main flow should be find in the list of flows
						// TODO

						// the first flow is known
						// the first flow ist unknown
					}
					// process SYN/ACK
					else if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
						DEBUGPRINT("[IN] Got SYN/ACK Src-Port %d -  Dest-Port %d: > MPTCP MP_JOIN",tcpseg->getSrcPort(),tcpseg->getDestPort());

						// TODO if everything OK, add subflow to flow of pcb
					}
					// process ACK
					else if((!tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
						DEBUGPRINT("[IN] Got ACK Src-Port %d -  Dest-Port %d: > MPTCP MP_JOIN",tcpseg->getSrcPort(),tcpseg->getDestPort());
						// TODO if everything OK, add subflow to flow of pcb
					}
				}
			}
		}
	}
	return 1;
}

/**
 * TODO Scheduler
 */
TCPConnection* MPTCP_PCB::lookupMPTCPConnection(int connId,
		TCPConnection* subflow, TCPSegment *tcpseg) {

	//TODO OK, now we have to choose by the scheduler which flow we should use next....
	//TODO Scheduler

	return subflow;
}

/**
 * PCB lookup by ID
 */
MPTCP_PCB* MPTCP_PCB::lookupMPTCP_PCB(int connid, int aAppGateIndex) {
	// TODO check if connection for flow
	MPTCP_PCB* tmp = first;
	while(tmp != NULL){
		MPTCP_Flow* flow = tmp->getFlow();
		if((flow->appID == connid)
		  && (flow->appGateIndex == aAppGateIndex)){
			return tmp;
		}
		tmp = tmp->next;
	}
	return NULL;
}

/**
 * PCB lookup by subflow
 */
MPTCP_PCB* MPTCP_PCB::lookupMPTCP_PCB(TCPSegment *tcpseg, TCPConnection* subflow) {
	// TODO check if connection for flow
	MPTCP_PCB* tmp = first;
	while(tmp != NULL){
		DEBUGPRINT("[IN] MPTCP Flow ID  %d",tmp->id);
		// the information we are looking for are part of an subflow of the connection (flow)
		MPTCP_Flow* flow = tmp->getFlow();
		if(flow->isSubflowOf(subflow)){
			// So here we are, this subflow belongs to this flow, this flow is controlled by this PCB
			return tmp;
		}
		tmp = tmp->next;
	}
	return NULL;
}

/**
 * PCB lookup by Key
 */
MPTCP_PCB* MPTCP_PCB::lookupMPTCP_PCB(TCPSegment *tcpseg){

	return NULL;
}


/**
 * TODO Check Function
 */
int MPTCP_PCB::clearAll() {
	// TODO shutdown
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
