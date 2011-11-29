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


#include "TCP.h"
#include "TCPMultipath.h"
#include "TCPConnection.h"
#include "TCPSegment.h"
#include <ASSERT.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <inttypes.h>


// For defines for debugging (Could be removed)
#define WHERESTR  "\n[MPTCP][file %s, line %d]: "
#define WHEREARG  __FILE__, __LINE__
#define DEBUGPRINT2(...)  fprintf(stderr, __VA_ARGS__)

#ifdef PRIVATE_DEBUG
#define DEBUGPRINT(_fmt, ...)  DEBUGPRINT2(WHERESTR _fmt, WHEREARG, __VA_ARGS__)
#else
#define	DEBUGPRINT(_fmt, ...) ;
#endif


// some defines
#define COMMON_MPTCP_OPTION_HEADER_SIZE 16
#define SENDER_KEY_SIZE 				64
#define RECEIVER_KEY_SIZE 				64

// Some defines for MP_CAPABLE
#define MP_CAPABLE_SIZE_SYN    ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + SENDER_KEY_SIZE) >> 3)
#define MP_CAPABLE_SIZE_SYNACK ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + RECEIVER_KEY_SIZE) >> 3)
#define MP_CAPABLE_SIZE_ACK    ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + SENDER_KEY_SIZE + RECEIVER_KEY_SIZE) >> 3)


// Some defines for MP_JOIN
#define MP_JOIN_SIZE_SYN 				12
#define MP_JOIN_SIZE_SYNACK 			16
#define MP_JOIN_SIZE_ACK 				24

// Version of MPTCP
#define VERSION 0x0

// Some constants for help
const unsigned int MP_SIGNAL_FIRST_VALUE_TYPE = 16;
const unsigned int MP_SUBTYPE_POS = MP_SIGNAL_FIRST_VALUE_TYPE - 4;
const unsigned int MP_VERSION_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - 4;
const unsigned int MP_C_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - MP_VERSION_POS - 1;
const unsigned int MP_RESERVED_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - MP_VERSION_POS - MP_C_POS - 4;
const unsigned int MP_S_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - MP_VERSION_POS - MP_C_POS - MP_RESERVED_POS - 1;

/**
 * Constructor
 * @param ID ID for each Flow
 */
MPTCP_Flow::MPTCP_Flow(int connID, int aAppGateIndex) :
	cnt_subflows(0), state(IDLE), initiator(false), sender_key(0), receiver_key(0) {

	// Start state of the Multipath FLOW is IDLE
	state = IDLE;
	// For easy PCB Lookup set ID and Application Index
	appID = connID;
	appGateIndex = aAppGateIndex;

	// Init the flow
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
	// 1) lookup for all available IP adresses
	// 2) setup a list of local adresses
	// We need cross layer information of available interfaces

	IInterfaceTable *ift = interfaceTableAccess.get();

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

			// ############################
			// List of local adress tuples
			list_laddrtuple.push_back(addr);
		}
	}
	else
	{
		// Should never happen...
		tcpEV<<"Problems by adding all known IP adresses\n";
	}
	return;
}

/**
 * Add a subflow to a MPTCP connection
 * */
int MPTCP_Flow::addSubflow(int id, TCPConnection* subflow) {
	// 1) Add the given subflow to the flow/connections
	// 2) Check if further subflows are possible
	// 3) Initiate possible new subflows by a selfmessage (add to join queue)

	// Create a subflow entry in the list, a entry is stateful
	TCP_SUBFLOW_T *t = new TCP_SUBFLOW_T();
	subflow->isSubflow = true;

// TODO perhaps it is a good IDEA to add the PCB to the subflow !!!!
	// subflow-multi_pcb = pcb

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

	// ###################################
	// Check for further possible subflows

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

	// ############################################################
	// we have to trigger the new handshakes of the other subflows


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
					// add to join queue () - joinConnection() will work for this queue
					join_queue.push_back(to_join);
				}
			}
		}
	}

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
 * TODO ???
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

	// 1) Depending on state and segment type add multipath tcp options
	// TODO Split segment, if there is not enough space for the options
	// TODO Better error handling
	// TODO Generate a extra message e.g. an duplicate ACK (see draft section 2)
	// TODO CHECK FLOW FLAGS, eg. report or delete address
	// Other TODO see on different states

	// Initiate some helper
	uint options_len  = 0;
	uint16 first_bits = 0x00;
	TCPOption option;

	// First check if is it allowed to add further options
	for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
		options_len = options_len + tcpseg->getOptions(i).getLength();

	// Check on not increasing the TCP Option
	ASSERT(options_len <= 40);

	// Only work on MPTCP Options!! (Note: If this is a design problem to do it here, we could move this to TCP...)
	option.setKind(TCPOPTION_MPTCP); // TODO depending on IANA request
	DEBUGPRINT("[OUT] Support of MPTCP Kind: %d",TCPOPTION_MPTCP);

	// If SYN remark this combi as tried
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

	/**********************************************************************************
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
	// Connection initiation SYN; SYN/ACK; ACK of the whole flow it must contain the MP_CAPABLE Option
// MPTCP IDLE
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
			option.setValuesArraySize(3);
			option.setValues(0, first_bits);
			setSenderKey(generateKey());			// generate sender_key
			DEBUGPRINT("[OUT] Generate Sender Key: %llu",getSenderKey());
			// set 64 bit value
			uint32 value = (uint32) getSenderKey();
			option.setValues(1, value);
			value = getSenderKey() >> 32;
			option.setValues(2, value);

			state = PRE_ESTABLISHED;

		} else if (tcpseg->getSynBit() && tcpseg->getAckBit()) { // SYN/ACK
			option.setLength(MP_CAPABLE_SIZE_SYNACK);
			option.setValuesArraySize(3);
			option.setValues(0, first_bits);
			setReceiverKey(generateKey()); 		// generate receiver_key -> important is key of ACK
			DEBUGPRINT("[OUT] Generate Receiver Key: %llu",getReceiverKey());
			ASSERT(receiver_key != 0);

			// set 64 bit value
			uint32 value = (uint32) getReceiverKey();
			option.setValues(1, value);
			value = getReceiverKey() >> 32;
			option.setValues(2, value);

			state = PRE_ESTABLISHED;
		} else
			ASSERT(false); // TODO Just for Testing

		tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
		tcpseg->setOptions(t, option);
		t++;
		DEBUGPRINT("[OUT] Leave IDLE for connection Src-Port %u -  Dest-Port %u PRE-ESTABLISHED",tcpseg->getSrcPort(),tcpseg->getDestPort());
		break;
	}
// MPTCP PRE_ESTABLISHED
	case PRE_ESTABLISHED: { // whether ACK for a SYN ACK is send -> new MPTCP Flow
		DEBUGPRINT("[OUT] Enter PRE_ESTABLISHED for connection Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());

		first_bits = first_bits | ((uint16) MP_CAPABLE << MP_SUBTYPE_POS);
		first_bits = first_bits | ((uint16) VERSION << MP_VERSION_POS);

		// OK we are stateful, however the handshake is not complete
		if (tcpseg->getAckBit()) { // ACK
			option.setLength(MP_CAPABLE_SIZE_ACK);
			option.setValuesArraySize(5);

			// ACK include both keys
			option.setValues(0, first_bits);

			// set 64 bit value
			uint32 value = (uint32) getSenderKey();
			option.setValues(1, value);
			value = getSenderKey() >> 32;
			option.setValues(2, value);

			// set 64 bit value
			value = (uint32) getReceiverKey();
			option.setValues(3, value);
			value = getReceiverKey() >> 32;
			option.setValues(4, value);


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
// MPTCP ESTABLISHED
	case ESTABLISHED: { // whether a SYN or ACK for a SYN ACK is send -> new MPTCP Flow
		// 1) Handle new adresses and/or connections MP_JOIN
		// TODO ADD_ADDR/ REMOVE ADDR
		// TODO DSS

// MPTCP OUT MP_JOIN SYN
		// Add MP_JOIN on a SYN of a etablished MULTIPATH Connection
		if (tcpseg->getSynBit() && (!tcpseg->getAckBit())) {
			// OK, we are still etablished so, this must be a JOIN or ADD.
			// ADD is not handled here (TODO ADD), so it must be a MP_JOIN
			// this is triggert by a self message, called by joinConnection()
			DEBUGPRINT("[OUT] In state ESTABLISHED, starting SYN with MP_JOIN Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());
			first_bits = first_bits | ((uint16) MP_JOIN << MP_SUBTYPE_POS);

			// TODO B -> use it purely as backup?
			// TODO Adress ID (!)

			assert(MP_JOIN_SIZE_SYN==12); // In the draft it is defined as 12
			option.setLength(MP_JOIN_SIZE_SYN);
			option.setValuesArraySize(3);

			option.setValues(0, first_bits);
			option.setValues(1, getFlow_token()); 		// Receivers Token
			subflow->randomA = (uint32)generateKey();
			option.setValues(2, subflow->randomA); // TODO Sender's random number (Generator perhaps other one??)

			// However, we need knowledge of the subflow random number to re-calculate HMAC
			// TODO Check if multipath PCB is the correct one
			addSubflow(subflow->connId,subflow);	// connection becomes stateful on SYN

			tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
			tcpseg->setOptions(t, option);
			t++;
		}
// MPTCP OUT MP_JOIN SYN ACK
		// Add MP_JOIN on a SYN/ACK of a etablished MULTIPATH Connection
		else if (tcpseg->getSynBit() && (tcpseg->getAckBit())) {
				DEBUGPRINT("[OUT] In state ESTABLISHED, starting SYN with MP_JOIN Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());

				first_bits = first_bits | ((uint16) MP_JOIN << MP_SUBTYPE_POS);
				// TODO B
				// TODO Adress ID

				assert(MP_JOIN_SIZE_SYNACK==16); // In the draft it is defined as 12
				option.setLength(MP_JOIN_SIZE_SYNACK);
				option.setValuesArraySize(3);

				option.setValues(0, first_bits);
				// generate the tuncated MAC (64) and the random Number of the Receiver (Sender of the Packet)
				// TODO For second Parameter
				option.setValues(1, 0); // TODO truncated MAC 64

				option.setValues(2, 0); // TODO Random Number

				tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
				tcpseg->setOptions(t, option);
				t++;
				// TODO for the last ACK we should etablish a connection
		}else if ((!tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
// MPTCP OUT MP_JOIN ACK
				// TODO - Im not sure how to detect the kind of acks who have to transport the MP_JOIN

				// TODO compute the HMAC 160 add in a Option Block
		}
		else{
			DEBUGPRINT("[OUT] In state ESTABLISHED, Check for a new join - Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());
		}

		joinConnection();	// TODO -> Perhaps there is a better place, but in first try we check if there are new data received

		DEBUGPRINT("[OUT] Leave ESTABLISHED for connection Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());
		break;
	}
	default:
		DEBUGPRINT("[OUT] Enter default for connection Src-Port %u -  Dest-Port %u - BUT THIS IS NOT WANTED",tcpseg->getSrcPort(),tcpseg->getDestPort());
		tcpEV<<"ERROR: Options length exceeded! Segment will be sent without options" << "\n";
		ASSERT(false); // TODO Just for Testing
		break;

	}
	DEBUGPRINT("[OUT] Leave function with %d header Src-Port %u -  Dest-Port %u",t, tcpseg->getSrcPort(),tcpseg->getDestPort());
	return t;
}


/**
 * Initiation of a new subflow of a multipath TCP connection
 */
bool MPTCP_Flow::joinConnection() {
	// 1) Check for valid adresses and combinations
	// 2) Setup selfmessages
	// 3) Delete combination from join queue

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

		// #############################################
		// Create selfmessage for new subflow initiation

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

		// ###################
		// clean up the staff
		join_queue.erase(join_queue.begin());
		delete c;
	}
	return true;
}

// KEY AND ID GENERATING

uint64 MPTCP_Flow::generateKey() {
	// TODO check if this is the correct API -> there is an warning
	return intrand(UINT64_MAX); // Hier ist was faul...das ist kein Zufall ;-)
}

/**
 * helper set function
 */
int MPTCP_Flow::setState(MPTCP_State s) {
	state = s;
	return state;
}




/**
 * generate
 * - Start SQN
 * - Token ID
 */
int MPTCP_Flow::generateTokenAndSQN(uint64 s, uint64 r) {

	// TODO: irgendwas ist faul

	SHA_CTX       ctx;
	char s1[64];
	char s2[64];

	uint32 out32 = {0};
	uint64 out64 = {0};

	sender_key = s;
	receiver_key = r;
	// sender_key and receiver_key are not allowed to be 0
	ASSERT(sender_key != 0);
	ASSERT(receiver_key != 0);
	sprintf(s1,"%20llu",sender_key);	// I'm not sure if this is correct, for external interface
	sprintf(s2,"%20llu",receiver_key);// I'm not sure if this is correct, for external interface

	DEBUGPRINT("[OUT] Generate token: with sender key %llu and receiver key %llu:  ",sender_key, receiver_key);

	SHA1_Init(&ctx);
	// generate SHA-1 for token
	SHA1_Update(&ctx,s1,strlen(s1));
	SHA1_Update(&ctx,s2,strlen(s2));

	SHA1_Final((unsigned char*) &out32, &ctx);
	SHA1_Final((unsigned char*) &out64, &ctx);

	DEBUGPRINT("[OUT] Generate token: %u:  ",out32);
	DEBUGPRINT("[OUT] Generate seq: %llu:  ",out64);
	flow_token = out32;
	seq = out64;
	return 0;
}

/**
 * generate body of SYN/ACK HMAC
 */
unsigned char* MPTCP_Flow::generateSYNACK_HMAC(uint64 ka, uint64 kb, uint32 ra, uint32 rb, unsigned char* digist) {
	// On Host B - Not Initiator
	char key[38];
	char msg[20];

	// Need MAC-B
	// MAC(KEY=(Key-B + Key-A)), Msg=(R-B + R-A))
	sprintf(key,"%19llu%19llu",kb,ka);
	sprintf(msg,"%10u%10u",rb,ra);
	hmac_md5((unsigned char*) msg,strlen(msg),(unsigned char*) key,strlen(key),digist);
	return digist;
}
/**
 * generate body of ACK HMAC
 */
unsigned char* MPTCP_Flow::generateACK_HMAC(uint64 ka, uint64 kb, uint32 ra, uint32 rb, unsigned char* digist) {
	// On Host A - The Initiator
	char key[38];
	char msg[20];

	// Need MAC-A
	// MAC(KEY=(Key-A + Key-B)), Msg=(R-A + R-B))
	sprintf(key,"%19llu%19llu",ka,kb);
	sprintf(msg,"%10u%10u",ra,rb);
	hmac_md5((unsigned char*) msg,strlen(msg),(unsigned char*) key,strlen(key),digist);
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
void MPTCP_Flow::hmac_md5(unsigned char*  text, int text_len,unsigned char*  key, int key_len, unsigned char* digest)

{
        MD5_CTX context;
        unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
        unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */
        unsigned char tk[16];
        int i;
        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64) {

                MD5_CTX      tctx;

                MD5_Init(&tctx);
                MD5_Update(&tctx, key, key_len);
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
        bzero( k_ipad, sizeof k_ipad);
        bzero( k_opad, sizeof k_opad);
        bcopy( key, k_ipad, key_len);
        bcopy( key, k_opad, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner MD5
         */
        MD5_Init(&context);                   /* init context for 1st
                                              * pass */
        MD5_Update(&context, k_ipad, 64);      /* start with inner pad */
        MD5_Update(&context, text, text_len); /* then text of datagram */
        MD5_Final(digest, &context);          /* finish up 1st pass */
        /*
         * perform outer MD5
         */
        MD5_Init(&context);                   /* init context for 2nd
                                              * pass */
        MD5_Update(&context, k_opad, 64);     /* start with outer pad */
        MD5_Update(&context, digest, 16);     /* then results of 1st
                                              * hash */
        MD5_Final(digest, &context);          /* finish up 2nd pass */
}
// Getter/ Setter

/**
 * getter function sender_key
 */
uint64 MPTCP_Flow::getSenderKey() {
	return sender_key;
}

/**
 * getter function receiver_key
 */
uint64 MPTCP_Flow::getReceiverKey() {
	return receiver_key;
}

/**
 * getter function for state flow_token
 */
uint32 MPTCP_Flow::getFlow_token(){
	return flow_token;
}

/**
 * getter function for state
 */
MPTCP_State MPTCP_Flow::getState() {
	return state;
}
/**
 * setter for sender_key
 */
void MPTCP_Flow::setReceiverKey(uint64 key){
	receiver_key = key;
}
/**
 * setter for sender_key
 */
void MPTCP_Flow::setSenderKey(uint64 key){
	sender_key = key;
}

// end MPTCP_Flow

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
						if((flow->getFlow_token() == receiver_key)){
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
	// TODO -> Something goes wrong - we havt to find a communication channel
	// tcpseg->setRstBit();
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
					if (option.getValuesArraySize() < 3) {
						ASSERT(true);
						return 0; //should never be happen
					}
					// In every case we expect a sender key
					if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
						// SYN/ACK: We aspect the sender key in the MP_CAPABLE Option

						// read 64 bit keys
						uint64 key = option.getValues(2);
						key =  (key << 32) | option.getValues(1);
						flow->setReceiverKey(key); // Could be generated every time -> important is key of ACK


						DEBUGPRINT("[IN] Got SYN/ACK with sender key %llu",flow->getSenderKey());
						DEBUGPRINT("[IN] Got SYN/ACK with receiver key %llu",flow->getReceiverKey());
						DEBUGPRINT("[IN] Got SYN/ACK Src-Port %d -  Dest-Port %d: -> MPTCP CONNECTION ESTABLISHED",tcpseg->getSrcPort(),tcpseg->getDestPort());

						// OK new stateful MPTCP flow, calculate the token and Start-SQN
						flow->generateTokenAndSQN(flow->getSenderKey(), flow->getReceiverKey());

						// add (First) Subflow of the connection
						flow->addSubflow(connId,subflow);

						return 1;
					}
					else if(tcpseg->getAckBit()) {
						// ACK: We aspect the sender key in the MP_CAPABLE Option
						if (option.getValuesArraySize() < 5) {
							ASSERT(false);
							return 0; //should never be happen
						}

						// read 64 bit keys
						uint64 key = option.getValues(2);
						key =  (key << 32) | option.getValues(1);
						flow->setSenderKey(key);
						key = option.getValues(4);
						key =  (key << 32) | option.getValues(3);

						flow->setReceiverKey(key);
						DEBUGPRINT("[IN] Got ACK with Sender Key %llu",flow->getSenderKey());
						DEBUGPRINT("[IN] Got ACK with Receiver Key %llu",flow->getReceiverKey());
						DEBUGPRINT("[IN] Got ACK Src-Port %d -  Dest-Port %d: -> MPTCP CONNECTION ESTABLISHED",tcpseg->getSrcPort(),tcpseg->getDestPort());
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
						flow->generateTokenAndSQN(flow->getSenderKey(), flow->getReceiverKey());

						// Add (First) Subflow of the connection
						flow->addSubflow(connId,subflow);
						flow->setState(ESTABLISHED);

					} else {
						// SYN
						// read 64 bit keys
						uint64 key = option.getValues(2);
						key =  (key << 32) | option.getValues(1);
						flow->setSenderKey(key);

						DEBUGPRINT("[IN] Got SYN with sender key %llu",flow->getSenderKey());

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

						// OK if we are here there exist
						// - a valid Multipath TCP Control Block
						// - next step is to send SYN/ACK
						// ==> add subflow to connection/ multipath flow (For first -> TODO, handle TCP RST)

						flow->addSubflow(connId,subflow);

						// process the security part

						// get important information of the segment
						subflow->randomA = option.getValues(2);
						// It is also a got time to generate Random of B
						subflow->randomB = (uint32) flow->generateKey();

						// Generate truncated
						flow->generateSYNACK_HMAC(flow->getSenderKey(), flow->getReceiverKey(), subflow->randomA, subflow->randomB, subflow->MAC64);
						flow->generateACK_HMAC(flow->getSenderKey(), flow->getReceiverKey(), subflow->randomA, subflow->randomB, subflow->MAC160);

					}
					// process SYN/ACK
					else if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
						DEBUGPRINT("[IN] Got SYN/ACK Src-Port %d -  Dest-Port %d: > MPTCP MP_JOIN",tcpseg->getSrcPort(),tcpseg->getDestPort());
						// TODO - Check if this is the correct subflow - we added the flow still on the MPTCP SYN - I'm not sure if this is OK

						// Read the truncated MAC
						option.getValues(1);
						option.getValues(2);

						// However, we need the Host-B random number
						subflow->randomA = option.getValues(3);

						// Here we should check the HMAC
						// TODO int err isValidTruncatedHMAC();
						// if(err)
							// TCP RST TODO


					}
					// process ACK
					else if((!tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
						DEBUGPRINT("[IN] Got ACK Src-Port %d -  Dest-Port %d: > MPTCP MP_JOIN",tcpseg->getSrcPort(),tcpseg->getDestPort());
						unsigned char mac160[160];
						int offset = 0;
						for(int i = 1; i <= 5; i++){ // 20 Octets/ 160 Bits
							uint32 value = option.getValues(i);
							memcpy(&mac160[offset],&value,sizeof(uint32));
							offset = 2 << i;
						}
						// Here we should check the HMAC
						// Idea, compute the input bevor sending the packet
						// TODO int err isValidHMAC();
						// if(err)
							// TCP RST TODO

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
