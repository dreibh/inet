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

#include "TCPMultipath.h"

#if defined(__APPLE__)
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#define SHA1 CC_SHA1
#else
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <inttypes.h>
#endif

// Helper to set state for a subflow
#define FSM(state) setState(state); fprintf(stderr,"\n[FSM] CHANGE STATE %d line %d\n",state,__LINE__);

// Defines for debugging (Could be removed)
#define WHERESTR  "\n[MPTCP][file %s, line %d]: "
#define WHEREARG  __FILE__, __LINE__
#define DEBUGPRINT2(...)  fprintf(stderr, __VA_ARGS__)

#ifdef PRIVATE_DEBUG
#define DEBUGPRINT(_fmt, ...)  DEBUGPRINT2(WHERESTR _fmt, WHEREARG, __VA_ARGS__)
#else
#define	DEBUGPRINT(_fmt, ...) ;
#endif

// some defines for maximum sizes
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

// Some helper defines
#define STATEFULL  1
#define STATELESS 0

// Some constants for help
const unsigned int MP_SIGNAL_FIRST_VALUE_TYPE = 16;
const unsigned int MP_SUBTYPE_POS = MP_SIGNAL_FIRST_VALUE_TYPE - 4;
const unsigned int MP_VERSION_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS
		- 4;
const unsigned int MP_C_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS
		- MP_VERSION_POS - 1;
const unsigned int MP_RESERVED_POS = MP_SIGNAL_FIRST_VALUE_TYPE
		- MP_SUBTYPE_POS - MP_VERSION_POS - MP_C_POS - 4;
const unsigned int MP_S_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS
		- MP_VERSION_POS - MP_C_POS - MP_RESERVED_POS - 1;

/**
 * Constructor
 * @param int ID for each Flow
 * @param int aAppGateIndex Application Gate Index for Flow
 * @param int MPTCP_PCB Protocol Control Block for Flow
 */
MPTCP_Flow::MPTCP_Flow(int connID, int aAppGateIndex, MPTCP_PCB* aPCB) :
	state(IDLE), sender_key(0),
			receiver_key(0) {

	// Start state of the Multipath FLOW is IDLE
	this->FSM(IDLE);
	// For easy PCB Lookup set ID and Application Index
	appID = connID;
	appGateIndex = aAppGateIndex;
	pcb = aPCB;
	joinToACK = false;
	isPassive = false;
	// Init the flow
	initFlow();
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
void MPTCP_Flow::initFlow() {
	// 1) lookup for all available IP addresses
	// 2) setup a list of local addresses
	// We need cross layer information of available interfaces

	IInterfaceTable *ift = interfaceTableAccess.get();

	// Setup a list of available addresses
	if (!list_laddrtuple.size()) {
		for (int32 i = 0; i < ift->getNumInterfaces(); ++i) {
			AddrTupple_t* addr = new AddrTupple_t();

			if (ift->getInterface(i)->ipv4Data() != NULL) {
				tcpEV<<"[MPTCP FLOW] add IPv4: " << ift->getInterface(i)->ipv4Data()->getIPAddress() << "\n";
				addr->addr = ift->getInterface(i)->ipv4Data()->getIPAddress();
			}
			else if (ift->getInterface(i)->ipv6Data()!=NULL)
			{
				for (int32 j=0; j<ift->getInterface(i)->ipv6Data()->getNumAddresses(); j++)
				{
					tcpEV<<"[MPTCP FLOW] add IPv6: " << ift->getInterface(i)->ipv6Data()->getAddress(j) << "\n";
					addr->addr = ift->getInterface(i)->ipv6Data()->getAddress(j);
				}
			}
			else {
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
			// FIXME 1 is this a Problem?
			// ASSERT(false);
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
			tcpEV<< "[MPTCP][PREPARE ADD SUBFLOW] Base Addr:" << subflow->localAddr << "\n";
			// collect data for possible new connections
			if (!tmp_l->addr.equals(subflow->localAddr)) {
				AddrCombi_t* to_join = new AddrCombi_t();
				to_join->local = tmp_l;
				to_join->remote = tmp_r;
				tcpEV<< "[MPTCP][PREPARE ADD SUBFLOW] ADD Possible new Subflow " << tmp_l->addr << "<-->"<< tmp_r->addr <<"\n";
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

	// First check if is it allowed to add further options
	for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
		options_len = options_len + tcpseg->getOptions(i).getLength();

	// Check on not increasing the TCP Option
	ASSERT(options_len <= 40);

	// Only work on MPTCP Options!!
	// (Note: If this is a design problem to do it here, we could move this to TCP...)
	option.setKind(TCPOPTION_MPTCP); // FIXME depending on IANA request
	DEBUGPRINT("[FLOW][OUT] Support of MPTCP Kind: %d",TCPOPTION_MPTCP);

	// If SYN remark this combination as tried
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
			DEBUGPRINT("[FLOW][OUT] ESTABLISHED (%i)\n",state);
			// complete additional subflow setup
			// If we in ESTABLISHED state and there comes up a syn we have to add a join for MPTCP transfer
			if ( (subflow->isSubflow) &&	((tcpseg->getSynBit())  || joinToACK) ) {
				t = joinHandshake(t, subflow_state, tcpseg, subflow, &option);
				joinToACK = false;

			}else if (subflow->isSubflow){
				DEBUGPRINT("[FLOW][OUT] Do SQN for subflow (%d) by utilizing DSS",subflow->isSubflow);
				processSQN(t, subflow_state, tcpseg, subflow, &option);
			}
			break;
		}
		case SHUTDOWN:
			DEBUGPRINT("[FLOW][OUT] SHUTDOWN  (%i)",state);
			break;
		case PRE_ESTABLISHED:
			DEBUGPRINT("[FLOW][OUT] PRE ESTABLISHED (%i)",state);
			/* no break */
		default: {
		case IDLE:
			DEBUGPRINT("[FLOW][OUT] Work on state %i - Figure out what to do",state);
			if ((tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
				DEBUGPRINT("[FLOW][OUT] Not ESTABLISHED here we go %i",state);
				// If we send the SYN ACK, we are the passive side, please note this
				isPassive = true;
			}
			t = initialHandshake(t, subflow_state, tcpseg, subflow,  &option);
			break;
		}
	}
	if(this->state == ESTABLISHED){
		// FIXME Perhaps we need a switch for also handshake from passive side
		//
		if(!isPassive){
			// 3.2. Starting a New Subflow
			// It is permitted for
			// either host in a connection to initiate the creation of a new
			// subflow, but it is expected that this will normally be the original
			// connection initiator
			joinConnection(); // FIXME -> Perhaps there is a better place, but in first try we check if there are new data received
		}
	}
	return t;
}

/*
 * Do the MP_CAPABLE Handshake
 */
int MPTCP_Flow::initialHandshake(uint t, TCPStateVariables* subflow_state,
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
	uint32 first_bits = 0x00;

	tcpEV<<"Multipath FSM: Enter Initial Handshake " << "\n";
	switch (state) {
		// Connection initiation SYN; SYN/ACK; ACK of the whole flow it must contain the MP_CAPABLE Option
		// MPTCP IDLE
		case IDLE: { // whether a SYN or ACK for a SYN ACK is send -> new MPTCP Flow

			if (!tcpseg->getSynBit()) {
				DEBUGPRINT("[FLOW][OUT] ERROR MPTCP Connection state: %d", getState());
				ASSERT(false);
				return t;
			}

			first_bits = first_bits | ((uint16) MP_CAPABLE << MP_SUBTYPE_POS);
			first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);
			first_bits = first_bits | ((uint16) VERSION << MP_VERSION_POS);
			first_bits = first_bits << (MP_VERSION_POS + MP_SIGNAL_FIRST_VALUE_TYPE);
// SYN MP_CAPABLE
			// Check if it is whether a SYN or SYN/ACK
			if (tcpseg->getSynBit() && (!tcpseg->getAckBit())) { // SYN
				tcpEV<< "[MPTCP][HANDSHAKE][MP_CAPABLE] IDLE working for sending a SYN\n";

				option->setLength(MP_CAPABLE_SIZE_SYN);
				option->setValuesArraySize(3);
				option->setValues(0, first_bits);

				// generate sender_key(!!) Section 3.1 => only time the key will send in clear
				setSenderKey(generateKey()); // use setter helper to set in object
				// set 64 bit value
				uint32_t value = (uint32_t) getSenderKey();
				option->setValues(1, value);
				value = getSenderKey() >> 32;
				option->setValues(2, value);

				DEBUGPRINT("[FLOW][OUT] Generate Sender Key in IDLE for SYN: %lu",getSenderKey());
				this->FSM(IDLE);	//03.08
// SYN-ACK MP_CAPABLE
			} else if (tcpseg->getSynBit() && tcpseg->getAckBit()) { // SYN/ACK
				tcpEV << "[MPTCP][HANDSHAKE][MP_CAPABLE] IDLE working for sending a SYN-ACK \n";

				option->setLength(MP_CAPABLE_SIZE_SYNACK);
				option->setValuesArraySize(3);
				option->setValues(0, first_bits);

				// generate receiver_key -> important is key of ACK
				setReceiverKey(generateKey());
				ASSERT(receiver_key != 0);
				uint32 value = (uint32) getReceiverKey();
				// set 64 bit value
				option->setValues(1, value);
				value = getReceiverKey() >> 32;
				option->setValues(2, value);

				DEBUGPRINT("[FLOW][OUT] Generate Receiver Key in IDLE for SYN-ACK: %lu",getReceiverKey());
				this->FSM(ESTABLISHED);
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

			first_bits = first_bits | ((uint16) MP_CAPABLE);
			first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);
			first_bits = first_bits | ((uint16) VERSION);
			first_bits = first_bits << (MP_VERSION_POS + MP_SIGNAL_FIRST_VALUE_TYPE);

// ACK MP_CAPABLE
			// OK we are stateful, however the handshake is not complete
			if (tcpseg->getAckBit()) { // ACK
				tcpEV << "[MPTCP][HANDSHAKE][MP_CAPABLE] PRE_ESTABLISHED working for sending  a ACK\n";
				option->setLength(MP_CAPABLE_SIZE_ACK);
				option->setValuesArraySize(5);

				// ACK include both keys
				option->setValues(0, first_bits);

				// set 64 bit value
				uint32 value = (uint32) getSenderKey();
				option->setValues(1, value);
				value = getSenderKey() >> 32;
				option->setValues(2, value);

				// set 64 bit value
				value = (uint32) getReceiverKey();
				option->setValues(3, value);
				value = getReceiverKey() >> 32;
				option->setValues(4, value);

				tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
				tcpseg->setOptions(t, *option);
				t++;
				this->FSM(ESTABLISHED);
				tcpEV << "[MPTCP][HANDSHAKE][MP_CAPABLE] ESTABLISHED after enqueue a ACK\n";

			} else {
				ASSERT(false); // FIXME Just for Testing
			}
			break;
		}
		// MPTCP ESTABLISHED

		default:
			tcpEV<<"[MPTCP][HANDSHAKE][MP_CAPABLE][ERROR] Options length exceeded! Segment will be sent without options" << "\n";
			ASSERT(false); // FIXME Just for Testing
		break;
	}
	return t;
}

/**
 * Do the MP_JOIN Handshake
 */
int MPTCP_Flow::joinHandshake(uint t, TCPStateVariables* subflow_state,
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
	uint32 first_bits = 0x0;

	// the state is still established for another subflow, but here we need to initiate the handshake
	// whether a SYN or ACK for a SYN ACK is send -> new MPTCP Flow

	// 1) Handle new adresses and/or connections MP_JOIN
	// FIXME ADD_ADDR/ REMOVE ADDR
	// FIXME DSS

	tcpEV<< "[MPTCP][HANDSHAKE][MP_JOIN] ESTABLISHED should use MP_JOIN \n";


// SYN MP_JOIN
	// Add MP_JOIN on a SYN of a established MULTIPATH Connection
	if (tcpseg->getSynBit() && (!tcpseg->getAckBit())) {
		// OK, we are still established so, this must be a JOIN or ADD.
		// ADD is not handled here (FIXME ADD), so it must be a MP_JOIN
		// this is triggert by a self message, called by joinConnection()
		tcpEV << "[MPTCP][HANDSHAKE][MP_JOIN] SYN with MP_JOIN \n";
		first_bits = (first_bits | ((uint16) MP_JOIN)); //12
		first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);


	// FIXME Missing Address ID (!!!!)

		assert(MP_JOIN_SIZE_SYN==12); // In the draft it is defined as 12
		option->setLength(MP_JOIN_SIZE_SYN);
		option->setValuesArraySize(3);
		option->setValues(0, first_bits);

		option->setValues(1, getFlow_token()); // Get SSH-1 Token (Most time Token-B Sha-1(Key-B)) [Section 3.2]


		subflow->randomA = (uint32)generateKey();
		option->setValues(2, subflow->randomA); // FIXME Sender's random number (Generator perhaps other one??)

		addSubflow(subflow->connId,subflow); // connection becomes stateful on SYN because we have to remember all values -> not needed for real implemenation

		tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
		tcpseg->setOptions(t, *option);
		t++;
	}

// SYN-ACK MP_JOIN
	// Add MP_JOIN on a SYN/ACK of a etablished MULTIPATH Connection
	else if (tcpseg->getSynBit() && (tcpseg->getAckBit())) {

		first_bits = (first_bits | ((uint16) MP_JOIN));
		first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);

		// FIXME B
		// FIXME Adress ID
		assert(MP_JOIN_SIZE_SYNACK==16); // In the draft it is defined as 12
		option->setLength(MP_JOIN_SIZE_SYNACK);
		option->setValuesArraySize(3);

		option->setValues(0, first_bits);
		// generate the tuncated MAC (64) and the random Number of the Receiver (Sender of the Packet)
		// FIXME For second Parameter
		option->setValues(1, 0); // FIXME truncated MAC 64
		option->setValues(2, 0); // FIXME Random Number

		tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
		tcpseg->setOptions(t, *option);
		t++;
		tcpEV << "[MPTCP][HANDSHAKE][MP_JOIN] Pre-Established after enqueue of SYN-ACK" << "\n";
		this->FSM(PRE_ESTABLISHED);	// Only intern, if the general Flow in ESTABLISHED it will set back later
		// FIXME for the last ACK we should etablish a connection
// ACK MP_JOIN
	} else if ((!tcpseg->getSynBit()) && (tcpseg->getAckBit())) {
		// MPTCP OUT MP_JOIN ACK
		tcpEV << "[MPTCP][HANDSHAKE][MP_JOIN] ACK with MP_JOIN <Not filled yet>\n";
		first_bits = (first_bits | ((uint16) MP_JOIN));
		first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);


		assert(MP_JOIN_SIZE_ACK==24); // In the draft it is defined as 12
		option->setLength(MP_JOIN_SIZE_ACK);
		option->setValuesArraySize(3);
		option->setValues(0, first_bits);
		// generate the tuncated MAC (64) and the random Number of the Receiver (Sender of the Packet)
		// FIXME For second Parameter
		option->setValues(1, 0); // FIXME truncated MAC 64
		option->setValues(2, 0); // FIXME Random Number

		tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
		tcpseg->setOptions(t, *option);
		t++;

		tcpEV << "[MPTCP][HANDSHAKE][MP_JOIN] Established after enqueue of SYN" << "\n";
		this->FSM(ESTABLISHED);
	}
	else {
		tcpEV << "[MPTCP][HANDSHAKE][ERRROR]\n";
	}
	return t;
}

	/**
	 * Initiation of a new subflow of a multipath TCP connection
	 */
bool MPTCP_Flow::joinConnection() {
	// 1) Check for valid adresses and combinations
	// 2) Setup selfmessages
	// 3) Delete combination from join queue

	if(this->getState() != ESTABLISHED) return false;

	// In case we know new address pairs...
	while (join_queue.size() > 0) {
		ASSERT(subflow_list.size() != 0);
		bool skip = false;

		TCP_subflow_t* subflow = (TCP_subflow_t *) (*(subflow_list.begin()));
		TCPConnection* tmp = subflow->subflow;
		ASSERT(tmp->getTcpMain()!=NULL);

		// OK, there is a possible new subflow, so there should a connection exist with all required info

		AddrCombi_t* c = (AddrCombi_t*) *(join_queue.begin());
		tcpEV<< "[MPTCP][PREPARE JOIN] New subflow join: " << c->local->addr << "<->" << c->remote->addr << "\n";

		// ignore local addresses
		if(IPvXAddress("127.0.0.1").equals(c->local->addr)){
			tcpEV<< "[MPTCP][PREPARE JOIN] skip 127.0.0.1\n";
		    skip = true;
		}
		if(IPvXAddress("0.0.0.0").equals(c->local->addr)){
			tcpEV<< "[MPTCP][PREPARE JOIN] skip 0.0.0.0\n";
			skip = true;
		}

		// ignore still etablished subflows
		TCP_JoinVector_t::const_iterator it_tj;
		for (it_tj = tried_join.begin(); it_tj != tried_join.end(); it_tj++) {
			AddrCombi_t* tmp = (AddrCombi_t*) *it_tj;
			tcpEV<< "[MPTCP][PREPARE JOIN] Check if new subflow join ok: " << tmp->local->addr << "<->" << tmp->remote->addr << "\n";
			if ((c->local->addr.equals(tmp->local->addr)) && (c->remote->addr.equals(tmp->remote->addr))) {

				tcpEV<< "[MPTCP][PREPARE JOIN] Connection still known\n";
				skip = true;
				break;
			}
		}

		// #############################################
		// Create selfmessage for new subflow initiation

		// Is this a possible new subflow?
		if(!skip) {
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
			openCmd->setSubFlowNumber(this->getFlow_token());

			// initiate handshake for subflow
			openCmd->setIsMptcpSubflow(true);
			msg->setControlInfo(openCmd);
			msg->setContextPointer(tmp);
			tcpEV<< "[MPTCP][PREPARE JOIN] Schedule join of new Subflow " << c->local->addr << "<-->" << c->remote->addr <<"\n";

			tmp->getTcpMain()->scheduleAt(simTime() + 0.0001, msg);

		}

		// ###################
		// clean up the staff
		join_queue.erase(join_queue.begin());
		delete c;
	}
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
int MPTCP_Flow::processSQN(uint t,
			TCPStateVariables* subflow_state, TCPSegment *tcpseg,
			TCPConnection* subflow, TCPOption* option){

	// Initiate some helper
	uint32 first_bits = 0x0;
	tcpEV << "[MPTCP][PROCESS SQN] start\n";
	first_bits = (first_bits | ((uint16) MP_DSS));
	first_bits = first_bits << (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE);

	// DSS size is variable ... 8...20
	option->setLength(8);
	option->setValuesArraySize(1);
	option->setValues(0, first_bits);
	// generate the tuncated MAC (64) and the random Number of the Receiver (Sender of the Packet)
	// FIXME For second Parameter
//	option->setValues(1, 0); // FIXME truncated MAC 64
//	option->setValues(2, 0); // FIXME Random Number

	tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
	tcpseg->setOptions(t, *option);
	t++;

	return 0;
}


// ########################################### KEY HELPER STUFF #########################################
/**
 * Generate a 64 Byte Key
 * @return unit64 The Key
 */
uint64_t MPTCP_Flow::generateKey() {
	// FIXME check if this is the correct API -> there is an warning
	// FIXME be sure it is unique
	return intrand(UINT64_MAX);
}



/**
 * generate
 * - Start SQN
 * - Token ID
 */
int MPTCP_Flow::generateTokenAndSQN(uint64_t key) {

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
	DEBUGPRINT("[FLOW][OUT] Generate SQN: %lu:  ",*out64);
	flow_token = *out32;
	seq = *out64;
	return 0;
}

/**
 * generate body of SYN/ACK HMAC
 */
unsigned char* MPTCP_Flow::generateSYNACK_HMAC(uint64 ka, uint64 kb, uint32 ra,
		uint32 rb, unsigned char* digist) {
	// On Host B - Not Initiator
	char key[38];
	char msg[20];

	// Need MAC-B
	// MAC(KEY=(Key-B + Key-A)), Msg=(R-B + R-A))
	sprintf(key, "%19lu%19lu", kb, ka);
	sprintf(msg, "%10u%10u", rb, ra);
	hmac_md5((unsigned char*) msg, strlen(msg), (unsigned char*) key, strlen(
			key), digist);
	return digist;
}
/**
 * generate body of ACK HMAC
 */
unsigned char* MPTCP_Flow::generateACK_HMAC(uint64 ka, uint64 kb, uint32 ra,
		uint32 rb, unsigned char* digist) {
	// On Host A - The Initiator
	char key[38];
	char msg[20];

	// Need MAC-A
	// MAC(KEY=(Key-A + Key-B)), Msg=(R-A + R-B))
	sprintf(key, "%19lu%19lu", ka, kb);
	sprintf(msg, "%10u%10u", ra, rb);
	hmac_md5((unsigned char*) msg, strlen(msg), (unsigned char*) key, strlen(
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
void MPTCP_Flow::hmac_md5(unsigned char* text, int text_len,
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
	bzero(k_ipad, sizeof k_ipad);
	bzero(k_opad, sizeof k_opad);
	bcopy(key, k_ipad, key_len);
	bcopy(key, k_opad, key_len);

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
	MD5_Update(&context, k_ipad, 64); /* start with inner pad */
	MD5_Update(&context, text, text_len); /* then text of datagram */
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
uint64_t MPTCP_Flow::getSenderKey() {
	return sender_key;
}

/**
 * getter function receiver_key
 */
uint64_t MPTCP_Flow::getReceiverKey() {
	return receiver_key;
}

/**
 * getter function for state flow_token
 */
uint32_t MPTCP_Flow::getFlow_token() {
	return flow_token;
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
/**
 * setter for sender_key
 */
void MPTCP_Flow::setReceiverKey(uint64_t key) {
	receiver_key = key;
}
/**
 * setter for sender_key
 */
void MPTCP_Flow::setSenderKey(uint64_t key) {
	sender_key = key;
}
/**
 * helper set function
 */
int MPTCP_Flow::setState(MPTCP_State s) {
	state = s;
	return state;
}


// end MPTCP_Flow

//##################################################################################################
//#
//#	THE MULTIPATH TCP PROTOCOL CONTROL BLOCK
//#
//#################################################################################################


AllMultipathSubflowsVector_t MPTCP_PCB::subflows_vector;
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
	t->joinToAck=false;
	flow = t->flow;
	subflows_vector.push_back(t);
// For Debug
	this->printFlowOverview();
}
/**
 * De-Constructor
 */
MPTCP_PCB::~MPTCP_PCB() {
	// FIXME delete flow
	DEBUGPRINT("[PCB][Destroy] Currently %lu MPTCP Protocol Control Blocks used",subflows_vector.size());
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
	int ret = tmp->processSegment(connId, subflow, tcpseg);
	return ret;
}



/**
* Internal helper to process packet for a flow
* FIXME Something goes wrong (TCP RST)
*/
int MPTCP_PCB::processSegment(int connId, TCPConnection* subflow,
	TCPSegment *tcpseg) {
	printFlowOverview();
	// We are here; so it must be Multipath TCP Stack
	if (!subflow->getTcpMain()->multipath) {
		ASSERT(true); // FIXME Only for testing
		return 0;
	}

	/**
	 * CASE "NEW MPTCP FLOW" or "NO MPTCP FLOW"
	 */
	// Check if this is still a Multipath Connection with an existing Flow
	if (flow == NULL || (flow->getState() == IDLE) || (flow->getState() >= PRE_ESTABLISHED)) {

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
			//			short length = option.getLength();

			if (kind == TCPOPTION_MPTCP) {
				if(option.getLength() < 4) {
					ASSERT(true); //should never be happen
					return 0;
				}

				uint32 first = option.getValues(0);
				uint16 sub = (first >> (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE));


				// OK, it is a MPTCP Option, so lets figure out which subtype
				switch(sub){
					case MP_CAPABLE:
						tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] MP_CAPABLE" << "\n";
						processMP_CAPABLE(connId, subflow, tcpseg, &option);
						break;
					case MP_JOIN:
						tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] MP_JOIN" << "\n";
						processMP_JOIN_IDLE(connId, subflow, tcpseg, &option);
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
			//			short length = option.getLength();


			if(kind == TCPOPTION_MPTCP)
			{
				tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] process" << "\n";
				if(option.getLength() < 4) {
					ASSERT(true); //should never be happen
					return 0;
				}

				uint32 value = option.getValues(0);
				uint16 sub = (value >> (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE));

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
					processMP_JOIN_ESTABLISHED(connId, subflow, tcpseg, &option);
					break;
				case MP_DSS:
					tcpEV << "[MPTCP][IDLE][MPTCP OPTION][IN] MP_DSS" << "\n";
					this->processMP_DSS(connId, subflow, tcpseg, &option);
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

int MPTCP_PCB::processMP_CAPABLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option) {

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
		flow->setReceiverKey(key); // Could be generated every time -> important is key of ACK

		DEBUGPRINT("[PRE_ESTABLISHED][CAPABLE][IN] Got SYN/ACK with sender key %lu",
				flow->getSenderKey());
		DEBUGPRINT("[PRE_ESTABLISHED][CAPABLE][IN Got SYN/ACK with receiver key %lu",
				flow->getReceiverKey());


		// OK new stateful MPTCP flow, calculate the token and Start-SQN
		flow->generateTokenAndSQN(flow->getSenderKey());

		// add (First) Subflow of the connection
// FIXME Draft 03 expect only the initator of the connection do a try on new adresses
    	// flow->addSubflow(connId, subflow);

		flow->FSM(PRE_ESTABLISHED);
		return STATEFULL;
	} else if (tcpseg->getAckBit()) {
		// ACK: We aspect the sender key in the MP_CAPABLE Option
		if (option->getValuesArraySize() < 5) {
			ASSERT(false);
			return 0; //should never be happen
		}

		// read 64 bit keys
		uint64 key = option->getValues(2);
		key = (key << 32) | option->getValues(1);
		flow->setSenderKey(key);
		key = option->getValues(4);
		key = (key << 32) | option->getValues(3);

		flow->setReceiverKey(key);
		DEBUGPRINT("[IDLE][CAPABLE][IN] Got ACK with Sender Key %lu", flow->getSenderKey());
		DEBUGPRINT("[IDLE][CAPABLE][IN] Got ACK with Receiver Key %lu",
				flow->getReceiverKey());

		// Status: Check MPTCP FLOW
		// - this is a MULTIPATH Stack: 			OK
		// - This is a New MPTCP Flow: 				OK
		// - The needed MP_CAPABLE Option exits: 	OK
		// - Valid keys:							OK
		// ==> Create a stateful Flow: generate token and SQN and Buffer

		if (flow == NULL) {
			// we have to be ESTABLISHED and is has to be an ACK
			if (tcpseg->getAckBit())
				flow = new MPTCP_Flow(connId, subflow->appGateIndex,this);
		}
		ASSERT(flow!=NULL);

		// OK new stateful MPTCP flow, calculate the token and Start-SQN

		flow->generateTokenAndSQN(flow->getReceiverKey());
		// Add (First) Subflow of the connection
		flow->addSubflow(connId, subflow);

		flow->FSM(ESTABLISHED);


	} else {
		// SYN
		// read 64 bit keys
		uint64 key = option->getValues(2);
		key = (key << 32) | option->getValues(1);
		flow->setSenderKey(key);
		flow->FSM(IDLE);
		DEBUGPRINT("[IDLE][CAPABLE][IN] Got SYN with sender key %lu", flow->getSenderKey());
	}

	return STATELESS; // OK we got a MP_CAPABLE in a SYN, we are still stateless
}
int MPTCP_PCB::processMP_JOIN_IDLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const TCPOption* option) {
	// Only SYN is important in IDLE
	// The Rest we just ignore
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
		subflow->randomB = (uint32) flow->generateKey();

		// Generate truncated
		flow->generateSYNACK_HMAC(flow->getSenderKey(), flow->getReceiverKey(), subflow->randomA, subflow->randomB, subflow->MAC64);
		flow->generateACK_HMAC(flow->getSenderKey(), flow->getReceiverKey(), subflow->randomA, subflow->randomB, subflow->MAC160);
		flow->joinToACK = true;
		flow->FSM(IDLE);
	}
	return 0;
}

int MPTCP_PCB::processMP_JOIN_ESTABLISHED(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const TCPOption* option){

	if (option->getValuesArraySize() < 2) {
		ASSERT(true);
		return 0; //should never be happen
	}

	// Now it is time to start a new SUBFLOW
	// We have to do the normal staff, but we have also look on the still existing flow
	// - procees SYN	-> Error in Established
	// - process SYN/ACK
	// - process ACK

// process SYN
	if((tcpseg->getSynBit()) && (!tcpseg->getAckBit()) ) {
		tcpEV << "[MPTCP][ESTABLISHED][JOIN] process SYN" << "\n";
		ASSERT(true);
	}
// process SYN/ACK
	else if((tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
		tcpEV << "[MPTCP][ESTABLISHED][JOIN] process SYN ACK" << "\n";
		// FIXME - Check if this is the correct subflow - we added the flow still on the MPTCP SYN - I'm not sure if this is OK

		// Read the truncated MAC
		option->getValues(1);
		option->getValues(2);

		// However, we need the Host-B random number
// FIXME		subflow->randomA = option->getValues(3);

		// Here we should check the HMAC
		// FIXME int err isValidTruncatedHMAC();
		// if(err)
		// TCP RST FIXME

		// if everything is fine, we can go to established
		flow->FSM(PRE_ESTABLISHED);
	}
// process ACK
	else if((!tcpseg->getSynBit()) && (tcpseg->getAckBit()) ) {
		tcpEV << "[MPTCP][ESTABLISHED][JOIN] process ACK" << "\n";
//		unsigned char mac160[160];
//		int offset = 0;
		// FIXME Interprete MP_JOIN ACK
		//for(int i = 1; i <= 5; i++) { // 20 Octets/ 160 Bits
		//	uint32 value = option->getValues(i);
		//	memcpy(&mac160[offset],&value,sizeof(uint32));
		//	offset = 2 << i;
		//}
		// Here we should check the HMAC
		// Idea, compute the input bevor sending the packet
		// FIXME int err isValidHMAC();
		// if(err)
		// TCP RST FIXME

		// if everything is fine, we can go to established
		flow->FSM(ESTABLISHED);
	}
	flow->joinToACK = true;
	return 0;
}

int MPTCP_PCB::processMP_DSS(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option){
		tcpEV << "[MPTCP][ESTABLISHED][DSS] process MPTCP Option DSS" << "\n";
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
			uint16 value = option.getValues(0);
			uint16 sub = (value >> (MP_SUBTYPE_POS + MP_SIGNAL_FIRST_VALUE_TYPE));
			if(sub == MP_JOIN) {
				// OK, it is a MP_JOIN
				if (option.getValuesArraySize() < 2) {
					return NULL;
				}

				// Check MPCB for MP_JOIN SYN
				if( (tcpseg->getSynBit()) && (!tcpseg->getAckBit()) ) {
					uint64 receiver_key = option.getValues(1);
					AllMultipathSubflowsVector_t::const_iterator it;
					// FIXME Check if the comparison is correct here
					for (it = subflows_vector.begin(); it != subflows_vector.end(); it++) {
							TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
							if (t->flow->getFlow_token() == receiver_key) {
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

MPTCP_PCB* MPTCP_PCB::lookupMPTCP_PCB(int connId, int aAppGateIndex,TCPSegment *tcpseg,  TCPConnection* subflow){
	MPTCP_PCB* tmp = NULL;
	if(tmp == NULL){

		// the best is we have the flow id

			if((uint32)subflow->getTcpMain()->subflow_id!=0){
				AllMultipathSubflowsVector_t::const_iterator it;
				for (it = subflows_vector.begin(); it != subflows_vector.end(); it++) {
					TuppleWithStatus_t* t = (TuppleWithStatus_t *)(*it);
					if (((uint32)subflow->getTcpMain()->subflow_id) == t->flow->getFlow_token()){
						return t->flow->getPCB();
					}
				}
			}
		}


	if(tmp == NULL)
		tmp = _lookupMPTCP_PCB(connId, aAppGateIndex);
	if(tmp == NULL)
		tmp = _lookupMPTCP_PCBbyMP_JOIN_Option(tcpseg, subflow);
	if(tmp == NULL)
		tmp = _lookupMPTCPbySubflow_PCB(tcpseg, subflow);
	if(tmp == NULL)
		DEBUGPRINT("[IDLE][lookupMPTCP_PCB] found no PCB for %i and %i",connId,aAppGateIndex);
	return tmp;
}


void MPTCP_PCB::printFlowOverview(){
	tcpEV<< "[MPTCP][OVERVIEW][PCB] =======================================" << "\n";
	AllMultipathSubflowsVector_t::const_iterator it;
	for (it = subflows_vector.begin(); it != subflows_vector.end(); it++) {
		TuppleWithStatus_t* tmp = (TuppleWithStatus_t *)(*it);
		;
		switch(tmp->flow->getState()){
		case IDLE:
			tcpEV<< "[MPTCP][OVERVIEW][PCB] IDLE \n";
			DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID  %d IDLE",tmp->flow->getFlow_token());
			break;
		case PRE_ESTABLISHED:
			tcpEV<< "[MPTCP][OVERVIEW][PCB] PRE_ESTABLISHED \n";
			DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW] Flow ID  %d PRE_ESTABLISHED",tmp->flow->getFlow_token());
			break;
		case SHUTDOWN:
			tcpEV<< "[MPTCP][OVERVIEW][PCB] SHUTDOWN \n";
			DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW]  Flow ID  %d SHUTDOWN",tmp->flow->getFlow_token());
			break;
		case ESTABLISHED:
			tcpEV<< "[MPTCP][OVERVIEW][PCB] ESTABLISHED \n";
			DEBUGPRINT("[MPTCP][OVERVIEW][PCB][FLOW]  Flow ID  %d ESTABLISHED",tmp->flow->getFlow_token());
			break;
		default:
			ASSERT(false);
			break;
		}


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

}

/**
 * FIXME Check Function
 */
int MPTCP_PCB::clearAll() {
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
