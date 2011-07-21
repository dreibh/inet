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
#define DEBUGPRINT2(...)  fprintf(stderr, __VA_ARGS__,...)
//#define DEBUGPRINT(_fmt, ...)  DEBUGPRINT2(WHERESTR _fmt, WHEREARG, __VA_ARGS__)

#ifndef PRIVATE_DEBUG
#define DEBUGPRINT(_fmt, ...)  DEBUGPRINT2(WHERESTR _fmt, WHEREARG, __VA_ARGS__)
#else
#define	DEBUGPRINT(_fmt, ...) ;
#endif

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

#define COMMON_MPTCP_OPTION_HEADER_SIZE 16
#define SENDER_KEY_SIZE 64
#define RECEIVER_KEY_SIZE 64

#define MP_CAPABLE_SIZE_SYN    ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + SENDER_KEY_SIZE) >> 3)
#define MP_CAPABLE_SIZE_SYNACK ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + RECEIVER_KEY_SIZE) >> 3)
#define MP_CAPABLE_SIZE_ACK    ((COMMON_MPTCP_OPTION_HEADER_SIZE + MP_SIGNAL_FIRST_VALUE_TYPE + SENDER_KEY_SIZE + RECEIVER_KEY_SIZE) >> 3)

#define MP_JOIN_SIZE 	0
// const int MPTCP_ACKOPTION_SIZE = 10;
// const int MPTCP_DATAOPTION_SIZE = 16;

#define VERSION 0x0

/**
 * Constructor
 */
MPTCP_Flow::MPTCP_Flow(int ID) :
		cnt_subflows(0), state(IDLE), initiator(false), sender_key(0), receiver_key(0) {
	appID = ID;
	state = IDLE;

	initFlow();
}

/**
 * Destructor
 */
MPTCP_Flow::~MPTCP_Flow() {
	// TODO
}

void MPTCP_Flow::initFlow() {
	IInterfaceTable *ift = interfaceTableAccess.get();
	tcpEV<<"add local address\n";
	DEBUGPRINT("[INIT] add local addresses to list, currently in list: %ju",list_laddrtuple.size());
	    if (!list_laddrtuple.size())
	    {
	        for (int32 i=0; i<ift->getNumInterfaces(); ++i)
	        {
	        	AddrTupple_t* addr = new AddrTupple_t();

	        	if (ift->getInterface(i)->ipv4Data()!=NULL)
	            {
	        		tcpEV<<"add IPv4: " << ift->getInterface(i)->ipv4Data()->getIPAddress() << "\n";
	        		addr->addr = ift->getInterface(i)->ipv4Data()->getIPAddress();
	            }
	            else if (ift->getInterface(i)->ipv6Data()!=NULL)
	            {
	                for (int32 j=0; j<ift->getInterface(i)->ipv6Data()->getNumAddresses(); j++)
	                {
	                	tcpEV<<"add IPv6: " << ift->getInterface(i)->ipv6Data()->getAddress(j) << "\n";
	                	addr->addr =  ift->getInterface(i)->ipv6Data()->getAddress(j);
	                }
	            }
	            else{
	            	ASSERT(false);
	            }
	        	list_laddrtuple.push_back(addr);
	        }
	    }
	    else
	    {
	        tcpEV<<"Problems by adding all known IP adresses\n";
	    }
	    DEBUGPRINT("[INIT] Found local Adresse: %ju",list_laddrtuple.size());
}

	/**
	 * Add a subflow to a MPTCP connection
	 */
int MPTCP_Flow::addFlow(int id, TCPConnection* subflow) {
	TCP_SUBFLOW_T *t = new TCP_SUBFLOW_T();


	for (TCP_SubFlowVector_t::iterator i = subflow_list.begin(); i
			!= subflow_list.end(); ++i) {
		TCP_SUBFLOW_T* entry = (*i);
		if ((entry->flow->remoteAddr == subflow->remoteAddr)
				&& (entry->flow->remotePort == subflow->remotePort)
				&& (entry->flow->localAddr == subflow->localAddr)
				&& (entry->flow->localPort == subflow->localPort))
			ASSERT(false);
	}

	t->active = true;
	t->flow = subflow;
	subflow_list.push_back(t);
	cnt_subflows++;


	bool found = false;
	TCP_AddressVector_t::const_iterator it_r;
	for (it_r = list_raddrtuple.begin(); it_r != list_raddrtuple.end(); it_r++) {
		AddrTupple_t* tmp_r = (AddrTupple_t*) *it_r;
		if ((tmp_r->addr.equals(subflow->remoteAddr)) && (tmp_r->port == subflow->remotePort)) {
			found = true;
		}
	}
	if (!found) {
		AddrTupple_t *a = new AddrTupple_t();
		a->addr = subflow->remoteAddr;
		a->port = subflow->remotePort;
		list_raddrtuple.push_back(a);
	}

	// sender side; we have to check if there are more possibles
//	if (initiator) {	TODO I have to check, if both sides could do this
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
//	}


	// TODO we have to check if there are any new MP_JOIN possible
	// if this remote address is new, we have to add all possible combinations
	// check if address is new
	// if yes put into remote address vector
	// if yes put all possible combinations with all local addresses to the JOIN queue
	return 1;
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
	uint options_len = 0;
	uint16 first_bits = 0x00;
	TCPOption option;

	// First check if is it allowed to add further options
	for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
		options_len = options_len + tcpseg->getOptions(i).getLength();

	// Check on not increasing the TCP OPTION
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
		first_bits = first_bits & ((uint16) MP_CAPABLE << MP_SUBTYPE_POS);
		first_bits = first_bits & ((uint16) VERSION << MP_VERSION_POS);

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

		first_bits = first_bits & ((uint16) MP_CAPABLE << MP_SUBTYPE_POS);
		first_bits = first_bits & ((uint16) VERSION << MP_VERSION_POS);

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

		// TODO -> Perhaps there is a better place, but in first try we check if there are new data received
		joinConnection();

		DEBUGPRINT("[OUT] Leave ESTABLISHED for connection Src-Port %u -  Dest-Port %u",tcpseg->getSrcPort(),tcpseg->getDestPort());
		break;
	}
	default:
		DEBUGPRINT("[OUT] Enter default for connection Src-Port %u -  Dest-Port %u - BUT THIS IS NOT WANTED",tcpseg->getSrcPort(),tcpseg->getDestPort());
		tcpEV<<"ERROR: Options length exceeded! Segment will be sent without options" << "\n";
		ASSERT(false);
		// TODO CHECK FLOW FLAGS, eg. report or delete address
	}
	DEBUGPRINT("[OUT] Leave function with %d header Src-Port %u -  Dest-Port %u",t, tcpseg->getSrcPort(),tcpseg->getDestPort());
	return t;
}

bool MPTCP_Flow::joinConnection() {

	while (join_queue.size() > 0) {
		// OK, there is a possible new subflow, so there should a connection exist with all required info
		ASSERT(subflow_list.size() != 0);
		bool skip = false;;
		TCP_SUBFLOW_T* subflow = (TCP_SUBFLOW_T *) (*(subflow_list.begin()));
		TCPConnection* tmp = subflow->flow;
		ASSERT(tmp->getTcpMain()!=NULL);


		AddrCombi_t* c = (AddrCombi_t*) *(join_queue.begin());
		tcpEV<< "New subflow join: " << c->local->addr << "<->" << c->remote->addr << "\n";
		if(IPvXAddress("127.0.0.1").equals(c->local->addr))
			skip = true;
		if(IPvXAddress("0.0.0.0").equals(c->local->addr))
			skip = true;

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
//#######################################################################################

MPTCP_PCB::MPTCP_PCB() :
	flow(NULL) {
}
MPTCP_PCB::~MPTCP_PCB() {
	// TODO
	//	if(flow!=NULL)
	//		delete flow;
}

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
		MPTCP_SUBTYPES subtype = MP_FAIL;

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
				if(((first & (uint16)MP_CAPABLE << MP_SUBTYPE_POS) >> MP_SUBTYPE_POS) == MP_CAPABLE) {
					subtype = MP_CAPABLE;

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

						flow->addFlow(connId,subflow);

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
							flow = new MPTCP_Flow(connId);
						}
						ASSERT(flow!=NULL);

						// OK new stateful MPTCP flow, calculate the token and Start-SQN
						flow->generateTokenAndSQN(sender_key, receiver_key);

						// Add (First) Subflow of the connection
						flow->addFlow(connId,subflow);

						// Set internal state to pre_established -> etablished by real sending the ACK SYN/ACK
						flow->setState(ESTABLISHED);

					} else {

						sender_key = option.getValues(1);
						DEBUGPRINT("[IN] Got SYN Src-Port %u -  Dest-Port %u: Sender Key %ju",tcpseg->getSrcPort(),tcpseg->getDestPort(),sender_key);
						DEBUGPRINT("[IN] Got SYN Src-Port %u -  Dest-Port %u: Receiver Key %ju",tcpseg->getSrcPort(),tcpseg->getDestPort(),receiver_key);
						DEBUGPRINT("[IN] Got SYN Src-Port %d -  Dest-Port %d: > MPTCP CONNECTION PRE ESTABLISHED",tcpseg->getSrcPort(),tcpseg->getDestPort());

						return 0; // OK we got a MP_CAPABLE in a SYN, we a steless anymore
					}

					break; // OK we got a MP_CAPABLE, lets become stateful
				}

				// OK, it is a MPTCP Option, so lets figure out which subtype
				tcpEV << "MPTCP Option\n";
			} // MPTCP Options
		} // end for each option
	}
	else { // This is a MPTCP Flow
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

				uint16 first = option.getValues(0);
				if(((first & (uint16)MP_CAPABLE << MP_SUBTYPE_POS) >> MP_SUBTYPE_POS) == MP_CAPABLE) {
					tcpEV << "MPTCP Option MP_CAPABLE" << "\n";
					// ASSERT(false);
				} // Connection etablished

			}
		}

	}
	return 1;
}

TCPConnection* MPTCP_PCB::lookupMPTCPConnection(int connId,
		TCPConnection* subflow) {
	// In the end it is quit simple, if MPTCP is enabled we should initiate th MPTCP Protocol Control Block
	// We are a mptcp block, without a connection
	if (subflow->mPCB->getFlow() == NULL) {
		flow = new MPTCP_Flow(connId);
		return subflow;
	}

	//TODO OK, now we have to choose by the scheduler which flow we should use next....

	TCPConnection* conn = subflow;
	return subflow;
}

MPTCP_Flow* MPTCP_PCB::lookupMPTCPFlow(TCPConnection* subflow) {
	// TODO check if connection for flow
	return NULL;
}

int MPTCP_PCB::clearAll() {
	// TODO shutdown
	if (flow != NULL) {
		delete flow;
		flow = NULL;
	}
	return 0;
}

MPTCP_Flow* MPTCP_PCB::getFlow() {
	return flow;
}
