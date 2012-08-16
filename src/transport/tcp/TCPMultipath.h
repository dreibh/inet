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

// Include the MPTCP FLOW
// Include the MPTCP PCB
#ifdef PRIVATE

#ifndef __INET_MPTCP_H
#define __INET_MPTCP_H

#include <omnetpp.h>

#include <vector>
#include <map>
#include <set>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "TCPCommand_m.h"
#include "TCPSegment.h"
#include "IPvXAddress.h"

// Lower layer info
#include "RoutingTable.h"
#include "RoutingTableAccess.h"
#include "InterfaceTable.h"
#include "InterfaceTableAccess.h"
#include "IPv4InterfaceData.h"
#include "IPv6InterfaceData.h"

// TCP dependencies
#include "TCPConnection.h"
#include "TCP.h"
#include "TCPMultipathQueueMngmt.h"

class TCPConnection;
class TCPSegment;
class TCPStateVariables;

class INET_API MPTCP_PCB;

using std::vector;

typedef struct _addr_tuple{
	IPvXAddress addr;
	int 		port;
} AddrTupple_t;
typedef vector <AddrTupple_t*> 			TCP_AddressVector_t;

typedef struct _addr_combi{
	AddrTupple_t* local;
	AddrTupple_t* remote;
} AddrCombi_t;
typedef vector <AddrCombi_t*> 			TCP_JoinVector_t;

typedef struct _subflow{
  TCPConnection* subflow;
  bool active;
} TCP_subflow_t;
typedef vector <TCP_subflow_t*> 		TCP_SubFlowVector_t;


enum MPTCP_State {IDLE, PRE_ESTABLISHED, ESTABLISHED, SHUTDOWN};
// compare Section 8. IANA Considerations
enum MPTCP_SUBTYPES {MP_CAPABLE=0x0000, MP_JOIN=0x0001, MP_DSS=0x0002, MP_ADD_ADDR=0x0003, MP_REMOVE_ADDR=0x0004, MP_PRIO=0x0005, MP_FAIL=0x0006};

// DSS Flags -> Section 3.3
const uint8_t DSS_FLAG_A = 0x1;		// Data ACK present
const uint8_t DSS_FLAG_a = 0x2;		// Data ACK is 8 octets
const uint8_t DSS_FLAG_M = 0x4;		// Data Sequence Number, Subflow Sequence Number, Data-level  Length, and Checksum present
const uint8_t DSS_FLAG_m = 0x8;		// Data SQN is 8 Octets

const uint16_t DSS_FLAG_F = 0x10;	// FIN FLAG

// ###############################################################################################################
//													MULTIPATH TCP
//														FLOW
// ###############################################################################################################
/**
 * The MULTIPATH TCP Flow
 */
class INET_API MPTCP_Flow
{
  private:
	 int rcvbuf;							// receive message queue
	 int sndbuf;							// send message queue

	 MPTCP_PCB* pcb;								// the pcb

	 TCP_AddressVector_t list_laddrtuple;	// list of local addresses
	 TCP_AddressVector_t list_raddrtuple;	// list of remote addresses
	 TCP_SubFlowVector_t subflow_list; 		// list of all subflows
	 TCP_JoinVector_t join_queue;			// a queue with all join possibilities
	 TCP_JoinVector_t tried_join;

	 // Internal organization
	 MPTCP_State state;						// Internal State of the multipath protocol control block
	 TCPMultipathQueueMngmt* queue_mgr;     // Receiver queue


	 void _initFlow();
	 int _writeInitialHandshakeHeader(uint t,
	 		TCPStateVariables* subflow_state, TCPSegment *tcpseg,
	 		TCPConnection* subflow, TCPOption* option);
	 int _writeJoinHandshakeHeader(uint t,
	 		TCPStateVariables* subflow_state, TCPSegment *tcpseg,
	 		TCPConnection* subflow, TCPOption* option);
	 int _writeDSSHeaderandProcessSQN(uint t,
			TCPStateVariables* subflow_state, TCPSegment *tcpseg,
			TCPConnection* subflow, TCPOption* option);
	 bool _prepareJoinConnection();

  protected:


	 uint64_t seq;							// start seq-no generated after getting keys

	 uint64_t local_key;	// B.1.1 Authentication and Metadata
	 uint64_t remote_key;	// B.1.1 Authentication and Metadata
	 // TODO MPTCP CHECKSUM // B.1.1 Authentication and Metadata

	 bool checksum;
	 bool isPassive;
	 InterfaceTableAccess interfaceTableAccess;
  public:

	MPTCP_Flow(int ID, int aAppGateIndex, MPTCP_PCB* aPCB);
	~MPTCP_Flow();

	// It is public

	uint32 local_token;		// B.1.1 Authentication and Metadata
	uint32 remote_token;	// B.1.1 Authentication and Metadata
	// helper

	MPTCP_State getState();
	int setState(MPTCP_State s);
	uint32_t getFlow_token();
	MPTCP_PCB* getPCB();


	// Setter and Getter for Keys
	void setRemoteKey(uint64_t key);
	uint64_t getRemoteKey();
	void setLocalKey(uint64_t key);
	uint64_t getLocalKey();

	uint64_t getHighestCumSQN();

	// use cases Data IN/OUT
	int sendByteStream(TCPConnection* subflow);
	int writeMPTCPHeaderOptions(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg, TCPConnection* subflow);

	// crypto functions ==> see also rfc 2104
	uint64 generateLocalKey();
	int generateToken(uint64_t key, bool type);

	unsigned char* generateSYNACK_HMAC(uint64 ka, uint64 kr, uint32 ra, uint32 rb, unsigned char* digist);
	unsigned char* generateACK_HMAC(uint64 kb, uint64 kr, uint32 ra, uint32 rb, unsigned char* digist);
	void hmac_md5(unsigned char*  text, int text_len,unsigned char*  key, int key_len, unsigned char* digest);

	// subflow organisation
	int addSubflow(int id, TCPConnection*);
	bool isSubflowOf(TCPConnection* subflow);
	const TCP_SubFlowVector_t* getSubflows();

	// common identifier
	int  appID;								// The application ID of this Flow
    int  appGateIndex;
};

typedef struct _4tupleWithStatus{
	MPTCP_Flow* flow;
} TuppleWithStatus_t;
typedef vector <TuppleWithStatus_t*>	AllMultipathSubflowsVector_t;



// ###############################################################################################################
//													MULTIPATH TCP
//														PCB
// ###############################################################################################################
/**
 * The Multipath TCP Protocol Control Block and Meta-socket
 */
class INET_API MPTCP_PCB
{
	public:
		MPTCP_PCB(int connId,int appGateIndex, TCPConnection* subflow); // public constructor
		~MPTCP_PCB();
		// Static helper elements for organization
		static AllMultipathSubflowsVector_t subflows_vector;
		// Connection handling
		static MPTCP_PCB* lookupMPTCP_PCB(int connid, int aAppGateIndex,TCPSegment *tcpseg,  TCPConnection* subflow);
		TCPConnection*    lookupMPTCPConnection(int connId,int aAppGateIndex, TCPConnection* subflow,TCPSegment *tcpseg);
		// Use Case
		static int processMPTCPSegment(int connId,int aAppGateIndex, TCPConnection* subflow, TCPSegment *tcpseg);

		// Getter/ Setter
		MPTCP_Flow* getFlow();
		int getID();


	private:
		MPTCP_PCB();

		MPTCP_Flow* flow;
		// helper for process Segments
		int _processSegment(int connId, TCPConnection* subflow, TCPSegment *tcpseg);
		int _processMP_CAPABLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const TCPOption* option);
		int _processMP_JOIN_IDLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg, const TCPOption* option);
		int _processMP_JOIN_ESTABLISHED(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option);
		int _processMP_DSS(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option);
		// cleanup
		int _clearAll();


		// Lookup for Multipath Control Block management
		static MPTCP_PCB* _lookupMPTCP_PCB(int connid, int aAppGateIndex);
		static MPTCP_PCB* _lookupMPTCPbySubflow_PCB(TCPSegment *tcpseg,  TCPConnection* subflow);
		static MPTCP_PCB* _lookupMPTCP_PCBbyMP_JOIN_Option(TCPSegment* tcpseg, TCPConnection* subflow);

		// Sending side
		uint64_t snd_una; // B.1.2
		uint64_t snd_nxt; // B.1.2
		uint32_t snd_wnd; // B.1.2

		// Receiver Side
		uint64_t rcv_nxt; // B.1.2
		uint64_t rcv_wnd; // B.1.2

		// debug
		int id;
		void _printFlowOverview();
};


#endif // __INET_MPTCP_H
#endif // Private

