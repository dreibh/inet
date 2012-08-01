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

class TCPConnection;
class TCPSegment;
class TCPStateVariables;

using std::vector;

typedef struct _addr_tuple{
	IPvXAddress addr;
	int 		port;
} AddrTupple_t;

typedef struct _addr_combi{
	AddrTupple_t* local;
	AddrTupple_t* remote;
} AddrCombi_t;

typedef struct _subflow{
  TCPConnection* flow;
  bool active;
} TCP_SUBFLOW_T;

typedef std::vector <AddrTupple_t*> TCP_AddressVector_t;
typedef vector <AddrCombi_t*> TCP_JoinVector_t;
typedef vector<TCP_SUBFLOW_T*> TCP_SubFlowVector_t;

enum MPTCP_State {IDLE, PRE_ESTABLISHED, ESTABLISHED, SHUTDOWN};
enum MPTCP_SUBTYPES {MP_CAPABLE=0x0000, MP_JOIN=0x0001, MP_DSS=0x0002, MP_ADD_ADDR=0x0003, MP_REMOVE_ADDR=0x0004, MP_PRIO=0x0005, MP_FAIL=0x0006};


class INET_API MPTCP_Flow
{
  private:
	 int rcvbuf;							// receive message queue
	 int sndbuf;							// send message queue
	 // TODO								// mptcp 64-bits sequence numbering

	 TCP_AddressVector_t list_laddrtuple;	// list of local addresses
	 TCP_AddressVector_t list_raddrtuple;	// list of remote addresses

	 int cnt_subflows; 						// count of subflows
	 TCP_SubFlowVector_t subflow_list; 		// list of all subflows
	 TCP_JoinVector_t join_queue;				// a queue with all join possibilities
	 TCP_JoinVector_t tried_join;
	 MPTCP_State state;						// Internal State of the multipath protocol control block

	 bool initiator;
	 void initFlow();
	 int initialHandshake(uint t,
	 		TCPStateVariables* subflow_state, TCPSegment *tcpseg,
	 		TCPConnection* subflow, TCPOption* option);
	 int joinHandshake(uint t,
	 		TCPStateVariables* subflow_state, TCPSegment *tcpseg,
	 		TCPConnection* subflow, TCPOption* option);

  protected:

	 uint32 flow_token;						// generate after getting keys
	 uint64 seq;							// start seq-no generated after getting keys
	 uint64 sender_key;						// setup during handshake
	 uint64 receiver_key;					// setup during handshake

	 bool checksum;

	 InterfaceTableAccess interfaceTableAccess;
  public:

	MPTCP_Flow(int ID, int aAppGateIndex);
	~MPTCP_Flow();

	// getter /setter
	uint64 getSenderKey();
	uint64 getReceiverKey();
	MPTCP_State getState();
	uint32 getFlow_token();
	int setState(MPTCP_State s);
	void setReceiverKey(uint64 key);
	void setSenderKey(uint64 key);

	// use cases
	int sendByteStream(TCPConnection* subflow);
	int writeMPTCPHeaderOptions(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg, TCPConnection* subflow);

	// crypto stuff TODO -> all crypto should be moved to a helper class as static functions
	static uint64 generateKey();
	int generateTokenAndSQN(uint64 ks, uint64 kr);
	// see rfc 2104
	unsigned char* generateSYNACK_HMAC(uint64 ka, uint64 kr, uint32 ra, uint32 rb, unsigned char* digist);
	unsigned char* generateACK_HMAC(uint64 kb, uint64 kr, uint32 ra, uint32 rb, unsigned char* digist);
	void hmac_md5(unsigned char*  text, int text_len,unsigned char*  key, int key_len, unsigned char* digest);


	// manage subflows
	bool joinConnection();
	int addSubflow(int id, TCPConnection* );
	bool isSubflowOf(TCPConnection* subflow);

	// common identifier
	int appID;								// The application ID of this Flow
    int appGateIndex;


    bool joinToACK ;							// TODO Nicht optimal, es können mehr joins in system grad bearbeitet werden
};


class INET_API MPTCP_PCB
{
	public:
		MPTCP_PCB(int connId,int appGateIndex, TCPConnection* subflow); // public constructor

		// Static helper elements for organization
		static int count ;				// starts by default with zero
		static MPTCP_PCB* first;

		// Lookup for Multipath Control Block management
		static MPTCP_PCB* lookupMPTCP_PCB(int connid, int aAppGateIndex);
		static MPTCP_PCB* lookupMPTCP_PCB(TCPSegment *tcpseg);
		static MPTCP_PCB* lookupMPTCP_PCB(TCPSegment *tcpseg,  TCPConnection* subflow);
		static MPTCP_PCB* lookupMPTCP_PCBbyMP_JOIN_Option(TCPSegment* tcpseg, TCPConnection* subflow);
		TCPConnection*    lookupMPTCPConnection(int connId, TCPConnection* subflow,TCPSegment *tcpseg);

		// Use Case
		static int processMPTCPSegment(int connId,int aAppGateIndex, TCPConnection* subflow, TCPSegment *tcpseg);

		// Getter/ Setter
		MPTCP_Flow* getFlow();

		// common identifier
		int id;

	private:
		MPTCP_PCB();
		~MPTCP_PCB();

		// helper for process Segments
		int processSegment(int connId, TCPConnection* subflow, TCPSegment *tcpseg);
		int processMP_CAPABLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const TCPOption* option);
		int processMP_JOIN_IDLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg, const TCPOption* option);
		int processMP_JOIN_ESTABLISHED(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option);

		// cleanup
		int clearAll();

		// Sending side
		uint64 snd_una;
		uint64 snd_nxt;
		uint32 snd_wnd;

		// Receiver Side
		uint64 rcv_nxt;
		uint64 rcv_wnd;

		// Members for self-organization
		MPTCP_Flow* flow;
		MPTCP_PCB* next;
};


#endif // __INET_MPTCP_H


