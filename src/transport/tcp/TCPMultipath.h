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

#include <map>
#include <set>
#include "assert.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "TCPCommand_m.h"
#include "IPvXAddress.h"

// Lower layer info
#include "RoutingTable.h"
#include "RoutingTableAccess.h"
#include "InterfaceTable.h"
#include "InterfaceTableAccess.h"
#include "IPv4InterfaceData.h"
#include "IPv6InterfaceData.h"

class TCPConnection;
class TCPSegment;
class TCPStateVariables;

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

typedef std::vector<AddrTupple_t*> TCP_AddressVector_t;
typedef std::vector<AddrCombi_t*> TCP_JoinVector_t;
typedef std::vector<TCP_SUBFLOW_T*> TCP_SubFlowVector_t;
enum MPTCP_State {IDLE, PRE_ESTABLISHED, ESTABLISHED, SHUTDOWN};
enum MPTCP_SUBTYPES {MP_CAPABLE=0x0, MP_JOIN=0x1, MP_DSS=0x2, MP_ADD_ADDR=0x3, MP_REMOVE_ADDR=0x4, MP_PRIO=0x5, MP_FAIL=0x6};


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

  protected:
	 uint64 sender_key;						// setup during handshake
	 uint64 receiver_key;					// setup during handshake
	 uint32 flow_token;						// generate after getting keys
	 uint64 seq;							// start seq-no generated after getting keys

	 InterfaceTableAccess interfaceTableAccess;

	 int appID;								// The application ID of this Flow
  public:
	MPTCP_Flow(){};

	MPTCP_Flow(int ID);
	~MPTCP_Flow();
	uint64 getSenderKey();

	MPTCP_State getState();
	int setState(MPTCP_State s);
	int addFlow(int id, TCPConnection* );
	int sendByteStream(TCPConnection* subflow);
	int writeMPTCPHeaderOptions(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg, TCPConnection* subflow);

	static uint64 generateKey();
	int generateTokenAndSQN(uint64 s, uint64 r);
	bool joinConnection();

};


class INET_API MPTCP_PCB
{
	private:
		MPTCP_Flow* flow;
	protected:
		static int ID_COUNTER ;				// starts by default with zero
		static int CONNECTION_COUNTER;		// starts by default with zero
	public:
		MPTCP_PCB();
		~MPTCP_PCB();
		TCPConnection* lookupMPTCPConnection(int connId, TCPConnection* subflow);
		int processSegment(int connId, TCPConnection* subflow, TCPSegment *tcpseg);
		MPTCP_Flow* lookupMPTCPFlow(TCPConnection* subflow);
		MPTCP_Flow* getFlow();
		int clearAll();
};


#endif // __INET_MPTCP_H


