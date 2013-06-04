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

#ifndef __TCP_MULTIPATH_H
#define __TCP_MULTIPATH_H

#include <omnetpp.h>

#include <vector>
#include <map>
#include <set>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <cstring>
#include <inttypes.h>

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

#include "TCP.h"

class TCP;
class TCPConnection;
class TCPSegment;
class TCPStateVariables;
class INET_API MPTCP_PCB;

using std::vector;

// ###############################################################################################################
//                                                  MULTIPATH TCP
//                                                 Typedef STUFF
// ###############################################################################################################

typedef struct _addr_tuple{
	IPvXAddress addr;
	int 		port;
} AddrTupple_t;
typedef vector <AddrTupple_t*> 			TCP_AddressVector_t;

typedef struct _addr_combi{
	AddrTupple_t local;
	AddrTupple_t remote;
} AddrCombi_t;
typedef vector <AddrCombi_t*> 			TCP_JoinVector_t;

enum MPTCP_State {IDLE, PRE_ESTABLISHED, ESTABLISHED, SHUTDOWN};
typedef struct _subflow{
  TCPConnection* subflow;
  bool active;
  int cnt;
} TCP_subflow_t;
typedef vector <TCP_subflow_t*>         TCP_SubFlowVector_t;
//#include "TCPMultipath.h"


// compare Section 8. IANA Considerations
enum MPTCP_SUBTYPES {MP_CAPABLE=0x0000, MP_JOIN=0x0001, MP_DSS=0x0002, MP_ADD_ADDR=0x0003, MP_REMOVE_ADDR=0x0004, MP_PRIO=0x0005, MP_FAIL=0x0006};

// DSS Flags -> Section 3.3
const uint8_t DSS_FLAG_A = 0x01;		// Data ACK present
const uint8_t DSS_FLAG_a = 0x02;		// Data ACK is 8 octets
const uint8_t DSS_FLAG_M = 0x04;		// Data Sequence Number, Subflow Sequence Number, Data-level  Length, and Checksum present
const uint8_t DSS_FLAG_m = 0x08;		// Data SQN is 8 Octets

const uint16_t DSS_FLAG_F = 0x10;	// FIN FLAG

// ###############################################################################################################
//                                                  MULTIPATH TCP
//                                                   DEBUG STUFF
// ###############################################################################################################
#ifdef PRIVATE
static char DEBUGBUF[255];
// Defines for debugging (Could be removed)
#define WHERESTR  "\n[MPTCP][file %s, line %u]: "
#define WHEREARG  __FILE__, __LINE__
#define DEBUGPRINT2(...)  fprintf(stderr, __VA_ARGS__); sprintf(DEBUGBUF,__VA_ARGS__);   tcpEV << DEBUGBUF << endl;
#define DEBUGINFO(_s) DEBUGPRINT2(WHERESTR,_s)
#define DEBUGPRINT(_fmt, ...)  DEBUGPRINT2(WHERESTR _fmt, WHEREARG, __VA_ARGS__);
#else
#define DEBUGINFO(_s);
#define DEBUGPRINT(_fmt, ...) ;
#endif

// ###############################################################################################################
//                                                  MULTIPATH TCP
//                                                   HELPER STUFF
// ###############################################################################################################


// Some helper defines
#define MPTCP_STATEFULL  1
#define MPTCP_STATELESS 0
#define MPTCP_LOCAL  1
#define MPTCP_REMOTE 0

// Some constants for help
const unsigned int MP_SIGNAL_FIRST_VALUE_TYPE = 16;
const unsigned int MP_SUBTYPE_POS = MP_SIGNAL_FIRST_VALUE_TYPE - 4;
const unsigned int MP_VERSION_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - 4;
const unsigned int MP_C_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - MP_VERSION_POS - 1;
const unsigned int MP_RESERVED_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - MP_VERSION_POS - MP_C_POS - 4;
const unsigned int MP_S_POS = MP_SIGNAL_FIRST_VALUE_TYPE - MP_SUBTYPE_POS - MP_VERSION_POS - MP_C_POS - MP_RESERVED_POS - 1;


const unsigned int MP_DSS_OPTIONLENGTH_4BYTE = 20;

// Helper to set state for a subflow
#define MPTCP_FSM(state) setState(state); // fprintf(stderr,"\n[FSM] CHANGE STATE %u line %u\n",state,__LINE__);








#endif // __TCP_MULTIPATH_H
#endif // Private

