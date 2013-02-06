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

#ifdef PRIVATE

#ifndef TCPMULTIPATHQUEUEMNGMT_H_
#define TCPMULTIPATHQUEUEMNGMT_H_

#include <omnetpp.h>
#include "INETDefs.h"
#include <assert.h>


#define MAX_MPTCP_SQN_BAND 0xfffffff
#define SQN_DEFAULT   0x0000
#define SQN_CUM_ACKED 0x0001
#define SQN_NOT_ACKED 0x0002
#define SQN_GAP_ACKED 0x0004
#define SQN_HIGH	  0x0008


typedef struct _MPTCP_RECEIVE_QUEUE{
	uint64_t last_cum;
	uint64_t last_send_cum;
	uint64_t high_sqn;
	char     rbuf[MAX_MPTCP_SQN_BAND];	// FIXME -> room for space optimization
} MPTCP_RECEIVE_QUEUE_t;

typedef struct _MPTCP_SEND_QUEUE{
	uint64_t highest_received_cum;
} MPTCP_SEND_QUEUE_t;


class INET_API  TCPMultipathQueueMngmt : public cPolymorphic {

private:
	MPTCP_RECEIVE_QUEUE_t rcv_queue;
	MPTCP_SEND_QUEUE_t	  snd_queue;
	bool isInit;

public:
	TCPMultipathQueueMngmt();
	virtual ~TCPMultipathQueueMngmt();
	// Receiver Queue
	bool initRECVQueue(uint64_t sqn);
	bool updateRECVQueue();
	uint64_t getCumSQN();

	// Send Queue
	uint64_t getHighestReceivedSQN();
	bool updateHighestReceivedSQN(uint64_t update);
};

#endif /* TCPMULTIPATHQUEUEMNGMT_H_ */

#endif
