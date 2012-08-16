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

#include "TCPMultipathQueueMngmt.h"
#include <string.h>

TCPMultipathQueueMngmt::TCPMultipathQueueMngmt(){
	isInit = false;

}

TCPMultipathQueueMngmt::~TCPMultipathQueueMngmt() {
	// TODO Auto-generated destructor stub
}

/**
 * Init the recvQueue with the start SQN
 * @param uint64_t The start sqn
 */
bool TCPMultipathQueueMngmt::initRECVQueue(uint64_t sqn){
	rcv_queue.last_cum  = sqn;
	rcv_queue.high_sqn  = sqn;
	rcv_queue.last_send_cum = sqn;
	rcv_queue.rbuf[sqn] = 0x0;
	rcv_queue.rbuf[sqn] |= SQN_CUM_ACKED;
	rcv_queue.rbuf[sqn] |= SQN_HIGH;

	snd_queue.highest_received_cum = 0;
	isInit = true;
	return true;
}

/**
 * Update the receive queue with new send infos
 */
bool TCPMultipathQueueMngmt::updateRECVQueue(){
	ASSERT(isInit);
	// What is new cum ack
	// What is the highest ack
	// What is gap acked
	return false;
}

uint64_t TCPMultipathQueueMngmt::getCumSQN(){
	return rcv_queue.last_cum;
}

uint64_t TCPMultipathQueueMngmt::getHighestReceivedSQN(){
	return snd_queue.highest_received_cum;
}

bool TCPMultipathQueueMngmt::updateHighestReceivedSQN(uint64_t update){
	snd_queue.highest_received_cum = update;
	return true;
}

#endif
