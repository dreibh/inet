//
// Copyright (C) 2004 Andras Varga
// Copyright (C) 2014 Martin Becke
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

#ifndef __INET_TCPMultipathReceiveQueue_H
#define __INET_TCPMultipathReceiveQueue_H

#include <omnetpp.h>
#include <vector>
#include "TCPMultipathFlow.h"


class TCPSegment;
class TCPCommand;
class MPTCP_Flow;

/**
 * Abstract base class for TCP receive queues. This class represents
 * data received by TCP but not yet passed up to the application.
 * The class also accomodates for selective retransmission, i.e.
 * also acts as a segment buffer.
 *
 * This class goes hand-in-hand with TCPSendQueue.
 *
 * This class is polymorphic because depending on where and how you
 * use the TCP model you might have different ideas about "sending data"
 * on a simulated connection: you might want to transmit real bytes,
 * "dummy" (byte count only), cMessage objects, etc; see discussion
 * at TCPSendQueue. Different subclasses can be written to accomodate
 * different needs.
 *
 * @see TCPSendQueue
 */
class INET_API TCPMultipathReceiveQueue : public cPolymorphic
{
  protected:
    MPTCP_Flow *flow; // the connection that owns this queue

  public:
    /**
     * Ctor.
     */
    TCPMultipathReceiveQueue()  {flow=NULL;}

    /**
     * Virtual dtor.
     */
    virtual ~TCPMultipathReceiveQueue() {}

    /**
     * Set the connection that owns this queue.
     */
    virtual void setFlow(MPTCP_Flow *_flow)  {flow = _flow;}

    /**
     * Set initial receive sequence number.
     */
    virtual void init(uint64 startSeq) = 0;

    virtual void printInfo() = 0;

    virtual void clear() = 0;
    /**
     * Called when a TCP segment arrives, it should extract the payload
     * from the segment and store it in the receive queue. The segment
     * object should *not* be deleted.
     *
     * The method should return the sequence number to be ACKed.
     */
    virtual uint64 insertBytesFromSegment(TCPSegment *tcpseg,  uint64 dss_start_seq, uint32 data_len) = 0;

    /**
     * Should create a packet to be passed up to the app, up to (but NOT
     * including) the given sequence no (usually rcv_nxt).
     * It should return NULL if there's no more data to be passed up --
     * this method is called several times until it returns NULL.
     */
    virtual cPacket *extractBytesUpTo(uint64 seq) = 0;

    /**
     * Returns the number of bytes (out-of-order-segments) currently buffered in queue.
     */
    virtual uint64 getAmountOfBufferedBytes() = 0;

    /**
     * Returns the number of bytes currently free (=available) in queue. freeRcvBuffer = maxRcvBuffer - usedRcvBuffer
     */
    virtual uint64 getAmountOfFreeBytes(uint64 maxRcvBuffer) = 0;
    virtual uint64  getOccupiedMemory() = 0;
    /**
     * Returns the number of blocks currently buffered in queue.
     */
    virtual uint64 getQueueLength() = 0;

    /**
     * Shows current queue status.
     */
    virtual void getQueueStatus() = 0;

    /**
     * Returns left edge of enqueued region.
     */
    virtual uint64 getLE(uint64 fromSeqNum) = 0;

    /**
     * Returns right edge of enqueued region.
     */
    virtual uint64 getRE(uint64 toSeqNum) = 0;
};

#endif
