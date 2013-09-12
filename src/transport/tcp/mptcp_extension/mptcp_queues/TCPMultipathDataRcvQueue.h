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

#ifndef __INET_TCPMultipathDataRcvQueue_H
#define __INET_TCPMultipathDataRcvQueue_H

#include <list>
#include <string>
#include <map>
#include "TCPSegment.h"
#include "TCPMultipathReceiveQueue.h"

/**
 * Receive queue that manages "virtual bytes", that is, byte counts only.
 *
 * @see TCPVirtualDataSendQueue
 */

class INET_API TCPMultipathDataRcvQueue : public TCPMultipathReceiveQueue
{
  protected:

    typedef struct _data_pair{
        uint64 begin;
        uint32 len;
    } Data_Pair;
    typedef std::map<uint64,Data_Pair*> MPTCP_DataMap;

    MPTCP_DataMap data;
    uint64 virtual_start;

    // returns number of bytes extracted
    ulong extractTo(uint64 toSeq);

  public:
    /**
     * Ctor.
     */
    TCPMultipathDataRcvQueue();

    /**
     * Virtual dtor.
     */
    virtual ~TCPMultipathDataRcvQueue();

    /**
     * Set initial receive sequence number.
     */
    virtual void init(uint64 startSeq);

    /**
     * Returns a string with region stored.
     */
    virtual void info();

    void shiftPayloadTo(TCPSegment *n, TCPSegment *d);
    virtual void clear();

    /**
     * Called when a TCP segment arrives. Returns sequence number for ACK.
     */
    virtual uint64 insertBytesFromSegment(uint64 dss_start_seq, uint32 data_len);

    /**
     *
     */
    virtual cPacket *extractBytesUpTo(uint64 seq);

    /**
     * Returns the number of bytes (out-of-order-segments) currently buffered in queue.
     */
    virtual uint64 getAmountOfBufferedBytes();


    virtual uint64 getOccupiedMemory();

    virtual void printInfo();
    /**
     * Returns the number of bytes currently free (=available) in queue. freeRcvBuffer = maxRcvBuffer - usedRcvBuffer
     */
    virtual uint64 getAmountOfFreeBytes(uint64 maxRcvBuffer);

    /**
     *
     */
    virtual uint64 getQueueLength();

    /**
     *
     */
    virtual void getQueueStatus();


};

#endif
