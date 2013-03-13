//
// Copyright (C) 2004 Andras Varga
// Copyright (C) 2013 Martin Becke
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


#include "TCPMultipathVirtualDataRcvQueue.h"


Register_Class(TCPMultipathVirtualDataRcvQueue);


TCPMultipathVirtualDataRcvQueue::TCPMultipathVirtualDataRcvQueue() : TCPMultipathReceiveQueue()
{
}

TCPMultipathVirtualDataRcvQueue::~TCPMultipathVirtualDataRcvQueue()
{
}

void TCPMultipathVirtualDataRcvQueue::init(uint64 startSeq)
{
    rcv_nxt = startSeq;
}

std::string TCPMultipathVirtualDataRcvQueue::info() const
{
    std::string res;
    char buf[32];
    sprintf(buf, "rcv_nxt=%ld ", rcv_nxt);
    res = buf;

    for (RegionList::const_iterator i=regionList.begin(); i!=regionList.end(); ++i)
    {
        sprintf(buf, "[%ld..%ld) ", i->begin, i->end);
        res+=buf;
    }
    return res;
}

uint64 TCPMultipathVirtualDataRcvQueue::insertBytesFromSegment(TCPSegment *tcpseg,  uint64 dss_start_seq, uint32 data_len)
{
    merge(dss_start_seq, dss_start_seq+data_len);
    if (rcv_nxt >= regionList.begin()->begin)
        rcv_nxt = regionList.begin()->end;
    DEBUGPRINT("[MPTCP][RCV QUEUE] size after insert %lu",regionList.size());
    return rcv_nxt;
}

void TCPMultipathVirtualDataRcvQueue::merge(uint64 segmentBegin, uint64 segmentEnd)
{
    // Here we have to update our existing regions with the octet range
    // tcpseg represents. We either have to insert tcpseg as a separate region
    // somewhere, or (if it overlaps with an existing region) extend
    // existing regions; we also may have to merge existing regions if
    // they become overlapping (or touching) after adding tcpseg.

    Region seg;
    seg.begin = segmentBegin;
    seg.end = segmentEnd;

    RegionList::iterator i = regionList.begin();
    if (i==regionList.end())
    {
        // insert as first and only region
        regionList.insert(regionList.begin(), seg);
        return;
    }

    // skip regions which fall entirely before seg (no overlap or touching)
    while (i!=regionList.end() && i->end < seg.begin)
    {
        ++i;
    }

    if (i==regionList.end())
    {
        // seg is entirely past last region: insert as separate region at end
        regionList.insert(regionList.end(), seg);
        return;
    }

    if ((seg.end < i->begin))
    {
        // segment entirely before region "i": insert as separate region before "i"
        regionList.insert(i, seg);
        return;
    }

    if ((seg.begin < i->begin))
    {
        // segment starts before region "i": extend region
        i->begin = seg.begin;
    }

    if ((i->end < seg.end))
    {
        // segment ends past end of region "i": extend region
        i->end = seg.end;

        // maybe we have to merge region "i" with next one(s)
        RegionList::iterator j = i;
        ++j;
        while (j!=regionList.end() && (i->end >= j->begin)) // while there's overlap
        {
            // if "j" is longer: extend "i"
            if ((i->end < j->end))
                i->end = j->end;

            // erase "j" (it was merged into "i")
            RegionList::iterator oldj = j++;
            regionList.erase(oldj);
        }
    }
}

cPacket *TCPMultipathVirtualDataRcvQueue::extractBytesUpTo(uint64 seq)
{
    ulong numBytes = extractTo(seq);
    if (numBytes==0)
        return NULL;

    DEBUGPRINT("[MPTCP][RCV QUEUE] after extract %lu",regionList.size());

    cPacket *msg = new cPacket("data");
    msg->setByteLength(numBytes);
    return msg;
}

ulong TCPMultipathVirtualDataRcvQueue::extractTo(uint64 seq)
{
    ASSERT((seq <= rcv_nxt));

    RegionList::iterator i = regionList.begin();
    if (i==regionList.end())
        return 0;

    ASSERT((i->begin < i->end)); // empty regions cannot exist

    // seq below 1st region
    if ((seq <= i->begin))
        return 0;
    // Just for debug
    static uint64 old_end = i->begin;

    if ((seq < i->end))
    {
        // part of 1st region
        ulong octets = seq - i->begin;
        i->begin = seq;
        ASSERT(i->begin == old_end && "UPS....not in order");
        old_end = i->end;
        regionList.erase(i);
        DEBUGPRINT("[MPTCP][RCV QUEUE][OUT IN SEQUENCE] %x%x ...%x%x", (uint32)(i->begin>>32),(uint32)i->begin,(uint32) (i->end>>32),(uint32) i->end );
        return octets;
    }
    else
    {
        // full 1st region
        ulong octets = i->end - i->begin;
        ASSERT(i->begin == old_end && "UPS....not in order");
        old_end = i->end;
        DEBUGPRINT("[MPTCP][RCV QUEUE][OUT IN SEQUENCE] %x%x ...%x%x", (uint32)(i->begin>>32),(uint32)i->begin,(uint32) (i->end>>32),(uint32) i->end );
        regionList.erase(i);
        return octets;
    }
}

uint64 TCPMultipathVirtualDataRcvQueue::getAmountOfBufferedBytes()
{
    uint64 bytes=0;

    RegionList::iterator i = regionList.begin();
    if (i==regionList.end()) // is queue empty?
        return 0;

    while (i!=regionList.end())
    {
        bytes = bytes + (i->end - i->begin);
        i++;
    }
    return bytes;
}

uint64 TCPMultipathVirtualDataRcvQueue::getAmountOfFreeBytes(uint64 maxRcvBuffer)
{
    uint64 usedRcvBuffer = getAmountOfBufferedBytes();
    uint64 freeRcvBuffer = maxRcvBuffer - usedRcvBuffer;
    return freeRcvBuffer;
}

size_t TCPMultipathVirtualDataRcvQueue::getQueueLength()
{
    return regionList.size();
}

void TCPMultipathVirtualDataRcvQueue::getQueueStatus()
{
    tcpEV << "receiveQLength=" << regionList.size() << " " << info() << "\n";
}


uint64 TCPMultipathVirtualDataRcvQueue::getLE(uint64 fromSeqNum)
{
    RegionList::iterator i = regionList.begin();
    while (i!=regionList.end())
    {
        if ((i->begin < fromSeqNum) && (fromSeqNum < i->end))
        {
//            tcpEV << "Enqueued region: [" << i->begin << ".." << i->end << ")\n";
            if ((i->begin < fromSeqNum))
                return i->begin;
            return fromSeqNum;
        }
        i++;
    }
    return fromSeqNum;
}

uint64 TCPMultipathVirtualDataRcvQueue::getRE(uint64 toSeqNum)
{
    RegionList::iterator i = regionList.begin();
    while (i!=regionList.end())
    {
        if ((i->begin < toSeqNum) && (toSeqNum < i->end))
        {

            if ((toSeqNum <  i->end))
                return i->end;
            return toSeqNum;
        }
        i++;
    }
    return toSeqNum;
}
