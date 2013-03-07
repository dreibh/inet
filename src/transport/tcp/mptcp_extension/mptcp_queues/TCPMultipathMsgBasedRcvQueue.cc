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


#include "TCPMultipathMsgBasedRcvQueue.h"

Register_Class(TCPMultipathMsgBasedRcvQueue);


TCPMultipathMsgBasedRcvQueue::TCPMultipathMsgBasedRcvQueue() : TCPMultipathVirtualDataRcvQueue()
{
}

TCPMultipathMsgBasedRcvQueue::~TCPMultipathMsgBasedRcvQueue()
{
}

void TCPMultipathMsgBasedRcvQueue::init(uint64 startSeq)
{
    TCPMultipathVirtualDataRcvQueue::init(startSeq);
}

std::string TCPMultipathMsgBasedRcvQueue::info() const
{
    std::stringstream os;

    os << "rcv_nxt=" << rcv_nxt;

    for (RegionList::const_iterator i = regionList.begin(); i != regionList.end(); ++i)
    {
        os << " [" << i->begin << ".." << i->end << ")";
    }

    os << " " << payloadList.size() << " msgs";

    return os.str();
}

uint64 TCPMultipathMsgBasedRcvQueue::insertBytesFromSegment(TCPSegment *tcpseg)
{
    TCPMultipathVirtualDataRcvQueue::insertBytesFromSegment(tcpseg);


    cPacket *msg;
    uint64 endSeqNo;
/*    while ((msg=tcpseg->removeFirstPayloadMessage(endSeqNo))!=NULL)
    {
        // insert, avoiding duplicates
        PayloadList::iterator i = payloadList.find(endSeqNo);
        if (i!=payloadList.end()) {delete msg; continue;}
        payloadList[endSeqNo] = msg;
    }
*/
    return rcv_nxt;
}

cPacket *TCPMultipathMsgBasedRcvQueue::extractBytesUpTo(uint64 seq)
{
    extractTo(seq);

    // pass up payload messages, in sequence number order
    if (payloadList.empty() || seqGreater(payloadList.begin()->first, seq))
        return NULL;

    cPacket *msg = payloadList.begin()->second;
    payloadList.erase(payloadList.begin());
    return msg;
}

