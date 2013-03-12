//
// Copyright (C) 2009-2010 Thomas Reschka
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


#include "TCPSACKRexmitQueue.h"


TCPSACKRexmitQueue::TCPSACKRexmitQueue()
{
    conn = NULL;
    begin = end = 0;
}

TCPSACKRexmitQueue::~TCPSACKRexmitQueue()
{
    while (!rexmitQueue.empty())
        rexmitQueue.pop_front();
}

void TCPSACKRexmitQueue::init(uint32 seqNum)
{
    begin = seqNum;
    end = seqNum;
}

std::string TCPSACKRexmitQueue::str() const
{
    std::stringstream out;
    out << "[" << begin << ".." << end << ")";
    return out.str();
}

void TCPSACKRexmitQueue::info()
{
//    str();
    RexmitQueue::iterator i = rexmitQueue.begin();
    uint j = 1;
#ifdef PRIVATE
 //   fprintf(stderr,"\t\t[TCP]][SACK][CONNECTION] local:  %s:%d remote %s:%d RexmitQueue Size in INFO:%i\n", conn->localAddr.str().c_str(), conn->localPort, conn->remoteAddr.str().c_str(), conn->remotePort,rexmitQueue.size());
#endif
    while (i!=rexmitQueue.end())
    {
        tcpEV << j << ". region: [" << i->beginSeqNum << ".." << i->endSeqNum << ") \t sacked=" << i->sacked << "\t rexmitted=" << i->rexmitted << "\n";
#ifdef PRIVATE
 //       fprintf(stderr,"\t\t[TCP]][SACK][IN] Rexmit Queue-Entry %i \tregion[%i..%i] %i sacked=%i rexmitted=%i\n",j, i->beginSeqNum,i->endSeqNum,(i->endSeqNum-i->beginSeqNum),i->sacked, i->rexmitted);
#endif
        i++;
        j++;
    }
}

uint32 TCPSACKRexmitQueue::getBufferStartSeq()
{
    return begin;
}

uint32 TCPSACKRexmitQueue::getBufferEndSeq()
{
    return end;
}

void TCPSACKRexmitQueue::discardUpTo(uint32 seqNum)
{
    if (rexmitQueue.empty())
        return;
    int j = 1;
    if(false == (seqLE(begin,seqNum) && seqLE(seqNum,end)))
    ASSERT(seqLE(begin,seqNum) && seqLE(seqNum,end));

    begin = seqNum;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end()) // discard/delete regions from rexmit queue, which have been acked
    {
        if (seqLess(i->beginSeqNum,begin)){
//            fprintf(stderr,"\t\t[TCP]][SACK][DEL] Rexmit Queue-Entry %i \tregion[%i..%i] step %i sacked=%i rexmitted=%i\n",j, i->beginSeqNum,i->endSeqNum,(i->endSeqNum-i->beginSeqNum),i->sacked, i->rexmitted);
            i = rexmitQueue.erase(i);
        }
        else
            i++;
        j++;
    }
#ifdef PRIVATE
//    fprintf(stderr,"\t\t[TCP]][SACK][QUEUE] local: %s:%d remote %s:%d rexmitQueue size %i\n", conn->localAddr.str().c_str(), conn->localPort, conn->remoteAddr.str().c_str(), conn->remotePort, rexmitQueue.size());
#endif
    // update begin and end of rexmit queue
    if (rexmitQueue.empty()){
        rexmitQueue.clear();
        begin = end = 0;
    }
    else
    {
        i = rexmitQueue.begin();
        begin = i->beginSeqNum;
        i = rexmitQueue.end();
        end = i->endSeqNum;
    }
}

void TCPSACKRexmitQueue::enqueueSentData(uint32 fromSeqNum, uint32 toSeqNum)
{
    bool found = false;

    tcpEV << "rexmitQ: " << str() << " enqueueSentData [" << fromSeqNum << ".." << toSeqNum << ")\n";

    Region region;
    region.beginSeqNum = fromSeqNum;
    region.endSeqNum = toSeqNum;
    region.sacked = false;
    region.rexmitted = false;

    if (getQueueLength()==0)
    {
        begin = fromSeqNum;
        end = toSeqNum;
        rexmitQueue.push_back(region);
//        tcpEV << "rexmitQ: rexmitQLength=" << getQueueLength() << "\n";
        return;
    }
#ifndef PRIVATE // old
    if (seqLE(begin,fromSeqNum) && seqLE(toSeqNum,end))
    {
        // Search for region in queue!
        RexmitQueue::iterator i = rexmitQueue.begin();
        while (i!=rexmitQueue.end())
        {
            if (i->beginSeqNum == fromSeqNum && i->endSeqNum == toSeqNum)
            {
                i->rexmitted = true; // set rexmitted bit
                found = true;
            }
            i++;
        }
    }
#else
    if (seqLE(begin,fromSeqNum) && seqLE(toSeqNum,end))
     {
         // Search for region in queue!
         RexmitQueue::iterator i = rexmitQueue.begin();
         while (i!=rexmitQueue.end())
         {
             if (i->beginSeqNum == fromSeqNum && i->endSeqNum == toSeqNum)
             {
                 i->rexmitted = true; // set rexmitted bit
                 found = true;
             }
             i++;
         }
     }
#endif
    if (!found)
    {
        if(!seqLE(end,toSeqNum))
            tcpEV << "rexmitQ: rexmitQLength=" << getQueueLength() << "\n";

        end = toSeqNum;
        rexmitQueue.push_back(region);
    }
//    tcpEV << "rexmitQ: rexmitQLength=" << getQueueLength() << "\n";
}

uint32 TCPSACKRexmitQueue::getEndOfRegion(uint32 fromSeqNum){
    RexmitQueue::iterator i = rexmitQueue.begin();
       while (i!=rexmitQueue.end())
       {
           if (i->beginSeqNum == fromSeqNum)
               return i->endSeqNum;
           i++;
       }
       return 0;
}

void TCPSACKRexmitQueue::setSackedBit(uint32 fromSeqNum, uint32 toSeqNum)
{
    bool found = false;

    if (seqLE(toSeqNum,end))
    {
        RexmitQueue::iterator i = rexmitQueue.begin();
        while (i!=rexmitQueue.end())
        {
            if (i->beginSeqNum == fromSeqNum && seqGE(toSeqNum, i->endSeqNum)) // Search for LE of region in queue!
            {
                i->sacked = true; // set sacked bit
                found = true;
                i++;
                while (seqGE(toSeqNum, i->endSeqNum) && i!=rexmitQueue.end()) // Search for RE of region in queue!
                {
                    i->sacked = true; // set sacked bit
                    i++;
                }
            }
            else
                i++;
        }
    }

    if (!found)
        tcpEV << "FAILED to set sacked bit for region: [" << fromSeqNum << ".." << toSeqNum << "). Not found in retransmission queue.\n";
}

bool TCPSACKRexmitQueue::getSackedBit(uint32 seqNum)
{
    bool found = false;

    if (seqLE(begin,seqNum))
    {
        RexmitQueue::iterator i = rexmitQueue.begin();
        while (i!=rexmitQueue.end())
        {
            if (i->beginSeqNum == seqNum) // Search for region in queue!
            {
                found = i->sacked;
                break;
            }
            i++;
        }
    }
    return found;
}

uint32 TCPSACKRexmitQueue::getQueueLength()
{
    return rexmitQueue.size();
}

uint32 TCPSACKRexmitQueue::getHighestSackedSeqNum()
{
    uint32 tmp_highest_sacked = 0;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        if (i->sacked)
            tmp_highest_sacked = i->endSeqNum;
        i++;
    }
    return tmp_highest_sacked;
}

uint32 TCPSACKRexmitQueue::getHighestRexmittedSeqNum()
{
    uint32 tmp_highest_rexmitted = 0;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        if (i->rexmitted)
            tmp_highest_rexmitted = i->endSeqNum;
        i++;
    }
    return tmp_highest_rexmitted;
}

uint32 TCPSACKRexmitQueue::checkRexmitQueueForSackedOrRexmittedSegments(uint32 fromSeqNum)
{
    uint32 counter = 0;

    if (fromSeqNum==0 || rexmitQueue.empty() || !(seqLE(begin,fromSeqNum) && seqLE(fromSeqNum,end)))
        return counter;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        // search for fromSeqNum (snd_nxt)
        if (i->beginSeqNum == fromSeqNum)
            break;
        else
            i++;
    }

    // search for adjacent sacked/rexmitted regions
    while (i!=rexmitQueue.end())
    {
        if (i->sacked || i->rexmitted)
        {
            counter = counter + (i->endSeqNum - i->beginSeqNum);

            // adjacent regions?
            uint32 tmp = i->endSeqNum;
            i++;
            if (i->beginSeqNum != tmp)
                break;
        }
        else
            break;
    }
    return counter;
}

void TCPSACKRexmitQueue::resetSackedBit()
{
    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        i->sacked = false; // reset sacked bit
        i++;
    }
}

void TCPSACKRexmitQueue::resetRexmittedBit()
{
    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        i->rexmitted = false; // reset rexmitted bit
        i++;
    }
}

uint32 TCPSACKRexmitQueue::getTotalAmountOfSackedBytes()
{
    uint32 bytes = 0;
    uint32 counter = 0;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        if (i->sacked)
        {
            counter++;
            bytes = bytes + (i->endSeqNum - i->beginSeqNum);
        }
        i++;
    }
    return bytes;
}

uint32 TCPSACKRexmitQueue::getAmountOfSackedBytes(uint32 seqNum)
{
    uint32 bytes = 0;
    uint32 counter = 0;
    uint32 intern = 0;
    if (rexmitQueue.empty() || seqGE(seqNum,end))
        return counter;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end() && seqLess(i->beginSeqNum, seqNum)) // search for seqNum
    {
        i++;
        if (i->beginSeqNum == seqNum)
            break;
        intern++;
    }
    // don 't go over Queue size
     if(!(intern < rexmitQueue.size())){
         return counter;
     }

    ASSERT(seqLE(seqNum,i->beginSeqNum) || seqGE(seqNum,(i->endSeqNum-1)));

    while (i!=rexmitQueue.end())
    {
        if (i->sacked)
        {
            counter++;
            bytes = bytes + (i->endSeqNum - i->beginSeqNum);
        }
        i++;
    }
    return bytes;
}


uint32 TCPSACKRexmitQueue::getNumOfDiscontiguousSacks(uint32 seqNum)
{
    uint32 counter = 0;
    uint32 max = 0;
    uint32 intern = 0;
    if (rexmitQueue.empty() || seqGE(seqNum,end))
        return counter;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end() && seqLess(i->beginSeqNum, seqNum)) // search for seqNum
    {
        i++;
        if (i->beginSeqNum == seqNum)
            break;
        max++;
        intern++;
    }
    // don 't go over Queue size
    if(!(intern < rexmitQueue.size())){
        return counter;
    }

    ASSERT(seqLE(seqNum,i->beginSeqNum) || seqGE(seqNum,(i->endSeqNum-1)));


    // search for discontiguous sacked regions
    while (i!=rexmitQueue.end())
    {
        if (i->sacked)
        {
            counter++;
            uint32 tmp = i->endSeqNum;
            i++;
            while (i->sacked && i->beginSeqNum == tmp && i!=rexmitQueue.end()) // adjacent sacked regions?
            {
                tmp = i->endSeqNum;
                i++;
            }
        }
        else
            i++;
    }
    return counter;
}
