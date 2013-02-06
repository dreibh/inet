//
// Copyright (C) 2005 Andras Varga
// Copyright (C) 2009-2012 Thomas Dreibholz
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

#include <omnetpp.h>

// ====== Activate debugging mode here! =====================================
// #define REDQUEUE_DEBUG             // Print drops, queue status, etc.
// #define REDQUEUE_DEBUG_FORWARDS    // Print all forwards
// ==========================================================================

#ifdef REDQUEUE_DEBUG
#include "IPDatagram_m.h"
#include "SCTPMessage.h"
#include "SCTPAssociation.h"
#define EV std::cout
#endif
#include "REDQueue.h"


Define_Module(REDQueue);

void REDQueue::initialize()
{
    PassiveQueueBase::initialize();
    queue.setName("l2queue");

    avgQlenVec.setName("avg queue length");
    qlenVec.setName("queue length");
    dropVec.setName("drops");

    // configuration
    wq = par("wq");
    minth = par("minth");
    maxth = par("maxth");
    maxp = par("maxp");
    pkrate = par("pkrate");

    outGate = gate("out");

    // state
    avg = 0;
    q_time = 0;
    count = -1;
    numEarlyDrops = 0;

    WATCH(avg);
    WATCH(q_time);
    WATCH(count);
    WATCH(numEarlyDrops);

#ifdef REDQUEUE_DEBUG
    // print configuration
    const cModule* ppp = outGate->getPathEndGate()->getOwnerModule();
    if(ppp) {
        const cGate* networkOutputGate = ppp->gate("phys$o");
        if(networkOutputGate) {
            const cModule* remoteSide = networkOutputGate->getPathEndGate()->getOwnerModule();
            if(remoteSide) {
                EV << "REDQueue from " << ppp->getFullPath() << " to "
                          << remoteSide->getFullPath()
                          << ":\twq=" << wq
                          << "\tminth=" << minth << "\tmaxth=" << maxth
                          << "\tmaxp=" << maxp << "\tpkrate=" << pkrate << endl;
            }
        }
    }
#endif
}

bool REDQueue::enqueue(cMessage* msg)
{
    //"
    // for each packet arrival
    //    calculate the new average queue size avg:
    //        if the queue is nonempty
    //            avg <- (1-wq)*avg + wq*q
    //        else
    //            m <- f(time-q_time)
    //            avg <- (1-wq)^m * avg
    //"
    if (!queue.empty())
    {
        avg = (1-wq)*avg + wq*queue.length();
    }
    else
    {
        // Note: f() is supposed to estimate the number of packets
        // that could have arrived during the idle interval (see Section 11
        // of the paper). We use pkrate for this purpose.
        double m = SIMTIME_DBL(simTime()-q_time) * pkrate;
        avg = pow(1-wq, m) * avg;
    }

    // statistics
    avgQlenVec.record(avg);

    //"
    //    if minth <= avg < maxth
    //        increment count
    //        calculate probability pa:
    //            pb <- maxp*(avg-minth) / (maxth-minth)
    //            pa <- pb / (1-count*pb)
    //        with probability pa:
    //            mark the arriving packet
    //            count <- 0
    //    else if maxth <= avg
    //        mark the arriving packet
    //        count <- 0
    //    else count <- -1
    //"

    bool mark = false;
    if ((minth <= avg) && (avg < maxth))   // avg in [minth,maxth)
    {
        count++;
        const double pb = maxp*(avg-minth) / (maxth-minth);
        double pa;
        if(count*pb >= 1) {
           // T.D. 29.07.2011: This condition must be checked. Otherwise, pa
           //                  may become negative => queue works like FIFO.
           pa = 1.0;
        }
        else {
           pa = pb / (1-count*pb);
        }
        const double r = dblrand();

#if 0
        const IPDatagram*  ip      = dynamic_cast<const IPDatagram*>(msg);
        SCTPMessage*       sctpMsg = dynamic_cast<SCTPMessage*>(ip->getEncapsulatedPacket());
        if(sctpMsg) {
           std::cout << simTime() << "\t" << getFullPath() << ":\t" << " SCTP message "
                     << ip->getSrcAddress()  << ":" << sctpMsg->getSrcPort()  << " - "
                     << ip->getDestAddress() << ":" << sctpMsg->getDestPort() << " -->"
                     << "\tpa="    << pa
                     << "\tpb="    << pb
                     << "\tcount=" << count
                     << "\tr="     << r
                     << "\tmark="  << (r < pa) << endl;
        }
#endif

        if (r < pa)
        {
            EV << "Random early packet drop (avg queue len=" << avg << ", pa=" << pa << ")\n";
            mark = true;
            count = 0;
            numEarlyDrops++;
        }
    }
    else if ( (avg >= maxth) /* || (queue.length() >= maxth) */ )
       // maxth is also the "hard" limit
    {
       // T.D. 10.12.09: The hard limit must be checked here.
       // When mark is set to "true", the count must be reset to 0!
        EV << "Avg queue len " << avg << ", queue len "
           << queue.length() << " => dropping packet.\n";
        mark = true;
        count = 0;
    }
    else
    {
        count = -1;
    }

    // carry out decision
    if (mark)
    {
#ifdef REDQUEUE_DEBUG
        dumpInfo("DROPPING", msg);
        EV << " mark=" << (mark ? "yes" : "no") << endl;
#endif
        delete msg;
        dropVec.record(1);
        return true;
    }
    else
    {
#ifdef REDQUEUE_DEBUG_FORWARDS
        dumpInfo("Queuing", msg);
        EV << endl;
#endif
        queue.insert(msg);
        qlenVec.record(queue.length());
        return false;
    }
}

cMessage *REDQueue::dequeue()
{
    if (queue.empty())
        return NULL;

    //"
    // when queue becomes empty
    //    q_time <- time
    //"
    cMessage *pk = (cMessage *)queue.pop();
    if (queue.length()==0)
        q_time = simTime();

    // statistics
    qlenVec.record(queue.length());

    return pk;
}

void REDQueue::sendOut(cMessage* msg)
{
#ifdef REDQUEUE_DEBUG_FORWARDS
    dumpInfo("Sending", msg);
    EV << endl;
#endif
    send(msg, outGate);
}

void REDQueue::finish()
{
    PassiveQueueBase::finish();
    recordScalar("packets dropped early by RED", numEarlyDrops);
}

#ifdef REDQUEUE_DEBUG
// T.D. 10.12.09: Print information on forwarded/dropped packets.
//                For SCTP, also the ports and DATA chunk TSNs are printed.
void REDQueue::dumpInfo(const char* info, cMessage* msg)
{
   const IPDatagram*  ip      = dynamic_cast<const IPDatagram*>(msg);
   SCTPMessage*       sctpMsg = dynamic_cast<SCTPMessage*>(ip->getEncapsulatedPacket());
   if(sctpMsg) {
      EV << simTime() << "\t" << getFullPath() << ":\t" << info << " SCTP message "
         << ip->getSrcAddress()  << ":" << sctpMsg->getSrcPort()  << " - "
         << ip->getDestAddress() << ":" << sctpMsg->getDestPort() << " -->";

      for(uint32 i = 0;i < sctpMsg->getChunksArraySize();i++) {
         const SCTPChunk* chunk = (const SCTPChunk*)sctpMsg->getChunks(i);
         if(chunk->getChunkType() == DATA) {
            const SCTPDataChunk* dataChunk = dynamic_cast<const SCTPDataChunk*>(chunk);
            EV << "\t" << "DATA " << dataChunk->getTsn();
         }
         else if(chunk->getChunkType() == HEARTBEAT) {
            EV << "\t" << "HEARTBEAT";
         }
         else if(chunk->getChunkType() == HEARTBEAT_ACK) {
            EV << "\t" << "HEARTBEAT_ACK";
         }
      }
   }
   else {
      EV << simTime() << ": " << info << " message "
         << ip->getSrcAddress()  << " - "
         << ip->getDestAddress() << "   ";
   }
   EV << "\tqueueLength=" << queue.length()
      << "\tavg=" << avg
      << "\tminTh=" << minth
      << "\tmaxTh=" << maxth
      << "\tcount=" << count;
}
#endif
