//
// Copyright (C) 2005 Andras Varga
// Copyright (C) 2010-2012 Thomas Dreibholz
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

// ====== Activate debugging mode here! ===================
// #define DTQUEUE_DEBUG                 // Print drops, queue status, etc.
// #define DTQUEUE_DEBUG_FORWARDS        // Print all forwards
// ========================================================

#ifdef DTQUEUE_DEBUG
#include "IPDatagram_m.h"
#include "SCTPMessage.h"
#include "SCTPAssociation.h"
#define EV std::cout
#endif
#include "DropTailQueue.h"



Define_Module(DropTailQueue);

void DropTailQueue::initialize()
{
    PassiveQueueBase::initialize();
    queue.setName("l2queue");

    qlenVec.setName("queue length");
    dropVec.setName("drops");

    outGate = gate("out");

    // configuration
    frameCapacity = par("frameCapacity");
}

bool DropTailQueue::enqueue(cMessage *msg)
{
    if (frameCapacity && queue.length() >= frameCapacity)
    {
        EV << "Queue full, dropping packet.\n";
#ifdef DTQUEUE_DEBUG
        dumpInfo("DROPPING", msg);
#endif
        delete msg;
        dropVec.record(1);
        return true;
    }
    else
    {
#ifdef DTQUEUE_DEBUG_FORWARDS
        dumpInfo("Queuing", msg);
#endif
        queue.insert(msg);
        qlenVec.record(queue.length());
        return false;
    }
}

cMessage *DropTailQueue::dequeue()
{
    if (queue.empty())
        return NULL;

    cMessage *pk = (cMessage *)queue.pop();

    // statistics
    qlenVec.record(queue.length());

    return pk;
}

void DropTailQueue::sendOut(cMessage *msg)
{
#ifdef DTQUEUE_DEBUG_FORWARDS
    dumpInfo("Sending", msg);
    EV << endl;
#endif
    send(msg, outGate);
}

#ifdef DTQUEUE_DEBUG
// T.D. 03.03.2010: Print information on forwarded/dropped packets.
//                  For SCTP, also the ports and DATA chunk TSNs are printed.
void DropTailQueue::dumpInfo(const char* info, cMessage* msg)
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
   EV << "\tqueueLength=" << queue.length() << endl;
}
#endif
