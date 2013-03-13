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
#include <omnetpp.h>
#include <vector>
#include <map>
#include <set>

#include "TCPMultipath.h"
#include "TCPConnection.h"
#include "TCPMultipathRoundRobinScheduler.h"
#include "TCPSendQueue.h"

Register_Class(MPTCP_RoundRobinScheduler);

TCPConnection* MPTCP_RoundRobinScheduler::lastUsed = NULL;

MPTCP_RoundRobinScheduler::MPTCP_RoundRobinScheduler(){
}

MPTCP_RoundRobinScheduler::~MPTCP_RoundRobinScheduler(){
    lastUsed = NULL;
}

void MPTCP_RoundRobinScheduler::schedule(TCPConnection* origin, cMessage* msg){

    TCPConnection tmp_last;
    if(lastUsed==NULL){
          lastUsed = origin;
    }
    // We have to split data on mss size
    cPacket* pkt = check_and_cast<cPacket*> (msg);

    DEBUGPRINT("What is the application doing...sending more data as we have buffer [Configured %d] [Application Send %d]",lastUsed->getState()->sendQueueLimit, pkt->getByteLength());
    if(lastUsed->getState()->sendQueueLimit)
        ASSERT(lastUsed->getState()->sendQueueLimit > pkt->getByteLength() && "What is the application doing...? Too much data!");
    while(pkt->getByteLength() > lastUsed->getState()->snd_mss){

        if(pkt->getByteLength() > lastUsed->getState()->snd_mss){
            cPacket* msg_tmp = new cPacket(*pkt);
            msg_tmp->setByteLength(lastUsed->getState()->snd_mss);
            _next(msg_tmp->getByteLength());
            _createMSGforProcess(msg_tmp);
            pkt->setByteLength(pkt->getByteLength()- lastUsed->getState()->snd_mss); // FIXME What is about the options
            if(lastUsed->scheduledBytesVector)
                lastUsed->scheduledBytesVector->record(msg_tmp->getByteLength());
        }
    }
    _next(pkt->getByteLength());
    _createMSGforProcess(pkt);
    if(lastUsed->scheduledBytesVector)
        lastUsed->scheduledBytesVector->record(pkt->getByteLength());
}

void MPTCP_RoundRobinScheduler::_next(uint32 bytes){
    bool foundLast = true;
    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)lastUsed->flow->getSubflows();

    TCP_subflow_t* entry = NULL;
    TCP_SubFlowVector_t::iterator it;
    for (it = subflow_list->begin(); it != subflow_list->end(); it++) {
       entry = (*it);

       if(!foundLast){
           lastUsed = entry->subflow;
           const uint32 free = lastUsed->getState()->sendQueueLimit - lastUsed->getSendQueue()->getBytesAvailable(lastUsed->getState()->snd_una);
           if(free < bytes){
               continue;
           }
           foundLast = true;
           break;
       }
       // first we have to check if buffer is empty
       if(entry->subflow == lastUsed){
           foundLast = false;
           continue;
       }
    }
    if(!foundLast){ // it was the last element in the list
        it = subflow_list->begin();
        lastUsed= (*it)->subflow;
    }
    ASSERT((lastUsed->getState()->sendQueueLimit - lastUsed->getSendQueue()->getBytesAvailable(lastUsed->getState()->snd_una)>0) && "Not enough space in buffer");
}

void MPTCP_RoundRobinScheduler::initialize(MPTCP_Flow* f){
    flow= f;
}

uint32_t MPTCP_RoundRobinScheduler::getFreeSendBuffer(){
    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*) flow->getSubflows();
    uint32 abated = 0;
    for (TCP_SubFlowVector_t::iterator it = subflow_list->begin(); it != subflow_list->end(); it++) {
          TCP_subflow_t* entry = (*it);
          TCPConnection* conn = entry->subflow;
          uint32 free = conn->getState()->sendQueueLimit - conn->getSendQueue()->getBytesAvailable(conn->getState()->snd_una);
          abated += free;
    }
    return abated ;
}

void MPTCP_RoundRobinScheduler::_createMSGforProcess(cMessage *msg) {
    if(lastUsed==NULL)
          return;
    msg->setKind(TCP_C_MPTCP_SEND);
    DEBUGPRINT(
            "[SCHEDULER][ROUND ROBIN][OUT] Send via  %s:%d to %s:%d",
            lastUsed->localAddr.str().c_str(), lastUsed->localPort, lastUsed->remoteAddr.str().c_str(), lastUsed->remotePort);

    TCPSendCommand *cmd = new TCPSendCommand();
    cmd->setConnId(lastUsed->connId);
    msg->setControlInfo(cmd);
    lastUsed->processAppCommand(msg);

    //sc->getTcpMain()->scheduleAt(simTime() + 0.0001, msg);
}
#endif
