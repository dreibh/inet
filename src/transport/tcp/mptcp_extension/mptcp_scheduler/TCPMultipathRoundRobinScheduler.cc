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

    if(lastUsed->getState()->sendQueueLimit)
        ASSERT(lastUsed->getState()->sendQueueLimit > pkt->getByteLength() && "What is the application doing...? Too much data!");
    while(pkt->getByteLength() > lastUsed->getState()->snd_mss){

        if(pkt->getByteLength() > lastUsed->getState()->snd_mss){
            cPacket* msg_tmp = new cPacket(*pkt);
            msg_tmp->setByteLength(lastUsed->getState()->snd_mss);
            _next(msg_tmp->getByteLength());
            if(lastUsed==NULL) {
                delete msg;
                return; // NO SUBFLOW FOR DATA
            }
            _createMSGforProcess(msg_tmp);
            pkt->setByteLength(pkt->getByteLength()- lastUsed->getState()->snd_mss); // FIXME What is about the options
            if(lastUsed->scheduledBytesVector)
                lastUsed->scheduledBytesVector->record(msg_tmp->getByteLength());
        }
    }
    _next(pkt->getByteLength());
    if(lastUsed==NULL) {
        delete msg;
        return; // NO SUBFLOW FOR DATA
    }
    _createMSGforProcess(pkt);
    if(lastUsed->scheduledBytesVector)
        lastUsed->scheduledBytesVector->record(pkt->getByteLength());
}

void MPTCP_RoundRobinScheduler::_next(uint32 bytes){
    bool foundLast = false;
    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)lastUsed->flow->getSubflows();

    TCP_subflow_t* entry = NULL;
    TCP_SubFlowVector_t::iterator it = subflow_list->begin();
    uint32_t max_counter = 0;
    while (true) {
       entry = (*it);

       // First organize the send queue limit
       if(!lastUsed->getState()->sendQueueLimit )
           lastUsed->getState()->sendQueueLimit = flow->flow_send_queue_limit;
       // go to the nextwith free space
       if(foundLast){
           lastUsed = entry->subflow;
           const uint32 free = lastUsed->getState()->sendQueueLimit - lastUsed->getSendQueue()->getBytesAvailable(lastUsed->getSendQueue()->getBufferStartSeq());
           if(bytes < free && lastUsed->isQueueAble){
               //DEBUGPRINT("[SCHEDLUER][ROUND ROBIN][QUEUE] fill %d! Send queue local %s:%d remote %s:%d [left: %d]",
               //                   max_counter, lastUsed->localAddr.str().c_str(), lastUsed->localPort, lastUsed->remoteAddr.str().c_str(), lastUsed->remotePort, free - bytes);
               break;
           }
           //DEBUGPRINT("[SCHEDLUER][ROUND ROBIN][QUEUE] Next %d! Send queue of local %s:%d remote %s:%d is full [left: %d]",
           //        max_counter, lastUsed->localAddr.str().c_str(), lastUsed->localPort, lastUsed->remoteAddr.str().c_str(), lastUsed->remotePort, free);

#ifdef PRIVATE  // for debug
           if(!(max_counter < subflow_list->size())){
               // FIXME -> MSG Data Queues (something is wrong in their behaivior)
               fprintf(stderr,"[SCHEDLUER][ROUND ROBIN][QUEUE][ERROR] too much data for buffer %d",bytes);
               tcpEV << "[SCHEDLUER][ROUND ROBIN][QUEUE][ERROR] too much data for buffer " << bytes << endl;
               lastUsed = NULL;
               break;
           }
           // Assert not reached because, we work here wit warnings...
#endif
           ASSERT(max_counter < subflow_list->size() && "Ups...The Application send more Data as I can handle..");
           max_counter++;
       }
       // first we have to check if buffer is empty
       else if(entry->subflow == lastUsed){
           foundLast = true;
       }
       it++;
       if(it == subflow_list->end())
           it = subflow_list->begin();
    }
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
//    DEBUGPRINT(
//            "[SCHEDULER][ROUND ROBIN][OUT] Send via  %s:%d to %s:%d",
//            lastUsed->localAddr.str().c_str(), lastUsed->localPort, lastUsed->remoteAddr.str().c_str(), lastUsed->remotePort);

    TCPSendCommand *cmd = new TCPSendCommand();
    cmd->setConnId(lastUsed->connId);
    msg->setControlInfo(cmd);
    lastUsed->processAppCommand(msg);

    //sc->getTcpMain()->scheduleAt(simTime() + 0.0001, msg);
}
#endif
