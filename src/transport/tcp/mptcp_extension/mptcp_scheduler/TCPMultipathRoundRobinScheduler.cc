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



MPTCP_RoundRobinScheduler::MPTCP_RoundRobinScheduler(){

}

MPTCP_RoundRobinScheduler::~MPTCP_RoundRobinScheduler(){

}

void MPTCP_RoundRobinScheduler::schedule(TCPConnection* conn, cMessage* msg){
    static TCP* test = NULL;

    // fist we have to check ownership
    // We have to split data on mss size

    if( conn->flow->lastused==NULL){
        conn->flow->lastused = conn;
    }

    ASSERT(conn->flow->lastused);

    cPacket* pkt = check_and_cast<cPacket*> (msg);
    int64 cond = pkt->getByteLength();
    _next(cond, conn);
    if(!conn->flow->lastused) return;
    DEBUGPRINT("appGate %i connID %i QueueAble %s TCPMain %x",lastUsed->appGateIndex, lastUsed->connId, (lastUsed->isQueueAble?"true":"false"),lastUsed->getTcpMain());
    DEBUGPRINT("FLOW appGate %i connID %i ",lastUsed->flow->appID,lastUsed->flow->appGateIndex);

    _createMSGforProcess(msg,conn);
    if(conn->flow->lastused->scheduledBytesVector)
        conn->flow->lastused->scheduledBytesVector->record(pkt->getByteLength());
}

void MPTCP_RoundRobinScheduler::_next(uint32 bytes, TCPConnection* conn){

    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)conn->flow->lastused->flow->getSubflows();
    ASSERT(conn->flow->lastused);
    TCPConnection* tmp = NULL;
    bool firstrun = true;
    bool found = false;
    int cnt = 0;
    for(;;){
        for (TCP_SubFlowVector_t::iterator it = subflow_list->begin(); it != subflow_list->end(); it++, cnt++) {
            TCP_subflow_t*  entry = (*it);
            tmp = entry->subflow;
            DEBUGPRINT(
                      "[Scheduler][%i][STATUS] Check Connections  %s:%d to %s:%d",
                           cnt, entry->subflow->localAddr.str().c_str(), entry->subflow->localPort, entry->subflow->remoteAddr.str().c_str(), entry->subflow->remotePort);
            // First organize the send queue limit
            if(!tmp->getState()->sendQueueLimit){
                for (TCP_SubFlowVector_t::iterator si = subflow_list->begin(); si != subflow_list->end(); si++) {
                  if((*si)->subflow->getState()->sendQueueLimit){
                      tmp->getState()->sendQueueLimit = (*si)->subflow->getState()->sendQueueLimit;
                      break;
                  }
                }
            }

            if(tmp == conn->flow->lastused && firstrun){
                firstrun = !firstrun;
            }
            else if(tmp == conn->flow->lastused && (!firstrun)){
                found = true;
                break;
            }
            else if(tmp->getTcpMain() == conn->flow->lastused->getTcpMain()){
                const uint32 free = tmp->getState()->sendQueueLimit - tmp->getSendQueue()->getBytesAvailable(tmp->getSendQueue()->getBufferStartSeq());
                if(bytes < free && tmp->isQueueAble){
                    found = true;
                    break;
                }
            }
        }
        if(found){
            conn->flow->lastused = tmp;
            DEBUGPRINT(
                      "[Scheduler][%i][STATUS]found",cnt);
            break;
        }
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

void MPTCP_RoundRobinScheduler::_createMSGforProcess(cMessage *msg, TCPConnection* conn) {
    ASSERT(conn->flow->lastused);
    msg->setKind(TCP_C_MPTCP_SEND);
    TCPSendCommand *cmd = new TCPSendCommand();
    cmd->setConnId(conn->flow->lastused->connId);
    msg->setControlInfo(cmd);

    conn->flow->lastused->processAppCommand(msg);
    DEBUGPRINT(
                         "[Scheduler][STATUS] USE Connections  %s:%d to %s:%d",
                               lastUsed->localAddr.str().c_str(), lastUsed->localPort, lastUsed->remoteAddr.str().c_str(), lastUsed->remotePort);
}
#endif
