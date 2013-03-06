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
    bool foundLast = true;
    // get subflow list
    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)origin->flow->getSubflows();
    // Round Robin works like the following:
    // - First identifier available sub-connections
    // - check last used connection
    if(lastUsed==NULL){
        lastUsed = origin;
    }

    TCP_subflow_t* entry = NULL;
    TCP_SubFlowVector_t::iterator it;
    for (it = subflow_list->begin(); it != subflow_list->end(); it++) {
       entry = (*it);

       if(!foundLast){
           lastUsed = entry->subflow;
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
    _createMSGforProcess(msg);
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
          uint32 alreadyQueued = conn->getSendQueue()->getBytesAvailable(conn->getSendQueue()->getBufferStartSeq());
          abated += (conn->getState()->sendQueueLimit > alreadyQueued) ? conn->getState()->sendQueueLimit - alreadyQueued : 0;
    }
    return abated;
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
