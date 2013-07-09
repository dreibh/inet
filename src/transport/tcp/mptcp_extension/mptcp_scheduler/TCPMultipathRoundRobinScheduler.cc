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



MPTCP_RoundRobinScheduler::MPTCP_RoundRobinScheduler(){

}

MPTCP_RoundRobinScheduler::~MPTCP_RoundRobinScheduler(){

}

void MPTCP_RoundRobinScheduler::schedule(TCPConnection* conn, cMessage* msg){
    static TCP* test = NULL;
    static uint32 msg_counter = 0;

    // First some initialization stuff
    if( conn->flow->lastenqueued==NULL){
        conn->flow->lastenqueued = conn;
    }
    if(conn->flow->lastscheduled==NULL){
         conn->flow->lastscheduled = conn;
    }
    ASSERT(conn->flow->lastenqueued);
    ASSERT(conn->flow->lastscheduled);


    cPacket* pkt = check_and_cast<cPacket*> (msg);
    _next(pkt->getByteLength(), conn);
    _createMSGforProcess(msg,conn);

}

void MPTCP_RoundRobinScheduler::_next(uint32 bytes, TCPConnection* conn){

    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)conn->flow->getSubflows();
    ASSERT(conn->flow->lastenqueued);
    TCPConnection* tmp = NULL;
    bool firstrun = true;
    bool found = false;
    int cnt = 0;
    static size_t discard = 0;
    while(!found){
        for (TCP_SubFlowVector_t::iterator it = subflow_list->begin(); it != subflow_list->end(); it++, cnt++) {
            TCP_subflow_t*  entry = (*it);
            tmp = entry->subflow;

            if(tmp->getState()->sendQueueLimit == 0){
                break;
            }
            if(tmp == conn->flow->lastenqueued && firstrun){
                firstrun = false;
                cnt = 0;
                continue;
            }
            else if (firstrun) continue;

            if(((0 == tmp->getState()->enqueued) || (tmp->getState()->requested > bytes-1)) && tmp->isQueueAble){
                found = true;
                break;
            }
            if(cnt > subflow_list->size()){
                discard += bytes;
                // fprintf(stderr,"Discard....%i", discard);
                return;
            }
        }

        if(found){
            conn->flow->lastenqueued = tmp;
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
    ASSERT(conn->flow->lastenqueued);
    msg->setKind(TCP_C_MPTCP_SEND);
    TCPSendCommand *cmd = new TCPSendCommand();

    // We need the overflow
    cmd->setConnId(conn->flow->lastenqueued->connId);
    msg->setControlInfo(cmd);
    conn->flow->lastenqueued->processAppCommand(msg);

    DEBUGPRINT(
                         "[Scheduler][STATUS] USE Connections  %s:%d to %s:%d",
                         conn->flow->lastenqueued->localAddr.str().c_str(),  conn->flow->lastenqueued->localPort,  conn->flow->lastenqueued->remoteAddr.str().c_str(),  conn->flow->lastenqueued->remotePort);
}
#endif
