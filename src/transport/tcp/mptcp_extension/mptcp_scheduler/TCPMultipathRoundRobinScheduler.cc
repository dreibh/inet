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
#include "TCPMultipath.h"
#include "TCPConnection.h"
#include "TCPMultipathRoundRobinScheduler.h"

Register_Class(MPTCP_RoundRobinScheduler);

MPTCP_RoundRobinScheduler::MPTCP_RoundRobinScheduler(){
}

MPTCP_RoundRobinScheduler::~MPTCP_RoundRobinScheduler(){
}

void MPTCP_RoundRobinScheduler::schedule(TCPConnection* origin, cMessage* msg){

    _createMSGforProcess(msg, origin);
}
void MPTCP_RoundRobinScheduler::initialize(MPTCP_Flow* flow){

}


void MPTCP_RoundRobinScheduler::_createMSGforProcess(cMessage *msg, TCPConnection* sc) {
    msg->setKind(TCP_C_MPTCP_SEND);
    DEBUGPRINT(
            "[FLOW][SUBFLOW][STATUS] Send via  %s:%d to %s:%d",
            sc->localAddr.str().c_str(), sc->localPort, sc->remoteAddr.str().c_str(), sc->remotePort);

    TCPSendCommand *cmd = new TCPSendCommand();
    cmd->setConnId(sc->connId);
    msg->setControlInfo(cmd);
    sc->processAppCommand(msg);
    //sc->getTcpMain()->scheduleAt(simTime() + 0.0001, msg);
}
#endif
