//
// Copyright (C) 2004 Andras Varga
// Copyright (C) 2010 Robin Seggelmann
// Copyright (C) 2010-2011 Thomas Dreibholz
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


#include <string.h>
#include "TCP.h"
#include "TCPConnection.h"
#include "TCPSegment.h"
#include "TCPCommand_m.h"
#include "TCPSendQueue.h"
#include "TCPReceiveQueue.h"
#include "TCPAlgorithm.h"


//
// Event processing code
//

void TCPConnection::process_OPEN_ACTIVE(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    TCPOpenCommand *openCmd = check_and_cast<TCPOpenCommand *>(tcpCommand);
    IPvXAddress localAddr, remoteAddr;
    int localPort, remotePort;

    switch (fsm.getState())
    {
        case TCP_S_INIT:
            initConnection(openCmd);

            // store local/remote socket
            state->active = true;
            localAddr = openCmd->getLocalAddr();
            remoteAddr = openCmd->getRemoteAddr();
            localPort = openCmd->getLocalPort();
            remotePort = openCmd->getRemotePort();

#ifdef PRIVATE
            { // MBe: {} create context
            bool skip = false;
            if(getTcpMain()->multipath){
                tcpEV << "MPTCP: We do not proof ports in case of a MPTCP links" << endl;
                if(this->isSubflow){
                    tcpEV << "We know this subflow as MPTCP flow" << endl;
                    skip=true;
                }
            }
            if(!skip){
#endif  // PRIVATE
            if (remoteAddr.isUnspecified() || remotePort == -1)
               throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: remote address and port must be specified");

            if (localPort == -1)
            {
                localPort = tcpMain->getEphemeralPort();
                tcpEV << "Assigned ephemeral port " << localPort << "\n";
            }

            tcpEV << "OPEN: " << localAddr << ":" << localPort << " --> " << remoteAddr << ":" << remotePort << "\n";
#ifdef PRIVATE
            }} // End skip and MPTCP contex
#endif // PRIVATE
            tcpMain->addSockPair(this, localAddr, remoteAddr, localPort, remotePort);

#ifdef PRIVATE
            if(getTcpMain()->multipath){
                getTcpMain()->multipath_subflow_id = openCmd->getSubFlowNumber();
        	}
#endif // PRIVATE
            // send initial SYN
            selectInitialSeqNum();
            sendSyn();
            startSynRexmitTimer();
            scheduleTimeout(connEstabTimer, 1);
            break;

        default:
#ifdef PRIVATE
            if(!getTcpMain()->multipath)
#endif // PRIVATE
            throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: connection already exists");
            break; // MBe add because of Warning
    }

    delete openCmd;
    delete msg;
}

void TCPConnection::process_OPEN_PASSIVE(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    TCPOpenCommand *openCmd = check_and_cast<TCPOpenCommand *>(tcpCommand);
    IPvXAddress localAddr;
    int localPort;

    switch (fsm.getState())
    {
        case TCP_S_INIT:
            initConnection(openCmd);

            // store local/remote socket
            state->active = false;
            state->fork = openCmd->getFork();
            localAddr = openCmd->getLocalAddr();
            localPort = openCmd->getLocalPort();

            if (localPort == -1)
                throw cRuntimeError(tcpMain, "Error processing command OPEN_PASSIVE: local port must be specified");

            tcpEV << "Starting to listen on: " << localAddr << ":" << localPort << "\n";

            tcpMain->addSockPair(this, localAddr, IPvXAddress(), localPort, -1);
            break;

        default:
            throw cRuntimeError(tcpMain, "Error processing command OPEN_PASSIVE: connection already exists");
            break; // MBe add because of Warning
    }

    delete openCmd;
    delete msg;
}

#ifdef PRIVATE



void TCPConnection::process_MPTCPSEND(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg){

    if(this->getTcpMain()->multipath && isSubflow){
#warning "Experiment SETUP for scheduling experiments -> should find the best..."
        // MBe: OK here we got data -> we are able to schedule now, but at least we could enqueue this data and schedule it later
        // depends on the scheduler and queue size
        flow->schedule(this, msg);
    }
    else if(this->getState()){
        process_SEND(event,tcpCommand,msg);
    }
    else{
        delete msg;
    }

}
#endif // PRIVATE

void TCPConnection::process_SEND(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{

    TCPSendCommand *sendCommand = check_and_cast<TCPSendCommand *>(tcpCommand);
#ifdef PRIVATE
    cPacket* pkt = PK(msg);
    {
    static uint64 cnt = 0;
    static int number = 0;
    number++;

    cnt += pkt->getByteLength();

    // Overflow is correct
    }
#endif // PRIVATE
    // FIXME how to support PUSH? One option is to treat each SEND as a unit of data,
    // and set PSH at SEND boundaries
    switch (fsm.getState())
    {
        case TCP_S_INIT:
            if(!this->getTcpMain()->multipath)
                throw cRuntimeError(tcpMain, "Error processing command SEND: connection not open");
        case TCP_S_LISTEN:
            tcpEV << "SEND command turns passive open into active open, sending initial SYN\n";
            state->active = true;
            selectInitialSeqNum();
            sendSyn();
            startSynRexmitTimer();
            scheduleTimeout(connEstabTimer, TCP_TIMEOUT_CONN_ESTAB);
#ifndef PRIVATE
            sendQueue->enqueueAppData(PK(msg));  // queue up for later
#else
            if(state->sendQueueLimit) getTcpMain()->request_for_data = true;
            if(getTcpMain()->multipath)
                tmp_msg_buf->push(PK(msg));
            else
                sendQueue->enqueueAppData((PK(msg)));
            if(state->sendQueueLimit){
                (getState()->requested > PK(msg)->getByteLength())?getState()->requested -= PK(msg)->getByteLength():getState()->requested=0;
                getState()->enqueued += PK(msg)->getByteLength();
            }
#endif
            tcpEV << sendQueue->getBytesAvailable(state->snd_una) << " bytes in queue\n";
            break;

        case TCP_S_SYN_RCVD:
        case TCP_S_SYN_SENT:
            tcpEV << "Queueing up data for sending later.\n";
#ifndef PRIVATE
            sendQueue->enqueueAppData(PK(msg)); // queue up for later
#else
            if(state->sendQueueLimit) getTcpMain()->request_for_data = true;
            if(getTcpMain()->multipath)
                tmp_msg_buf->push(PK(msg));
            else
                sendQueue->enqueueAppData((PK(msg)));
            if(state->sendQueueLimit){
                (getState()->requested > PK(msg)->getByteLength())?getState()->requested -= PK(msg)->getByteLength():getState()->requested=0;
                getState()->enqueued += PK(msg)->getByteLength();
            }
#endif
            tcpEV << sendQueue->getBytesAvailable(state->snd_una) << " bytes in queue\n";
            break;

        case TCP_S_ESTABLISHED:
        case TCP_S_CLOSE_WAIT:
#ifndef PRIVATE
            sendQueue->enqueueAppData(PK(msg));
#else
            if(state->sendQueueLimit) getTcpMain()->request_for_data = true;
            if(getTcpMain()->multipath)
                tmp_msg_buf->push(PK(msg));
            else
                sendQueue->enqueueAppData((PK(msg)));
            if(state->sendQueueLimit){
                (getState()->requested > PK(msg)->getByteLength())?getState()->requested -= PK(msg)->getByteLength():getState()->requested=0;
                getState()->enqueued += PK(msg)->getByteLength();
            }
#endif
            tcpEV << sendQueue->getBytesAvailable(state->snd_una) << " bytes in queue, plus "
                 << (state->snd_max-state->snd_una) << " bytes unacknowledged\n";

#ifdef PRIVATE
            if(getTcpMain()->multipath)
                this->flow->sendCommandInvoked();
            else
#endif
            tcpAlgorithm->sendCommandInvoked();
            break;
        case TCP_S_LAST_ACK:
        case TCP_S_FIN_WAIT_1:
        case TCP_S_FIN_WAIT_2:
        case TCP_S_CLOSING:
        case TCP_S_TIME_WAIT:
            throw cRuntimeError(tcpMain, "Error processing command SEND: connection closing");
            /* no break */
    }
    delete sendCommand; // msg itself has been taken by the sendQueue
}
void TCPConnection::process_CLOSE(){
#ifdef PRIVATE

        state->setSndNxt(state->snd_max);
        sendFin();
        tcpAlgorithm->restartRexmitTimer();
        state->setSndNxt(state->getSndNxt() + 1);
        state->snd_max = state->getSndNxt();

        if (unackedVector)
            unackedVector->record(state->snd_max - state->snd_una);
        FSM_Goto(this->fsm, TCP_S_CLOSE_WAIT);
#endif
}
void TCPConnection::process_CLOSE(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    delete tcpCommand;
    delete msg;

    switch (fsm.getState())
    {
        case TCP_S_INIT:
            //throw cRuntimeError(tcpMain, "Error processing command CLOSE: connection not open");

#ifdef PRIVATE
            if(!getTcpMain()->multipath)
            	if(!this->isSubflow)
#else // PRIVATE !! NEED NEXT LINE !!!
                throw cRuntimeError(tcpMain, "Error processing command CLOSE: connection not open");
#endif
            /* no break */
        case TCP_S_LISTEN:
            // Nothing to do here
            break;

        case TCP_S_SYN_SENT:
            // Delete the TCB and return "error:  closing" responses to any
            // queued SENDs, or RECEIVEs.
            break;

        case TCP_S_SYN_RCVD:
        case TCP_S_ESTABLISHED:
        case TCP_S_CLOSE_WAIT:
            //
            // SYN_RCVD processing (ESTABLISHED and CLOSE_WAIT are similar):
            //"
            // If no SENDs have been issued and there is no pending data to send,
            // then form a FIN segment and send it, and enter FIN-WAIT-1 state;
            // otherwise queue for processing after entering ESTABLISHED state.
            //"
            if (state->snd_max == sendQueue->getBufferEndSeq())
            {
                tcpEV << "No outstanding SENDs, sending FIN right away, advancing snd_nxt over the FIN\n";
                state->setSndNxt(state->snd_max);
                sendFin();
                tcpAlgorithm->restartRexmitTimer();
                state->setSndNxt((state->getSndNxt() + 1));
                state->snd_max = state->getSndNxt();

                if (unackedVector)
                    unackedVector->record(state->snd_max - state->snd_una);

                // state transition will automatically take us to FIN_WAIT_1 (or LAST_ACK)
            }
            else
            {
                tcpEV << "SEND of " << (sendQueue->getBufferEndSeq() - state->snd_max)
                      << " bytes pending, deferring sending of FIN\n";
                event = TCP_E_IGNORE;
            }
            state->send_fin = true;
            state->snd_fin_seq = sendQueue->getBufferEndSeq();
#ifdef PRIVATE
            if(this->getTcpMain()->multipath)
                if(this->isSubflow)
                    flow->isFIN = true;
#endif //PRIVATE
            break;

        case TCP_S_FIN_WAIT_1:
        case TCP_S_FIN_WAIT_2:
        case TCP_S_CLOSING:
#ifdef PRIVATE
            if(getTcpMain()->multipath){
                if(this->isSubflow){
                    this->flow->close();
                }
            }
#endif // PRIVATE
        case TCP_S_LAST_ACK:
        case TCP_S_TIME_WAIT:
            // RFC 793 is not entirely clear on how to handle a duplicate close request.
            // Here we treat it as an error.
            throw cRuntimeError(tcpMain, "Duplicate CLOSE command: connection already closing");
            /* no break */
    }
    // workaround FIXME - Something goes wrong here
#ifdef PRIVATE
    if(state)
#endif
    sendRst(getState()->getSndNxt());
}

void TCPConnection::process_ABORT(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    delete tcpCommand;
    delete msg;

    //
    // The ABORT event will automatically take the connection to the CLOSED
    // state, flush queues etc -- no need to do it here. Also, we don't need to
    // send notification to the user, they know what's going on.
    //
    switch (fsm.getState())
    {
        case TCP_S_INIT:

            // throw cRuntimeError("Error processing command ABORT: connection not open"); FIXME
            return;
        case TCP_S_SYN_RCVD:
        case TCP_S_ESTABLISHED:
        case TCP_S_FIN_WAIT_1:
        case TCP_S_FIN_WAIT_2:
        case TCP_S_CLOSE_WAIT:
            //"
            // Send a reset segment:
            //
            //   <SEQ=SND.NXT><CTL=RST>
            //"
            sendRst(state->getSndNxt());
            break;
    }

}

void TCPConnection::process_STATUS(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    delete tcpCommand; // but reuse msg for reply

    if (fsm.getState() == TCP_S_INIT)
        throw cRuntimeError("Error processing command STATUS: connection not open");

    TCPStatusInfo *statusInfo = new TCPStatusInfo();

    statusInfo->setState(fsm.getState());
    statusInfo->setStateName(stateName(fsm.getState()));

    statusInfo->setLocalAddr(localAddr);
    statusInfo->setRemoteAddr(remoteAddr);
    statusInfo->setLocalPort(localPort);
    statusInfo->setRemotePort(remotePort);

    statusInfo->setSnd_mss(state->snd_mss);
    statusInfo->setSnd_una(state->snd_una);
    statusInfo->setSnd_nxt(state->getSndNxt());
    statusInfo->setSnd_max(state->snd_max);
    statusInfo->setSnd_wnd(state->snd_wnd);
    statusInfo->setSnd_up(state->snd_up);
    statusInfo->setSnd_wl1(state->snd_wl1);
    statusInfo->setSnd_wl2(state->snd_wl2);
    statusInfo->setIss(state->iss);
    statusInfo->setRcv_nxt(state->rcv_nxt);
    statusInfo->setRcv_wnd(state->rcv_wnd);
    statusInfo->setRcv_up(state->rcv_up);
    statusInfo->setIrs(state->irs);
    statusInfo->setFin_ack_rcvd(state->fin_ack_rcvd);

    msg->setControlInfo(statusInfo);
    msg->setKind(TCP_I_STATUS);
    sendToApp(msg);
}

void TCPConnection::process_QUEUE_BYTES_LIMIT(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    if(state == NULL) {
        opp_error("Called process_QUEUE_BYTES_LIMIT on uninitialized TCPConnection!");
    }
    state->sendQueueLimit = tcpCommand->getUserId();
    state->requested = tcpCommand->getUserId(); // On start netperfmeter send one queue size
    if(getTcpMain()->multipath){
            TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*) flow->getSubflows();

           for (TCP_SubFlowVector_t::iterator it = subflow_list->begin(); it != subflow_list->end(); it++) {
                 TCP_subflow_t* entry = (*it);
                 TCPConnection* conn = entry->subflow;
                 conn->getState()->sendQueueLimit = tcpCommand->getUserId();
           }
        flow->commonSendQueueLimit = tcpCommand->getUserId();
    }
    delete msg;
    delete tcpCommand;
}
