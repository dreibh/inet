//
// Copyright (C) 2004 Andras Varga
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

    switch(fsm.getState())
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
            { // create own contex
            bool multipath =  tcpMain->par("multipath");
            bool skip = false;
            if(multipath){
                tcpEV << "MPTCP: We do not proof ports in case of a multpath link" << endl;
                if(this->isSubflow){
                    tcpEV << "We know this subflow as MPTCP flow" << endl;
                    skip=true;
                }
            }
            if(!skip){
#endif
            if (remoteAddr.isUnspecified() || remotePort==-1)
                opp_error("Error processing command OPEN_ACTIVE: remote address and port must be specified");

            if (localPort==-1)
            {
                localPort = tcpMain->getEphemeralPort();
                tcpEV << "Assigned ephemeral port " << localPort << "\n";
            }

            tcpEV << "OPEN: " << localAddr << ":" << localPort << " --> " << remoteAddr << ":" << remotePort << "\n";
#ifdef PRIVATE
            }} // End Multipath contex
#endif
            tcpMain->addSockPair(this, localAddr, remoteAddr, localPort, remotePort);

#ifdef PRIVATE
            { // MPTCP Context
            bool multipath =  tcpMain->par("multipath");
        	// TODO Overwrok, which variable do we need
            if(multipath){
        		tcpMain->multipath_subflow_id = openCmd->getSubFlowNumber();
        	}
            } // END MPTCP Context

#endif
            // send initial SYN
            selectInitialSeqNum();
            sendSyn();
            startSynRexmitTimer();
            scheduleTimeout(connEstabTimer, TCP_TIMEOUT_CONN_ESTAB);
            break;

        default:
#ifdef PRIVATE
            if(!tcpMain->par("multipath"))
#endif
            opp_error("Error processing command OPEN_ACTIVE: connection already exists");
            break; // MBe add because of Warning
    }

    delete openCmd;
    delete msg;
#ifdef PRIVATE
    msg = NULL;
#endif
}

void TCPConnection::process_OPEN_PASSIVE(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    TCPOpenCommand *openCmd = check_and_cast<TCPOpenCommand *>(tcpCommand);
    IPvXAddress localAddr;
    int localPort;

    switch(fsm.getState())
    {
        case TCP_S_INIT:
            initConnection(openCmd);

            // store local/remote socket
            state->active = false;
            state->fork = openCmd->getFork();
            localAddr = openCmd->getLocalAddr();
            localPort = openCmd->getLocalPort();

            if (localPort==-1)
                opp_error("Error processing command OPEN_PASSIVE: local port must be specified");

            tcpEV << "Starting to listen on: " << localAddr << ":" << localPort << "\n";

            tcpMain->addSockPair(this, localAddr, IPvXAddress(), localPort, -1);
            break;

        default:
            opp_error("Error processing command OPEN_PASSIVE: connection already exists");
            break; // MBe add because of Warning
    }

    delete openCmd;
    delete msg;
}
#ifdef PRIVATE
void TCPConnection::process_MPTCPSEND(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg){


    if(this->isSubflow){
        // easy scheduler for testing
        TCPConnection* scheduledConn = this->flow->schedule(this, msg);
        //scheduledConn->process_SEND(event,tcpCommand,msg);
    }
    else
        this->process_SEND(event,tcpCommand,msg);
}
#endif
void TCPConnection::process_SEND(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{

    TCPSendCommand *sendCommand = check_and_cast<TCPSendCommand *>(tcpCommand);
#ifdef PRIVATE
            {
            static uint64 cnt = 0;
            static int number = 0;
            number++;
            char message_name[255];
            cPacket* test = check_and_cast<cPacket *> (msg);
            cnt += test->getByteLength();
//            fprintf(stderr, "[FLOW][SUBFLOW][STATUS] Send Bytes %lu Name: %s - %i\n",cnt,test->getName(),number);
            }
#endif
    // FIXME how to support PUSH? One option is to treat each SEND as a unit of data,
    // and set PSH at SEND boundaries
    switch(fsm.getState())
    {
        case TCP_S_INIT:
            opp_error("Error processing command SEND: connection not open");
            /* no break */

        case TCP_S_LISTEN:
            tcpEV << "SEND command turns passive open into active open, sending initial SYN\n";
            state->active = true;
            selectInitialSeqNum();
            sendSyn();
            startSynRexmitTimer();
            scheduleTimeout(connEstabTimer, TCP_TIMEOUT_CONN_ESTAB);
            sendQueue->enqueueAppData(PK(msg));  // queue up for later
            tcpEV << sendQueue->getBytesAvailable(state->snd_una) << " bytes in queue\n";
            break;

        case TCP_S_SYN_RCVD:
        case TCP_S_SYN_SENT:
            tcpEV << "Queueing up data for sending later.\n";
            sendQueue->enqueueAppData(PK(msg)); // queue up for later
            tcpEV << sendQueue->getBytesAvailable(state->snd_una) << " bytes in queue\n";
            break;

        case TCP_S_ESTABLISHED:
        case TCP_S_CLOSE_WAIT:
            sendQueue->enqueueAppData(PK(msg));
            tcpEV << sendQueue->getBytesAvailable(state->snd_una) << " bytes in queue, plus "
                  << (state->snd_max-state->snd_una) << " bytes unacknowledged\n";
            tcpAlgorithm->sendCommandInvoked();
            break;

        case TCP_S_LAST_ACK:
        case TCP_S_FIN_WAIT_1:
        case TCP_S_FIN_WAIT_2:
        case TCP_S_CLOSING:
        case TCP_S_TIME_WAIT:
            opp_error("Error processing command SEND: connection closing");
            /* no break */
    }
#ifndef PRIVATE
    if ((state->sendQueueLimit > 0) && (sendQueue->getBytesAvailable(state->snd_una) > state->sendQueueLimit)) {
        state->queueUpdate = false;
    }
#endif
    delete sendCommand; // msg itself has been taken by the sendQueue
}

void TCPConnection::process_CLOSE(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    delete tcpCommand;
    delete msg;

    switch(fsm.getState())
    {
        case TCP_S_INIT:
#ifdef PRIVATE
        	{bool multipath =  tcpMain->par("multipath");
            if(multipath){
            	//TODO
            }
            else{
#endif
            opp_error("Error processing command CLOSE: connection not open");
            /* no break */
#ifdef PRIVATE
        	}}
        	/* no break */
#endif
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
            if (state->snd_max==sendQueue->getBufferEndSeq())
            {
                tcpEV << "No outstanding SENDs, sending FIN right away, advancing snd_nxt over the FIN\n";
                state->snd_nxt = state->snd_max;
                sendFin();
                tcpAlgorithm->restartRexmitTimer();
                state->snd_max = ++state->snd_nxt;
                if (unackedVector) unackedVector->record(state->snd_max - state->snd_una);

                // state transition will automatically take us to FIN_WAIT_1 (or LAST_ACK)
            }
            else
            {
                tcpEV << "SEND of " << (sendQueue->getBufferEndSeq()-state->snd_max) <<
                      " bytes pending, deferring sending of FIN\n";
                event = TCP_E_IGNORE;
            }
            state->send_fin = true;
            state->snd_fin_seq = sendQueue->getBufferEndSeq();
            break;

        case TCP_S_FIN_WAIT_1:
        case TCP_S_FIN_WAIT_2:
        case TCP_S_CLOSING:
        case TCP_S_LAST_ACK:
        case TCP_S_TIME_WAIT:
            // RFC 793 is not entirely clear on how to handle a duplicate close request.
            // Here we treat it as an error.
            opp_error("Duplicate CLOSE command: connection already closing");
            /* no break */
    }
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
    switch(fsm.getState())
    {
        case TCP_S_INIT:
            opp_error("Error processing command ABORT: connection not open");
            /* no break */

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
            sendRst(state->snd_nxt);
            break;
    }

}

void TCPConnection::process_STATUS(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    delete tcpCommand; // but reuse msg for reply

    if (fsm.getState()==TCP_S_INIT)
        opp_error("Error processing command STATUS: connection not open");

    TCPStatusInfo *statusInfo = new TCPStatusInfo();

    statusInfo->setState(fsm.getState());
    statusInfo->setStateName(stateName(fsm.getState()));

    statusInfo->setLocalAddr(localAddr);
    statusInfo->setRemoteAddr(remoteAddr);
    statusInfo->setLocalPort(localPort);
    statusInfo->setRemotePort(remotePort);

    statusInfo->setSnd_mss(state->snd_mss);
    statusInfo->setSnd_una(state->snd_una);
    statusInfo->setSnd_nxt(state->snd_nxt);
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
    sendToApp(msg);
}

void TCPConnection::process_QUEUE_BYTES_LIMIT(TCPEventCode& event, TCPCommand *tcpCommand, cMessage *msg)
{
    if(state == NULL) {
        opp_error("Called process_QUEUE_BYTES_LIMIT on uninitialized TCPConnection!");
    }
#ifdef PRIVATE
    if(this->isSubflow)
        this->flow->setSendQueueLimit(tcpCommand->getUserId());
    else
#endif
    state->sendQueueLimit = tcpCommand->getUserId();

    tcpEV<<"state->sendQueueLimit set to "<<state->sendQueueLimit<<"\n";
    delete msg;
    delete tcpCommand;
}

