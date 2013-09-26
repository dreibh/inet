//
// Copyright (C) 2004 Andras Varga
// Copyright (C) 2009-2011 Thomas Reschka
// Copyright (C) 2011 Zoltan Bojthe
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
#include <algorithm>   // min,max

#include "TCP.h"
#include "TCPConnection.h"
#include "TCPSegment.h"
#include "TCPCommand_m.h"
#include "IPv4ControlInfo.h"
#include "IPv6ControlInfo.h"
#include "TCPSendQueue.h"
#include "TCPSACKRexmitQueue.h"
#include "TCPReceiveQueue.h"
#include "TCPAlgorithm.h"

//
// helper functions
//
#ifdef PRIVATE
#include "TCPMultipathPCB.h"
#include "TCPSchedulerManager.h"
#include "SACK_RFC3517.h"


#endif // PRIVATE

const char *TCPConnection::stateName(int state)
{
#define CASE(x) case x: s=#x+6; break
    const char *s = "unknown";
    switch (state)
    {
        CASE(TCP_S_INIT);
        CASE(TCP_S_CLOSED);
        CASE(TCP_S_LISTEN);
        CASE(TCP_S_SYN_SENT);
        CASE(TCP_S_SYN_RCVD);
        CASE(TCP_S_ESTABLISHED);
        CASE(TCP_S_CLOSE_WAIT);
        CASE(TCP_S_LAST_ACK);
        CASE(TCP_S_FIN_WAIT_1);
        CASE(TCP_S_FIN_WAIT_2);
        CASE(TCP_S_CLOSING);
        CASE(TCP_S_TIME_WAIT);
    }
    return s;
#undef CASE
}

const char *TCPConnection::eventName(int event)
{
#define CASE(x) case x: s=#x+6; break
    const char *s = "unknown";
    switch (event)
    {
        CASE(TCP_E_IGNORE);
        CASE(TCP_E_OPEN_ACTIVE);
        CASE(TCP_E_OPEN_PASSIVE);
        CASE(TCP_E_SEND);
        CASE(TCP_E_CLOSE);
        CASE(TCP_E_ABORT);
        CASE(TCP_E_STATUS);
        CASE(TCP_E_QUEUE_BYTES_LIMIT);    
        CASE(TCP_E_RCV_DATA);
        CASE(TCP_E_RCV_ACK);
        CASE(TCP_E_RCV_SYN);
        CASE(TCP_E_RCV_SYN_ACK);
        CASE(TCP_E_RCV_FIN);
        CASE(TCP_E_RCV_FIN_ACK);
        CASE(TCP_E_RCV_RST);
        CASE(TCP_E_RCV_UNEXP_SYN);
        CASE(TCP_E_TIMEOUT_2MSL);
        CASE(TCP_E_TIMEOUT_CONN_ESTAB);
        CASE(TCP_E_TIMEOUT_FIN_WAIT_2);
    }
    return s;
#undef CASE
}

const char *TCPConnection::indicationName(int code)
{
#define CASE(x) case x: s=#x+6; break
    const char *s = "unknown";
    switch (code)
    {
        CASE(TCP_I_DATA);
        CASE(TCP_I_URGENT_DATA);
        CASE(TCP_I_ESTABLISHED);
        CASE(TCP_I_PEER_CLOSED);
        CASE(TCP_I_CLOSED);
        CASE(TCP_I_CONNECTION_REFUSED);
        CASE(TCP_I_CONNECTION_RESET);
        CASE(TCP_I_TIMED_OUT);
        CASE(TCP_I_STATUS);
        CASE(TCP_I_SEND_MSG);
    }
    return s;
#undef CASE
}

const char *TCPConnection::optionName(int option)
{
    switch (option)
    {
        case TCPOPTION_END_OF_OPTION_LIST:   return "EOL";
        case TCPOPTION_NO_OPERATION:         return "NOP";
        case TCPOPTION_MAXIMUM_SEGMENT_SIZE: return "MSS";
        case TCPOPTION_WINDOW_SCALE:         return "WS";
        case TCPOPTION_SACK_PERMITTED:       return "SACK_PERMITTED";
        case TCPOPTION_SACK:                 return "SACK";
        case TCPOPTION_TIMESTAMP:            return "TS";
        default:                             return "unknown";
    }
}

void TCPConnection::printConnBrief() const
{
    tcpEV << "Connection "
          << localAddr << ":" << localPort << " to " << remoteAddr << ":" << remotePort
          << "  on app[" << appGateIndex << "], connId=" << connId
          << "  in " << stateName(fsm.getState())
          << "\n";
}

void TCPConnection::printSegmentBrief(TCPSegment *tcpseg)
{
    tcpEV << "." << tcpseg->getSrcPort() << " > ";
    tcpEV << "." << tcpseg->getDestPort() << ": ";

    if (tcpseg->getSynBit())  tcpEV << (tcpseg->getAckBit() ? "SYN+ACK " : "SYN ");

    if (tcpseg->getFinBit())  tcpEV << "FIN(+ACK) ";

    if (tcpseg->getRstBit())  tcpEV << (tcpseg->getAckBit() ? "RST+ACK " : "RST ");

    if (tcpseg->getPshBit())  tcpEV << "PSH ";

    if (tcpseg->getPayloadLength() > 0 || tcpseg->getSynBit())
    {
        tcpEV << "[" << tcpseg->getSequenceNo() << ".." << (tcpseg->getSequenceNo() + tcpseg->getPayloadLength()) << ") ";
        tcpEV << "(l=" << tcpseg->getPayloadLength() << ") ";
    }

    if (tcpseg->getAckBit())  tcpEV << "ack " << tcpseg->getAckNo() << " ";

    tcpEV << "win " << tcpseg->getWindow() << " ";

    if (tcpseg->getUrgBit())  tcpEV << "urg " << tcpseg->getUrgentPointer() << " ";

    if (tcpseg->getHeaderLength() > TCP_HEADER_OCTETS) // Header options present? TCP_HEADER_OCTETS = 20
    {
        tcpEV << "options ";

        for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
        {
            const TCPOption& option = tcpseg->getOptions(i);
            short kind = option.getKind();
            tcpEV << optionName(kind) << " ";
        }
    }
    tcpEV << "\n";
}

void TCPConnection::scheduleTimeout(cMessage *msg, simtime_t timeout)
{
    tcpMain->scheduleAt(simTime()+timeout, msg);
}
cMessage *TCPConnection::cancelEvent(cMessage *msg) {
    return tcpMain->cancelEvent(msg);
}

#ifdef PRIVATE
/* Clone a connection for MPTCP */
TCPConnection *TCPConnection::cloneMPTCPConnection(bool active, uint64 token,IPvXAddress laddr, IPvXAddress raddr){
    TCPConnection *conn = NULL;

    if(tcpMain->multipath){

		conn = (active)?(new TCPConnection(tcpMain,appGateIndex,connId)):(new TCPConnection(tcpMain,0,0));
		conn->remoteAddr = raddr;
		conn->remotePort = remotePort;


		// MBE: in every case in INIT
        TCPOpenCommand *openCmd = new TCPOpenCommand();
        openCmd->setSendQueueClass(
             getTcpMain()->par("sendQueueClass"));
        openCmd->setReceiveQueueClass(
             getTcpMain()->par("receiveQueueClass"));
        openCmd->setTcpAlgorithmClass(
             getTcpMain()->par("tcpAlgorithmClass"));
        openCmd->setSubFlowNumber(token);
        openCmd->setFork(true);
        openCmd->setConnId(connId);
        // MBE: initiate handshake for subflow
        openCmd->setIsMptcpSubflow(true);
        conn->isSubflow = true;
        conn->flow = flow;
        conn->inlist = false;
		if(!active){
			cMessage *msg = new cMessage("PassiveOPEN", TCP_E_OPEN_PASSIVE); // Passive Server Side
		    conn->localAddr = localAddr;
		    conn->localPort = localPort;

		    openCmd->setLocalAddr(IPvXAddress("0.0.0.0"));
			openCmd->setLocalPort(localPort);

			msg->setControlInfo(openCmd);
			msg->setContextPointer(conn);

			FSM_Goto(conn->fsm, TCP_S_INIT);
			conn->processAppCommand(msg);   // init queues, etc

			// newSubflow->getTcpMain()->scheduleAt(simTime() + 0.00001, msg);
			FSM_Goto(conn->fsm, TCP_S_LISTEN);
			// Leave in status LISTEN
		}
		else{
			cMessage *msg = new cMessage("ActiveOPEN", TCP_C_OPEN_ACTIVE); // Client Side Connection
			// setup the subflow
			openCmd->setLocalAddr(laddr);
			openCmd->setLocalPort(localPort);
			openCmd->setRemoteAddr(raddr);
			openCmd->setRemotePort(remotePort);

			msg->setControlInfo(openCmd);
			msg->setContextPointer(conn);
			FSM_Goto(conn->fsm, TCP_S_INIT);
			conn->processAppCommand(msg);  // init queues, etc
			// Leave in status INET
		}
		// Clean up stuff
		conn->removeVectors();

		// rename

		conn->renameMPTCPVectors();

		// check some configuration stuff
		conn->getState()->nagle_enabled = this->getState()->nagle_enabled;
		conn->getState()->delayed_acks_enabled = this->getState()->delayed_acks_enabled;
		conn->getState()->limited_transmit_enabled = this->getState()->limited_transmit_enabled;
		conn->getState()->increased_IW_enabled = this->getState()->increased_IW_enabled;
		conn->getState()->ws_support = this->getState()->ws_support;

		conn->getState()->snd_ws = this->getState()->snd_ws;
		conn->getState()->rcv_ws = this->getState()->rcv_ws;
		conn->getState()->rcv_wnd_scale = this->getState()->rcv_wnd_scale;
		conn->getState()->snd_wnd_scale = this->getState()->snd_wnd_scale;

		conn->getState()->ts_support = this->getState()->ts_support;
		conn->getState()->ts_enabled = this->getState()->ts_enabled;
		conn->getState()->snd_initial_ts = this->getState()->snd_initial_ts;
		conn->getState()->rcv_initial_ts = this->getState()->rcv_initial_ts;
		// TIMESTAMP related variables
		conn->getState()->sack_support = this->getState()->sack_support;
		conn->getState()->sack_enabled = this->getState()->sack_enabled;
		conn->getState()->ws_enabled = this->getState()->ws_enabled;
		conn->getState()->last_ack_sent = 0;
#ifndef PRIVATE
		conn->getState()->pipe = 0;
		conn->getState()->sackedBytes = 0;
#endif
		conn->getState()->dupacks = 0;
		conn->getState()->sendQueueLimit = this->getState()->sendQueueLimit;
		conn->transferMode = this->transferMode;
		conn->todelete = true;
		conn->inlist = false;
		return conn;    // this is our new connection
    }
    else return NULL;
}

void TCPConnection::removeVectors(){
	// remove old names
	if(sndWndVector != NULL) delete sndWndVector;
	sndWndVector = NULL;
	if(rcvWndVector != NULL) delete rcvWndVector;
	rcvWndVector = NULL;
	if(rcvAdvVector != NULL) delete rcvAdvVector;
	rcvAdvVector = NULL;
	if(sndNxtVector != NULL) delete sndNxtVector;
	sndNxtVector = NULL;
	if(sndAckVector != NULL) delete sndAckVector;
	sndAckVector = NULL;
	if(rcvSeqVector != NULL) delete rcvSeqVector;
	rcvSeqVector = NULL;
	if(rcvAckVector != NULL) delete rcvAckVector;
	rcvAckVector = NULL;
	if(unackedVector != NULL) delete unackedVector;
	unackedVector = NULL;
	if(dupAcksVector != NULL) delete dupAcksVector;
	dupAcksVector = NULL;
	if(sndSacksVector != NULL) delete sndSacksVector;
	sndSacksVector = NULL;
	if(rcvSacksVector != NULL) delete rcvSacksVector;
	rcvSacksVector = NULL;
	if(rcvOooSegVector != NULL) delete rcvOooSegVector;
	rcvOooSegVector = NULL;
	if(tcpRcvQueueBytesVector != NULL) delete tcpRcvQueueBytesVector;
	tcpRcvQueueBytesVector = NULL;
	if(tcpRcvQueueDropsVector != NULL) delete tcpRcvQueueDropsVector;
	tcpRcvQueueDropsVector = NULL;
	if(pipeVector != NULL) delete pipeVector;
	pipeVector = NULL;
	if(sackedBytesVector != NULL) delete sackedBytesVector;
	sackedBytesVector = NULL;

	// MPTCP Vectors
	if(scheduledBytesVector != NULL) delete scheduledBytesVector;
	scheduledBytesVector = NULL;

}

void TCPConnection::renameMPTCPVectors(){
	char name[255];
	sprintf(name,"[subflow][send window] %i%i", connId, subflowID);
	sndWndVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][receive window] %i%i",connId, subflowID);
	rcvWndVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][advertised window] %i%i",connId, subflowID);
	rcvAdvVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][sent seq] %i%i",connId, subflowID);
	sndNxtVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][sent ack] %i%i",connId, subflowID);
	sndAckVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][rcvd seq] %i%i",connId, subflowID);
	rcvSeqVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][rcvd ack] %i%i",connId, subflowID);
	rcvAckVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][unacked bytes] %i%i",connId, subflowID);
	unackedVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][rcvd dupAcks] %i%i",connId, subflowID);
	dupAcksVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][pipe] %i%i",connId, subflowID);
	pipeVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][sent sacks] %i%i",connId, subflowID);
	sndSacksVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][rcvd sacks] %i%i",connId, subflowID);
	rcvSacksVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][rcvd oooseg] %i%i",connId, subflowID);
	rcvOooSegVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][rcvd sackedBytes] %i%i",connId, subflowID);
	sackedBytesVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][tcpRcvQueueBytes] %i%i",connId, subflowID);
	tcpRcvQueueBytesVector = new cOutVector(name);
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][tcpRcvQueueDrops] %i%i",connId, subflowID);
	tcpRcvQueueDropsVector = new cOutVector(name);

	// MPTCP Vectors
	memset(name,'\0',sizeof(name));
	sprintf(name,"[subflow][scheduledBytes] %i%i",connId, subflowID);
	scheduledBytesVector = new cOutVector(name);

}
#endif // PRIVATE (includes complete methods)

TCPConnection *TCPConnection::cloneListeningConnection()
{
    TCPConnection *conn = new TCPConnection(tcpMain, appGateIndex, connId);

    conn->transferMode = transferMode;
    // following code to be kept consistent with initConnection()
    const char *sendQueueClass = sendQueue->getClassName();
    conn->sendQueue = check_and_cast<TCPSendQueue *>(createOne(sendQueueClass));
    conn->sendQueue->setConnection(conn);

    const char *receiveQueueClass = receiveQueue->getClassName();
    conn->receiveQueue = check_and_cast<TCPReceiveQueue *>(createOne(receiveQueueClass));
    conn->receiveQueue->setConnection(conn);

    // create SACK retransmit queue
#ifndef PRIVATE
    rexmitQueue = new TCPSACKRexmitQueue();
    rexmitQueue->setConnection(this);
#endif

    const char *tcpAlgorithmClass = tcpAlgorithm->getClassName();
    conn->tcpAlgorithm = check_and_cast<TCPAlgorithm *>(createOne(tcpAlgorithmClass));
    conn->tcpAlgorithm->setConnection(conn);

    conn->state = conn->tcpAlgorithm->getStateVariables();
    configureStateVariables();
    conn->tcpAlgorithm->initialize();

    // put it into LISTEN, with our localAddr/localPort
    conn->state->active = false;
    conn->state->fork = true;
    conn->localAddr = localAddr;
    conn->localPort = localPort;

#ifdef PRIVATE
    // We don t need it, and it is overhead, but rename it when multipath
    if(tcpMain->multipath){
		// Clean up stuff
		conn->removeVectors();
		conn->renameMPTCPVectors();
		conn->transferMode = this->transferMode;
		conn->todelete = true;
		conn->inlist = false;
		conn->getState()->ws_enabled = this->getState()->ws_enabled;
    }
#endif // PRIVATE

    FSM_Goto(conn->fsm, TCP_S_LISTEN);

    return conn;
}

void TCPConnection::sendToIP(TCPSegment *tcpseg)
{
    if(tcpseg->getSequenceNo() == 297867)
        std::cerr << " STOP  " << std::endl;
    // record seq (only if we do send data) and ackno
    if (sndNxtVector && tcpseg->getPayloadLength() != 0)
        sndNxtVector->record(tcpseg->getSequenceNo());

    if (sndAckVector)
        sndAckVector->record(tcpseg->getAckNo());

    // final touches on the segment before sending
    tcpseg->setSrcPort(localPort);
    tcpseg->setDestPort(remotePort);
    ASSERT(tcpseg->getHeaderLength() >= TCP_HEADER_OCTETS);     // TCP_HEADER_OCTETS = 20 (without options)
    ASSERT(tcpseg->getHeaderLength() <= TCP_MAX_HEADER_OCTETS); // TCP_MAX_HEADER_OCTETS = 60
    tcpseg->setByteLength(tcpseg->getHeaderLength() + tcpseg->getPayloadLength());
    state->sentBytes = tcpseg->getPayloadLength(); // resetting sentBytes to 0 if sending a segment without data (e.g. ACK)

    tcpEV << "Sending: ";
    printSegmentBrief(tcpseg);

    // TBD reuse next function for sending

    if (!remoteAddr.isIPv6())
    {
        // send over IPv4
        IPv4ControlInfo *controlInfo = new IPv4ControlInfo();
        controlInfo->setProtocol(IP_PROT_TCP);
        controlInfo->setSrcAddr(localAddr.get4());
        controlInfo->setDestAddr(remoteAddr.get4());
        tcpseg->setControlInfo(controlInfo);

        tcpMain->send(tcpseg, "ipOut");
    }
    else
    {
        // send over IPv6
        IPv6ControlInfo *controlInfo = new IPv6ControlInfo();
        controlInfo->setProtocol(IP_PROT_TCP);
        controlInfo->setSrcAddr(localAddr.get6());
        controlInfo->setDestAddr(remoteAddr.get6());
        tcpseg->setControlInfo(controlInfo);

        tcpMain->send(tcpseg, "ipv6Out");
    }
    // std::cerr << "Send Over..." << localAddr.str() << ".." << remoteAddr.str() << std::endl;
}

void TCPConnection::sendToIP(TCPSegment *tcpseg, IPvXAddress src, IPvXAddress dest)
{
    tcpEV << "Sending: ";
    printSegmentBrief(tcpseg);

    if (!dest.isIPv6())
    {
        // send over IPv4
        IPv4ControlInfo *controlInfo = new IPv4ControlInfo();
        controlInfo->setProtocol(IP_PROT_TCP);
        controlInfo->setSrcAddr(src.get4());
        controlInfo->setDestAddr(dest.get4());
        tcpseg->setControlInfo(controlInfo);

        check_and_cast<TCP *>(simulation.getContextModule())->send(tcpseg, "ipOut");
    }
    else
    {
        // send over IPv6
        IPv6ControlInfo *controlInfo = new IPv6ControlInfo();
        controlInfo->setProtocol(IP_PROT_TCP);
        controlInfo->setSrcAddr(src.get6());
        controlInfo->setDestAddr(dest.get6());
        tcpseg->setControlInfo(controlInfo);

        check_and_cast<TCP *>(simulation.getContextModule())->send(tcpseg, "ipv6Out");
    }
}

TCPSegment *TCPConnection::createTCPSegment(const char *name)
{
    return new TCPSegment(name);
}

void TCPConnection::signalConnectionTimeout()
{
    sendIndicationToApp(TCP_I_TIMED_OUT);
}

void TCPConnection::sendIndicationToApp(int code, const int id)
{
#ifdef PRIVATE
    // MBE: check if it is a good idea to request for further messages
//    if(this->getState()->send_fin || this->getState()->fin_rcvd)
//        return; // I think no
    switch (code)
    {
        case(TCP_I_DATA): break;
        case(TCP_I_URGENT_DATA): break;
        case(TCP_I_ESTABLISHED): break;
        case(TCP_I_PEER_CLOSED): break;
        case(TCP_I_CLOSED): break;
        case(TCP_I_CONNECTION_REFUSED): break;
        case(TCP_I_CONNECTION_RESET): break;
        case(TCP_I_TIMED_OUT): break;
        case(TCP_I_STATUS): break;
        case(TCP_I_SEND_MSG):
            if (state->send_fin){
                return;
            }

            break;
        default: break;
    }

#endif // PRIVATE
    tcpEV << "Notifying app: " << indicationName(code) << "\n";
    cMessage *msg = new cMessage(indicationName(code));
    msg->setKind(code);
    TCPConnectInfo *ind = new TCPConnectInfo();
    ind->setConnId(connId);
    ind->setUserId(id);
    msg->setControlInfo(ind);
    sendToApp(msg);
}

void TCPConnection::sendEstabIndicationToApp()
{
#ifdef PRIVATE
    isQueueAble = true;
    if(tcpMain->multipath){
        if(flow->sendEstablished){
            return; // we need no notification message
        }
        this->flow->sendEstablished = true;
    }

#endif // PRIVATE
    tcpEV << "Notifying app: " << indicationName(TCP_I_ESTABLISHED) << "\n";
    cMessage *msg = new cMessage(indicationName(TCP_I_ESTABLISHED));
    msg->setKind(TCP_I_ESTABLISHED);

    TCPConnectInfo *ind = new TCPConnectInfo();
    ind->setConnId(connId);
    ind->setLocalAddr(localAddr);
    ind->setRemoteAddr(remoteAddr);
    ind->setLocalPort(localPort);
    ind->setRemotePort(remotePort);

    msg->setControlInfo(ind);
    sendToApp(msg);
    // FIXME - Work around bis add_addr
    //sendIndicationToApp(TCP_I_SEND_MSG, 3*state->snd_mss);
    sendAck();
}

void TCPConnection::sendToApp(cMessage *msg)
{
#ifdef PRIVATE
    if((tcpMain->multipath) && (flow != NULL) &&  (msg->getKind()==TCP_I_DATA)){
        delete msg;
    }
    else
#endif
        tcpMain->send(msg, "appOut", appGateIndex);
}



void TCPConnection::initConnection(TCPOpenCommand *openCmd)
{
    transferMode = TCP_TRANSFER_OBJECT; // FIXME Merge (TCPDataTransferMode)(openCmd->getDataTransferMode());

    // create send queue
    sendQueue = tcpMain->createSendQueue(transferMode);
    sendQueue->setConnection(this);

    // create receive queue
    receiveQueue = tcpMain->createReceiveQueue(transferMode);
    receiveQueue->setConnection(this);
#ifndef PRIVATE
    // create SACK retransmit queue
    rexmitQueue = new TCPSACKRexmitQueue();
    rexmitQueue->setConnection(this);
#endif
    // create algorithm
#ifdef PRIVATE

    if(this->getTcpMain()->multipath){
        if(this->getTcpMain()->isRFC6356){
               tcpAlgorithm = check_and_cast<TCPAlgorithm *>(createOne("MPTCP_RFC6356"));
        }
        else{
            const char *tcpAlgorithmClass = openCmd->getTcpAlgorithmClass();
            if (!tcpAlgorithmClass || !tcpAlgorithmClass[0])
               tcpAlgorithmClass = tcpMain->par("tcpAlgorithmClass");
            tcpAlgorithm = check_and_cast<TCPAlgorithm *>(createOne(tcpAlgorithmClass));
        }
    }
    else {
#endif
    const char *tcpAlgorithmClass = openCmd->getTcpAlgorithmClass();
    if (!tcpAlgorithmClass || !tcpAlgorithmClass[0])
        tcpAlgorithmClass = tcpMain->par("tcpAlgorithmClass");

    tcpAlgorithm = check_and_cast<TCPAlgorithm *>(createOne(tcpAlgorithmClass));
#ifdef PRIVATE
    }
#endif
    tcpAlgorithm->setConnection(this);

    // create state block
    state = tcpAlgorithm->getStateVariables();
    configureStateVariables();
    tcpAlgorithm->initialize();

#ifdef PRIVATE
        if(getTcpMain()->multipath){
        	openCmd->getSubFlowNumber();
        	joinToAck = false;
        	joinToSynAck = false;
        }
#endif // PRIVATE
}

void TCPConnection::configureStateVariables()
{
    long advertisedWindowPar = tcpMain->par("advertisedWindow").longValue();
    state->ws_support = tcpMain->par("windowScalingSupport"); // if set, this means that current host supports WS (RFC 1323)

    if (!state->ws_support && (advertisedWindowPar > TCP_MAX_WIN || advertisedWindowPar <= 0))
        throw cRuntimeError("Invalid advertisedWindow parameter: %ld", advertisedWindowPar);
    state->rcv_wnd = advertisedWindowPar;
    state->rcv_adv = advertisedWindowPar;
    if(this->getTcpMain()->multipath && (flow!=NULL)){
        flow->mptcp_rcv_wnd = advertisedWindowPar;
        flow->mptcp_rcv_adv = advertisedWindowPar;
    }
    if (state->ws_support && advertisedWindowPar > TCP_MAX_WIN)
    {
        state->rcv_wnd = TCP_MAX_WIN; // we cannot to guarantee that the other end is also supporting the Window Scale (header option) (RFC 1322)
        state->rcv_adv = TCP_MAX_WIN; // therefore TCP_MAX_WIN is used as initial value for rcv_wnd and rcv_adv
    }

    state->maxRcvBuffer = advertisedWindowPar;
    state->delayed_acks_enabled = tcpMain->par("delayedAcksEnabled"); // delayed ACK algorithm (RFC 1122) enabled/disabled
    state->nagle_enabled = tcpMain->par("nagleEnabled"); // Nagle's algorithm (RFC 896) enabled/disabled
    state->limited_transmit_enabled = tcpMain->par("limitedTransmitEnabled"); // Limited Transmit algorithm (RFC 3042) enabled/disabled
    state->increased_IW_enabled = tcpMain->par("increasedIWEnabled"); // Increased Initial Window (RFC 3390) enabled/disabled
    state->snd_mss = tcpMain->par("mss").longValue(); // Maximum Segment Size (RFC 793)
    state->ts_support = tcpMain->par("timestampSupport"); // if set, this means that current host supports TS (RFC 1323)
    state->sack_support = tcpMain->par("sackSupport"); // if set, this means that current host supports SACK (RFC 2018, 2883, 3517)

#ifdef PRIVATE
    if(strcmp((const char*)tcpMain->par("cmtBufferOptimizationLevel"), "none") == 0) {
        state->cmtBufferOptimizationLevel = TCPStateVariables::C_None;
    }
    else if(strcmp((const char*)tcpMain->par("cmtBufferOptimizationLevel"), "SCTPlikeGlobecom") == 0) {
            state->cmtBufferOptimizationLevel = TCPStateVariables::C_SCTPlikeGlobecom;
    }
    else {
        throw cRuntimeError("Bad setting for cmtBufferOptimizationLevel: %s\n",
                 (const char*)tcpMain->par("cmtBufferOptimizationLevel"));
    }
    switch(state->cmtBufferOptimizationLevel){
    case TCPStateVariables::C_SCTPlikeGlobecom:
        if(strcmp((const char*)tcpMain->par("cmtBufferSplitVariant"), "none") == 0) {
            state->cmtBufferSplitVariant = TCPStateVariables::C_SCTPlikeGlobecom_None;
        }
        else if(strcmp((const char*)tcpMain->par("cmtBufferSplitVariant"), "senderOnly") == 0) {
           state->cmtBufferSplitVariant = TCPStateVariables:: C_SCTPlikeGlobecom_SenderOnly;
        }
        else if(strcmp((const char*)tcpMain->par("cmtBufferSplitVariant"), "receiverOnly") == 0) {
           state->cmtBufferSplitVariant = TCPStateVariables:: C_SCTPlikeGlobecom_ReceiverOnly;
        }
        else if(strcmp((const char*)tcpMain->par("cmtBufferSplitVariant"), "bothSides") == 0) {
           state->cmtBufferSplitVariant = TCPStateVariables::C_SCTPlikeGlobecom_BothSides;
        }
        else {
           throw cRuntimeError("Bad setting for cmtBufferSplitVariant: %s\n",
                    (const char*)tcpMain->par("cmtBufferSplitVariant"));
        }
        break;
    case TCPStateVariables::C_MPTCPlike:
        break;
    case TCPStateVariables::C_None:
        break;
    default:
        throw cRuntimeError("Bad setting for cmtBufferOptimizationLevel: %s\n",
                          (const char*)tcpMain->par("cmtBufferOptimizationLevel"));
    }
#endif

    if (state->sack_support)
    {
        std::string algorithmName1 = "TCPReno";
        std::string algorithmName3 = "TCPNewReno";
        std::string algorithmName2 = tcpMain->par("tcpAlgorithmClass");


        if ((algorithmName1 != algorithmName2) && (algorithmName3 != algorithmName2)) // TODO add additional checks for new SACK supporting algorithms here once they are implemented
        {
            EV << "If you want to use TCP SACK please set tcpAlgorithmClass to TCPReno\n";

            ASSERT(false);
        }
#ifdef PRIVATE
        // TODO ... Here add new SACK variants
       SACK_BLOCK = new SACK_RFC3517(this);
#endif
    }
}

void TCPConnection::selectInitialSeqNum()
{
    // set the initial send sequence number
    state->iss = (unsigned long)fmod(SIMTIME_DBL(simTime()) * 250000.0, 1.0 + (double)(unsigned)0xffffffffUL) & 0xffffffffUL;
    state->snd_una = state->snd_max = state->iss;
    state->setSndNxt(state->iss);
    sendQueue->init(state->iss + 1); // + 1 is for SYN

#ifndef PRIVATE

    rexmitQueue->init(state->iss + 1); // + 1 is for SYN
#else
    if(state->sack_enabled)
        SACK_BLOCK->initial();
    if(tcpMain->multipath){
        base_una_dss_info.subflow_seq = state->iss;
    }
#endif
}

bool TCPConnection::isSegmentAcceptable(TCPSegment *tcpseg) const
{
    // check that segment entirely falls in receive window
    // RFC 793, page 69:
    // "There are four cases for the acceptability test for an incoming segment:
    //    Segment Receive  Test
    //    Length  Window
    //    ------- -------  -------------------------------------------
    //       0       0     SEG.SEQ = RCV.NXT
    //       0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    //      >0       0     not acceptable
    //      >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    //                  or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND"
    uint32 len = tcpseg->getPayloadLength();
    uint32 seqNo = tcpseg->getSequenceNo();
    uint32 ackNo = tcpseg->getAckNo();
    uint32 rcvWndEnd = 0;

    rcvWndEnd = state->rcv_nxt + state->rcv_wnd;
    bool ret;

    if (len == 0)
    {
        if (state->rcv_wnd == 0){
            std::cerr << "Too high sqn for arwn = 0: " <<  seqNo - state->rcv_nxt << std::endl;
            ret = false; // FIXME (seqNo == state->rcv_nxt);
        }
        else // rcv_wnd > 0
            ret = seqLE(state->rcv_nxt, seqNo) && seqLE(seqNo, rcvWndEnd); // Accept an ACK on end of window
    }
    else // len > 0
    {
        if (state->rcv_wnd == 0)
            ret = false; // FIXME false;
        else // rcv_wnd > 0
            ret = (seqLE(state->rcv_nxt, seqNo) && seqLess(seqNo, rcvWndEnd))
                    || (seqLess(state->rcv_nxt, seqNo + len) && seqLE(seqNo + len, rcvWndEnd)); // Accept an ACK on end of window
    }

    // RFC 793, page 25:
    // "A new acknowledgment (called an "acceptable ack"), is one for which
    // the inequality below holds:
    //    SND.UNA < SEG.ACK =< SND.NXT"
    if (!ret && len == 0)
    {
        if (!state->afterRto)
            ret = (seqLess(state->snd_una, ackNo) && seqLE(ackNo, state->getSndNxt()));
        else
            ret = (seqLess(state->snd_una, ackNo) && seqLE(ackNo, state->snd_max)); // after RTO snd_nxt is reduced therefore we need to use snd_max instead of snd_nxt here
    }

    if (!ret)
        tcpEV << "Not Acceptable segment. seqNo=" << seqNo << " ackNo=" << ackNo << " len=" << len << " rcv_nxt="
              << state->rcv_nxt  << " rcv_wnd=" << state->rcv_wnd << " afterRto=" << state->afterRto << "\n";
    return ret;
}

void TCPConnection::sendSyn()
{
    if (remoteAddr.isUnspecified() || remotePort == -1)
        throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: foreign socket unspecified");

    if (localPort == -1)
        throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: local port unspecified");

#ifdef PRIVATE
        // Don t understand why this should be done, because it is don in updateRcvWnd

        // Update WS variables
        ulong scaled_rcv_wnd = state->maxRcvBuffer;
        state->rcv_wnd_scale = 0;

        while (scaled_rcv_wnd > TCP_MAX_WIN && state->rcv_wnd_scale < 14) // RFC 1323, page 11: "the shift count must be limited to 14"
        {
            scaled_rcv_wnd = scaled_rcv_wnd >> 1;
            state->rcv_wnd_scale++;
        }
#endif
    // create segment
    TCPSegment *tcpseg = createTCPSegment("SYN");
    tcpseg->setSequenceNo(state->iss);
    tcpseg->setSynBit(true);
    // No scaling on a syn - but I ignore FIXME
    tcpseg->setWindow(TCP_MAX_WIN);

    state->setSndNxt(state->iss + 1);
    state->snd_mptcp_syn = true;
    // write header options
#ifdef PRIVATE
    // Redirect
    base_una_dss_info.subflow_seq = state->snd_max - 1;
    writeHeaderOptionsWithMPTCP(tcpseg, 0);
#else
    writeHeaderOptions(tcpseg);
#endif // PRIVATE

    // send it
    sendToIP(tcpseg);
}

void TCPConnection::sendSynAck()
{
    // create segment
    TCPSegment *tcpseg = createTCPSegment("SYN+ACK");
    tcpseg->setSequenceNo(state->iss);
    tcpseg->setAckNo(state->rcv_nxt);
    tcpseg->setSynBit(true);
    tcpseg->setAckBit(true);
#ifdef PRIVATE
        // Don t understand why this should be done, because it is don in updateRcvWnd

        // Update WS variables
        ulong scaled_rcv_wnd = state->maxRcvBuffer;
        state->rcv_wnd_scale = 0;

        while (scaled_rcv_wnd > TCP_MAX_WIN && state->rcv_wnd_scale < 14) // RFC 1323, page 11: "the shift count must be limited to 14"
        {
            scaled_rcv_wnd = scaled_rcv_wnd >> 1;
            state->rcv_wnd_scale++;
        }
#endif
    // No scaling on a syn - but i ignore FIXME
    tcpseg->setWindow(TCP_MAX_WIN);
    state->setSndNxt(state->iss + 1);
    // write header options
#ifdef PRIVATE
    // Redirect
    base_una_dss_info.subflow_seq = state->snd_max - 1;
    writeHeaderOptionsWithMPTCP(tcpseg, 0);
#else
    writeHeaderOptions(tcpseg);
#endif

    // send it
    sendToIP(tcpseg);

    // notify
    tcpAlgorithm->ackSent();
}

void TCPConnection::sendRst(uint32 seqNo)
{
    sendRst(seqNo, localAddr, remoteAddr, localPort, remotePort);
}

void TCPConnection::sendRst(uint32 seq, IPvXAddress src, IPvXAddress dest, int srcPort, int destPort)
{
    TCPSegment *tcpseg = createTCPSegment("RST");

    tcpseg->setSrcPort(srcPort);
    tcpseg->setDestPort(destPort);

    tcpseg->setRstBit(true);
    tcpseg->setSequenceNo(seq);

    // send it
    sendToIP(tcpseg, src, dest);
}

void TCPConnection::sendRstAck(uint32 seq, uint32 ack, IPvXAddress src, IPvXAddress dest, int srcPort, int destPort)
{
    TCPSegment *tcpseg = createTCPSegment("RST+ACK");

    tcpseg->setSrcPort(srcPort);
    tcpseg->setDestPort(destPort);

    tcpseg->setRstBit(true);
    tcpseg->setAckBit(true);
    tcpseg->setSequenceNo(seq);
    tcpseg->setAckNo(ack);

    // send it
    sendToIP(tcpseg, src, dest);

    if (tcpAlgorithm)
    if (tcpAlgorithm)
        tcpAlgorithm->ackSent();
}

void TCPConnection::sendAck()
{
    TCPSegment *tcpseg = createTCPSegment("ACK");
    tcpseg->setAckBit(true);
    tcpseg->setSequenceNo(state->getSndNxt());
    tcpseg->setAckNo(state->rcv_nxt);

    tcpseg->setWindow(updateRcvWnd());



    // write header options
#ifdef PRIVATE
    writeHeaderOptionsWithMPTCP(tcpseg, 0);
#else
    writeHeaderOptions(tcpseg);
#endif
    // send it
    sendToIP(tcpseg);

    // notify
    tcpAlgorithm->ackSent();
}

void TCPConnection::sendFin()
{
    TCPSegment *tcpseg = createTCPSegment("FIN");

    // Note: ACK bit *must* be set for both FIN and FIN+ACK. What makes
    // the difference for FIN+ACK is that its ackNo acks the remote TCP's FIN.
    tcpseg->setFinBit(true);
    tcpseg->setAckBit(true);
    tcpseg->setAckNo(state->rcv_nxt);
    tcpseg->setSequenceNo(state->getSndNxt());
    tcpseg->setWindow(updateRcvWnd());

    // send it
    sendToIP(tcpseg);
    // notify
    tcpAlgorithm->ackSent();
}
#ifdef PRIVATE
bool TCPConnection::SCTPlikeBufferSplittingGlobecom(){
    // ------ Sender Side -------------------------------------
      if( (state->cmtBufferSplitVariant == TCPStateVariables::C_SCTPlikeGlobecom_SenderOnly) ||
          (state->cmtBufferSplitVariant == TCPStateVariables::C_SCTPlikeGlobecom_BothSides) ) {

         // Limit is 1/n of current sender-side buffer allocation
         const uint32 limit = ((state->sendQueueLimit != 0) ? state->sendQueueLimit : 0xffffffff) / this->flow->getSubflows()->size();
         if((state->snd_max + state->snd_una) + state->snd_mss > limit) {
             return false;
         }
      }

      // ------ Receiver Side -----------------------------------
      if(
          ( (state->cmtBufferSplitVariant == TCPStateVariables::C_SCTPlikeGlobecom_ReceiverOnly) ||
            (state->cmtBufferSplitVariant == TCPStateVariables::C_SCTPlikeGlobecom_BothSides) ) ) {

          // TODO
          ASSERT(false && "TODO");

      }
      return true;
}
#endif

bool TCPConnection::MPTCPlikeBufferSplitting(uint32 bytes){
    // Is there a message marked for retransmission

    // Do penalization
    // decrease the window of the  "slowest" path

    // In every RTT check and penalization

    // If penalization aktivated and we have no send side blocking (enough snd buffer memory)

    // Check for other sending queues if there exists a srrt 4 time less than the current path

    return false;
}


bool TCPConnection::sendSegment(uint32 bytes)
{
    if (state->sack_enabled && state->afterRto)
    {

        // check rexmitQ and try to forward snd_nxt before sending new data
#ifndef PRIVATE
        uint32 forward = 0;
        if(rexmitQueue->getQueueLength() > 0)
            forward = rexmitQueue->checkRexmitQueueForSackedOrRexmittedSegments(state->snd_nxt);

        if (forward > 0)
        {
            tcpEV << "sendSegment(" << bytes << ") forwarded " << forward << " bytes of snd_nxt from " << state->snd_nxt;
            state->snd_nxt += forward;
            tcpEV << " to "<< state->snd_nxt << endl;
            rexmitQueue->info();
        }
#else
        // FIXME
        // state->snd_nxt += SACK_BLOCK->do_forward();

#endif
    }
#ifdef PRIVATE
    if(this->getTcpMain()->multipath && this->isSubflow) {
        switch(state->cmtBufferOptimizationLevel){

        case TCPStateVariables::C_None:
            // turn all Bufferoptimization off
            break;
        case TCPStateVariables::C_SCTPlikeGlobecom:
            if(!SCTPlikeBufferSplittingGlobecom()) return false; // avoid of buffer blocking by buffer splitting
            break;
        case TCPStateVariables::C_MPTCPlike:
            if(!MPTCPlikeBufferSplitting(bytes)) return false; // avoid of buffer blocking by buffer splitting
            break;
        default:
            throw cRuntimeError("Bad setting for cmtBufferOptimizationLevel: %s\n",
                                   (const char*)getTcpMain()->par("cmtBufferOptimizationLevel"));
        }
    }
#endif
    ulong buffered = 0;
    uint start_offset = 0;
    buffered = sendQueue->getBytesAvailable(state->getSndNxt() + start_offset);


    if(buffered == 0){
        return false;
    }
    if (bytes > buffered) // last segment?
        bytes = buffered;

    // if header options will be added, this could reduce the number of data bytes allowed for this segment,
    // because following condition must to be respected:
    //     bytes + options_len <= snd_mss
    TCPSegment *tcpseg_temp = createTCPSegment(NULL);
    tcpseg_temp->setAckBit(true); // needed for TS option, otherwise TSecr will be set to 0

#ifdef PRIVATE
    updateRcvWnd();
    // redirect
    writeHeaderOptionsWithMPTCP(tcpseg_temp, bytes);
#else
    writeHeaderOptions(tcpseg_temp);
#endif // PRIVATE

    uint options_len = tcpseg_temp->getHeaderLength() - TCP_HEADER_OCTETS; // TCP_HEADER_OCTETS = 20

    ASSERT(options_len < state->snd_mss);

    if (bytes + options_len > state->snd_mss)
        bytes = std::min(bytes,(state->snd_mss - options_len));

    if(bytes == 0){
        // OH, option written but nothing send;  Ok we have to correct the mptcp staff
        if(tcpMain->multipath && (flow!=NULL)){
            TCPMultipathDSSStatus::const_iterator it = dss_dataMapofSubflow.find(state->getSndNxt());
            if(it != dss_dataMapofSubflow.end()){
                dss_dataMapofSubflow.erase(state->getSndNxt());
            }
        }

        return false;
    }

    state->sentBytes = bytes;

#ifndef PRIVATE
    // send one segment of 'bytes' bytes from snd_nxt, and advance snd_nxt
    TCPSegment *tcpseg  = sendQueue->createSegmentWithBytes(state->snd_nxt, bytes);
#else // FIXME Something goes wrong here
    TCPSegment* tcpseg  = sendQueue->createSegmentWithBytes(state->getSndNxt(), bytes);
    cMessage*   msg_tmp = check_and_cast<cMessage*> (tcpseg);
        // OK if we send it over another module, we have to dup this message
    if(msg_tmp->getOwner() != this->getTcpMain()){
        throw cRuntimeError("Why we are not Owner? - something goes wrong here");
    }
#endif // PRIVATE

    // if sack_enabled copy region of tcpseg to rexmitQueue
#ifdef PRIVATE
    bool doenq = true;
    if(this->getTcpMain()->multipath)
        if(this->flow->isFIN)
            doenq = false;
    if(doenq)
#endif // PRIVATE
#ifndef PRIVATE
    if (state->sack_enabled && (!this->getState()->fin_rcvd) && (!this->getState()->send_fin) && (!state->isRTX))
        rexmitQueue->enqueueSentData(state->snd_nxt, state->snd_nxt + bytes);
#else
   // if (state->sack_enabled)
   //         SACK_BLOCK->enqueueSACKReceiver(bytes);
   // Warum?
#endif
    tcpseg->setAckNo(state->rcv_nxt);
    tcpseg->setAckBit(true);
    tcpseg->setWindow(updateRcvWnd());

    // TBD when to set PSH bit?
    // TBD set URG bit if needed
    ASSERT(bytes == tcpseg->getPayloadLength());

    
    state->setSndNxt(state->getSndNxt() + bytes);

    // check if afterRto bit can be reset
    if (state->afterRto && seqGE(state->getSndNxt(), state->snd_max))
        state->afterRto = false;
    if (state->send_fin && state->getSndNxt() == state->snd_fin_seq)
    {
        tcpEV << "Setting FIN on segment\n";
        tcpseg->setFinBit(true);
        state->setSndNxt(state->snd_fin_seq + 1);
    }
    
    // add header options and update header length (from tcpseg_temp)
    tcpseg->setOptionsArraySize(tcpseg_temp->getOptionsArraySize());

    for (uint i = 0; i < tcpseg_temp->getOptionsArraySize(); i++)
        tcpseg->setOptions(i, tcpseg_temp->getOptions(i));

    tcpseg->setHeaderLength(tcpseg_temp->getHeaderLength());
    delete tcpseg_temp;
    
    // send it
    sendToIP(tcpseg);

    return true;
}
bool TCPConnection::orderBytesForQueue(uint32 bytesToSend){
#ifdef PRIVATE
    // OK for Multipath
    ulong buffered = sendQueue->getBytesAvailable(state->getSndNxt() + bytesToSend);
    bool test = true;
    if(tcpMain->multipath && flow != NULL){
        bytesToSend += state->snd_mss;
        if(buffered < bytesToSend){
            // check if there are pre-buffered Data
            uint32 enq = 0;
            if(tmp_msg_buf->empty()){
                // sendKeepAlive(); FIXME Works not as expected
            }
            else{
                while(!tmp_msg_buf->empty()){
                    cPacket* pkt = tmp_msg_buf->front();
                    if(enq <= bytesToSend){ // ONLY COMPLETE MESSAGES -> We don t fragment user Messages
                        enq += pkt->getByteLength();
                        sendQueue->enqueueAppData(PK(pkt));
                        if(state->enqueued >= pkt->getByteLength())
                            state->enqueued -= pkt->getByteLength();
                        else // Overbooked
                            sendIndicationToApp(TCP_I_SEND_MSG, pkt->getByteLength());
                        tmp_msg_buf->pop();
                    }
                    else break;
                }
            }
        }
        else{
            if(getState()->enqueued > bytesToSend)
                getState()->enqueued -= bytesToSend;
    }
        uint32 inMainQueue = (tmp_msg_buf->size() * state->snd_mss);
        test = (inMainQueue < flow->mptcp_snd_wnd);
    }

    // In every case we should request for more data if needed
    buffered = sendQueue->getBytesAvailable(state->getSndNxt());
    uint32 abated = 0;
    if(getTcpMain()->request_for_data && (buffered  < (bytesToSend + getState()->snd_mss)) &&  (getState()->requested < (3*getState()->snd_mss)) && test){
        if(this->isSubflow)
            abated  = (getState()->sendQueueLimit >  (getState()->enqueued/flow->getSubflows()->size())) ? getState()->sendQueueLimit - (getState()->enqueued/flow->getSubflows()->size()) : 0;
        else{
            if(getState()->sendQueueLimit > buffered)
                abated  = (getState()->sendQueueLimit > buffered) ? getState()->sendQueueLimit - buffered : 0;
            else
                abated = 0;
        }
        if(abated && getState()->sendQueueLimit){
          abated = std::min(getState()->sendQueueLimit, abated);
          if( ((getState()->requested == 0) && (abated > (uint32)state->snd_mss))){
              getState()->requested += getState()->sendQueueLimit;
              sendIndicationToApp(TCP_I_SEND_MSG, getState()->sendQueueLimit);
          }
        }
        getTcpMain()->request_for_data  = false;
    }
    if(!buffered)
        return false;
    return true;
#endif
}
bool TCPConnection::sendData(bool fullSegmentsOnly, uint32 congestionWindow)
{
    // we'll start sending from snd_max, if not after RTO
    if(!state->afterRto)
        state->setSndNxt(state->snd_max);
    uint32 sent = 0;

// DEBUG
    static uint64 runtime = 0;
    uint64 run = runtime++;
//    if(run == 14880){
//        std::cerr << "found";
//    }
// end debug
    uint32 old_highRxt = 0;
#ifndef PRIVATE
    if (state->sack_enabled && (rexmitQueue->getQueueLength() > 0 ))
        old_highRxt = rexmitQueue->getHighestRexmittedSeqNum();
#else
    if (state->sack_enabled)
        old_highRxt = SACK_BLOCK->getHighRxt();
#endif

    // maxWindow is minimum of snd_wnd and congestionWindow (snd_cwnd)
    uint32 maxWindow = state->snd_wnd;
    long effectiveWin = 0;

#ifdef PRIVATE
    // MPTCP
    int32 onWire = 0;
    if(this->getTcpMain()->multipath && (flow != NULL)){

        flow->refreshSendMPTCPWindow();
        maxWindow = flow->mptcp_snd_wnd;

        // if not isQueueAble we are not allowed to send anywhere
        if(!this->isQueueAble)
           return false;

        // we have to check similar as for one flow, but above all
        const TCP_SubFlowVector_t *subflow_list = flow->getSubflows();
        for (TCP_SubFlowVector_t::const_iterator i = subflow_list->begin();
                  i != subflow_list->end(); i++) {
              TCPConnection *conn = (*i)->subflow;
              sent += conn->getState()->getSndNxt() - conn->getState()->snd_una;
        }
        onWire = std::max(sent,(uint32) ((flow->mptcp_snd_nxt - 1) - flow->mptcp_snd_una));
    }
#endif

    maxWindow = std::min(congestionWindow, maxWindow);
    if(maxWindow > (state->getSndNxt() - state->snd_una))
        effectiveWin = maxWindow - (state->getSndNxt() - state->snd_una);

#ifdef PRIVATE
    if(this->getTcpMain()->multipath && (flow != NULL)){
        while(effectiveWin && ((effectiveWin + onWire) > flow->mptcp_snd_wnd)){
            effectiveWin--;
        }
    }
#endif
    if (effectiveWin <= 0)
    {
        tcpEV << "Effective window is zero (advertised window " << state->snd_wnd <<
            ", congestion window " << congestionWindow << "), cannot send.\n";
        return false;
    }

    uint32 bytesToSend = effectiveWin;
    uint32 effectiveMaxBytesSend = state->snd_mss;// FIXME std::min(bytesToSend,state->snd_mss);
    // Organize data
    orderBytesForQueue(bytesToSend);
    ulong buffered = sendQueue->getBytesAvailable(state->getSndNxt());

    if(buffered == 0)
        return false; // No data

    if (bytesToSend > buffered)
        bytesToSend = buffered;

    if (state->ts_enabled)
        effectiveMaxBytesSend -= TCP_OPTION_TS_SIZE;

#ifdef PRIVATE
    // recalculate for MPTCP OPTIONS
    if(this->isSubflow){
        uint32 dss_option_offset = MP_DSS_OPTIONLENGTH_4BYTE;
        if(this->getTcpMain()->multipath_DSSSeqNo8)
          dss_option_offset += 4;
        if(this->getTcpMain()->multipath_DSSDataACK8)
          dss_option_offset += 4;
        effectiveMaxBytesSend -= dss_option_offset;
    }
#endif // PRIVATE

    // last segment could be less than state->snd_mss (or less than snd_mss - TCP_OPTION_TS_SIZE if using TS option)
    if (fullSegmentsOnly && (bytesToSend < (effectiveMaxBytesSend)))
    {
        tcpEV << "Cannot send, not enough data for a full segment (SMSS=" << state->snd_mss
            << ", effectiveWindow=" << effectiveWin << ", bytesToSend=" << bytesToSend << ", in buffer " << buffered << ")\n";
        return false;
    }

    // start sending 'bytesToSend' bytes
    tcpEV << "Will send " << bytesToSend << " bytes (effectiveWindow " << effectiveWin
        << ", in buffer " << buffered << " bytes)\n";

    uint32 old_snd_nxt = state->getSndNxt();

    ASSERT(bytesToSend > 0);

#ifdef TCP_SENDFRAGMENTS  /* normally undefined */
    // make agressive use of the window until the last byte
    while (bytesToSend > 0)
    {
        ulong bytes = std::min(bytesToSend, state->snd_mss);
        sendSegment(bytes);
        bytesToSend -= state->sentBytes;
    }
#else
    // send < MSS segments only if it's the only segment we can send now
    // Note: if (bytesToSend == 1010 && MSS == 1012 && ts_enabled == true) => we may send
    // 2 segments (1000 payload + 12 optionsHeader and 10 payload + 12 optionsHeader)
    // FIXME this should probably obey Nagle's alg -- to be checked
#ifndef PRIVATE
    if (bytesToSend <= state->snd_mss)
    {
        sendSegment(bytesToSend);
#else
    if (bytesToSend <= effectiveMaxBytesSend)
    {
        sendSegment(effectiveMaxBytesSend);
#endif
        bytesToSend -= state->sentBytes;
    }
    else // send whole segments only (nagle_enabled)
    {
        while (bytesToSend >= effectiveMaxBytesSend)
        {
            const ulong b0 = sendQueue->getBytesAvailable(state->getSndNxt());
#ifndef PRIVATE
            sendSegment(state->snd_mss);
#else
            if(!sendSegment(effectiveMaxBytesSend))
                break;
#endif // PRIVATE
            const ulong b1 = sendQueue->getBytesAvailable(state->getSndNxt());

            if(b0 - state->sentBytes != b1) {
                // FIXME: This happens sometimes when SACKs are enabled. Is this a bug?
                break;
            }
            if(bytesToSend > state->sentBytes)
                bytesToSend -= state->sentBytes;
            else
                bytesToSend = 0;
        }
    }

    // check how many bytes we have - last segment could be less than state->snd_mss
    buffered = sendQueue->getBytesAvailable(state->getSndNxt());

    if (bytesToSend == buffered && buffered != 0) // last segment?
        sendSegment(bytesToSend);
    else if (bytesToSend > 0)
        tcpEV << bytesToSend << " bytes of space left in effectiveWindow\n";
#endif

    if (unackedVector)
        unackedVector->record(state->snd_max - state->snd_una);

    // notify (once is enough)
    tcpAlgorithm->ackSent();

    if (state->sack_enabled && state->lossRecovery && (old_highRxt != SACK_BLOCK->getHighRxt()))
    {
        // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
        tcpEV << "Retransmission sent during recovery, restarting REXMIT timer.\n";
        tcpAlgorithm->restartRexmitTimer();
    }
    else // don't measure RTT for retransmitted packets
        tcpAlgorithm->dataSent(old_snd_nxt);

    orderBytesForQueue(state->snd_max - state->snd_una);
    return true;
}

bool TCPConnection::sendKeepAlive(){
    uint32 old = state->getSndNxt();
    state->setSndNxt(state->snd_una - 1);
    sendAck();
    state->setSndNxt(old);
    return true;
}

bool TCPConnection::sendProbe()
{
    // we'll start sending from snd_max
    state->setSndNxt(state->snd_max);

    // check we have 1 byte to send
    if (sendQueue->getBytesAvailable(state->getSndNxt()) == 0)
    {
        tcpEV << "Cannot send probe because send buffer is empty\n";
        return false;
    }

    uint32 old_snd_nxt = state->getSndNxt();

    tcpEV << "Sending 1 byte as probe, with seq=" << state->getSndNxt() << "\n";
    sendSegment(1);

    if (unackedVector)
        unackedVector->record(state->snd_max - state->snd_una);

    // notify
    tcpAlgorithm->ackSent();
    tcpAlgorithm->dataSent(old_snd_nxt);

    return true;
}

void TCPConnection::retransmitOneSegment(bool called_at_rto)
{
    uint32 old_snd_nxt = state->getSndNxt();

    // retransmit one segment at snd_una, and set snd_nxt accordingly (if not called at RTO)
    state->setSndNxt(state->snd_una);

#ifndef PRIVATE
   // When FIN sent the snd_max - snd_nxt larger than bytes available in queue
    ulong bytes = std::min((ulong)std::min(state->snd_mss, state->snd_max - state->snd_nxt),
            sendQueue->getBytesAvailable(state->snd_nxt));
#else
    // TODO I use my solution....Perhaps This should switched to the old above
    uint32 bytes = state->snd_mss; // FIXME, why is sometimes the queue empty for retransmission?
#endif // PRIVATE
    // FIN (without user data) needs to be resent
    if (bytes == 0 && state->send_fin && state->snd_fin_seq == sendQueue->getBufferEndSeq())
    {
        state->snd_max = sendQueue->getBufferEndSeq();
        tcpEV << "No outstanding DATA, resending FIN, advancing snd_nxt over the FIN\n";
        state->setSndNxt(state->snd_max);
        sendFin();
        state->setSndNxt(state->getSndNxt() + 1);

        if (unackedVector)
            unackedVector->record(state->snd_max - state->snd_una);
    }
    else
    {
        if(0==bytes){
            tcpEV << "No signal and no data for retransmission...something went wrong" << endl;
            if(state->fin_rcvd || flow->isFIN)
                return;
       //     throw cRuntimeError("No signal and no data for retransmission...something went wrong");
        }
        ASSERT(bytes != 0);
#ifdef PRIVATE
        // Not every packet has the same length
        // we have to figure out what is inside the SACK Queue
        // TRY SACK Fix
        bool doit = true;
        if(this->getTcpMain()->multipath)
            if(flow->isFIN)
                doit = false;
        if(doit)    // First try
#endif // PRIVATE

        sendSegment(bytes);
        state->highRxt = state->getSndNxt() + 1;
        if (!called_at_rto)
        {
            if (seqGreater(old_snd_nxt, state->getSndNxt()))
                state->setSndNxt(old_snd_nxt);
        }

        // notify
        tcpAlgorithm->ackSent();

        if (state->sack_enabled)
        {
#ifdef PRIVATE
            SACK_BLOCK->updateStatus();
#else
            // RFC 3517, page 7: "(3) Retransmit the first data segment presumed dropped -- the segment
            // starting with sequence number HighACK + 1.  To prevent repeated
            // retransmission of the same data, set HighRxt to the highest
            // sequence number in the retransmitted segment."
            state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
#endif
        }
    }
}

void TCPConnection::retransmitData()
{
    // retransmit everything from snd_una
    state->setSndNxt(state->snd_una);

    uint32 bytesToSend = state->snd_max - state->getSndNxt();
    ASSERT(bytesToSend != 0);

    // TBD - avoid to send more than allowed - check cwnd and rwnd before retransmitting data!
    while (bytesToSend > 0)
    {
        uint32 bytes = std::min(bytesToSend, state->snd_mss);
        bytes = std::min(bytes, (uint32)(sendQueue->getBytesAvailable(state->getSndNxt())));
        if(!sendSegment(bytes))
            break;

        // Do not send packets after the FIN.
        // fixes bug that occurs in examples/inet/bulktransfer at event #64043  T=13.861159213744
        if (state->send_fin && state->getSndNxt() == state->snd_fin_seq + 1)
            break;

        bytesToSend -= state->sentBytes;
    }
}

void TCPConnection::readHeaderOptions(TCPSegment *tcpseg)
{
    tcpEV << "TCP Header Option(s) received:\n";

    for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
    {
        const TCPOption& option = tcpseg->getOptions(i);
        short kind = option.getKind();
        short length = option.getLength();
        bool ok = true;

        tcpEV << "Option type " << kind << " (" << optionName(kind) << "), length " << length << "\n";

        switch (kind)
        {
            case TCPOPTION_END_OF_OPTION_LIST: // EOL=0
            case TCPOPTION_NO_OPERATION: // NOP=1
                if (length != 1)
                {
                    tcpEV << "ERROR: option length incorrect\n";
                    ok = false;
                }
                break;

            case TCPOPTION_MAXIMUM_SEGMENT_SIZE: // MSS=2
                ok = processMSSOption(tcpseg, option);
                break;

            case TCPOPTION_WINDOW_SCALE: // WS=3
                ok = processWSOption(tcpseg, option);
                break;

            case TCPOPTION_SACK_PERMITTED: // SACK_PERMITTED=4
                ok = processSACKPermittedOption(tcpseg, option);
                break;

            case TCPOPTION_SACK: // SACK=5
#ifndef PRIVATE
                ok = processSACKOption(tcpseg, option);
#else
                ok = SACK_BLOCK->processSACKOption(tcpseg, option);
#endif
                break;

            case TCPOPTION_TIMESTAMP: // TS=8
                ok = processTSOption(tcpseg, option);
                break;
#ifdef PRIVATE
            case TCPOPTION_MPTCP: //	MPTCP
            	tcpEV << "Check on Multipath" << "\n";
                if(tcpMain->multipath){
                	 tcpEV << "INFO: MPTCP option - Please note we process it later " << "\n";
                }
                break;
#endif //PRIVATE
            // TODO add new TCPOptions here once they are implemented
            // TODO delegate to TCPAlgorithm as well -- it may want to recognized additional options

            default:
                tcpEV << "ERROR: Unsupported TCP option kind " << kind << "\n";
                break;
        }
        (void)ok; // unused
    }
}

bool TCPConnection::processMSSOption(TCPSegment *tcpseg, const TCPOption& option)
{
    if (option.getLength() != 4)
    {
        tcpEV << "ERROR: option length incorrect\n";
        return false;
    }

    if (fsm.getState() != TCP_S_LISTEN && fsm.getState() != TCP_S_SYN_SENT)
    {
        tcpEV << "ERROR: TCP Header Option MSS received, but in unexpected state\n";
        return false;
    }

    if (option.getValuesArraySize() == 0)
    {
        // since option.getLength() was already checked, this is a programming error not a TCP error
        throw cRuntimeError("TCPOption for MSS does not contain the data its getLength() promises");
    }

    // RFC 2581, page 1:
    // "The SMSS is the size of the largest segment that the sender can transmit.
    // This value can be based on the maximum transmission unit of the network,
    // the path MTU discovery [MD90] algorithm, RMSS (see next item), or other
    // factors.  The size does not include the TCP/IP headers and options."
    //
    // "The RMSS is the size of the largest segment the receiver is willing to accept.
    // This is the value specified in the MSS option sent by the receiver during
    // connection startup.  Or, if the MSS option is not used, 536 bytes [Bra89].
    // The size does not include the TCP/IP headers and options."
    //
    //
    // The value of snd_mss (SMSS) is set to the minimum of snd_mss (local parameter) and
    // the value specified in the MSS option received during connection startup.
    state->snd_mss = std::min(state->snd_mss, (uint32) option.getValues(0));

    if (state->snd_mss == 0)
        state->snd_mss = 536;

    tcpEV << "TCP Header Option MSS(=" << option.getValues(0) << ") received, SMSS is set to " << state->snd_mss << "\n";
    return true;
}

bool TCPConnection::processWSOption(TCPSegment *tcpseg, const TCPOption& option)
{
    if (option.getLength() != 3)
    {
        tcpEV << "ERROR: length incorrect\n";
        return false;
    }

    if (fsm.getState() != TCP_S_LISTEN && fsm.getState() != TCP_S_SYN_SENT)
    {
        tcpEV << "ERROR: TCP Header Option WS received, but in unexpected state\n";
        return false;
    }

    if (option.getValuesArraySize() == 0)
    {
        // since option.getLength() was already checked, this is a programming error not a TCP error
        throw cRuntimeError("TCPOption for WS does not contain the data its getLength() promises");
    }
    int scalefactor = 14;
#ifdef PRIVATE
    if(this->getTcpMain()->multipath){
        scalefactor = 20;
    }
    state->snd_ws = true; // why is this false, the next impression could never come true
#endif
    state->rcv_ws = true;
    state->ws_enabled = state->ws_support && state->snd_ws && state->rcv_ws;
    state->snd_wnd_scale = option.getValues(0);
    tcpEV << "TCP Header Option WS(=" << state->snd_wnd_scale << ") received, WS (ws_enabled) is set to " << state->ws_enabled << "\n";

    if (state->snd_wnd_scale > 14) // RFC 1323, page 11: "the shift count must be limited to 14"
    {
        tcpEV << "ERROR: TCP Header Option WS received but shift count value is exceeding 14\n";
        state->snd_wnd_scale = 14;
    }

    return true;
}

bool TCPConnection::processTSOption(TCPSegment *tcpseg, const TCPOption& option)
{
    if (option.getLength() != 10)
    {
        tcpEV << "ERROR: length incorrect\n";
        return false;
    }

    if ((!state->ts_enabled && fsm.getState() != TCP_S_LISTEN && fsm.getState() != TCP_S_SYN_SENT) ||
        (state->ts_enabled && fsm.getState() != TCP_S_SYN_RCVD && fsm.getState() != TCP_S_ESTABLISHED &&
                fsm.getState() != TCP_S_FIN_WAIT_1 && fsm.getState() != TCP_S_FIN_WAIT_2))
    {
        tcpEV << "ERROR: TCP Header Option TS received, but in unexpected state\n";
        return false;
    }

    if (option.getValuesArraySize() != 2)
    {
        // since option.getLength() was already checked, this is a programming error not a TCP error
        throw cRuntimeError("TCPOption for TS does not contain the data its getLength() promises");
    }

    if (!state->ts_enabled)
    {
        state->rcv_initial_ts = true;
        state->ts_enabled = state->ts_support && state->snd_initial_ts && state->rcv_initial_ts;
        tcpEV << "TCP Header Option TS(TSval=" << option.getValues(0) << ", TSecr=" << option.getValues(1) << ") received, TS (ts_enabled) is set to " << state->ts_enabled << "\n";
    }
    else
        tcpEV << "TCP Header Option TS(TSval=" << option.getValues(0) << ", TSecr=" << option.getValues(1) << ") received\n";

    // RFC 1323, page 35:
    // "Check whether the segment contains a Timestamps option and bit
    // Snd.TS.OK is on.  If so:
    //   If SEG.TSval < TS.Recent, then test whether connection has
    //   been idle less than 24 days; if both are true, then the
    //   segment is not acceptable; follow steps below for an
    //   unacceptable segment.
    //   If SEG.SEQ is equal to Last.ACK.sent, then save SEG.[TSval] in
    //   variable TS.Recent."
    if (state->ts_enabled)
    {
        if (seqLess(option.getValues(0), state->ts_recent))
        {
            if ((simTime() - state->time_last_data_sent) > PAWS_IDLE_TIME_THRESH) // PAWS_IDLE_TIME_THRESH = 24 days
            {
                tcpEV << "PAWS: Segment is not acceptable, TSval=" << option.getValues(0) << " in " <<  stateName(fsm.getState()) << " state received: dropping segment\n";
                return false;
            }
        }
        else if (seqLE(tcpseg->getSequenceNo(), state->last_ack_sent)) // Note: test is modified according to the latest proposal of the tcplw@cray.com list (Braden 1993/04/26)
        {
            state->ts_recent = option.getValues(0);
            tcpEV << "Updating ts_recent from segment: new ts_recent=" << state->ts_recent << "\n";
        }
    }

    return true;
}

bool TCPConnection::processSACKPermittedOption(TCPSegment *tcpseg, const TCPOption& option)
{
    if (option.getLength() != 2)
    {
        tcpEV << "ERROR: length incorrect\n";
        return false;
    }

    if (fsm.getState() != TCP_S_LISTEN && fsm.getState() != TCP_S_SYN_SENT)
    {
        tcpEV << "ERROR: TCP Header Option SACK_PERMITTED received, but in unexpected state\n";
        return false;
    }

    state->rcv_sack_perm = true;
    state->sack_enabled = state->sack_support && state->snd_sack_perm && state->rcv_sack_perm;
    tcpEV << "TCP Header Option SACK_PERMITTED received, SACK (sack_enabled) is set to " << state->sack_enabled << "\n";
    return true;
}

#ifdef PRIVATE
TCPSegment* TCPConnection::writeHeaderOptionsWithMPTCP(TCPSegment *tcpseg,uint32 bytes){
#else
TCPSegment TCPConnection::writeHeaderOptions(TCPSegment *tcpseg) //Question why not a pointer back, why dup?
{
#endif // PRIVATE
    TCPOption option;
    uint t = 0;

    // SYN flag set and connetion in INIT or LISTEN state (or after synRexmit timeout)
    if (tcpseg->getSynBit() && (fsm.getState() == TCP_S_INIT || fsm.getState() == TCP_S_LISTEN
            || ((fsm.getState() == TCP_S_SYN_SENT || fsm.getState() == TCP_S_SYN_RCVD)
            && state->syn_rexmit_count > 0)))
    {
        // MSS header option
        if (state->snd_mss > 0)
        {
            option.setKind(TCPOPTION_MAXIMUM_SEGMENT_SIZE); // MSS
            option.setLength(4);
            option.setValuesArraySize(1);

            // Update MSS
            option.setValues(0, state->snd_mss);
            tcpEV << "TCP Header Option MSS(=" << state->snd_mss << ") sent\n";
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
            tcpseg->setOptions(t++, option);
        }

        // WS header option
        if (state->ws_support && (state->rcv_ws || (fsm.getState() == TCP_S_INIT
                || (fsm.getState() == TCP_S_SYN_SENT && state->syn_rexmit_count > 0))))
        {
            // 1 padding byte
            option.setKind(TCPOPTION_NO_OPERATION); // NOP
            option.setLength(1);
            option.setValuesArraySize(0);
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
            tcpseg->setOptions(t++, option);

            option.setKind(TCPOPTION_WINDOW_SCALE);
            option.setLength(3);
            option.setValuesArraySize(1);
#ifndef PRIVATE
            // Don t understand why this should be done, because it is don in updateRcvWnd

            // Update WS variables
            ulong scaled_rcv_wnd = receiveQueue->getAmountOfFreeBytes(state->maxRcvBuffer);
            state->rcv_wnd_scale = 0;

            while (scaled_rcv_wnd > TCP_MAX_WIN && state->rcv_wnd_scale < 14) // RFC 1323, page 11: "the shift count must be limited to 14"
            {
                scaled_rcv_wnd = scaled_rcv_wnd >> 1;
                state->rcv_wnd_scale++;
            }
#endif
            option.setValues(0, state->rcv_wnd_scale); // rcv_wnd_scale is also set in scaleRcvWnd()
#ifndef PRIVATE
            state->snd_ws = true;
            state->rcv_ws = true; // Why is this false
            // Otherwise next expression never comes true

            state->ws_enabled = state->ws_support && state->snd_ws && state->rcv_ws;
            tcpEV << "TCP Header Option WS(=" << option.getValues(0) << ") sent, WS (ws_enabled) is set to " << state->ws_enabled << "\n";
#endif
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
            tcpseg->setOptions(t++, option);
        }

        // SACK_PERMITTED header option
        if (state->sack_support && (state->rcv_sack_perm || (fsm.getState() == TCP_S_INIT
                || (fsm.getState() == TCP_S_SYN_SENT && state->syn_rexmit_count > 0))))
        {
            if (!state->ts_support) // if TS is supported by host, do not add NOPs to this segment
            {
                // 2 padding bytes
                option.setKind(TCPOPTION_NO_OPERATION); // NOP
                option.setLength(1);
                option.setValuesArraySize(0);
                tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 2);
                tcpseg->setOptions(t++, option);
                tcpseg->setOptions(t++, option);
            }

            option.setKind(TCPOPTION_SACK_PERMITTED);
            option.setLength(2);
            option.setValuesArraySize(0);

            // Update SACK variables
            state->snd_sack_perm = true;
            state->sack_enabled = state->sack_support && state->snd_sack_perm && state->rcv_sack_perm;
            tcpEV << "TCP Header Option SACK_PERMITTED sent, SACK (sack_enabled) is set to " << state->sack_enabled << "\n";
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
            tcpseg->setOptions(t++, option);
        }

        // TS header option
        if (state->ts_support && (state->rcv_initial_ts || (fsm.getState() == TCP_S_INIT
                || (fsm.getState() == TCP_S_SYN_SENT && state->syn_rexmit_count > 0))))
        {
            if (!state->sack_support) // if SACK is supported by host, do not add NOPs to this segment
            {
                // 2 padding bytes
                option.setKind(TCPOPTION_NO_OPERATION); // NOP
                option.setLength(1);
                option.setValuesArraySize(0);
                tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 2);
                tcpseg->setOptions(t++, option);
                tcpseg->setOptions(t++, option);
            }

            option.setKind(TCPOPTION_TIMESTAMP);
            option.setLength(10);
            option.setValuesArraySize(2);

            // Update TS variables
            // RFC 1323, page 13: "The Timestamp Value field (TSval) contains the current value of the timestamp clock of the TCP sending the option."
            option.setValues(0, convertSimtimeToTS(simTime()));

            // RFC 1323, page 16: "(3) When a TSopt is sent, its TSecr field is set to the current TS.Recent value."
            // RFC 1323, page 13:
            // "The Timestamp Echo Reply field (TSecr) is only valid if the ACK
            // bit is set in the TCP header; if it is valid, it echos a times-
            // tamp value that was sent by the remote TCP in the TSval field
            // of a Timestamps option.  When TSecr is not valid, its value
            // must be zero."
            if (tcpseg->getAckBit())
                option.setValues(1, state->ts_recent);
            else
                option.setValues(1, 0);

            state->snd_initial_ts = true;
            state->ts_enabled = state->ts_support && state->snd_initial_ts && state->rcv_initial_ts;
            tcpEV << "TCP Header Option TS(TSval=" << option.getValues(0) << ", TSecr=" << option.getValues(1) << ") sent, TS (ts_enabled) is set to " << state->ts_enabled << "\n";
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
            tcpseg->setOptions(t++, option);
        }

        // TODO add new TCPOptions here once they are implemented
    }
    else if (fsm.getState() == TCP_S_SYN_SENT || fsm.getState() == TCP_S_SYN_RCVD
            || fsm.getState() == TCP_S_ESTABLISHED || fsm.getState() == TCP_S_FIN_WAIT_1
            || fsm.getState() == TCP_S_FIN_WAIT_2) // connetion is not in INIT or LISTEN state
    {
        // TS header option
        if (state->ts_enabled) // Is TS enabled?
        {
            if (!(state->sack_enabled && (state->snd_sack || state->snd_dsack))) // if SACK is enabled and SACKs need to be added, do not add NOPs to this segment
            {
                // 2 padding bytes
                option.setKind(TCPOPTION_NO_OPERATION); // NOP
                option.setLength(1);
                option.setValuesArraySize(0);
                tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 2);
                tcpseg->setOptions(t++, option);
                tcpseg->setOptions(t++, option);
            }

            option.setKind(TCPOPTION_TIMESTAMP);
            option.setLength(10);
            option.setValuesArraySize(2);

            // Update TS variables
            // RFC 1323, page 13: "The Timestamp Value field (TSval) contains the current value of the timestamp clock of the TCP sending the option."
            option.setValues(0, convertSimtimeToTS(simTime()));

            // RFC 1323, page 16: "(3) When a TSopt is sent, its TSecr field is set to the current TS.Recent value."
            // RFC 1323, page 13:
            // "The Timestamp Echo Reply field (TSecr) is only valid if the ACK
            // bit is set in the TCP header; if it is valid, it echos a times-
            // tamp value that was sent by the remote TCP in the TSval field
            // of a Timestamps option.  When TSecr is not valid, its value
            // must be zero."
            if (tcpseg->getAckBit())
                option.setValues(1, state->ts_recent);
            else
                option.setValues(1, 0);

            tcpEV << "TCP Header Option TS(TSval=" << option.getValues(0) << ", TSecr=" << option.getValues(1) << ") sent\n";
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize() + 1);
            tcpseg->setOptions(t++, option);

        }

        // SACK header option

        // RFC 2018, page 4:
        // "If sent at all, SACK options SHOULD be included in all ACKs which do
        // not ACK the highest sequence number in the data receiver's queue.  In
        // this situation the network has lost or mis-ordered data, such that
        // the receiver holds non-contiguous data in its queue.  RFC 1122,
        // Section 4.2.2.21, discusses the reasons for the receiver to send ACKs
        // in response to additional segments received in this state.  The
        // receiver SHOULD send an ACK for every valid segment that arrives
        // containing new data, and each of these "duplicate" ACKs SHOULD bear a
        // SACK option."
        if (state->sack_enabled && (state->snd_sack || state->snd_dsack))
        {
#ifndef PRIVATE
            addSacks(tcpseg);
#else
            SACK_BLOCK->addSACK(tcpseg);
#endif
            t = tcpseg->getOptionsArraySize();
        }

        // TODO add new TCPOptions here once they are implemented
        // TODO delegate to TCPAlgorithm as well -- it may want to append additional options
    }
#ifdef PRIVATE
	if(tcpMain->multipath){
		/**
		 * OK, we need signaling for MPTCP, in the draft it is done by options
		 *
		 */
	    if(tcpseg->getSynBit()){
            if(!flow){
                // Possible the first SYN, without any PCB
                new MPTCP_PCB(connId, appGateIndex,this);
            }
	    }
	    ASSERT(flow && "flow should be initialized");
		flow->writeMPTCPHeaderOptions(t,state,tcpseg, bytes, this);
	}
#endif // PRIVATE
    if (tcpseg->getOptionsArraySize() != 0){
        uint options_len = tcpseg->getOptionsArrayLength();
        if (options_len <= TCP_OPTIONS_MAX_SIZE) // Options length allowed? - maximum: 40 Bytes
            tcpseg->setHeaderLength(TCP_HEADER_OCTETS + options_len); // TCP_HEADER_OCTETS = 20
        else
        {
            tcpseg->setHeaderLength(TCP_HEADER_OCTETS); // TCP_HEADER_OCTETS = 20
            tcpseg->setOptionsArraySize(0); // drop all options
            tcpEV << "ERROR: Options length exceeded! Segment will be sent without options" << "\n";
        }
    }
    return tcpseg;
}

uint32 TCPConnection::getTSval(TCPSegment *tcpseg) const
{
    for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
    {
        const TCPOption& option = tcpseg->getOptions(i);
        short kind = option.getKind();

        if (kind == TCPOPTION_TIMESTAMP)
            return option.getValues(0);
    }

    return 0;
}

uint32 TCPConnection::getTSecr(TCPSegment *tcpseg) const
{
    for (uint i = 0; i < tcpseg->getOptionsArraySize(); i++)
    {
        const TCPOption& option = tcpseg->getOptions(i);
        short kind = option.getKind();

        if (kind == TCPOPTION_TIMESTAMP)
            return option.getValues(1);
    }

    return 0;
}

void TCPConnection::updateRcvQueueVars()
{
    // update receive queue related state variables
    state->freeRcvBuffer = receiveQueue->getAmountOfFreeBytes(state->maxRcvBuffer);
    state->usedRcvBuffer = state->maxRcvBuffer - state->freeRcvBuffer;

    // update receive queue related statistics
    if (tcpRcvQueueBytesVector)
        tcpRcvQueueBytesVector->record(state->usedRcvBuffer);

//    tcpEV << "receiveQ: receiveQLength=" << receiveQueue->getQueueLength() << " maxRcvBuffer=" << state->maxRcvBuffer << " usedRcvBuffer=" << state->usedRcvBuffer << " freeRcvBuffer=" << state->freeRcvBuffer << "\n";
}

unsigned short TCPConnection::updateRcvWnd()
{
    uint32 win = 0;

    // update receive queue related state variables and statistics
    updateRcvQueueVars();
    win = state->freeRcvBuffer;

    // Following lines are based on [Stevens, W.R.: TCP/IP Illustrated, Volume 2, chapter 26.7, pages 878-879]:
    // Don't advertise less than one full-sized segment to avoid SWS
    if (win < (state->maxRcvBuffer) && win < state->snd_mss)
        win = 0;

    // Do not shrink window
    // (rcv_adv minus rcv_nxt) is the amount of space still available to the sender that was previously advertised
    if (win < state->rcv_adv - state->rcv_nxt)
        win = state->rcv_adv - state->rcv_nxt;



    // Observe upper limit for advertised window on this connection
    if (win > TCP_MAX_WIN && !state->ws_enabled) // TCP_MAX_WIN = 65535 (16 bit)
        win = TCP_MAX_WIN; // Note: The window size is limited to a 16 bit value in the TCP header if WINDOW SCALE option (RFC 1323) is not used

    // Note: The order of the "Do not shrink window" and "Observe upper limit" parts has been changed to the order used in FreeBSD Release 7.1


    // update rcv_adv if needed
    if (win > 0 && seqGE(state->rcv_nxt + win, state->rcv_adv))
    {
        state->rcv_adv = state->rcv_nxt + win;

        if (rcvAdvVector)
            rcvAdvVector->record(state->rcv_adv);
    }
    uint32 scaled_rcv_wnd = 0;
    state->rcv_wnd = win;
    scaled_rcv_wnd = state->rcv_wnd;
#ifdef PRIVATE
    if(tcpMain->multipath && (flow!=NULL)){
        if(tcpMain->multipath && (flow != NULL)){
           flow->sendToApp();
        }

        if (win > 0 && seqGreater(win, flow->mptcp_rcv_wnd))
        {

            flow->refreshSendMPTCPWindow();

            win = flow->mptcp_rcv_wnd;

        }
        scaled_rcv_wnd = std::min((uint32)flow->mptcp_rcv_wnd,state->rcv_wnd);
    }
#endif


    if (rcvWndVector)
        rcvWndVector->record(state->rcv_wnd);

    // scale rcv_wnd:

    if (state->ws_enabled)
    {

// Don t understand this line - we set it by SYM
#ifndef PRIVATE
        int scalefactor = 14;
        while (scaled_rcv_wnd > TCP_MAX_WIN && (state->rcv_wnd_scale < scalefactor)) // RFC 1323, page 11: "the shift count must be limited to 14"
        {
            scaled_rcv_wnd = scaled_rcv_wnd >> 1;
            state->rcv_wnd_scale++;
        }
#else
        scaled_rcv_wnd = scaled_rcv_wnd >> state->rcv_wnd_scale;
#endif
    }
    ASSERT(scaled_rcv_wnd == (unsigned short)scaled_rcv_wnd);

    return (unsigned short) scaled_rcv_wnd;
}

void TCPConnection::updateWndInfo(TCPSegment *tcpseg, bool doAlways)
{
    uint32 true_window = tcpseg->getWindow();
    // RFC 1323, page 10:
    // "The window field (SEG.WND) in the header of every incoming
    // segment, with the exception of SYN segments, is left-shifted
    // by Snd.Wind.Scale bits before updating SND.WND:
    //    SND.WND = SEG.WND << Snd.Wind.Scale"
     if (state->ws_enabled && !tcpseg->getSynBit())
        true_window = true_window << state->snd_wnd_scale; // Shift on function is not safe

    // Following lines are based on [Stevens, W.R.: TCP/IP Illustrated, Volume 2, page 982]:
    if (doAlways || (tcpseg->getAckBit()
            && (seqLess(state->snd_wl1, tcpseg->getSequenceNo()) ||
            (state->snd_wl1 == tcpseg->getSequenceNo() && seqLE(state->snd_wl2, tcpseg->getAckNo())) ||
            (state->snd_wl2 == tcpseg->getAckNo() && true_window > state->snd_wnd))))
    {
        // send window should be updated
        state->snd_wnd = true_window;


        tcpEV << "Updating send window from segment: new wnd=" << state->snd_wnd << "\n";
        state->snd_wl1 = tcpseg->getSequenceNo();
        state->snd_wl2 = tcpseg->getAckNo();

        if (sndWndVector)
            sndWndVector->record(state->snd_wnd);
    }
#ifdef PRIVATE
    // FIXMe do Check if valid SQN aerea
    if(this->getTcpMain()->multipath && (flow != NULL)){
        // TODO - What happens if window information comes too late
        flow->mptcp_snd_wnd = true_window;
    }
#endif
}

void TCPConnection::sendOneNewSegment(bool fullSegmentsOnly, uint32 congestionWindow)
{
    // FIXME ASSERT(state->limited_transmit_enabled);

    // RFC 3042, page 3:
    // "When a TCP sender has previously unsent data queued for transmission
    // it SHOULD use the Limited Transmit algorithm, which calls for a TCP
    // sender to transmit new data upon the arrival of the first two
    // consecutive duplicate ACKs when the following conditions are
    // satisfied:
    //
    //  * The receiver's advertised window allows the transmission of the
    //  segment.
    //
    //  * The amount of outstanding data would remain less than or equal
    //  to the congestion window plus 2 segments.  In other words, the
    //  sender can only send two segments beyond the congestion window
    //  (cwnd).
    //
    // The congestion window (cwnd) MUST NOT be changed when these new
    // segments are transmitted.  Assuming that these new segments and the
    // corresponding ACKs are not dropped, this procedure allows the sender
    // to infer loss using the standard Fast Retransmit threshold of three
    // duplicate ACKs [RFC2581].  This is more robust to reordered packets
    // than if an old packet were retransmitted on the first or second
    // duplicate ACK.
    //
    // Note: If the connection is using selective acknowledgments [RFC2018],
    // the data sender MUST NOT send new segments in response to duplicate
    // ACKs that contain no new SACK information, as a misbehaving receiver
    // can generate such ACKs to trigger inappropriate transmission of data
    // segments.  See [SCWA99] for a discussion of attacks by misbehaving
    // receivers."


#ifndef PRIVATE
    if (!state->sack_enabled || (state->sack_enabled && state->sackedBytes_old != state->sackedBytes))
#else
    if (state->sack_enabled)
#endif
    {
        // check how many bytes we have
        ulong buffered = sendQueue->getBytesAvailable(state->snd_max);

        if (buffered >= state->snd_mss || (!fullSegmentsOnly && buffered > 0))
        {

            ulong outstandingData = 0;
            outstandingData = state->snd_max - state->snd_una;

            // check conditions from RFC 3042
            if (outstandingData + state->snd_mss <= state->snd_wnd &&
                outstandingData + state->snd_mss <= congestionWindow + 2 * state->snd_mss)
            {
                // RFC 3042, page 3: "(...)the sender can only send two segments beyond the congestion window (cwnd)."
                uint32 effectiveWin = std::min(state->snd_wnd, congestionWindow) - outstandingData + 2 * state->snd_mss;
#ifdef PRIVATE
                if(tcpMain->multipath && (flow != NULL) && (!flow->isMPTCP_RTX)){
                    uint32 sent = 0;
                    const TCP_SubFlowVector_t *subflow_list = flow->getSubflows();
                    for (TCP_SubFlowVector_t::const_iterator i = subflow_list->begin();
                              i != subflow_list->end(); i++) {
                          TCPConnection *conn = (*i)->subflow;
                          sent += conn->getState()->snd_max - conn->getState()->snd_una;
                    }
                    sent += state->snd_mss;
                    if(flow->mptcp_snd_wnd <  std::max(sent,(uint32) ((flow->mptcp_snd_nxt - 1) - flow->mptcp_snd_una ) + state->snd_mss))
                        return;
                }
#endif
                // bytes: number of bytes we're allowed to send now
                uint32 bytes = std::min(effectiveWin, state->snd_mss);

                if (bytes >= state->snd_mss || (!fullSegmentsOnly && bytes > 0))
                {
                    uint32 old_snd_nxt = state->getSndNxt();
                    // we'll start sending from snd_max
                    state->setSndNxt(state->snd_max);

                    tcpEV << "Limited Transmit algorithm enabled. Sending one new segment.\n";
                    sendSegment(bytes);

                    if (unackedVector)
                        unackedVector->record(state->snd_max - state->snd_una);

                    // reset snd_nxt if needed
                    if (state->afterRto)
                        state->setSndNxt(old_snd_nxt + state->sentBytes);

                    // notify
                    tcpAlgorithm->ackSent();
                    tcpAlgorithm->dataSent(old_snd_nxt);
                }
            }
            else{
               // std::cerr << "Window to small" << std::endl;
            }
        }
    }
}

uint32 TCPConnection::convertSimtimeToTS(simtime_t simtime)
{
    ASSERT(SimTime::getScaleExp() <= -3); // FIXME TODO - If the scale factor is different, we need to adjust our simTime to uint32 casts - we are currently using ms precision

    uint32 timestamp = (uint32) (simtime.dbl() * 1000);
    return timestamp;
}

simtime_t TCPConnection::convertTSToSimtime(uint32 timestamp)
{
    ASSERT(SimTime::getScaleExp() <= -3); // FIXME TODO - If the scale factor is different, we need to adjust our simTime to uint32 casts - we are currently using ms precision

    simtime_t simtime = (simtime_t) ((double) timestamp * 0.001);
    return simtime;
}

bool TCPConnection::isSendQueueEmpty()
{
    return (sendQueue->getBytesAvailable(state->getSndNxt()) == 0);
}
