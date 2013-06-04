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


#include "TCP.h"

#include "IPv4ControlInfo.h"
#include "IPv6ControlInfo.h"
#include "TCPConnection.h"
#include "TCPSegment.h"
#include "TCPCommand_m.h"

#ifdef WITH_IPv4
#include "ICMPMessage_m.h"
#endif

#ifdef WITH_IPv6
#include "ICMPv6Message_m.h"
#endif

#include "TCPByteStreamRcvQueue.h"
#include "TCPByteStreamSendQueue.h"
#include "TCPMsgBasedRcvQueue.h"
#include "TCPMsgBasedSendQueue.h"
#include "TCPVirtualDataRcvQueue.h"
#include "TCPVirtualDataSendQueue.h"

#ifdef PRIVATE
#include "TCPMultipathPCB.h"
#include "TCPMultipathFlow.h"
#endif

Define_Module(TCP);


bool TCP::testing;
bool TCP::logverbose;

#define EPHEMERAL_PORTRANGE_START 1024
#define EPHEMERAL_PORTRANGE_END   5000

static inline std::ostream& operator<<(std::ostream& os, const TCP::SockPair& sp)
{
    os << "loc=" << IPvXAddress(sp.localAddr) << ":" << sp.localPort << " "
       << "rem=" << IPvXAddress(sp.remoteAddr) << ":" << sp.remotePort;
    return os;
}

static inline std::ostream& operator<<(std::ostream& os, const TCP::AppConnKey& app)
{
    os << "connId=" << app.connId << " appGateIndex=" << app.appGateIndex;
    return os;
}

static inline std::ostream& operator<<(std::ostream& os, const TCPConnection& conn)
{
    os << "connId=" << conn.connId << " " << TCPConnection::stateName(conn.getFsmState())
       << " state={" << const_cast<TCPConnection&>(conn).getState()->info() << "}";
    return os;
}


void TCP::initialize()
{

#ifdef PRIVATE

     if(strcmp((const char*)par("cmtCCVariant"), "off") == 0) {
         multipath     = false;
     }
     else if(strcmp((const char*)par("cmtCCVariant"), "cmt") == 0) {
          multipath     = true;
     }
// TODO add new Congestion Control�
//         else if( (strcmp((const char*)sctpMain->par("cmtCCVariant"), "like-mptcp") == 0) ||
//                  (strcmp((const char*)sctpMain->par("cmtCCVariant"), "mptcp-like") == 0) ) {
//            state->cmtCCVariant = SCTPStateVariables::CCCV_Like_MPTCP;
//            state->allowCMT     = true;
//         }
//         else if( (strcmp((const char*)sctpMain->par("cmtCCVariant"), "cmtrp") == 0) ||
//                  (strcmp((const char*)sctpMain->par("cmtCCVariant"), "cmtrpv1") == 0) ) {
//            state->cmtCCVariant = SCTPStateVariables::CCCV_CMTRPv1;
//            state->allowCMT     = true;
//         }
//         else if(strcmp((const char*)sctpMain->par("cmtCCVariant"), "cmtrpv2") == 0) {
//            state->cmtCCVariant = SCTPStateVariables::CCCV_CMTRPv2;
//            state->allowCMT     = true;
//         }
//         else if(strcmp((const char*)sctpMain->par("cmtCCVariant"), "cmtrp-t1") == 0) {
//            state->cmtCCVariant = SCTPStateVariables::CCCV_CMTRP_Test1;
//            state->allowCMT     = true;
//         }
//         else if(strcmp((const char*)sctpMain->par("cmtCCVariant"), "cmtrp-t2") == 0) {
//            state->cmtCCVariant = SCTPStateVariables::CCCV_CMTRP_Test2;
//            state->allowCMT     = true;
//         }
     else {
        throw cRuntimeError("Bad setting for cmtCCVariant: %s\n",
                 (const char*)par("cmtCCVariant"));
     }

	if(multipath){
		tcpEV << "Initializing module TCP: Multipath TCP enabled\n";
		multipath_subflow_id = 0;

		multipath_DSSDataACK8 = par("multipath_DSSDataACK8");
		multipath_DSSSeqNo8 = par("multipath_DSSSeqNo8");
    

	}
	mptcp_pcb = NULL;
	scheduler = NULL;
#endif

    const char *q;
    q = par("sendQueueClass");
    if (*q != '\0')
        error("Don't use obsolete sendQueueClass = \"%s\" parameter", q);

    q = par("receiveQueueClass");
    if (*q != '\0')
        error("Don't use obsolete receiveQueueClass = \"%s\" parameter", q);

    lastEphemeralPort = EPHEMERAL_PORTRANGE_START;
    WATCH(lastEphemeralPort);

    WATCH_PTRMAP(tcpConnMap);
    WATCH_PTRMAP(tcpAppConnMap);

    recordStatistics = par("recordStats");

    cModule *netw = simulation.getSystemModule();
    testing = netw->hasPar("testing") && netw->par("testing").boolValue();
    logverbose = !testing && netw->hasPar("logverbose") && netw->par("logverbose").boolValue();
}

TCP::~TCP()
{


	while (!tcpAppConnMap.empty())
	{
		TcpAppConnMap::iterator i = tcpAppConnMap.begin();
#ifndef PRIVATE
		if((*i).second!= NULL){
#else
		if((*i).second!= NULL && (!(*i).second->isSubflow)){
#endif
			delete (*i).second;
		}
		(*i).second= NULL;
		tcpAppConnMap.erase(i);
	}
#ifdef PRIVATE
    if(this->multipath){
         delete this->mptcp_pcb;
    }
#endif

}

void TCP::handleMessage(cMessage *msg)
{
    if (msg->isSelfMessage())
    {
        TCPConnection *conn = (TCPConnection *) msg->getContextPointer();

#ifdef PRIVATE
        // Selfmessage could only be a timer, or a initiation if a new sublink
        if(multipath &&(msg->getControlInfo() != NULL)){

        	TCPOpenCommand *controlInfo = check_and_cast<TCPOpenCommand *>(msg->getControlInfo());
        	bool skip = false;


        	if((controlInfo!=NULL) && (controlInfo->getIsMptcpSubflow())){
        		tcpEV << "TCP connection is a subflow " << msg << "\n";

        		// make sure connection is unique
        		SockPair key;
        		key.localAddr  = controlInfo->getLocalAddr();
        		key.remoteAddr = controlInfo->getRemoteAddr();
        		key.localPort  = controlInfo->getLocalPort();
        		key.remotePort = controlInfo->getRemotePort();
        		TcpConnMap::iterator it = tcpConnMap.find(key);
        		if (it!=tcpConnMap.end())
				{
					skip = true;
				}

        		// Create connection
        		TCPConnection *subflow = NULL;
        		if(!skip)
        			subflow = createConnection(conn->appGateIndex, conn->connId);

        		// Lets do our job -> establish this subflow
        		if(subflow!=NULL){

					subflow->isSubflow = true;
					if (!(subflow->processAppCommand(msg))){
						removeConnection(subflow);
						subflow = NULL;
					}
					// TODO Should I add a subflow after a MP_JOIN SYN
        		}
        		else{
        			delete msg;
				//	delete controlInfo;
        		}
				if (ev.isGUI())
				        updateDisplayString();
				return;
        	}
        }
#endif
        bool ret = conn->processTimer(msg);
        if (!ret){
            removeConnection(conn);
            conn = NULL;
        }
    }
    else if (msg->arrivedOn("ipIn") || msg->arrivedOn("ipv6In"))
    {
        if (false
#ifdef WITH_IPv4
                || dynamic_cast<ICMPMessage *>(msg)
#endif
#ifdef WITH_IPv6
                || dynamic_cast<ICMPv6Message *>(msg)
#endif
            )
        {
            tcpEV << "ICMP error received -- discarding\n"; // FIXME can ICMP packets really make it up to TCP???
            delete msg;
        }
        else
        {
            // must be a TCPSegment
            TCPSegment *tcpseg = check_and_cast<TCPSegment *>(msg);

            // TODO TESTING
			if (tcpseg->getSynBit() && (!tcpseg->getAckBit()))
				tcpEV << "A SYN ARRIVES\n";
            if (tcpseg->getSynBit() && (tcpseg->getAckBit()))
            	tcpEV << "A SYN ACK ARRIVES\n";

            // get src/dest addresses
            IPvXAddress srcAddr, destAddr;

            if (dynamic_cast<IPv4ControlInfo *>(tcpseg->getControlInfo()) != NULL)
            {
// FIXME Merge del

                IPv4ControlInfo *controlInfo = (IPv4ControlInfo *)tcpseg->removeControlInfo();

                srcAddr = controlInfo->getSrcAddr();
                destAddr = controlInfo->getDestAddr();
                delete controlInfo;

            }
            else if (dynamic_cast<IPv6ControlInfo *>(tcpseg->getControlInfo()) != NULL)
            {

                IPv6ControlInfo *controlInfo = (IPv6ControlInfo *)tcpseg->removeControlInfo();
                srcAddr = controlInfo->getSrcAddr();
                destAddr = controlInfo->getDestAddr();
                delete controlInfo;
            }
            else
            {
                error("(%s)%s arrived without control info", tcpseg->getClassName(), tcpseg->getName());
            }
            TCPConnection *conn = findConnForSegment(tcpseg, srcAddr, destAddr);
            if (conn)
            {
#ifdef PRIVATE
               // We have to be realy sure, if the connection is the connection we look for
//              fprintf(stderr,"\n[TCP][NEW SEG] from  %s:%d to %s:%d\n", srcAddr.str().c_str(), tcpseg->getSrcPort(), destAddr.str().c_str(),tcpseg->getDestPort());
//              fprintf(stderr,"\n[TCP][WORK CONNECTION] use remote:  %s:%d local %s:%d\n", conn->remoteAddr.str().c_str(), conn->remotePort, conn->localAddr.str().c_str(), conn->localPort);

#endif
                bool ret = conn->processTCPSegment(tcpseg, srcAddr, destAddr);
                if (!ret){
                    removeConnection(conn);
                    conn = NULL;
                }
            }
            else
            {
#ifdef PRIVATE
            	// OK, perhapse we have to join a Multipath Connection
            	if(multipath){
            		// TODO INCOMING MULTIPATH TCP on closed Socket, when Server side open a connection active
            	    TCPConnection *mptcp_con=NULL;

            	    // The connection should be created in TCPMultipathFlow.cc for new incomming SYNs from Server side.
            	    // Check if we can find it...

            	    SockPair key;
            	    key.localAddr = srcAddr;
            	    key.remoteAddr = IPvXAddress();
            	    key.localPort = tcpseg->getDestPort();
            	    key.remotePort = -1;


            	    // try with fully qualified SockPair
            	    TcpConnMap::iterator i;
            	    i = tcpConnMap.find(key);
            	    if (i!=tcpConnMap.end())
            	            mptcp_con = i->second;
            	    if(mptcp_con!=NULL){
            	        tcpEV << "Someone is using MPTCP and tries to open a connection server side";
            	        mptcp_con->processTCPSegment(tcpseg, srcAddr, destAddr);

            	    }
            	    tcpEV << "Incomming Packets on closed Port, in default TCP we would send a RST\n";
            	}
            	else{
#endif
                segmentArrivalWhileClosed(tcpseg, srcAddr, destAddr);
#ifdef PRIVATE
            	}
#endif
            }
        }
    }
    else // must be from app
    {
        TCPCommand *controlInfo = check_and_cast<TCPCommand *>(msg->getControlInfo());
        int appGateIndex = msg->getArrivalGate()->getIndex();
        int connId = controlInfo->getConnId();

        TCPConnection *conn = findConnForApp(appGateIndex, connId);
        if (!conn)
        {
            conn = createConnection(appGateIndex, connId);

            // add into appConnMap here; it'll be added to connMap during processing
            // the OPEN command in TCPConnection's processAppCommand().
            AppConnKey key;
            key.appGateIndex = appGateIndex;
            key.connId = connId;
            tcpAppConnMap[key] = conn;

            tcpEV << "TCP connection created for " << msg << "\n";
        }

        bool ret = conn->processAppCommand(msg);
        if (!ret){
            removeConnection(conn);
            conn = NULL;
        }
    }

    if (ev.isGUI())
        updateDisplayString();
}

TCPConnection *TCP::createConnection(int appGateIndex, int connId)
{
    return new TCPConnection(this, appGateIndex, connId);
}

void TCP::segmentArrivalWhileClosed(TCPSegment *tcpseg, IPvXAddress srcAddr, IPvXAddress destAddr)
{
    TCPConnection *tmp = new TCPConnection();
    tmp->segmentArrivalWhileClosed(tcpseg, srcAddr, destAddr);
    delete tmp;
    delete tcpseg;
}

void TCP::updateDisplayString()
{
    if (ev.isDisabled())
    {
        // in express mode, we don't bother to update the display
        // (std::map's iteration is not very fast if map is large)
        getDisplayString().setTagArg("t", 0, "");
        return;
    }

    //char buf[40];
    //sprintf(buf,"%d conns", tcpAppConnMap.size());
    //getDisplayString().setTagArg("t",0,buf);

    int numINIT = 0, numCLOSED = 0, numLISTEN = 0, numSYN_SENT = 0, numSYN_RCVD = 0,
        numESTABLISHED = 0, numCLOSE_WAIT = 0, numLAST_ACK = 0, numFIN_WAIT_1 = 0,
        numFIN_WAIT_2 = 0, numCLOSING = 0, numTIME_WAIT = 0;

    for (TcpAppConnMap::iterator i = tcpAppConnMap.begin(); i != tcpAppConnMap.end(); ++i)
    {
        int state = (*i).second->getFsmState();

        switch (state)
        {
           case TCP_S_INIT:        numINIT++; break;
           case TCP_S_CLOSED:      numCLOSED++; break;
           case TCP_S_LISTEN:      numLISTEN++; break;
           case TCP_S_SYN_SENT:    numSYN_SENT++; break;
           case TCP_S_SYN_RCVD:    numSYN_RCVD++; break;
           case TCP_S_ESTABLISHED: numESTABLISHED++; break;
           case TCP_S_CLOSE_WAIT:  numCLOSE_WAIT++; break;
           case TCP_S_LAST_ACK:    numLAST_ACK++; break;
           case TCP_S_FIN_WAIT_1:  numFIN_WAIT_1++; break;
           case TCP_S_FIN_WAIT_2:  numFIN_WAIT_2++; break;
           case TCP_S_CLOSING:     numCLOSING++; break;
           case TCP_S_TIME_WAIT:   numTIME_WAIT++; break;
        }
    }

    char buf2[200];
    buf2[0] = '\0';

    if (numINIT > 0)       sprintf(buf2+strlen(buf2), "init:%d ", numINIT);
    if (numCLOSED > 0)     sprintf(buf2+strlen(buf2), "closed:%d ", numCLOSED);
    if (numLISTEN > 0)     sprintf(buf2+strlen(buf2), "listen:%d ", numLISTEN);
    if (numSYN_SENT > 0)   sprintf(buf2+strlen(buf2), "syn_sent:%d ", numSYN_SENT);
    if (numSYN_RCVD > 0)   sprintf(buf2+strlen(buf2), "syn_rcvd:%d ", numSYN_RCVD);
    if (numESTABLISHED > 0) sprintf(buf2+strlen(buf2), "estab:%d ", numESTABLISHED);
    if (numCLOSE_WAIT > 0) sprintf(buf2+strlen(buf2), "close_wait:%d ", numCLOSE_WAIT);
    if (numLAST_ACK > 0)   sprintf(buf2+strlen(buf2), "last_ack:%d ", numLAST_ACK);
    if (numFIN_WAIT_1 > 0) sprintf(buf2+strlen(buf2), "fin_wait_1:%d ", numFIN_WAIT_1);
    if (numFIN_WAIT_2 > 0) sprintf(buf2+strlen(buf2), "fin_wait_2:%d ", numFIN_WAIT_2);
    if (numCLOSING > 0)    sprintf(buf2+strlen(buf2), "closing:%d ", numCLOSING);
    if (numTIME_WAIT > 0)  sprintf(buf2+strlen(buf2), "time_wait:%d ", numTIME_WAIT);

    getDisplayString().setTagArg("t", 0, buf2);

}

#ifdef PRIVATE
bool TCP::isKnownConn(IPvXAddress srcAddr, int lPort, IPvXAddress destAddr,  int rPort){

    SockPair key;
    key.localAddr = destAddr;
    key.remoteAddr = srcAddr;
    key.localPort = lPort;
    key.remotePort =rPort;

    // try with fully qualified SockPair
    TcpConnMap::iterator i;
    i = tcpConnMap.find(key);
    if (i!=tcpConnMap.end())
        return true;

    key.localAddr = IPvXAddress();
    i = tcpConnMap.find(key);
    if (i!=tcpConnMap.end())
        return true;

    return false;
}

#endif
TCPConnection *TCP::findConnForSegment(TCPSegment *tcpseg, IPvXAddress srcAddr, IPvXAddress destAddr)
{

#ifdef PRIVATE // For Debug -> I want to know which Connection TCP knows
        int cnt = 0;
       for (TcpConnMap::iterator it = tcpConnMap.begin();
           it != tcpConnMap.end(); it++, cnt++) {
           TCPConnection *entry = (it->second);
           DEBUGPRINT(
                   "[GENERAL][TCP][STATUS][SUBFLOW][%i] Connections  %s:%d to %s:%d",
                   cnt, entry->localAddr.str().c_str(), entry->localPort, entry->remoteAddr.str().c_str(), entry->remotePort);
           DEBUGPRINT(
                   "[GENERAL][TCP][STATUS][SUBFLOW][%i]rcv_nxt: %i\t snd_nxt: %i\t snd_una: %i snd_max: %i",
                   cnt, entry->getState()->rcv_nxt, entry->getState()->snd_nxt, entry->getState()->snd_una, entry->getState()->snd_max);
       }
#endif
    SockPair key;
    key.localAddr = destAddr;
    key.remoteAddr = srcAddr;
    key.localPort = tcpseg->getDestPort();
    key.remotePort = tcpseg->getSrcPort();
    SockPair save = key;

    // try with fully qualified SockPair
    TcpConnMap::iterator i;
    i = tcpConnMap.find(key);

    if (i != tcpConnMap.end())
        return i->second;

    // try with localAddr missing (only localPort specified in passive/active open)
    key.localAddr = IPvXAddress();
    i = tcpConnMap.find(key);

    if (i != tcpConnMap.end())
        return i->second;
#ifdef PRIVATE
    if(tcpseg->getSynBit()){
#endif
    // try fully qualified local socket + blank remote socket (for incoming SYN)
    key = save;
    key.remoteAddr = IPvXAddress();
    key.remotePort = -1;
    i = tcpConnMap.find(key);

    if (i != tcpConnMap.end())
        return i->second;

    // try with blank remote socket, and localAddr missing (for incoming SYN)
    key.localAddr = IPvXAddress();
    i = tcpConnMap.find(key);

    if (i != tcpConnMap.end())
        return i->second;
#ifdef PRIVATE
    }
#endif
    // given up
    return NULL;
}

TCPConnection *TCP::findConnForApp(int appGateIndex, int connId)
{
    AppConnKey key;
    key.appGateIndex = appGateIndex;
    key.connId = connId;

    TcpAppConnMap::iterator i = tcpAppConnMap.find(key);
    return i == tcpAppConnMap.end() ? NULL : i->second;
}

ushort TCP::getEphemeralPort()
{
    // start at the last allocated port number + 1, and search for an unused one
    ushort searchUntil = lastEphemeralPort++;
    if (lastEphemeralPort == EPHEMERAL_PORTRANGE_END) // wrap
        lastEphemeralPort = EPHEMERAL_PORTRANGE_START;

    while (usedEphemeralPorts.find(lastEphemeralPort) != usedEphemeralPorts.end())
    {
        if (lastEphemeralPort == searchUntil) // got back to starting point?
            error("Ephemeral port range %d..%d exhausted, all ports occupied", EPHEMERAL_PORTRANGE_START, EPHEMERAL_PORTRANGE_END);

        lastEphemeralPort++;

        if (lastEphemeralPort == EPHEMERAL_PORTRANGE_END) // wrap
            lastEphemeralPort = EPHEMERAL_PORTRANGE_START;
    }

    // found a free one, return it
    return lastEphemeralPort;
}

void TCP::addSockPair(TCPConnection *conn, IPvXAddress localAddr, IPvXAddress remoteAddr, int localPort, int remotePort)
{
    // update addresses/ports in TCPConnection
    SockPair key;
    key.localAddr = conn->localAddr = localAddr;
    key.remoteAddr = conn->remoteAddr = remoteAddr;
    key.localPort = conn->localPort = localPort;
    key.remotePort = conn->remotePort = remotePort;

    // make sure connection is unique
    TcpConnMap::iterator it = tcpConnMap.find(key);
    if (it != tcpConnMap.end())
    {
        // throw "address already in use" error
        if (remoteAddr.isUnspecified() && remotePort==-1){
            error("Address already in use: there is already a connection listening on %s:%d",
                  localAddr.str().c_str(), localPort);

        }else{
#ifdef PRIVATE
            if(this->multipath){
                return;
            }
            else
#endif
            error("Address already in use: there is already a connection %s:%d to %s:%d",
                  localAddr.str().c_str(), localPort, remoteAddr.str().c_str(), remotePort);
        }
    }
    if(key.remotePort != conn->remotePort)
        error("Key and Connection is different connection %s:%d to %s:%d",
                          localAddr.str().c_str(), localPort, remoteAddr.str().c_str(), remotePort);
    // then insert it into tcpConnMap
    tcpConnMap[key] = conn;

    if(conn->getRexmitQueue()==NULL)
        tcpEV << "getRexmitQueue is empty "  << "\n";

    // mark port as used
    if (localPort >= EPHEMERAL_PORTRANGE_START && localPort < EPHEMERAL_PORTRANGE_END)
        usedEphemeralPorts.insert(localPort);
}

void TCP::updateSockPair(TCPConnection *conn, IPvXAddress localAddr, IPvXAddress remoteAddr, int localPort, int remotePort)
{
    // find with existing address/port pair...
    SockPair key;
    key.localAddr = conn->localAddr;
    key.remoteAddr = conn->remoteAddr;
    key.localPort = conn->localPort;
    key.remotePort = conn->remotePort;
    TcpConnMap::iterator it = tcpConnMap.find(key);

    ASSERT(it != tcpConnMap.end() && it->second == conn);

    // ...and remove from the old place in tcpConnMap
    tcpConnMap.erase(it);

    // then update addresses/ports, and re-insert it with new key into tcpConnMap
    conn->localAddr = localAddr;
    key.localAddr = localAddr;
    conn->remoteAddr = remoteAddr;
    key.remoteAddr =  remoteAddr;
    ASSERT(conn->localPort == localPort);
    conn->remotePort = remotePort;
    key.remotePort = remotePort;

    if(key.remotePort != conn->remotePort)
          error("Key and Connection is different connection %s:%d to %s:%d",
                            localAddr.str().c_str(), localPort, remoteAddr.str().c_str(), remotePort);
    tcpConnMap[key] = conn;

    // localPort doesn't change (see ASSERT above), so there's no need to update usedEphemeralPorts[].
}

void TCP::addForkedConnection(TCPConnection *conn, TCPConnection *newConn, IPvXAddress localAddr, IPvXAddress remoteAddr, int localPort, int remotePort)
{
    // update conn's socket pair, and register newConn (which'll keep LISTENing)
    updateSockPair(conn, localAddr, remoteAddr, localPort, remotePort);
    addSockPair(newConn, newConn->localAddr, newConn->remoteAddr, newConn->localPort, newConn->remotePort);

    // conn will get a new connId...
    AppConnKey key;
    key.appGateIndex = conn->appGateIndex;
    key.connId = conn->connId;
    tcpAppConnMap.erase(key);
    key.connId = conn->connId = ev.getUniqueNumber();
    tcpAppConnMap[key] = conn;

    // ...and newConn will live on with the old connId
    key.appGateIndex = newConn->appGateIndex;
    key.connId = newConn->connId;
    tcpAppConnMap[key] = newConn;
}

void TCP::removeConnection(TCPConnection *conn)
{
    tcpEV << "Deleting TCP connection\n";
#ifdef PRIVATE
    // In case of my tests this vectors are irritating
    conn->removeVectors();
#endif
    AppConnKey key;
    key.appGateIndex = conn->appGateIndex;
    key.connId = conn->connId;
    tcpAppConnMap.erase(key);

    SockPair key2;
    key2.localAddr = conn->localAddr;
    key2.remoteAddr = conn->remoteAddr;
    key2.localPort = conn->localPort;
    key2.remotePort = conn->remotePort;
    tcpConnMap.erase(key2);

    // IMPORTANT: usedEphemeralPorts.erase(conn->localPort) is NOT GOOD because it
    // deletes ALL occurrences of the port from the multiset.
    std::multiset<ushort>::iterator it = usedEphemeralPorts.find(conn->localPort);

    if (it != usedEphemeralPorts.end())
        usedEphemeralPorts.erase(it);

    delete conn;
#ifdef PRIVATE
     conn = NULL;
#endif
}

void TCP::finish()
{
    tcpEV << getFullPath() << ": finishing with " << tcpConnMap.size() << " connections open.\n";
}

TCPSendQueue* TCP::createSendQueue(TCPDataTransferMode transferModeP)
{
    switch (transferModeP)
    {
        case TCP_TRANSFER_BYTECOUNT:   return new TCPVirtualDataSendQueue();
        case TCP_TRANSFER_OBJECT:      return new TCPMsgBasedSendQueue();
        case TCP_TRANSFER_BYTESTREAM:  return new TCPByteStreamSendQueue();
        default: throw cRuntimeError("Invalid TCP data transfer mode: %d", transferModeP);
    }
}

TCPReceiveQueue* TCP::createReceiveQueue(TCPDataTransferMode transferModeP)
{
    switch (transferModeP)
    {
        case TCP_TRANSFER_BYTECOUNT:   return new TCPVirtualDataRcvQueue();
        case TCP_TRANSFER_OBJECT:      return new TCPMsgBasedRcvQueue();
        case TCP_TRANSFER_BYTESTREAM:  return new TCPByteStreamRcvQueue();
        default: throw cRuntimeError("Invalid TCP data transfer mode: %d", transferModeP);
    }
}
