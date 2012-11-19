/*
 * TCPMultipathPCB.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */
#ifdef PRIVATE
#ifndef TCPMULTIPATHPCB_H_
#define TCPMULTIPATHPCB_H_

#include "TCPMultipathFlow.h"

// ###############################################################################################################
//                                                  MULTIPATH TCP
//                                                      PCB
// ###############################################################################################################
/**
 * The Multipath TCP Protocol Control Block and Meta-socket
 */
class INET_API MPTCP_PCB
{
    public:
        MPTCP_PCB(int connId,int appGateIndex, TCPConnection* subflow); // public constructor
        ~MPTCP_PCB();
        // Static helper elements for organization
        static AllMultipathSubflowsVector_t subflows_vector;
        // Connection handling
        static MPTCP_PCB* lookupMPTCP_PCB(int connid, int aAppGateIndex,TCPSegment *tcpseg,  TCPConnection* subflow);
        TCPConnection*    lookupMPTCPConnection(int connId,int aAppGateIndex, TCPConnection* subflow,TCPSegment *tcpseg);
        // Use Case
        static int processMPTCPSegment(int connId,int aAppGateIndex, TCPConnection* subflow, TCPSegment *tcpseg);

        // Getter/ Setter
        MPTCP_Flow* getFlow();
        int getID();


    private:
        MPTCP_PCB();

        MPTCP_Flow* flow;
        // helper for process Segments
        int _processSegment(int connId, TCPConnection* subflow, TCPSegment *tcpseg);
        int _processMP_CAPABLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const TCPOption* option);
        int _processMP_JOIN_IDLE(int connId, TCPConnection* subflow, TCPSegment *tcpseg, const TCPOption* option);
        int _processMP_JOIN_ESTABLISHED(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option);
        int _processMP_DSS(int connId, TCPConnection* subflow, TCPSegment *tcpseg,const  TCPOption* option);
        // cleanup
        int _clearAll();


        // Lookup for Multipath Control Block management
        static MPTCP_PCB* _lookupMPTCP_PCB(int connid, int aAppGateIndex);
        static MPTCP_PCB* _lookupMPTCPbySubflow_PCB(TCPSegment *tcpseg,  TCPConnection* subflow);
        static MPTCP_PCB* _lookupMPTCP_PCBbyMP_JOIN_Option(TCPSegment* tcpseg, TCPConnection* subflow);

        // Sending side
        uint64_t snd_una; // B.1.2
        uint64_t snd_nxt; // B.1.2
        uint32_t snd_wnd; // B.1.2

        // Receiver Side
        uint64_t rcv_nxt; // B.1.2
        uint64_t rcv_wnd; // B.1.2

        // debug
        int id;
        void _printFlowOverview(int);
};


#endif /* TCPMULTIPATHPCB_H_ */
#endif /* PRIVATE */
