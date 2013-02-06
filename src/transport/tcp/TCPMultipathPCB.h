/*
 * TCPMultipathPCB.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */
#ifdef PRIVATE
#ifndef TCPMULTIPATHPCB_H_
#define TCPMULTIPATHPCB_H_

#include "TCPMultipath.h"
#include "TCPMultipathFlow.h"

class MPTCP_Flow;

typedef struct _4tupleWithStatus{
    MPTCP_Flow* flow;
    bool active;
    int  connID;
    int  appGateIndex;
} TuppleWithStatus_t;
typedef std::vector <TuppleWithStatus_t*>    AllMultipathTCPVector_t;

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

        // Connection handling
        static MPTCP_PCB* lookupMPTCP_PCB(int connid, int aAppGateIndex,TCPSegment *tcpseg,  TCPConnection* subflow);
        static void addMPTCPFlow(TuppleWithStatus_t* );
        TCPConnection*    lookupMPTCPConnection(int connId,int aAppGateIndex, TCPConnection* subflow,TCPSegment *tcpseg);

        // Data handling
        static MPTCP_PCB* processMPTCPSegment(int connId,int aAppGateIndex, TCPConnection* subflow, TCPSegment *tcpseg);

        // Getter
        MPTCP_Flow* getFlow();
        int getID();




        void DEBUGprintFlowOverview(int);


    private:
        MPTCP_PCB();
        MPTCP_Flow* flow;

        // Selforganisation
        TuppleWithStatus_t* t; // includes also the flow

        // Static helper elements for organization
        static AllMultipathTCPVector_t mptcp_flow_vector;

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
        static MPTCP_PCB* _lookupMPTCPbySubflow_PCB(int connId, int aAppGateIndex, TCPSegment *tcpseg,  TCPConnection* subflow);
        static MPTCP_PCB* _lookupMPTCP_PCBbyMP_Option(TCPSegment* tcpseg, TCPConnection* subflow);


        // debug
        int id;

};


#endif /* TCPMULTIPATHPCB_H_ */
#endif /* PRIVATE */
