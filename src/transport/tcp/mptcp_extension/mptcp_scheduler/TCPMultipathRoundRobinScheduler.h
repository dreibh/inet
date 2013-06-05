/*
 * TCPMultipathRoundRobinScheduler.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */

#ifndef TCPMULTIPATHROUNDROBINSCHEDULER_H_
#define TCPMULTIPATHROUNDROBINSCHEDULER_H_

#include <omnetpp.h>
#include "TCPMultipathSchedulerI.h"
#include "TCPConnection.h"



// ###############################################################################################################
//                                            MULTIPATH TCP Scheduler
//                                                  Round Robin
// ###############################################################################################################
/**
 * The MULTIPATH TCP Scheduler Interface
 */
class INET_API MPTCP_RoundRobinScheduler : public MPTCP_SchedulerI , public cPolymorphic
{

  public:
    MPTCP_RoundRobinScheduler ();
    virtual ~MPTCP_RoundRobinScheduler();
    virtual void initialize(MPTCP_Flow* flow);
    virtual void schedule(TCPConnection* origin, cMessage* msg);
    virtual uint32_t getFreeSendBuffer();
  private:
    // Message handlign -> TODO SCHEDULER
    size_t last;
    void _createMSGforProcess(cMessage *msg, TCPConnection* conn);
    void _next(uint32 bytes,  TCPConnection* lastUsed);
    MPTCP_Flow* flow;
};


#endif /* TCPMULTIPATHSCHEDULER_INTERFACE_H_ */
