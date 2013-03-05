/*
 * TCPMultipathRoundRobinScheduler.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */

#ifndef TCPMULTIPATHROUNDROBINSCHEDULER_H_
#define TCPMULTIPATHROUNDROBINSCHEDULER_H_


#include "TCPMultipathSchedulerI.h"


// ###############################################################################################################
//                                            MULTIPATH TCP Scheduler
//                                                  Round Robin
// ###############################################################################################################
/**
 * The MULTIPATH TCP Scheduler Interface
 */
class INET_API MPTCP_RoundRobinScheduler : public MPTCP_SchedulerI
{

  public:
    MPTCP_RoundRobinScheduler ();
    virtual ~MPTCP_RoundRobinScheduler();
    virtual void initialize(MPTCP_Flow* flow);
    virtual void schedule(TCPConnection* origin, cMessage* msg);
  private:
    // Message handlign -> TODO SCHEDULER
    void _createMSGforProcess(cMessage *msg, TCPConnection* sc);
};


#endif /* TCPMULTIPATHSCHEDULER_INTERFACE_H_ */
