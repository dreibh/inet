/*
 * TCPMultipathSchedulerI.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */

#ifndef TCPMULTIPATHSCHEDULER_INTERFACE_H_
#define TCPMULTIPATHSCHEDULER_INTERFACE_H_


#include "TCPMultipathFlow.h"


// ###############################################################################################################
//                                            MULTIPATH TCP Scheduler Interface
//
// ###############################################################################################################
/**
 * The MULTIPATH TCP Scheduler Interface
 */
class INET_API MPTCP_SchedulerI
{

  public:
    virtual void initialize(MPTCP_Flow* flow) = 0;
    virtual void schedule(TCPConnection* origin, cMessage* msg) = 0;
    virtual uint32_t getFreeSendBuffer() = 0;

};


#endif /* TCPMULTIPATHSCHEDULER_INTERFACE_H_ */
