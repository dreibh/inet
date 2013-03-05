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
//

#ifdef PRIVATE

#ifndef TCPSCHEDULERMANAGER_H_
#define TCPSCHEDULERMANAGER_H_

#include <omnetpp.h>
#include "INETDefs.h"

class TCPScheduler; 			// Interface to Scheduler
class TCPRoundRobinScheduler;	// Round Robin
// TODO Alternative Schedulers

class INET_API TCPSchedulerManager : public cPolymorphic
{
public:
	static bool sendTCPSegment();
	virtual ~TCPSchedulerManager();
private:
	TCPSchedulerManager();
	TCPScheduler* scheduler;
};

/**
 * Abstract Scheduler Class - Interface to scheduler function
 * Future scheduler classes should base on this
 */
class TCPScheduler
{
public:
	virtual ~TCPScheduler(){};
	virtual bool sendTCPSegment() = 0;
	virtual bool printStatus() = 0;
};

// Round Robin
class TCPRoundRobinScheduler: public TCPScheduler{
public:
	TCPRoundRobinScheduler();
	virtual ~TCPRoundRobinScheduler();
	virtual bool sendTCPSegment();
	virtual bool printStatus();
};

#endif /* TCPSCHEDULERMANAGER_H_ */

#endif
