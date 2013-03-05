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

#ifdef PRIVATE

#include "TCPSchedulerManager.h"

// ######################################################################################
//                           Scheduler manager
// ######################################################################################


TCPSchedulerManager::TCPSchedulerManager() {
	// TODO Auto-generated constructor stub

}

TCPSchedulerManager::~TCPSchedulerManager() {
	// TODO Auto-generated destructor stub
}


// ######################################################################################
//                           Round Robin Scheduler
// ######################################################################################

/**
 * Constructor
 */
TCPRoundRobinScheduler::TCPRoundRobinScheduler(){

}

/**
 * Destructor
 */
TCPRoundRobinScheduler::~TCPRoundRobinScheduler(){

}

/**
 * send TCP in Round Robin manner
 */
bool TCPRoundRobinScheduler::sendTCPSegment(){
	return true;
}

/**
 * Print statistical information for Round Robin
 */
bool TCPRoundRobinScheduler::printStatus(){
	return true;
}


#endif //Private
