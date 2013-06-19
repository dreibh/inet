//
// Copyright (C) 2013 Martin Becke
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

#ifndef __INET_MPTCP_RFC6356
#define __INET_MPTCP_RFC6356

#include "INETDefs.h"
#include "TCPNewReno.h"


/**
 * State variables for MPTCP_RFC6356.
 */
//typedef TCPTahoeRenoFamilyStateVariables MPTCP_RFC6356StateVariables;


/**
 * Implements TCP MPTCP_RFC6356.
 */
class INET_API MPTCP_RFC6356 : public TCPNewReno
{
  private:
    bool isCA;

    virtual void increaseCWND(uint32 increase);
    /** Utility function to recalculate path variables */
    virtual void recalculateMPTCPCCBasis();
//    virtual void updateCWND(uint32 firstSeqAcked);
//    virtual void decreaseCWND(uint32 decrease);
//    virtual void setCWND(uint32 newCWND);
//    virtual void initializeMPTCP_RFC6356();
//    virtual void initilazeCWND();
//
//    virtual uint32 bytesInFlight();
//
//  protected:
//    MPTCP_RFC6356StateVariables *&state; // alias to TCPAlgorithm's 'state'
//
//    /** Create and return a MPTCP_RFC6356StateVariables object. */
//    virtual TCPStateVariables *createStateVariables() {
//        return new MPTCP_RFC6356StateVariables();
//    }
//
//    /** Utility function to recalculate ssthresh */
//    virtual void recalculateSlowStartThreshold();
//
//
//    /** Redefine what should happen on retransmission */
//    virtual void processRexmitTimer(TCPEventCode& event);
//
  public:
//    /** Ctor */
    MPTCP_RFC6356();

//    /** Redefine what should happen when data got acked, to add congestion window management */
//    virtual void receivedDataAck(uint32 firstSeqAcked);
//
//    /** Redefine what should happen when dupAck was received, to add congestion window management */
//    virtual void receivedDuplicateAck();
//
//    /* redefine initialize*/
//    virtual void initialize();
};

#endif
