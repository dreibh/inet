//
// Copyright (C) 2009 Thomas Reschka
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

#ifndef __INET_TCPNEWRENO_H
#define __INET_TCPNEWRENO_H

#include "INETDefs.h"

#include "TCPTahoeRenoFamily.h"


/**
 * State variables for TCPNewReno.
 */
typedef TCPTahoeRenoFamilyStateVariables TCPNewRenoStateVariables;


/**
 * Implements TCP NewReno.
 */
class INET_API TCPNewReno : public TCPTahoeRenoFamily
{
  private:


  protected:
    TCPNewRenoStateVariables *&state; // alias to TCPAlgorithm's 'state'

    /** Create and return a TCPNewRenoStateVariables object. */
    virtual TCPStateVariables *createStateVariables() {
        return new TCPNewRenoStateVariables();
    }

    /** Utility function to recalculate ssthresh */
    virtual void recalculateSlowStartThreshold();

    /** Redefine what should happen on retransmission */
    virtual void processRexmitTimer(TCPEventCode& event);

    virtual void increaseCWND(uint32 increase);

    virtual void decreaseCWND(uint32 decrease);
    virtual void setCWND(uint32 newCWND);
    // virtual void initializeTCPNewReno();
    virtual void initilazeCWND();
    virtual void updateCWND(uint32 firstSeqAcked);
    virtual uint32 bytesInFlight();

  public:
    /** Ctor */
    TCPNewReno();
    uint32 acked;
    /** Redefine what should happen when data got acked, to add congestion window management */
    virtual void receivedDataAck(uint32 firstSeqAcked);

    /** Redefine what should happen when dupAck was received, to add congestion window management */
    virtual void receivedDuplicateAck();

    /* redefine initialize*/
    virtual void initialize();
};

#endif
