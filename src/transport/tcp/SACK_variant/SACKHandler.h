/*
 * SACKHandler.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */

#ifndef SACKHANDLER_H_
#define SACKHANDLER_H_
/*
 * TCPMultipathFlow.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */
#include "TCPConnection.h"

class TCPStateVariables;

class SACKHandler {
protected:
    TCPStateVariables *state;

public:
    SACKHandler( TCPStateVariables *n_state){
        state = n_state;
    }
    virtual ~SACKHandler(){};
    virtual void initial() = 0;             // Must
    virtual void updateStatus() = 0;        // Must
    virtual uint32 sendUnsackedSegment(uint32 wnd) = 0;             // Must


    virtual uint32 getHighRxt() = 0;    // RFC 3517, page 3: ""HighRxt" is the highest sequence number which has been retransmitted during the current loss recovery phase."
   virtual uint32 do_forward() = 0;
   virtual bool statusChanged() = 0;
    virtual void discardUpTo(uint32 to) = 0;
    virtual void flush() = 0;
    virtual void reset() = 0;
    virtual void setNewRecoveryPoint(uint32 r) = 0;
    virtual uint32 getRecoveryPoint() = 0;
    virtual TCPSegment* addSACK(TCPSegment *tcpseg) = 0;
    virtual bool processSACKOption(TCPSegment *tcpseg, const TCPOption& option) = 0;


};

#endif /* SACK_RFC3517_H_ */
