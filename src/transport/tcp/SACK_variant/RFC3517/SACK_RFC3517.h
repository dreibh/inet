/*
 * TCPMultipathFlow.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */

#ifndef SACK_RFC3517_H_
#define SACK_RFC3517_H_
/*
 * TCPMultipathFlow.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */
#include <omnetpp.h>
#include "INETDefs.h"
#include "SACKHandler.h"


#include <vector>
#include <map>
#include <set>

class TCPConnection;
typedef struct __sack_region{
    uint32 end;
    uint32 len;
    uint32 sacked_above;
    uint32 dup;
    bool lost;
} SACK_REGION;

typedef std::map<uint32, SACK_REGION*> SACK_MAP;    //uint32 start;

typedef struct _scoreboard{
    uint32 cum_acked;
    uint32 total_sacked;
    uint32 high_acked;
    uint32 high_data;
    uint32 high_rtx;
    uint32 pipe;
    uint32 recoveryPoint;
    SACK_MAP map;
    uint32 old_nxt;
} SCOREBOARD;

class SACK_RFC3517 : public SACKHandler{
private:
    TCPConnection* con;
   //  TCPNewSACKRexmitQueue *rexmitQueue;
    SCOREBOARD sb;
    static int ID_COUNTER;
    int ID;
    virtual void _setPipe();
    uint32 _nextSeg();
    virtual SACK_REGION* _isLost(SACK_MAP::iterator *i, uint32 seg);
    void _createIsLostTag();

    void _cntDup(uint32 start, uint32 end);
    void _print_and_check_sb();
public:
    SACK_RFC3517( TCPConnection *conn);
    virtual ~SACK_RFC3517();

    virtual void initial();
    virtual void updateStatus();

    virtual uint32 sendUnsackedSegment(uint32 wnd);

    virtual uint32 getHighRxt();    // RFC 3517, page 3: ""HighRxt" is the highest sequence number which has been retransmitted during the current loss recovery phase."
    virtual uint32 do_forward();
    virtual bool statusChanged();
    virtual void discardUpTo(uint32 to);
    virtual void flush();
    virtual void reset() ;
    virtual void setNewRecoveryPoint(uint32 r);
    virtual uint32 getRecoveryPoint();
    virtual TCPSegment * addSACK(TCPSegment *tcpseg);
    virtual bool processSACKOption(TCPSegment *tcpseg, const TCPOption& option);
};

#endif /* SACK_RFC3517_H_ */
