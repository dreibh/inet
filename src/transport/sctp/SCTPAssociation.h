//
// Copyright (C) 2008 Irene Ruengeler
// Copyright (C) 2009-2012 Thomas Dreibholz
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __SCTPASSOCIATION_H
#define __SCTPASSOCIATION_H

#include <omnetpp.h>
#include "IPvXAddress.h"
//#include "IPAddress.h"
#include "SCTP.h"
#include "RoutingTable.h"
#include "RoutingTableAccess.h"
#include "InterfaceTable.h"
#include "InterfaceTableAccess.h"
#include "TimeStatsCollector.h"
#ifdef PRIVATE
#include "QoSStatsCollector.h"
#endif
#include "ChunkMap.h"
#include "GapList.h"
#include "SCTPSeqNumbers.h"
#include "SCTPQueue.h"
#include "SCTPSendStream.h"
#include "SCTPReceiveStream.h"
#include "SCTPMessage.h"
#include "IPv4ControlInfo.h"
#include <list>
#include <iostream>
#include <errno.h>
#include <math.h>
#include <platdep/intxtypes.h>
#include "common.h"


class SCTPMessage;
class SCTPCommand;
class SCTPOpenCommand;
class SCTPReceiveStream;
class SCTPSendStream;
class SCTPAlgorithm;
class SCTP;

typedef std::vector<IPvXAddress> AddressVector;

enum SctpState
{
    SCTP_S_CLOSED            = 0,
    SCTP_S_COOKIE_WAIT       = FSM_Steady(1),
    SCTP_S_COOKIE_ECHOED     = FSM_Steady(2),
    SCTP_S_ESTABLISHED       = FSM_Steady(3),
    SCTP_S_SHUTDOWN_PENDING  = FSM_Steady(4),
    SCTP_S_SHUTDOWN_SENT     = FSM_Steady(5),
    SCTP_S_SHUTDOWN_RECEIVED = FSM_Steady(6),
    SCTP_S_SHUTDOWN_ACK_SENT = FSM_Steady(7)
};


//
// Event, strictly for the FSM state transition purposes.
// DO NOT USE outside performStateTransition()!
//
enum SCTPEventCode
{
    SCTP_E_ASSOCIATE,
    SCTP_E_OPEN_PASSIVE,
    SCTP_E_ABORT,
    SCTP_E_SHUTDOWN,
    SCTP_E_CLOSE,
    SCTP_E_SEND,
    SCTP_E_RCV_INIT,
    SCTP_E_RCV_ABORT,
    SCTP_E_RCV_VALID_COOKIE_ECHO,
    SCTP_E_RCV_INIT_ACK,
    SCTP_E_RCV_COOKIE_ACK,
    SCTP_E_RCV_SHUTDOWN,
    SCTP_E_RCV_SHUTDOWN_ACK,
    SCTP_E_RCV_SHUTDOWN_COMPLETE,
    SCTP_E_NO_MORE_OUTSTANDING,
    SCTP_E_TIMEOUT_INIT_TIMER,
    SCTP_E_TIMEOUT_SHUTDOWN_TIMER,
    SCTP_E_TIMEOUT_RTX_TIMER,
    SCTP_E_TIMEOUT_HEARTBEAT_TIMER,
    SCTP_E_IGNORE,
    SCTP_E_RECEIVE,
    SCTP_E_DUP_RECEIVED,
    SCTP_E_PRIMARY,
    SCTP_E_DELIVERED,
    SCTP_E_QUEUE_MSGS_LIMIT,
    SCTP_E_QUEUE_BYTES_LIMIT,
    SCTP_E_SEND_QUEUE_LIMIT,
    SCTP_E_SEND_SHUTDOWN_ACK,
    SCTP_E_STOP_SENDING,
    SCTP_E_STREAM_RESET,
    SCTP_E_SEND_ASCONF,
    SCTP_E_SET_STREAM_PRIO
};

enum SCTPChunkTypes
{
    DATA              = 0,
    INIT              = 1,
    INIT_ACK          = 2,
    SACK              = 3,
    HEARTBEAT         = 4,
    HEARTBEAT_ACK     = 5,
    ABORT             = 6,
    SHUTDOWN          = 7,
    SHUTDOWN_ACK      = 8,
    ERRORTYPE         = 9,
    COOKIE_ECHO       = 10,
    COOKIE_ACK        = 11,
    SHUTDOWN_COMPLETE = 14,
    FORWARD_TSN       = 192,
    STREAM_RESET      = 130,
    ASCONF            = 193,
    ASCONF_ACK        = 128,
    AUTH              = 15,
    NR_SACK           = 16,
    PKTDROP           = 129,
};


enum SCTPFlags
{
    COMPLETE_MESG_UNORDERED = 1,
    COMPLETE_MESG_ORDERED   = 0
};

enum SCTPPrMethods
{
    PR_NONE   = 0,
    PR_TTL    = 1,
    PR_RTX    = 2,
    PR_PRIO   = 3,
    PR_STRRST = 4
};

enum SCTPStreamResetConstants
{
    NOTHING_TO_DO       = 0,
    PERFORMED           = 1,
    DENIED              = 2,
    WRONG_SSN           = 3,
    REQUEST_IN_PROGRESS = 4,
    NO_RESET            = 5,
    RESET_OUTGOING      = 6,
    RESET_INCOMING      = 7,
    RESET_BOTH          = 8,
    SSN_TSN             = 9,
    OUTGOING_RESET_REQUEST_PARAMETER = 13,
    INCOMING_RESET_REQUEST_PARAMETER = 14,
    SSN_TSN_RESET_REQUEST_PARAMETER  = 15,
    STREAM_RESET_RESPONSE_PARAMETER  = 16
};

enum SCTPAddIPCorrelatedTypes
{
    SET_PRIMARY_ADDRESS          = 49156,
    ADAPTATION_LAYER_INDICATION  = 49158,
    SUPPORTED_EXTENSIONS         = 32776,
    ADD_IP_ADDRESS               = 49153,
    DELETE_IP_ADDRESS            = 49154,
    ERROR_CAUSE_INDICATION       = 49155,
    SUCCESS_INDICATION           = 49157,
    ERROR_DELETE_LAST_IP_ADDRESS = 256,
    ERROR_DELETE_SOURCE_ADDRESS  = 258
};

enum SCTPParameterTypes
{
    UNRECOGNIZED_PARAMETER          = 8,
    SUPPORTED_ADDRESS_TYPES         = 12,
    FORWARD_TSN_SUPPORTED_PARAMETER = 49152,
    RANDOM                          = 32770,
    CHUNKS                          = 32771,
    HMAC_ALGO                       = 32772
};

enum SCTPErrorCauses
{
    UNSUPPORTED_HMAC  = 261,
    MISSING_NAT_ENTRY = 177
};



enum SCTPCCModules
{
    RFC4960 = 0
};

enum SCTPStreamSchedulers
{
    ROUND_ROBIN            = 0,
    ROUND_ROBIN_PACKET     = 1,
    RANDOM_SCHEDULE        = 2,
    RANDOM_SCHEDULE_PACKET = 3,
    FAIR_BANDWITH          = 4,
    FAIR_BANDWITH_PACKET   = 5,
    PRIORITY               = 6,
    FCFS                   = 7,
    PATH_MANUAL            = 8,
    PATH_MAP_TO_PATH       = 9
};


#define SCTP_COMMON_HEADER             12    // without options
#define SCTP_INIT_CHUNK_LENGTH         20
#define SCTP_DATA_CHUNK_LENGTH         16
#define SCTP_SACK_CHUNK_LENGTH         16
#define SCTP_NRSACK_CHUNK_LENGTH       20
#define SCTP_HEARTBEAT_CHUNK_LENGTH     4
#define SCTP_ABORT_CHUNK_LENGTH         4
#define SCTP_COOKIE_ACK_LENGTH          4
#define SCTP_FORWARD_TSN_CHUNK_LENGTH   8
#define SCTP_SHUTDOWN_CHUNK_LENGTH      8
#define SCTP_SHUTDOWN_ACK_LENGTH        4
#define SCTP_ERROR_CHUNK_LENGTH         4    // without parameters
#define SCTP_STREAM_RESET_CHUNK_LENGTH                  4   // without parameters
#define SCTP_OUTGOING_RESET_REQUEST_PARAMETER_LENGTH   16   // without streams
#define SCTP_INCOMING_RESET_REQUEST_PARAMETER_LENGTH    8   // without streams
#define SCTP_SSN_TSN_RESET_REQUEST_PARAMETER_LENGTH     8
#define SCTP_STREAM_RESET_RESPONSE_PARAMETER_LENGTH    12
#define SCTP_ADD_IP_CHUNK_LENGTH                        8
#define SCTP_ADD_IP_PARAMETER_LENGTH                    8
#define SCTP_AUTH_CHUNK_LENGTH                          8
#define SCTP_PKTDROP_CHUNK_LENGTH                      16  // without included dropped packet
#define SHA_LENGTH                                     20
#define IP_HEADER_LENGTH                               20
#define SCTP_DEFAULT_ARWND                        (1 << 16)
#define SCTP_DEFAULT_INBOUND_STREAMS                   17
#define SCTP_DEFAULT_OUTBOUND_STREAMS                  17
#define VALID_COOKIE_LIFE_TIME                         10
#define SCTP_COOKIE_LENGTH                             76
#define HB_INTERVAL                                    30
#define PATH_MAX_RETRANS                                5
#ifdef PRIVATE
#define SCTP_COMPRESSED_NRSACK_CHUNK_LENGTH            16
#endif

#define SCTP_TIMEOUT_INIT_REXMIT           3   // initially 3 seconds
#define SCTP_TIMEOUT_INIT_REXMIT_MAX     240   // 4 mins
#define SACK_DELAY                       0.2
#define RTO_BETA                        0.25
#define RTO_ALPHA                      0.125
#define RTO_INITIAL                        3
#define IPTOS_DEFAULT                   0x10   // IPTOS_LOWDELAY

#define DEFAULT_MAX_SENDQUEUE              0       /* unlimited send queue */
#define DEFAULT_MAX_RECVQUEUE              0       /* unlimited recv queue - unused really */

#define MAX_ASSOCS                        10

#define SCTP_MAX_PAYLOAD                1488 // 12 bytes for common header

#define ADD_PADDING(x)                     ((((x) + 3) >> 2) << 2)

#define DEBUG                              1

#define SHUTDOWN_GUARD_TIMEOUT           180

/**
 * Returns the minimum of a and b.
 */
inline double min(const double a, const double b) { return (a < b) ? a : b; }

/**
 * Returns the maximum of a and b.
 */
inline double max(const double a, const double b) { return (a < b) ? b : a; }


class INET_API SCTPPathVariables : public cPolymorphic
{
  public:
    SCTPPathVariables(const IPvXAddress& addr, SCTPAssociation* assoc);
    ~SCTPPathVariables();

    SCTPAssociation*   association;
    IPvXAddress        remoteAddress;

    // ====== Path Management =============================================
    bool               activePath;
    bool               confirmed;
    bool               requiresRtx;
    bool               primaryPathCandidate;
    bool               forceHb;
    // ====== Last SACK ===================================================
    simtime_t          lastSACKSent;                   // T.D. 10.07.2011
    // ====== T3 Timer Handling ===========================================
    // Set to TRUE when CumAck has acknowledged TSNs on this path.
    // Needed to reset T3 timer.
    bool               newCumAck;                      // T.D. 05.12.2009
    // ====== Path Status =================================================
    uint32             pathErrorCount;
    uint32             pathErrorThreshold;
    uint32             pmtu;
    // ====== Congestion Control ==========================================
    uint32             cwnd;
#ifdef PRIVATE
    uint32             tempCwnd;                       // I.R. 08.04.2010
#endif
    uint32             ssthresh;
    uint32             partialBytesAcked;
    uint32             queuedBytes;                    // T.D. 19.02.2010
    uint32             outstandingBytes;
    // ~~~~~~ Temporary storage for SACK handling ~~~~~~~
    uint32             outstandingBytesBeforeUpdate;   // T.D. 20.10.2009
    uint32             newlyAckedBytes;                // T.D. 20.10.2009
    // ====== Fast Recovery ===============================================
    bool               fastRecoveryActive;             // T.D. 21.11.2009
    uint32             fastRecoveryExitPoint;          // T.D. 21.11.2009
    simtime_t          fastRecoveryEnteringTime;       // T.D. 03.12.2009
    // ====== Lowest TSN (used for triggering T3 RTX Timer Restart) =======
    bool               findLowestTSN;                  // T.D. 08.12.2009
    bool               lowestTSNRetransmitted;         // T.D. 08.12.2009

    // ====== Timers ======================================================
    cMessage*           HeartbeatTimer;
    cMessage*           HeartbeatIntervalTimer;
    cMessage*           CwndTimer;
    cMessage*           T3_RtxTimer;
    cMessage*           BlockingTimer;
    cMessage*           ResetTimer;
    cMessage*           AsconfTimer;
#ifdef PRIVATE
    // ====== QoS-SCTP ====================================================
    QoSStatsCollector  QoS;                            // T.D. 11.08.2010
    // ====== High-Speed CC ===============================================
    unsigned int       highSpeedCCThresholdIdx;        // T.D. 22.02.2010
    // ====== Max Burst ===================================================
    uint32             packetsInBurst;                 // T.D. 22.02.2010
    // ====== CMT Split Fast Retransmission ===============================
    bool               sawNewAck;                      // T.D. 24.03.2009
    uint32             lowestNewAckInSack;             // T.D. 04.02.2010
    uint32             highestNewAckInSack;            // T.D. 24.03.2009
    // ====== CMT Pseudo CumAck (CUCv1) ===================================
    bool               findPseudoCumAck;               // T.D. 23.03.2009
    bool               newPseudoCumAck;                // T.D. 23.03.2009
    uint32             pseudoCumAck;                   // T.D. 23.03.2009
    // ====== CMT RTX Pseudo CumAck (CUCv2) ===============================
    bool               findRTXPseudoCumAck;            // T.D. 24.03.2009
    bool               newRTXPseudoCumAck;             // T.D. 24.03.2009
    uint32             rtxPseudoCumAck;                // T.D. 24.03.2009
    uint32             oldestChunkTSN;                 // T.D. 02.03.2010
    simtime_t          oldestChunkSendTime;            // T.D. 02.03.2010
    simtime_t          newOldestChunkSendTime;         // T.D. 02.03.2010
    // ====== CMT Round-Robin among Paths =================================
    simtime_t          lastTransmission;               // T.D. 24.03.2009
    unsigned int       sendAllRandomizer;
    // ====== CMT/RP-SCTP =================================================
    unsigned int       cmtCCGroup;                     // T.D. 27.01.2011
    unsigned int       cmtGroupPaths;                  // T.D. 01.02.2011
    uint32             utilizedCwnd;                   // T.D. 03.02.2011
    uint32             cmtGroupTotalUtilizedCwnd;      // T.D. 03.02.2011
    uint32             cmtGroupTotalCwnd;              // T.D. 01.02.2011
    uint32             cmtGroupTotalSsthresh;          // T.D. 01.02.2011
    double             cmtGroupTotalCwndBandwidth;     // T.D. 03.02.2011
    double             cmtGroupTotalUtilizedCwndBandwidth; // T.D. 03.02.2011
    double             cmtGroupAlpha;                  // T.D. 01.02.2011
    // ====== CMT Sender Buffer Control ===================================
    simtime_t          blockingTimeout;                // T.D. 15.02.2010: do not use path until given time
    // ====== CMT Slow Path RTT Calculation ===============================
    bool               waitingForRTTCalculaton;        // T.D. 25.02.2010
    simtime_t          txTimeForRTTCalculation;        // T.D. 25.02.2010
    uint32             tsnForRTTCalculation;           // T.D. 25.02.2010
#endif

    // ====== Path Status =================================================
    simtime_t           heartbeatTimeout;
    simtime_t           heartbeatIntervalTimeout;
    simtime_t           rtxTimeout;
    simtime_t           cwndTimeout;
    simtime_t           rttUpdateTime;
    simtime_t           lastAckTime;
    simtime_t           pathRto;
    simtime_t           srtt;
    simtime_t           rttvar;

    // ====== Path Statistics =============================================
    unsigned int        gapAckedChunksInLastSACK;        // T.D. 18.10.2010: Per-path GapAck'ed chunks in last SACK (R+NR)
    unsigned int        gapNRAckedChunksInLastSACK;      // T.D. 18.10.2010: Per-path GapAck'ed chunks in last SACK (only NR)
    unsigned int        gapUnackedChunksInLastSACK;      // T.D. 18.10.2010: Per-path Not-GapAck'ed chunks in last SACK (i.e. chunks between GapAcks)
    unsigned int        numberOfDuplicates;
    unsigned int        numberOfFastRetransmissions;
    unsigned int        numberOfTimerBasedRetransmissions;
    unsigned int        numberOfHeartbeatsSent;
    unsigned int        numberOfHeartbeatAcksSent;
    unsigned int        numberOfHeartbeatsRcvd;
    unsigned int        numberOfHeartbeatAcksRcvd;

    // ====== Output Vectors ==============================================
    cOutVector*         statisticsPathRTO;
    cOutVector*         statisticsPathRTT;
    TimeStatsCollector* statisticsPathSSthresh;
    TimeStatsCollector* statisticsPathCwnd;
    TimeStatsCollector* statisticsPathOutstandingBytes;
    TimeStatsCollector* statisticsPathQueuedSentBytes;
    TimeStatsCollector* statisticsPathSenderBlockingFraction;
    TimeStatsCollector* statisticsPathReceiverBlockingFraction;
    TimeStatsCollector* statisticsPathGapAckedChunksInLastSACK;
    TimeStatsCollector* statisticsPathGapNRAckedChunksInLastSACK;
    TimeStatsCollector* statisticsPathGapUnackedChunksInLastSACK;
    TimeStatsCollector* statisticsPathBandwidth;
    cOutVector*         vectorPathFastRecoveryState;
    cOutVector*         vectorPathPbAcked;
    cOutVector*         vectorPathTSNFastRTX;
    cOutVector*         vectorPathTSNTimerBased;
    cOutVector*         vectorPathAckedTSNCumAck;
    cOutVector*         vectorPathAckedTSNGapAck;
#ifdef PRIVATE
    cOutVector*         vectorPathPseudoCumAck;
    cOutVector*         vectorPathRTXPseudoCumAck;
    cOutVector*         vectorPathBlockingTSNsMoved;
#endif
    cOutVector*         vectorPathSentTSN;
    cOutVector*         vectorPathReceivedTSN;
    cOutVector*         vectorPathHb;
    cOutVector*         vectorPathRcvdHb;
    cOutVector*         vectorPathHbAck;
    cOutVector*         vectorPathRcvdHbAck;
};



class INET_API SCTPDataVariables : public cPolymorphic
{
  public:
    SCTPDataVariables();
    ~SCTPDataVariables();

    inline void setInitialDestination(SCTPPathVariables* path) {
        initialDestination = path;
    }
    inline const IPvXAddress& getInitialDestination() const {
        if (initialDestination != NULL) {
            return (initialDestination->remoteAddress);
        }
        return (zeroAddress);
    }
    inline SCTPPathVariables* getInitialDestinationPath() const {
        return (initialDestination);
    }

    inline void setLastDestination(SCTPPathVariables* path) {
        lastDestination = path;
    }
    inline const IPvXAddress& getLastDestination() const {
        if (lastDestination != NULL) {
            return (lastDestination->remoteAddress);
        }
        return (zeroAddress);
    }
    inline SCTPPathVariables* getLastDestinationPath() const {
        return (lastDestination);
    }

    inline void setNextDestination(SCTPPathVariables* path) {
        nextDestination = path;
    }
    inline const IPvXAddress& getNextDestination() const {
        if (nextDestination != NULL) {
            return (nextDestination->remoteAddress);
        }
        return (zeroAddress);
    }
    inline SCTPPathVariables* getNextDestinationPath() const {
        return (nextDestination);
    }

    // ====== Chunk Data Management =======================================
    cPacket*           userData;
    uint32             len;                       // Different from wire
    uint32             booksize;
    uint32             tsn;
    uint16             sid;
    uint16             ssn;
    uint32             ppid;
    uint32             fragments;                 // Number of fragments => TSNs={tsn, ..., tsn+fragments-1}
    bool               enqueuedInTransmissionQ;   // In transmissionQ? Otherwise, it is just in retransmissionQ.
    bool               countsAsOutstanding;       // Is chunk outstanding?
    bool               hasBeenFastRetransmitted;
    bool               hasBeenAbandoned;
    bool               hasBeenReneged;            // Has chunk been reneged?
    bool               hasBeenAcked;              // Has chunk been SACK'ed?
    bool               hasBeenCountedAsNewlyAcked; // Chunk has been counted as newly SACK'ed
    bool               bbit;
    bool               ebit;
    bool               ibit;
    bool               ordered;

    // ====== Retransmission Management ===================================
    uint32             gapReports;
    simtime_t          enqueuingTime;
    simtime_t          sendTime;
    simtime_t          expiryTime;
    uint32             numberOfRetransmissions;
    uint32             numberOfTransmissions;
    uint32             allowedNoRetransmissions;

    // ====== Advanced Chunk Information ==================================
    SCTPPathVariables* queuedOnPath;              // T.D. 10.02.2010: The path to account this chunk in qCounters.queuedOnPath
    SCTPPathVariables* ackedOnPath;               // T.D. 24.02.2010: The path this chunk has been acked on
    bool               hasBeenTimerBasedRtxed;    // T.D. 11.03.2010: Has chunk been timer-based retransmitted?
    bool               hasBeenMoved;              // T.D. 18.02.2010: Chunk has been moved to solve buffer blocking
    bool               wasDropped;                // For receiving side of PKTDROP: chunk dropped
    bool               wasPktDropped;             // Stays true even if the TSN has been transmitted
    bool               qs;                        // If true, chunk was sent with quickstart
    uint32             prMethod;
    uint32             priority;
    bool               strReset;
    simtime_t          firstSendTime;
    bool               sendForwardIfAbandoned;

  public:
    static const IPvXAddress zeroAddress;

    // ====== Private Control Information =================================
  private:
    SCTPPathVariables* initialDestination;
    SCTPPathVariables* lastDestination;
    SCTPPathVariables* nextDestination;
};



class INET_API SCTPStateVariables : public cPolymorphic
{
  public:
    SCTPStateVariables();
    ~SCTPStateVariables();
  public:
    inline void setPrimaryPath(SCTPPathVariables* path) {
       primaryPath = path;
    }
    inline const IPvXAddress& getPrimaryPathIndex() const {
       if (primaryPath != NULL) {
          return (primaryPath->remoteAddress);
       }
       return (SCTPDataVariables::zeroAddress);
    }
    inline SCTPPathVariables* getPrimaryPath() const {
       return (primaryPath);
    }

    bool                     active;
    bool                     fork;
    bool                     ackPointAdvanced;
    bool                     dataChunkReceived;
    bool                     initReceived;
    bool                     cookieEchoReceived;
    bool                     newChunkReceived;
    bool                     firstChunkReceived;
    bool                     swsAvoidanceInvoked;
    bool                     probingIsAllowed;
    bool                     zeroWindowProbing;
    bool                     alwaysBundleSack;
    bool                     fastRecoverySupported;
    bool                     nagleEnabled;
    bool                     sackAllowed;
    bool                     reactivatePrimaryPath;
    bool                     resetPending;
    bool                     stopReceiving;        // incoming data will be discarded
    bool                     stopOldData;          // data with TSN<peerTsnAfterReset will be discarded
    bool                     queueUpdate;
    bool                     firstDataSent;
    bool                     peerWindowFull;
    bool                     zeroWindow;
    bool                     stopSending;          // will be called when SCTP_E_SHUTDOWN arrived
    bool                     inOut;
    bool                     noMoreOutstanding;
    uint32                   numGapReports;
    IPvXAddress              initialPrimaryPath;
    std::list<SCTPPathVariables*> lastDataSourceList;   // DATA chunk sources for new SACK
    SCTPPathVariables*       lastDataSourcePath;
    AddressVector            localAddresses;
    uint32                   errorCount;           // overall error counter
    uint64                   peerRwnd;
    uint64                   initialPeerRwnd;
    uint64                   localRwnd;

    uint32                   nextTSN;              // TSN to be sent
    uint32                   lastTsnAck;           // stored at the sender side; cumTSNAck announced in a SACK
    uint32                   highestTsnAcked;
    uint32                   lastTsnReceived;      // SACK
    uint32                   lastTSN;              // my very last TSN to be sent
    uint32                   ackState;             // number of packets to be acknowledged

    GapList                  gapList;              // GapAck list for incoming DATA chunks
    std::list<uint32>        dupList;              // Duplicates list for incoming DATA chunks

    uint32                   packetsInTotalBurst;
    simtime_t                lastTransmission;

    uint64                   outstandingBytes;     // Number of bytes outstanding
    uint64                   queuedSentBytes;      // Number of bytes in sender queue
    uint64                   queuedDroppableBytes; // Bytes in send queue droppable by PR-SCTP
    uint64                   queuedReceivedBytes;  // Number of bytes in receiver queue
    uint32                   lastStreamScheduled;
    uint32                   assocPmtu;            // smallest overall path mtu
    uint32                   msgNum;               // indicates the sequence number of the message
    uint64                   bytesRcvd;
    uint32                   numRequests;
    uint32                   bytesToRetransmit;
    uint32                   messagesToPush;
    int32                    pushMessagesLeft;
    uint32                   count;
    uint8                    localTieTag[32];
    uint8                    peerTieTag[32];
    uint64                   queuedMessages;       // Messages buffered at the sender side
    uint32                   messageAcceptLimit;
    uint32                   queueLimit;
    uint16                   header;
    int32                    probingTimeout;
    std::vector<int32>       numMsgsReq;
    int32                    cookieLifeTime;
    /** Counter for init and cookie retransmissions */
    int16                    initRetransCounter;
    simtime_t                initRexmitTimeout;
    /** pointer to the init chunk data structure (for retransmissions) */
    SCTPInitChunk*           initChunk;
    /** pointer to the cookie chunk data structure (for retransmissions) */
    SCTPCookieEchoChunk*     cookieChunk;
    /** pointer to the resetChunk (for retransmission) */
    SCTPShutdownChunk*       shutdownChunk;
    SCTPShutdownAckChunk*    shutdownAckChunk;
    SCTPMessage*             sctpmsg;
    uint64                   sendQueueLimit;
    uint64                    sendBuffer;
    bool                     appSendAllowed;
    simtime_t                lastSendQueueAbated;
    uint32                   nextRSid;
    uint32                   swsLimit;
    bool                     lastMsgWasFragment;
    bool                     enableHeartbeats;
    bool                     sendHeartbeatsOnActivePaths;
    SCTPMessage*             sctpMsg;
    uint16                   chunksAdded;
    uint16                   dataChunksAdded;
    uint32                   packetBytes;
    bool                     authAdded;

    // ====== NR-SACK =====================================================
    bool                     nrSack;                       // T.D. 03.03.2010
    uint32                   gapReportLimit;               // T.D. 29.10.2010
    enum GLOVariant {
       GLOV_None       = 0,
       GLOV_Optimized1 = 1,
       GLOV_Optimized2 = 2,
       GLOV_Shrunken   = 3
    };
    uint32                   gapListOptimizationVariant;   // T.D. 18.10.2010
    bool                     smartOverfullSACKHandling;    // T.D. 25.10.2010
    bool                     disableReneging;              // T.D. 29.10.2010

    // ====== Retransmission Method =======================================
    uint32                   rtxMethod;
    // ====== Max Burst ===================================================
    uint32                   maxBurst;
#ifdef PRIVATE
    enum MBVariant {
       MBV_UseItOrLoseIt                    = 0,
       MBV_CongestionWindowLimiting         = 1,
       MBV_UseItOrLoseItTempCwnd            = 2,
       MBV_CongestionWindowLimitingTempCwnd = 3,
       MBV_MaxBurst                         = 4,
       MBV_AggressiveMaxBurst               = 5,
       MBV_TotalMaxBurst                    = 6
    };
    MBVariant                maxBurstVariant;
    uint32                   initialWindow;
    // ====== CMT-SCTP ====================================================
    bool                     allowCMT;
    bool                     (*cmtSendAllComparisonFunction)(const SCTPPathVariables* left, const SCTPPathVariables* right);
    const char*              cmtRetransmissionVariant;

    enum CUCVariant {
       CUCV_Normal         = 0,
       CUCV_PseudoCumAck   = 1,
       CUCV_PseudoCumAckV2 = 2
    };
    CUCVariant               cmtCUCVariant;               // Cwnd Update for CMT (CUC)

    enum BufferSplitVariant {
       CBSV_None         = 0,
       CBSV_SenderOnly   = 1,
       CBSV_ReceiverOnly = 2,
       CBSV_BothSides    = 3
    };
    BufferSplitVariant       cmtBufferSplitVariant;       // Buffer Splitting for CMT
    bool                     cmtBufferSplittingUsesOSB;  // Use outstanding instead of queued bytes for Buffer Splitting

    enum ChunkReschedulingVariant {
       CCRV_None         = 0,
       CCRV_SenderOnly   = 1,
       CCRV_ReceiverOnly = 2,
       CCRV_BothSides    = 3,
       CCRV_Test         = 99    // Test only!
    };
    ChunkReschedulingVariant cmtChunkReschedulingVariant;   // Chunk Rescheduling
    double                   cmtChunkReschedulingThreshold; // Blocking Threshold for Chunk Rescheduling

    bool                     cmtSmartT3Reset;            // Smart T3 Reset for CMT
    bool                     cmtSmartFastRTX;            // Smart Fast RTX for CMT
    bool                     cmtSmartReneging;           // Smart Reneging for CMT
    bool                     cmtSlowPathRTTUpdate;       // Slow Path RTT Update for CMT
    bool                     cmtUseSFR;                  // Split Fast Retransmission (SFR) for CMT
    bool                     cmtUseDAC;                  // Delayed Ack for CMT (DAC)
    bool                     cmtUseFRC;                  // Fast Recovery for CMT (FRC)
    bool                     cmtIntelligentReneging;     // Consider SACK path on reneging
    bool                     cmtSuspendPathOnBlocking;   // After moving blocking chunk, do not use path for Timer-Based RTX during 1 RTO
    bool                     cmtMovedChunksReduceCwnd;   // Subtract moved chunk from cwnd of old path
    double                   movedChunkFastRTXFactor;
    unsigned int             blockingTSNsMoved;
    bool                     strictCwndBooking;          // Strict overbooking handling
    enum CSackPath {
       CSP_Standard     = 0,
       CSP_Primary      = 1,
       CSP_RoundRobin   = 2,
       CSP_SmallestSRTT = 3
    };
    CSackPath                cmtSackPath;                // SACK path selection variant for CMT
    // ====== High-Speed SCTP =============================================
    bool                     highSpeedCC;                // HighSpeed CC (RFC 3649)

    // ====== CMT/RP-SCTP =================================================
    enum CCCVariant {
       CCCV_Off         = 0,   // Standard SCTP
       CCCV_CMT         = 1,   // CMT-SCTP
       CCCV_CMTRPv1     = 2,   // CMT/RP-SCTP with path MTU optimization
       CCCV_CMTRPv2     = 3,   // CMT/RP-SCTP with path MTU optimization and bandwidth consideration
       CCCV_Like_MPTCP  = 4,   // RP like MPTCP
       CCCV_CMTRP_Test1 = 100,
       CCCV_CMTRP_Test2 = 101
    };
    CCCVariant               cmtCCVariant;
    bool                     rpPathBlocking;          // T.D. 10.08.2011: CMT/RP path blocking
    bool                     rpScaleBlockingTimeout;  // T.D. 15.08.2011: Scale blocking timeout by number of paths
    uint32                   rpMinCwnd;               // T.D. 15.08.2011: Minimum cwnd in MTUs
#endif

    // ====== SACK Sequence Number Checker ================================
    bool                     checkSackSeqNumber;         // Ensure handling SACKs in original sequence
    uint32                   outgoingSackSeqNum;
    uint32                   incomingSackSeqNum;

    // ====== Further features ============================================
    bool                     osbWithHeader;
    bool                     padding;
    bool                     streamReset;
    bool                     peerStreamReset;
    bool                     pktDropSent;
    bool                     peerPktDrop;
    uint32                   advancedPeerAckPoint;    // PR-SCTP
    uint32                   lastTsnBeforeReset;      // lastTsn announced in OutgoingStreamResetParameter
    uint32                   streamResetSequenceNumber;
    uint32                   expectedStreamResetSequenceNumber;
    uint32                   peerRequestSn;
    uint32                   inRequestSn;
    uint32                   peerTsnAfterReset;
    uint32                   asconfSn;                // own AddIP serial number
    uint32                   corrIdNum;
    uint32                   prMethod;
    uint16                   hmacType;
    uint16                   numberAsconfReceived;
    bool                     peerAuth;
    bool                     auth;
    bool                     asconfOutstanding;
    std::vector<uint16>      chunkList;
    std::vector<uint16>      peerChunkList;
    uint8                    keyVector[512];
    uint32                   sizeKeyVector;
    uint8                    peerKeyVector[512];
    uint32                   sizePeerKeyVector;
    uint8                    sharedKey[512];
    SCTPStreamResetChunk*    resetChunk;
    SCTPAsconfChunk*         asconfChunk;
    bool                     peerAllowsChunks;        // Flowcontrol: indicates whether the peer adjusts the window according to a number of messages
    uint32                   initialPeerMsgRwnd;
    uint32                   localMsgRwnd;
    uint32                   peerMsgRwnd;             // Flowcontrol: corresponds to peerRwnd
    uint32                   bufferedMessages;        // Messages buffered at the receiver side
    uint32                   outstandingMessages;     // Outstanding messages on the sender side; used for flowControl; including retransmitted messages
    uint32                   bytesToAddPerRcvdChunk;
    uint32                   bytesToAddPerPeerChunk;
    bool                     tellArwnd;
    bool                     swsMsgInvoked;           // Flowcontrol: corresponds to swsAvoidanceInvoked
    bool                     ssOneStreamLeft;
    std::map<uint16,uint32>  ssPriorityMap;
    std::map<uint16,int32>   ssFairBandwidthMap;
    std::map<uint16,int32>   ssStreamToPathMap;
    simtime_t                lastThroughputTime;
    std::map<uint16,uint32>  streamThroughput;
    simtime_t                lastAssocThroughputTime;
    uint32                   assocThroughput;
    double                   throughputInterval;
    bool                     ssNextStream;
    bool                     ssLastDataChunkSizeSet;

  private:
    SCTPPathVariables*       primaryPath;
};



class INET_API SCTPAssociation : public cObject
{
    friend class SCTP;
    friend class SCTPPathVariables;

    // map for storing the path parameters
    typedef std::map<IPvXAddress,SCTPPathVariables*> SCTPPathMap;
    // map for storing the queued bytes per path
    typedef std::map<IPvXAddress, uint32> CounterMap;
    typedef struct counter {
        uint64     roomSumSendStreams;
        uint64     bookedSumSendStreams;
        uint64     roomSumRcvStreams;
        CounterMap roomTransQ;
        CounterMap bookedTransQ;
        CounterMap roomRetransQ;
    } QueueCounter;
    typedef struct calcBytesToSend {
        bool chunk;
        bool packet;
        uint32 bytesToSend;
    } BytesToBeSent;
    typedef struct congestionControlFunctions {
        void(SCTPAssociation::*ccInitParams)(SCTPPathVariables* path);
        void(SCTPAssociation::*ccUpdateBeforeSack)();
        void(SCTPAssociation::*ccUpdateAfterSack)();
        void(SCTPAssociation::*ccUpdateAfterCwndTimeout)(SCTPPathVariables* path);
        void(SCTPAssociation::*ccUpdateAfterRtxTimeout)(SCTPPathVariables* path);
        void(SCTPAssociation::*ccUpdateMaxBurst)(SCTPPathVariables* path);
        void(SCTPAssociation::*ccUpdateBytesAcked)(SCTPPathVariables* path, const uint32 ackedBytes, const bool ctsnaAdvanced);
    } CCFunctions;
    typedef std::map<uint32, SCTPSendStream*>    SCTPSendStreamMap;
    typedef std::map<uint32, SCTPReceiveStream*> SCTPReceiveStreamMap;

  public:
    // connection identification by apps: appgateIndex+assocId
    int32                 appGateIndex; // Application gate index
    int32                 assocId;      // Identifies connection within the app
    IPvXAddress           remoteAddr;   // Remote address from last message
    IPvXAddress           localAddr;    // Local address from last message
    uint16                localPort;    // Remote port from last message
    uint16                remotePort;   // Local port from last message
    uint32                localVTag;    // Local verification tag
    uint32                peerVTag;     // Remote verification tag
    bool                  listen;

    // Timers
    cMessage*             T1_InitTimer;
    cMessage*             T2_ShutdownTimer;
    cMessage*             T5_ShutdownGuardTimer;
    cMessage*             SackTimer;
    cMessage*             StartTesting;
    cMessage*             StartAddIP;
    cOutVector*           advMsgRwnd;
    cOutVector*           EndToEndDelay;
    bool                  fairTimer;
    std::map<uint16,cOutVector*> streamThroughputVectors;
    cOutVector*           assocThroughputVector;
    cMessage*             FairStartTimer;
    cMessage*             FairStopTimer;

#ifdef PRIVATE
    // ------ CMT Delayed Ack (DAC) ---------------------
    uint8_t               dacPacketsRcvd;
#endif

  protected:
    AddressVector         localAddressList;
    AddressVector         remoteAddressList;
    uint32                numberOfRemoteAddresses;
    uint32                inboundStreams;
    uint32                outboundStreams;

    int32                 status;
    uint32                initTsn;
    uint32                initPeerTsn;
    uint32                sackFrequency;
    double                sackPeriod;
    CCFunctions           ccFunctions;
    uint16                ccModule;

    cOutVector*           advRwnd;
    cOutVector*           cumTsnAck;
    cOutVector*           sendQueue;
    cOutVector*           numGapBlocks;
    // ------ Transmission Statistics -------------------------------------
    TimeStatsCollector*   statisticsOutstandingBytes;
    TimeStatsCollector*   statisticsQueuedReceivedBytes;
    TimeStatsCollector*   statisticsQueuedSentBytes;
    TimeStatsCollector*   statisticsTotalSSthresh;
    TimeStatsCollector*   statisticsTotalCwnd;
    TimeStatsCollector*   statisticsTotalBandwidth;
    // ------ Received SACK Statistics ------------------------------------
    TimeStatsCollector*   statisticsRevokableGapBlocksInLastSACK;    // T.D. 18.10.2010: Revokable GapAck blocks in last received SACK
    TimeStatsCollector*   statisticsNonRevokableGapBlocksInLastSACK; // T.D. 18.10.2010: Non-Revokable GapAck blocks in last received SACK
    TimeStatsCollector*   statisticsArwndInLastSACK;
    TimeStatsCollector*   statisticsPeerRwnd;
    // ------ Sent SACK Statistics ----------------------------------------
    TimeStatsCollector*   statisticsNumTotalGapBlocksStored;         // T.D. 18.10.2010: Number of GapAck blocks stored (NOTE: R + NR!)
    TimeStatsCollector*   statisticsNumRevokableGapBlocksStored;     // T.D. 18.10.2010: Number of Revokable GapAck blocks stored
    TimeStatsCollector*   statisticsNumNonRevokableGapBlocksStored;  // T.D. 18.10.2010: Number of Non-Revokable GapAck blocks stored
    TimeStatsCollector*   statisticsNumDuplicatesStored;             // T.D. 18.10.2010: Number of duplicate TSNs stored
    TimeStatsCollector*   statisticsNumRevokableGapBlocksSent;       // T.D. 18.10.2010: Number of Revokable GapAck blocks sent in last SACK
    TimeStatsCollector*   statisticsNumNonRevokableGapBlocksSent;    // T.D. 18.10.2010: Number of Non-Revokable GapAck blocks sent in last SACK
    TimeStatsCollector*   statisticsNumDuplicatesSent;               // T.D. 18.10.2010: Number of duplicate TSNs sent in last SACK
    TimeStatsCollector*   statisticsSACKLengthSent;                  // T.D. 18.10.2010: Length of last sent SACK

    // Variables associated with the state of this association
    SCTPStateVariables*   state;
    BytesToBeSent         bytes;
    SCTP*                 sctpMain;              // SCTP module
    cFSM*                 fsm;                   // SCTP state machine
    SCTPPathMap           sctpPathMap;
    QueueCounter          qCounter;
    ChunkMap*             chunkMap;
    SCTPQueue*            transmissionQ;
    SCTPQueue*            retransmissionQ;
    SCTPSendStreamMap     sendStreams;
    SCTPReceiveStreamMap  receiveStreams;
    SCTPAlgorithm*        sctpAlgorithm;

  public:
    /**
    * Constructor.
    */
    SCTPAssociation(SCTP* mod, int32 appGateIndex, int32 assocId);
    /**
    * Destructor.
    */
    ~SCTPAssociation();
    /**
    * Utility: Send data from sendQueue.
    */
    void sendOnPath(SCTPPathVariables* pathId, const bool firstPass = true);
    void sendOnAllPaths(SCTPPathVariables* firstPath);

    /** Utility: returns name of SCTP_I_xxx constants */
    static const char* indicationName(const int32 code);

    /* @name Various getters */
    //@{
    inline int32 getFsmState() const { return fsm->getState(); };
    inline SCTPStateVariables* getState() const { return state; };
    inline SCTPQueue* getTransmissionQueue() const { return transmissionQ; };
    inline SCTPQueue* getRetransmissionQueue() const { return retransmissionQ; };
    inline SCTPAlgorithm* getSctpAlgorithm() const { return sctpAlgorithm; };
    inline SCTP* getSctpMain() const { return sctpMain; };
    inline cFSM* getFsm() const { return fsm; };
    inline cMessage* getInitTimer() const { return T1_InitTimer; };
    inline cMessage* getShutdownTimer() const { return T2_ShutdownTimer; };
    inline cMessage* getSackTimer() const { return SackTimer; };

    /** Utility: returns name of SCTP_S_xxx constants */
    static const char* stateName(const int32 state);

    /* Process self-messages (timers).
    * Normally returns true. A return value of false means that the
    * connection structure must be deleted by the caller (SCTPMain).
    */
    bool processTimer(cMessage* msg);
    /**
    * Process incoming SCTP segment. Normally returns true. A return value
    * of false means that the connection structure must be deleted by the
    * caller (SCTP).
    */
    bool processSCTPMessage(SCTPMessage* sctpmsg, const IPvXAddress& srcAddr, const IPvXAddress& destAddr);
    /**
    * Process commands from the application.
    * Normally returns true. A return value of false means that the
    * connection structure must be deleted by the caller (SCTP).
    */
    bool processAppCommand(cPacket* msg);
    void removePath();
    void removePath(const IPvXAddress& addr);
    void deleteStreams();
    void stopTimer(cMessage* timer);
    void stopTimers();
    inline SCTPPathVariables* getPath(const IPvXAddress& pathId) const {
        SCTPPathMap::const_iterator iterator = sctpPathMap.find(pathId);
        if (iterator != sctpPathMap.end()) {
            return iterator->second;
        }
        return NULL;
    }
    void printSctpPathMap() const;


  protected:
    /** @name FSM transitions: analysing events and executing state transitions */
    //@{
    /** Maps app command codes (msg kind of app command msgs) to SCTP_E_xxx event codes */
    SCTPEventCode preanalyseAppCommandEvent(int32 commandCode);
    /** Implemements the pure SCTP state machine */
    bool performStateTransition(const SCTPEventCode& event);
    void stateEntered(int32 state);
    //@}
    /** @name Processing app commands. Invoked from processAppCommand(). */
    //@{
    void process_ASSOCIATE(SCTPEventCode& event, SCTPCommand* sctpCommand, cPacket* msg);
    void process_OPEN_PASSIVE(SCTPEventCode& event, SCTPCommand* sctpCommand, cPacket* msg);
    void process_SEND(SCTPEventCode& event, SCTPCommand* sctpCommand, cPacket* msg);
    void process_CLOSE(SCTPEventCode& event);
    void process_ABORT(SCTPEventCode& event);
    void process_STATUS(SCTPEventCode& event, SCTPCommand* sctpCommand, cPacket* msg);
    void process_RECEIVE_REQUEST(SCTPEventCode& event, SCTPCommand* sctpCommand);
    void process_PRIMARY(SCTPEventCode& event, SCTPCommand* sctpCommand);
    void process_STREAM_RESET(SCTPCommand* sctpCommand);
    //@}

    /** @name Processing SCTP message arrivals. Invoked from processSCTPMessage(). */
    //@{
    bool process_RCV_Message(SCTPMessage* sctpseg, const IPvXAddress& src, const IPvXAddress& dest);
    /**
    * Process incoming SCTP packets. Invoked from process_RCV_Message
    */
    bool processInitArrived(SCTPInitChunk* initChunk, int32 sport, int32 dport);
    bool processInitAckArrived(SCTPInitAckChunk* initAckChunk);
    bool processCookieEchoArrived(SCTPCookieEchoChunk* cookieEcho, IPvXAddress addr);
    bool processCookieAckArrived();
    SCTPEventCode processDataArrived(SCTPDataChunk* dataChunk);
    SCTPEventCode processSackArrived(SCTPSackChunk* sackChunk);
    SCTPEventCode processHeartbeatAckArrived(SCTPHeartbeatAckChunk* heartbeatack, SCTPPathVariables* path);
    SCTPEventCode processForwardTsnArrived(SCTPForwardTsnChunk* forChunk);
    bool processPacketDropArrived(SCTPPacketDropChunk* pktdrop);
    void processErrorArrived(SCTPErrorChunk* error);
    //@}

    /** @name Processing timeouts. Invoked from processTimer(). */
    //@{
    void process_TIMEOUT_RTX(SCTPPathVariables* path);
    void process_TIMEOUT_BLOCKING(SCTPPathVariables* path);
    void process_TIMEOUT_HEARTBEAT(SCTPPathVariables* path);
    void process_TIMEOUT_HEARTBEAT_INTERVAL(SCTPPathVariables* path, bool force);
    void process_TIMEOUT_INIT_REXMIT(SCTPEventCode& event);
    void process_TIMEOUT_RESET(SCTPPathVariables* path);
    void process_TIMEOUT_ASCONF(SCTPPathVariables* path);
    void process_TIMEOUT_PROBING();
    void process_TIMEOUT_SHUTDOWN(SCTPEventCode& event);
    int32 updateCounters(SCTPPathVariables* path);
    //@}

    void startTimer(cMessage* timer, const simtime_t& timeout);

    /** Utility: clone a listening association. Used for forking. */
    SCTPAssociation* cloneAssociation();

    /** Utility: creates send/receive queues and sctpAlgorithm */
    void initAssociation(SCTPOpenCommand* openCmd);

    /** Methods dealing with the handling of TSNs  **/
    bool tsnIsDuplicate(const uint32 tsn) const;
    bool makeRoomForTsn(const uint32 tsn, const uint32 length, const bool uBit);

    /** Methods for creating and sending chunks */
    void sendInit();
    void sendInitAck(SCTPInitChunk* initchunk);
    void sendCookieEcho(SCTPInitAckChunk* initackchunk);
    void sendCookieAck(const IPvXAddress& dest);
    void sendAbort();
    void sendHeartbeat(const SCTPPathVariables* path);
    void sendHeartbeatAck(const SCTPHeartbeatChunk* heartbeatChunk,
                          const IPvXAddress&        src,
                          const IPvXAddress&        dest);
    void sendSack();
    void sendShutdown();
    void sendShutdownAck(const IPvXAddress& dest);
    void sendShutdownComplete();
    SCTPSackChunk* createSack();
    void sendStreamResetRequest(uint16 type);
    void sendStreamResetResponse(uint32 srrsn);
    void sendStreamResetResponse(SCTPSSNTSNResetRequestParameter* requestParam,
                                 bool                             options);
    void sendOutgoingResetRequest(SCTPIncomingSSNResetRequestParameter* requestParam);
    void sendPacketDrop(const bool flag);
    void sendHMacError(const uint16 id);

    SCTPForwardTsnChunk* createForwardTsnChunk(const IPvXAddress& pid);

    /** Retransmitting chunks */
    void retransmitInit();
    void retransmitCookieEcho();
    void retransmitReset();
    void retransmitShutdown();
    void retransmitShutdownAck();

    /** Utility: adds control info to message and sends it to IP */
    void sendToIP(SCTPMessage* sctpmsg, const IPvXAddress& dest);
    inline void sendToIP(SCTPMessage* sctpmsg) {
        sendToIP(sctpmsg, remoteAddr);
    }
    void scheduleSack();
    /** Utility: signal to user that connection timed out */
    void signalConnectionTimeout();

    /** Utility: start a timer */
    inline void scheduleTimeout(cMessage* msg, const simtime_t& timeout) {
        sctpMain->scheduleAt(simulation.getSimTime() + timeout, msg);
    }

    /** Utility: cancel a timer */
    inline cMessage* cancelEvent(cMessage* msg) {
        return sctpMain->cancelEvent(msg);
    }

    /** Utility: sends packet to application */
    void sendToApp(cPacket* msg);

    /** Utility: sends status indication (SCTP_I_xxx) to application */
    void sendIndicationToApp(const int32 code, const int32 value = 0);

    /** Utility: sends SCTP_I_ESTABLISHED indication with SCTPConnectInfo to application */
    void sendEstabIndicationToApp();
    void pushUlp();
    void sendDataArrivedNotification(const uint16 sid);
    void putInDeliveryQ(const uint16 sid);
    bool msgMustBeAbandoned(SCTPDataMsg* msg, int32 stream, bool ordered); //PR-SCTP
    void advancePeerTsn();
#ifdef PRIVATE
    inline void cucProcessGapReports(const SCTPDataVariables* chunk,
                                     SCTPPathVariables*       path,
                                     const bool               isAcked);   // CMT-SCTP
#endif

    /** Utility: prints local/remote addr/port and app gate index/assocId */
    void printAssocBrief();
    /** Utility: prints important header fields */
    static void printSegmentBrief(SCTPMessage* sctpmsg);


    /** Utility: returns name of SCTP_E_xxx constants */
    static const char* eventName(const int32 event);

    void addPath(const IPvXAddress& addr);
    SCTPPathVariables* getNextPath(const SCTPPathVariables* oldPath) const;
    inline const IPvXAddress& getNextAddress(const SCTPPathVariables* oldPath) const {
        const SCTPPathVariables* nextPath = getNextPath(oldPath);
        if (nextPath != NULL) {
           return (nextPath->remoteAddress);
        }
       return (SCTPDataVariables::zeroAddress);
    }
    SCTPPathVariables* getNextDestination(const SCTPDataVariables* chunk) const;

    void bytesAllowedToSend(SCTPPathVariables* path, const bool firstPass);

    void pathStatusIndication(const SCTPPathVariables* path, const bool status);

    bool allPathsInactive() const;

    /**
     * Manipulating chunks
     */
    SCTPDataChunk* transformDataChunk(SCTPDataVariables* chunk);
    SCTPDataVariables* makeVarFromMsg(SCTPDataChunk* datachunk);

    /**
     * Dealing with streams
     */

    int32 streamScheduler(SCTPPathVariables* path, bool peek);
    void initStreams(uint32 inStreams, uint32 outStreams);
    int32 numUsableStreams();
    int32 streamSchedulerRoundRobinPacket(SCTPPathVariables* path, bool peek);
    int32 streamSchedulerRandom(SCTPPathVariables* path, bool peek);
    int32 streamSchedulerRandomPacket(SCTPPathVariables* path, bool peek);
    int32 streamSchedulerFairBandwidth(SCTPPathVariables* path, bool peek);
    int32 streamSchedulerFairBandwidthPacket(SCTPPathVariables* path, bool peek);
    int32 streamSchedulerPriority(SCTPPathVariables* path, bool peek);
    int32 streamSchedulerFCFS(SCTPPathVariables* path, bool peek);
    int32 pathStreamSchedulerManual(SCTPPathVariables* path, bool peek);
    int32 pathStreamSchedulerMapToPath(SCTPPathVariables* path, bool peek);
    typedef struct streamSchedulingFunctions {
        void(SCTPAssociation::*ssInitStreams)(uint32 inStreams, uint32 outStreams);
        int32(SCTPAssociation::*ssGetNextSid)(SCTPPathVariables* path, bool peek);
        int32(SCTPAssociation::*ssUsableStreams)();
    } SSFunctions;
    SSFunctions ssFunctions;
    uint16 ssModule;

    /**
     * Queue Management
     */
    void process_QUEUE_MSGS_LIMIT(const SCTPCommand* sctpCommand);
    void process_QUEUE_BYTES_LIMIT(const SCTPCommand* sctpCommand);
    int32 getOutstandingBytes() const;
    void dequeueAckedChunks(const uint32       tsna,
                            SCTPPathVariables* path,
                            simtime_t&         rttEstimation);
    SCTPDataMsg* peekOutboundDataMsg();
    SCTPDataVariables* peekAbandonedChunk(const SCTPPathVariables* path);
    SCTPDataVariables* getOutboundDataChunk(const SCTPPathVariables* path,
                                            const int32              availableSpace,
                                            const int32              availableCwnd);
    SCTPDataMsg* dequeueOutboundDataMsg(SCTPPathVariables* path,
                                        const int32 availableSpace,
                                        const int32 availableCwnd);
    bool nextChunkFitsIntoPacket(SCTPPathVariables* path, int32 bytes);
    void putInTransmissionQ(uint32 tsn, SCTPDataVariables* chunk);

    uint32 getAllTransQ();

    /**
     * Flow control
     */
    void pmStartPathManagement();
    void pmDataIsSentOn(SCTPPathVariables* path);
    void pmClearPathCounter(SCTPPathVariables* path);
    void pmRttMeasurement(SCTPPathVariables* path,
                          const simtime_t&   rttEstimation);

    void disposeOf(SCTPMessage* sctpmsg);

    /** Methods for Stream Reset **/
    void resetSsns();
    void resetExpectedSsns();
    SCTPParameter* makeOutgoingStreamResetParameter(uint32 srsn);
    SCTPParameter* makeIncomingStreamResetParameter(uint32 srsn);
    SCTPParameter* makeSSNTSNResetParameter(uint32 srsn);
    void sendOutgoingRequestAndResponse(uint32 inRequestSn, uint32 outRequestSn);
    SCTPEventCode processInAndOutResetRequestArrived(SCTPIncomingSSNResetRequestParameter* inRequestParam, SCTPOutgoingSSNResetRequestParameter* outRequestParam);
    SCTPEventCode processOutAndResponseArrived(SCTPOutgoingSSNResetRequestParameter* outRequestParam, SCTPStreamResetResponseParameter* responseParam);
    SCTPEventCode processStreamResetArrived(SCTPStreamResetChunk*strResChunk);
    void processOutgoingResetRequestArrived(SCTPOutgoingSSNResetRequestParameter* requestParam);
    void processIncomingResetRequestArrived(SCTPIncomingSSNResetRequestParameter* requestParam);
    void processSSNTSNResetRequestArrived(SCTPSSNTSNResetRequestParameter* requestParam);
    void processResetResponseArrived(SCTPStreamResetResponseParameter* responseParam);

    /** Methods for Add-IP and AUTH **/
    void sendAsconf(const char* type, const bool remote = false);
    void sendAsconfAck(const uint32 serialNumber);
    SCTPEventCode processAsconfArrived(SCTPAsconfChunk* asconfChunk);
    SCTPEventCode processAsconfAckArrived(SCTPAsconfAckChunk* asconfAckChunk);
    void retransmitAsconf();
    bool typeInChunkList(const uint16 type);
    SCTPAsconfAckChunk*      createAsconfAckChunk(const uint32 serialNumber);
    SCTPAuthenticationChunk* createAuthChunk();
    SCTPSuccessIndication*   createSuccessIndication(uint32 correlationId);
    void calculateAssocSharedKey();
    bool compareRandom();

    void makeRoutingEntry(const char* route);
    void calculateRcvBuffer();
    void listOrderedQ();
    void tsnWasReneged(SCTPDataVariables*       chunk,
                       const SCTPPathVariables* sackPath,
                       const int                type);
    void printOutstandingTsns();

    /** SCTPCCFunctions  **/
    void initCCParameters(SCTPPathVariables* path);
    void updateFastRecoveryStatus(const uint32 lastTsnAck);
    void cwndUpdateBeforeSack();
    void cwndUpdateAfterSack();
    void cwndUpdateAfterCwndTimeout(SCTPPathVariables* path);
    void cwndUpdateAfterRtxTimeout(SCTPPathVariables* path);
    void cwndUpdateMaxBurst(SCTPPathVariables* path);
    void cwndUpdateBytesAcked(SCTPPathVariables* path,
                              const uint32       ackedBytes,
                              const bool         ctsnaAdvanced);
    int32 rpPathBlockingControl(SCTPPathVariables* path, const double reduction);

  private:
    SCTPDataVariables* makeDataVarFromDataMsg(SCTPDataMsg*       datMsg,
                                              SCTPPathVariables* path);
    SCTPPathVariables* choosePathForRetransmission();
    void timeForSack(bool& sackOnly, bool& sackWithData);
    void sendSACKviaSelectedPath(SCTPMessage* sctpMsg);
    void checkOutstandingBytes();
#ifdef PRIVATE
      void updateHighSpeedCCThresholdIdx(SCTPPathVariables* path);
#endif
    uint32 getInitialCwnd(const SCTPPathVariables* path) const;
    void recordCwndUpdate(SCTPPathVariables* path);
    void generateSendQueueAbatedIndication(const uint64 bytes);
    void renegablyAckChunk(SCTPDataVariables* chunk,
                           SCTPPathVariables* sackPath);
    void nonRenegablyAckChunk(SCTPDataVariables* chunk,
                              SCTPPathVariables* sackPath,
                              simtime_t&         rttEstimation,
                              SCTP::AssocStat*   assocStat);
    void handleChunkReportedAsAcked(uint32&            highestNewAck,
                                    simtime_t&         rttEstimation,
                                    SCTPDataVariables* myChunk,
                                    SCTPPathVariables* sackPath,
                                    const bool         sackIsNonRevokable);
    void handleChunkReportedAsMissing(const SCTPSackChunk*     sackChunk,
                                      const uint32             highestNewAck,
                                      SCTPDataVariables*       myChunk,
                                      const SCTPPathVariables* sackPath);
    void moveChunkToOtherPath(SCTPDataVariables* chunk,
                              SCTPPathVariables* newPath);
    void decreaseOutstandingBytes(SCTPDataVariables* chunk);
    void increaseOutstandingBytes(SCTPDataVariables* chunk,
                                  SCTPPathVariables* path);
    int32 calculateBytesToSendOnPath(const SCTPPathVariables* pathVar);
    void storePacket(SCTPPathVariables* pathVar,
                     SCTPMessage*       sctpMsg,
                     const uint16       chunksAdded,
                     const uint16       dataChunksAdded,
                     const bool         authAdded);
    void loadPacket(SCTPPathVariables* pathVar,
                    SCTPMessage**      sctpMsg,
                    uint16*            chunksAdded,
                    uint16*            dataChunksAdded,
                    bool*              authAdded);

    inline void ackChunk(SCTPDataVariables* chunk, SCTPPathVariables* sackPath) {
        chunkMap->ack(chunk->tsn);
        chunk->hasBeenAcked = true;
        chunk->ackedOnPath = sackPath;
    }
    inline void unackChunk(SCTPDataVariables* chunk) {
        chunkMap->unack(chunk->tsn);
        chunk->hasBeenAcked = false;
    }
    inline bool chunkHasBeenAcked(const SCTPDataVariables* chunk) const {
        return (chunk->hasBeenAcked);
    }
    inline bool chunkHasBeenAcked(const uint32 tsn) const {
        return (chunkMap->isAcked(tsn));
    }

    void recordTransmission(SCTPMessage* sctpMsg, SCTPPathVariables* path);
    void recordAcknowledgement(SCTPDataVariables* chunk, SCTPPathVariables* path);
    void recordDequeuing(SCTPDataVariables* chunk);

#ifdef PRIVATE
    void checkPseudoCumAck(const SCTPPathVariables* path);
    static bool pathMapLargestSSThreshold(const SCTPPathVariables* left, const SCTPPathVariables* right);
    static bool pathMapLargestSpace(const SCTPPathVariables* left, const SCTPPathVariables* right);
    static bool pathMapLargestSpaceAndSSThreshold(const SCTPPathVariables* left, const SCTPPathVariables* right);
    static bool pathMapSmallestLastTransmission(const SCTPPathVariables* left, const SCTPPathVariables* right);
    static bool pathMapRandomized(const SCTPPathVariables* left, const SCTPPathVariables* right);
    std::vector<SCTPPathVariables*> getSortedPathMap();
    void chunkReschedulingControl(SCTPPathVariables* path);
#endif

    void dumpPaths(std::ostream& os = sctpEV3) const;
    void dumpQueue(std::ostream& os = sctpEV3);

    inline bool addAuthChunkIfNecessary(SCTPMessage* sctpMsg,
                                        const uint16 chunkType,
                                        const bool   authAdded) {
       if ((state->auth) &&
          (state->peerAuth) &&
          (typeInChunkList(chunkType)) &&
          (authAdded == false)) {
           SCTPAuthenticationChunk* authChunk = createAuthChunk();
           sctpMsg->addChunk(authChunk);
           return (true);
       }
       return (false);
    }
};

#endif
