/*
 * TCPMultipathFlow.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */

#ifndef TCPMULTIPATHFLOW_H_
#define TCPMULTIPATHFLOW_H_
#include <omnetpp.h>
#include "INETDefs.h"

#include <vector>
#include <map>
#include <set>
#include "InterfaceTableAccess.h"
#include "TCPConnection.h"
#include "TCPMultipath.h"

class TCPStateVariables;
class TCPMultipathReceiveQueue;
class TCPConnection;



typedef struct _subflow{
  TCPConnection* subflow;
  bool active;
  int cnt;
} TCP_subflow_t;
typedef std::vector <TCP_subflow_t*>         TCP_SubFlowVector_t;

typedef struct _addr_tuple{
    IPvXAddress addr;
    int         port;
} AddrTupple_t;
typedef std::vector <AddrTupple_t*>          TCP_AddressVector_t;

typedef struct _addr_combi{
    AddrTupple_t local;
    AddrTupple_t remote;
} AddrCombi_t;
typedef std::vector <AddrCombi_t*>           TCP_JoinVector_t;

enum MPTCP_State {IDLE, PRE_ESTABLISHED, ESTABLISHED, SHUTDOWN};

#ifdef PRIVATE
#include <queue>
typedef std::queue<cPacket*>         Tmp_Buffer_t;
#endif

// ###############################################################################################################
//                                                  MULTIPATH TCP
//                                                      FLOW
// ###############################################################################################################
/**
 * The MULTIPATH TCP Flow
 */
class INET_API MPTCP_Flow
{

  public:
	static int CNT;
	int ID;
    // Flow could only be initilized with an Protocol Control Block
    MPTCP_Flow(int ID, int aAppGateIndex,TCPConnection* subflow, MPTCP_PCB* aPCB);
    ~MPTCP_Flow();

    // Some helper for request state of MPTCP Extension
    MPTCP_State getState();
    MPTCP_PCB*  getPCB();

    //######################################################
    // Use Cases
    // 1) Exchange with socket interface (Send)
    // 2) Exchange with application
    // 3) Manipulate message format
    // 4) Read Msg (is done by PCB)
    // 6) Schedule msg
    // 7) Congestion & Flow Control ->Open

    // for 2 -> Omnet Interface
    void enqueueMPTCPData(TCPSegment *tcpseg, uint64 dss_start_seq, uint32 data_len);
    void sendToApp(cMessage* msg, TCPConnection *conn);
    // for 1 & 3
    int writeMPTCPHeaderOptions(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg, uint32, TCPConnection* subflow);
    // for 6
    TCPConnection* schedule(TCPConnection* save, cMessage* msg);

    void refreshSendMPTCPWindow();
    //######################################################
    // Security
    void initKeyMaterial(TCPConnection* subflow);
    bool keysAreEqual(uint64_t rk, uint64_t lk );
    void     setRemoteKey(uint64_t key);
    void     setLocalKey(uint64_t key);
    uint32_t getRemoteToken();              // unique per PCB
    uint32_t getLocalToken();               // unique per PCB
    bool sendCommandInvoked();
    bool close();
    //######################################################
    // SQN and buffer
    uint64_t getHighestCumSQN();
    uint64_t getBaseSQN();          // Base of Offset SQN calculation
    uint64_t getSQN();
    void setBaseSQN(uint64_t s);
    int  setState(MPTCP_State s);
    void setSendQueueLimit(int limit);
    // Some Helper for Omnet ID stuff
    int getAppID();
    int getappGateIndex();

    //######################################################
    // subflow organisation
    int addSubflow(int id, TCPConnection*);
    void removeSubflow(TCPConnection*);
    bool isSubflowOf(TCPConnection* subflow);
    const TCP_SubFlowVector_t* getSubflows();
    bool sendEstablished;

    //######################################################
    // Debug
    void DEBUGprintStatus();
    void DEBUGprintMPTCPFlowStatus();
    void DEBUGprintDSSInfo();

    //######################################################
    // Draft stuff
    // Sending side
    uint64_t mptcp_snd_una;                       // B.1.2
    uint64_t mptcp_snd_nxt;                       // B.1.2
    uint32_t mptcp_snd_wnd;                       // B.1.2

    // Receiver Side
    uint64_t mptcp_rcv_nxt;                       // B.1.2
    uint64_t mptcp_rcv_wnd;                       // B.1.2
    uint64_t seq;                           	  // start seq-no generated after getting keys for the first flow
    uint64_t start_seq;

    //######################################################
    // MPTCP CC stuff
    uint32             utilizedCMTCwnd;
    uint32             totalCMTCwnd;
    uint32             totalCMTSsthresh;
    // double             maxCwndBasedBandwidth;
    // double             totalCwndBasedBandwidth;
    double             cmtCC_alpha;
    // helper
   // uint32_t flow_send_queue_limit;
  protected:
    bool checksum;
    bool isPassive;
    bool ordered;
    InterfaceTableAccess interfaceTableAccess;

    // Vector and Scalar
    cOutVector *mptcpRcvBufferSize;

  private:
    // Receive Queue
    TCPMultipathReceiveQueue* mptcp_receiveQueue;

    // From the ITEF Draft
    MPTCP_State state;                      // Internal State of the multipath protocol control block
    MPTCP_PCB* pcb;                                // the pcb

    uint64_t local_key;                     // B.1.1 Authentication and Metadata
    uint64_t remote_key;                    // B.1.1 Authentication and Metadata

    // Organisation helper
    TCP_AddressVector_t     list_laddrtuple;   // list of local addresses
    TCP_AddressVector_t     list_raddrtuple;   // list of remote addresses
    TCP_SubFlowVector_t     subflow_list;      // list of all subflows
    TCP_JoinVector_t        join_queue;           // a queue with all join possibilities
    TCP_JoinVector_t        tried_join;


    void _initFlow(int port);
    // Helper - Write packets
    int _writeInitialHandshakeHeader(uint t,
    TCPStateVariables* subflow_state, TCPSegment *tcpseg,
    TCPConnection* subflow, TCPOption* option);
    int _writeJoinHandshakeHeader(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg,
              TCPConnection* subflow, TCPOption* option);
    int _writeDSSHeaderandProcessSQN(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg, uint32 bytes,
              TCPConnection* subflow, TCPOption* option);
    bool _prepareJoinConnection();

    // crypto functions ==> see also rfc 2104
    uint64 _generateLocalKey();
    int    _generateToken(uint64_t key, bool type);

    unsigned char* _generateSYNACK_HMAC(uint64 ka, uint64 kr, uint32 ra, uint32 rb, unsigned char* digist);
    unsigned char* _generateACK_HMAC(uint64 kb, uint64 kr, uint32 ra, uint32 rb, unsigned char* digist);
    void _hmac_md5(unsigned char*  text, int text_len,unsigned char*  key, int key_len, unsigned char* digest);

    uint64_t _getRemoteKey();
    uint64_t _getLocalKey();
    void     setRemoteToken(uint32_t key);
    void     setLocalToken(uint32_t key);



    // MPTCP Flow Organisation
    // Token to identify
    uint32_t local_token;                   // B.1.1 Authentication and Metadata
    uint32_t remote_token;                  // B.1.1 Authentication and Metadata




public:
    // common Omnetpp identifier
    TCPConnection *lastscheduled;
    TCPConnection *lastenqueued;
    bool isFIN;
    int  appID;                             // The application ID of this Flow
    int  appGateIndex;
    uint32 commonSendQueueLimit;
    Tmp_Buffer_t* tmp_msg_buf;
};


#endif /* TCPMULTIPATHFLOW_H_ */
