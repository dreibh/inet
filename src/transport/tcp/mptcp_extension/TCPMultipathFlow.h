/*
 * TCPMultipathFlow.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */

#ifndef TCPMULTIPATHFLOW_H_
#define TCPMULTIPATHFLOW_H_
#include <vector>
#include <map>
#include <set>

#include "TCPMultipath.h"


//#include "TCPMultipath.h"


// helper


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

    // Flow could only be initilized with an Protocol Control Block
    MPTCP_Flow(int ID, int aAppGateIndex,TCPConnection* subflow, MPTCP_PCB* aPCB);
    ~MPTCP_Flow();

    // Some helper for request state of MPTCP Extension
    MPTCP_State getState();
    MPTCP_PCB*  getPCB();


    // Some Helper for Omnet ID stuff
    int getAppID();
    int getappGateIndex();
    void sendToApp(cMessage* msg);

    // use cases Data IN/OUT
    int sendByteStream(TCPConnection* subflow);
    int writeMPTCPHeaderOptions(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg, TCPConnection* subflow);
    TCPConnection* schedule(TCPConnection* save, cMessage* msg);

    void initKeyMaterial(TCPConnection* subflow);
    bool keysAreEqual(uint64_t rk, uint64_t lk );
    void     setRemoteKey(uint64_t key);
    void     setLocalKey(uint64_t key);
    uint32_t getRemoteToken();              // unique per PCB
    uint32_t getLocalToken();               // unique per PCB
    uint64_t getHighestCumSQN();
    uint64_t getBaseSQN();          // Base of Offset SQN calculation

    uint64_t getSQN();
    void setBaseSQN(uint64_t s);

    int  setState(MPTCP_State s);

    void setSendQueueLimit(int limit);

    // subflow organisation
    int addSubflow(int id, TCPConnection*);
    bool isSubflowOf(TCPConnection* subflow);
    const TCP_SubFlowVector_t* getSubflows();

    void DEBUGprintStatus();
    void DEBUGprintMPTCPFlowStatus();

    bool sendEstablished;
  protected:

    bool checksum;
    bool isPassive;
    InterfaceTableAccess interfaceTableAccess;

  private:
    // From the ITEF Draft
    int rcvbuf;                             // receive message queue
    int sndbuf;                             // send message queue

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
    TCPMultipathQueueMngmt* queue_mgr;     // Receiver queue

    void _initFlow(int port);
    // Helper - Write packets
    int _writeInitialHandshakeHeader(uint t,
    TCPStateVariables* subflow_state, TCPSegment *tcpseg,
    TCPConnection* subflow, TCPOption* option);
    int _writeJoinHandshakeHeader(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg,
              TCPConnection* subflow, TCPOption* option);
    int _writeDSSHeaderandProcessSQN(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg,
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

    // Message handlign -> TODO SCHEDULER
    void _createMSGforProcess(cMessage *msg, TCPConnection* sc);

    // MPTCP Flow Organisation
    // Token to identify
    uint32_t local_token;                   // B.1.1 Authentication and Metadata
    uint32_t remote_token;                  // B.1.1 Authentication and Metadata


    // Sending side
    uint64_t snd_una;                       // B.1.2
    uint64_t snd_nxt;                       // B.1.2
    uint32_t snd_wnd;                       // B.1.2

    // Receiver Side
    uint64_t rcv_nxt;                       // B.1.2
    uint64_t rcv_wnd;                       // B.1.2
    uint64_t seq;                           // start seq-no generated after getting keys for the first flow


    // common Omnetpp identifier
    int  appID;                             // The application ID of this Flow
    int  appGateIndex;
};


#endif /* TCPMULTIPATHFLOW_H_ */
