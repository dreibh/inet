/*
 * TCPMultipathFlow.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */

#ifndef TCPMULTIPATHFLOW_H_
#define TCPMULTIPATHFLOW_H_

#include "TCPMultipath.h"
<<<<<<< HEAD
//#include "TCP.h"
=======
#include "TCPMultipathPCB.h"

>>>>>>> ade60ba539b19ff5c06a5fe2f7ccc667d0675b87

// ###############################################################################################################
//                                                  MULTIPATH TCP
//                                                      FLOW
// ###############################################################################################################
/**
 * The MULTIPATH TCP Flow
 */
class INET_API MPTCP_Flow
{
<<<<<<< HEAD
=======
  private:
     int rcvbuf;                            // receive message queue
     int sndbuf;                            // send message queue

     MPTCP_PCB* pcb;                                // the pcb

     TCP_AddressVector_t list_laddrtuple;   // list of local addresses
     TCP_AddressVector_t list_raddrtuple;   // list of remote addresses
     TCP_SubFlowVector_t subflow_list;      // list of all subflows
     TCP_JoinVector_t join_queue;           // a queue with all join possibilities
     TCP_JoinVector_t tried_join;

     // Internal organization
     MPTCP_State state;                     // Internal State of the multipath protocol control block
     TCPMultipathQueueMngmt* queue_mgr;     // Receiver queue


     void _initFlow();
     int _writeInitialHandshakeHeader(uint t,
            TCPStateVariables* subflow_state, TCPSegment *tcpseg,
            TCPConnection* subflow, TCPOption* option);
     int _writeJoinHandshakeHeader(uint t,
            TCPStateVariables* subflow_state, TCPSegment *tcpseg,
            TCPConnection* subflow, TCPOption* option);
     int _writeDSSHeaderandProcessSQN(uint t,
            TCPStateVariables* subflow_state, TCPSegment *tcpseg,
            TCPConnection* subflow, TCPOption* option);
     bool _prepareJoinConnection();

  protected:


     uint64_t base_seq;          // start seq-no generated after getting keys

     uint64_t local_key;    // B.1.1 Authentication and Metadata
     uint64_t remote_key;   // B.1.1 Authentication and Metadata
     // TODO MPTCP CHECKSUM // B.1.1 Authentication and Metadata

     bool checksum;
     bool isPassive;
     InterfaceTableAccess interfaceTableAccess;
>>>>>>> ade60ba539b19ff5c06a5fe2f7ccc667d0675b87
  public:

    MPTCP_Flow(int ID, int aAppGateIndex, MPTCP_PCB* aPCB);
    ~MPTCP_Flow();



    uint32 local_token;     // B.1.1 Authentication and Metadata
    uint32 remote_token;    // B.1.1 Authentication and Metadata
    // helper

    MPTCP_State getState();
    MPTCP_PCB* getPCB();


    // use cases Data IN/OUT
    int sendByteStream(TCPConnection* subflow);
    int writeMPTCPHeaderOptions(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg, TCPConnection* subflow);

    // Helper

    // Getter
    uint32_t getFlow_token();
    uint64_t getRemoteKey();
    uint64_t getLocalKey();
<<<<<<< HEAD
    uint64_t getHighestCumSQN();
=======

    uint64_t getHighestCumSQN();    // SQN band complete up to this number
    uint64_t getBaseSQN();          // Base of Offset SQN calculation
>>>>>>> ade60ba539b19ff5c06a5fe2f7ccc667d0675b87

    // Setter
    void setRemoteKey(uint64_t key);
    void setLocalKey(uint64_t key);
    int setState(MPTCP_State s);

    // crypto functions ==> see also rfc 2104
    uint64 generateLocalKey();
    int generateToken(uint64_t key, bool type);

    unsigned char* generateSYNACK_HMAC(uint64 ka, uint64 kr, uint32 ra, uint32 rb, unsigned char* digist);
    unsigned char* generateACK_HMAC(uint64 kb, uint64 kr, uint32 ra, uint32 rb, unsigned char* digist);
    void hmac_md5(unsigned char*  text, int text_len,unsigned char*  key, int key_len, unsigned char* digest);

    // subflow organisation
    int addSubflow(int id, TCPConnection*);
    bool isSubflowOf(TCPConnection* subflow);
    const TCP_SubFlowVector_t* getSubflows();

    // common Omnetpp identifier
    int  appID;                             // The application ID of this Flow
    int  appGateIndex;

  protected:


    uint64_t seq;                          // start seq-no generated after getting keys
    uint64_t local_key;    // B.1.1 Authentication and Metadata
    uint64_t remote_key;   // B.1.1 Authentication and Metadata
    // TODO MPTCP CHECKSUM // B.1.1 Authentication and Metadata

    bool checksum;
    bool isPassive;
    InterfaceTableAccess interfaceTableAccess;

  private:
    int rcvbuf;                            // receive message queue
    int sndbuf;                            // send message queue

    MPTCP_PCB* pcb;                                // the pcb

    TCP_AddressVector_t list_laddrtuple;   // list of local addresses
    TCP_AddressVector_t list_raddrtuple;   // list of remote addresses
    TCP_SubFlowVector_t subflow_list;      // list of all subflows
    TCP_JoinVector_t join_queue;           // a queue with all join possibilities
    TCP_JoinVector_t tried_join;

    // Internal organization
    MPTCP_State state;                     // Internal State of the multipath protocol control block
    TCPMultipathQueueMngmt* queue_mgr;     // Receiver queue

    void _initFlow();
    // Helper - Write packets
    int _writeInitialHandshakeHeader(uint t,
    TCPStateVariables* subflow_state, TCPSegment *tcpseg,
    TCPConnection* subflow, TCPOption* option);
    int _writeJoinHandshakeHeader(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg,
              TCPConnection* subflow, TCPOption* option);
    int _writeDSSHeaderandProcessSQN(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg,
              TCPConnection* subflow, TCPOption* option);
    bool _prepareJoinConnection();
};


#endif /* TCPMULTIPATHFLOW_H_ */
