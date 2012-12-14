/*
 * TCPMultipathFlow.h
 *
 *  Created on: Nov 19, 2012
 *      Author: becke
 */

#ifndef TCPMULTIPATHFLOW_H_
#define TCPMULTIPATHFLOW_H_

#include "TCPMultipath.h"
// ###############################################################################################################
//                                                  MULTIPATH TCP
//                                                      FLOW
// ###############################################################################################################
/**
 * The MULTIPATH TCP Flow
 */
class INET_API MPTCP_Flow
{
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
  public:

    MPTCP_Flow(int ID, int aAppGateIndex, MPTCP_PCB* aPCB);
    ~MPTCP_Flow();

    // It is public

    uint32 local_token;     // B.1.1 Authentication and Metadata
    uint32 remote_token;    // B.1.1 Authentication and Metadata
    // helper

    MPTCP_State getState();
    int setState(MPTCP_State s);
    uint32_t getFlow_token();
    MPTCP_PCB* getPCB();


    // Setter and Getter for Keys
    void setRemoteKey(uint64_t key);
    uint64_t getRemoteKey();
    void setLocalKey(uint64_t key);
    uint64_t getLocalKey();

    uint64_t getHighestCumSQN();    // SQN band complete up to this number
    uint64_t getBaseSQN();          // Base of Offset SQN calculation

    // use cases Data IN/OUT
    int sendByteStream(TCPConnection* subflow);
    int writeMPTCPHeaderOptions(uint t, TCPStateVariables* subflow_state, TCPSegment *tcpseg, TCPConnection* subflow);

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

    // common identifier
    int  appID;                             // The application ID of this Flow
    int  appGateIndex;
};


#endif /* TCPMULTIPATHFLOW_H_ */
