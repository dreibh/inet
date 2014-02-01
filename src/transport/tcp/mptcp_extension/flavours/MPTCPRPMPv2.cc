//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 


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


// cite RFC 6356
/*###############################################################################
 *   The algorithm we present(RFC 6356) only applies to the increase phase of the
 *   congestion avoidance state specifying how the window inflates upon
 *   receiving an ACK.  The slow start, fast retransmit, and fast recovery
 *   algorithms, as well as the multiplicative decrease of the congestion
 *   avoidance state are the same as in standard TCP [RFC5681].
 ##############################################################################*/

#include <algorithm>   // min,max
#include <math.h>
#include "MPTCPRPMPv2.h"
#include "TCP.h"
#include "TCPMultipathFlow.h"


Register_Class(MPTCP_RPMPv2);
MPTCP_RPMPv2::MPTCP_RPMPv2() {
    // TODO Auto-generated constructor stub

}

MPTCP_RPMPv2::~MPTCP_RPMPv2() {
    // TODO Auto-generated destructor stub
}

void MPTCP_RPMPv2::initialize(){
    TCPNewReno::initialize();
}

void MPTCP_RPMPv2::increaseCWND(uint32 ackedBytes, bool print){
    // in CA
    TCPTahoeRenoFamilyStateVariables* r_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (conn->getTcpAlgorithm()->getStateVariables());
    double r_sRTT = GET_SRTT(r_state->srtt.dbl());

    double numerator_1 = r_state->snd_cwnd/(r_sRTT);
    double denominator_1 = 0;
    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)(conn->flow->getSubflows());
    for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++) {

           TCPConnection *p = (*it)->subflow;
           if(!conn->isQueueAble) continue;
           TCPTahoeRenoFamilyStateVariables* p_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (p->getTcpAlgorithm()->getStateVariables());
           double p_sRTT = GET_SRTT(p_state->srtt.dbl());
           denominator_1 += (p_state->snd_cwnd/p_sRTT);
    }
    double term1 = numerator_1/ denominator_1;
    if ((!(state->snd_cwnd < state->ssthresh)) && (!this->conn->getState()->lossRecovery) && ackedBytes){
        state->snd_cwnd += (uint32) ceil(term1 * std::min(ackedBytes, r_state->snd_mss));
    }
    else{
       // Slow Start threshold
        state->snd_cwnd += (uint32) ceil( term1 * r_state->snd_mss); //
    }
    if(print)
    if (cwndVector)
      cwndVector->record(state->snd_cwnd);
    return;
}

void MPTCP_RPMPv2::processRexmitTimerSetCWND(){

    double df = 0.0;
    TCPTahoeRenoFamilyStateVariables* r_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (conn->getTcpAlgorithm()->getStateVariables());
    double r_sRTT = GET_SRTT(r_state->srtt.dbl());

    double denominator_1  = r_state->snd_cwnd/(r_sRTT);
    double numerator_1 = 0;
    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)(conn->flow->getSubflows());
    for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++) {
           TCPConnection *p = (*it)->subflow;
           if(!p->isQueueAble) continue;
           TCPTahoeRenoFamilyStateVariables* p_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (p->getTcpAlgorithm()->getStateVariables());
           double p_sRTT = GET_SRTT(p_state->srtt.dbl());
           numerator_1 += (p_state->snd_cwnd/p_sRTT);
    }
    double term1 = numerator_1/ denominator_1;
    df = std::max(0.5,0.5*term1);
    state->ssthresh = std::max((state->snd_cwnd >(uint32)ceil((bytesInFlight() * df) ))?(state->snd_cwnd -(uint32)ceil((bytesInFlight() * df))):0, state->snd_mss);

    setCWND(state->snd_mss);
    if (ssthreshVector)
       ssthreshVector->record(state->ssthresh);
}

void MPTCP_RPMPv2::receivedDuplicateAckSetCWND(){
    double df = 0.0;
    TCPTahoeRenoFamilyStateVariables* r_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (conn->getTcpAlgorithm()->getStateVariables());
    double r_sRTT = GET_SRTT(r_state->srtt.dbl());

     double denominator_1  = r_state->snd_cwnd/(r_sRTT);
     double numerator_1 = 0;
     TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)(conn->flow->getSubflows());
     for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++) {
            TCPConnection *p = (*it)->subflow;
            if(!p->isQueueAble) continue;
            TCPTahoeRenoFamilyStateVariables* p_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (p->getTcpAlgorithm()->getStateVariables());
            double p_sRTT = GET_SRTT(p_state->srtt.dbl());
            numerator_1 += (p_state->snd_cwnd/p_sRTT);
     }
    double term1 = numerator_1/ denominator_1;
    df = std::max(0.5,0.5*term1);
    state->ssthresh = std::max((state->snd_cwnd >(uint32)ceil((bytesInFlight() * df) ))?(state->snd_cwnd -(uint32)ceil((bytesInFlight() * df))):0, state->snd_mss);
    setCWND(state->ssthresh + (3 * state->snd_mss));
    if (ssthreshVector)
       ssthreshVector->record(state->ssthresh);
}

void MPTCP_RPMPv2::receivedDataAck(uint32 firstSeqAcked){
    TCPNewReno::receivedDataAck(firstSeqAcked);
}

void MPTCP_RPMPv2::receivedDuplicateAck(){
    TCPNewReno::receivedDuplicateAck();
}

void MPTCP_RPMPv2::processRexmitTimer(TCPEventCode& event){
    TCPNewReno::processRexmitTimer(event);
}
