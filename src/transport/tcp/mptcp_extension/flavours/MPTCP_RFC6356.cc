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
#include "MPTCP_RFC6356.h"
#include "TCP.h"
#include "TCPMultipathFlow.h"


Register_Class(MPTCP_RFC6356);


MPTCP_RFC6356::MPTCP_RFC6356() : TCPNewReno()
{
    isCA = false;
}
static inline double GET_SRTT(const double srtt)
{
    return (floor(1000.0 * srtt * 8.0));
}


//############################# helper ##############################################

//void MPTCP_RFC6356::recalculateMPTCPCCBasis(){
//    // it is necessary to calculate all flow information
//    double numerator = 0.0;
//    double denominator = 0.0;
//
//    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)(conn->flow->getSubflows());
//    conn->flow->totalCMTCwnd = 0;
//    conn->flow->totalCMTSsthresh = 0;
//    conn->flow->utilizedCMTCwnd = 0;
//    double bestCWND = 0.0;
//    double bestSRTT = 0.0;
//    double maxCwndBasedBandwidth = 0.0;
//    double totalCwndBasedBandwidth = 0.0;
//    int cnt = 0;
//    fprintf(stderr,"\n");
//    // conn->flow->totalCwndBasedBandwidth = 0;
//    for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++, cnt++) {
//        if(!conn->isQueueAble) continue;
//        TCPConnection* tmp = (*it)->subflow;
//        TCPTahoeRenoFamilyStateVariables* another_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (tmp->getTcpAlgorithm()->getStateVariables());
//        fprintf(stderr,"CWND %i - %i\n",cnt,(tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd);
//        tmp->flow->totalCMTCwnd     += (tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd;
//        tmp->flow->totalCMTSsthresh += another_state->ssthresh;
//
//        numerator =  (tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd;
//        //numerator =  (tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd * (tmp->getState()->snd_mss * tmp->getState()->snd_mss);
//        denominator = GET_SRTT(another_state->srtt.dbl())*GET_SRTT(another_state->srtt.dbl());
//        maxCwndBasedBandwidth = std::max(maxCwndBasedBandwidth, (numerator / denominator));
//
//        numerator =  (tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd;
//        // numerator =  (tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd * tmp->getState()->snd_mss;
//        denominator = GET_SRTT(another_state->srtt.dbl());
//        totalCwndBasedBandwidth += std::max(maxCwndBasedBandwidth, (numerator / denominator));
//    }
//
///*
// *   The formula to compute alpha is:
// *
// *                          MAX (cwnd_i/rtt_i^2)
// *     alpha = cwnd_total * -------------------------           (2)
// *                          (SUM (cwnd_i/rtt_i))^2
// */
//      numerator   = maxCwndBasedBandwidth;
//      denominator = totalCwndBasedBandwidth * totalCwndBasedBandwidth; // power 2
//      conn->flow->cmtCC_alpha = (uint32)ceil(this->alpha_scale * conn->flow->totalCMTCwnd *  numerator / denominator );
//}

void MPTCP_RFC6356::recalculateMPTCPCCBasis(){
    // it is necessary to calculate all flow information

    double denominator = 0.0;

    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)(conn->flow->getSubflows());
    conn->flow->totalCMTCwnd = 0;
    conn->flow->totalCMTSsthresh = 0;
    conn->flow->utilizedCMTCwnd = 0;
    uint32 bestCWND = 0;
    double bestSRTT = 0;
    int cnt = 0;
    double maxCwndBasedBandwidth = 0.0;
    double oldMaxCwndBasedBandwidth = 0.0;
    double totalCwndBasedBandwidth = 0.0;
    int flowID = conn->flow->ID;
    fprintf(stderr,"\n");
    // conn->flow->totalCwndBasedBandwidth = 0;
    for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++, cnt++) {
        if(!conn->isQueueAble) continue;
        TCPConnection* tmp = (*it)->subflow;
        TCPTahoeRenoFamilyStateVariables* another_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (tmp->getTcpAlgorithm()->getStateVariables());

        ASSERT(flowID==tmp->flow->ID);
        fprintf(stderr,"CWND %i - %i\n",cnt,(tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd);
        tmp->flow->totalCMTCwnd     +=  (tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd;

        maxCwndBasedBandwidth = (double)((tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd) /
                                         (GET_SRTT(another_state->srtt.dbl())*GET_SRTT(another_state->srtt.dbl()));
        if(oldMaxCwndBasedBandwidth < maxCwndBasedBandwidth){
            oldMaxCwndBasedBandwidth = maxCwndBasedBandwidth;
            bestCWND = (tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd;
            bestSRTT = GET_SRTT(another_state->srtt.dbl());
            fprintf(stderr,"MAX cwnd %i and srtt %.2f\n",bestCWND,bestSRTT);
        }
    }

    for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++) {
           if(!conn->isQueueAble) continue;
           TCPConnection* tmp = (*it)->subflow;
           TCPTahoeRenoFamilyStateVariables* another_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (tmp->getTcpAlgorithm()->getStateVariables());

           fprintf(stderr,"Calc BestRTT : %.2f CWND %i / RTT %.2f\n",bestSRTT,(tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd, GET_SRTT(another_state->srtt.dbl()));
           totalCwndBasedBandwidth += bestSRTT * (double)(tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd / GET_SRTT(another_state->srtt.dbl());
    }
/*
 *   The formula to compute alpha is:
 *
 *                          MAX (cwnd_i/rtt_i^2)
 *     alpha = cwnd_total * -------------------------           (2)
 *                          (SUM (cwnd_i/rtt_i))^2
 */
/*// we use it like 4.3 (similar to Linux)
 *  Note that the calculation of alpha does not take into account path
 *  MSS and is the same for stacks that keep cwnd in bytes or packets.
 *  With this formula, the algorithm for computing alpha will match the
 *  rate of TCP on the best path in B/s for byte-oriented stacks, and in
 *  packets/s in packet-based stacks.  In practice, MSS rarely changes
 *  between paths so this shouldn't be a problem.
 *
 *                                               cwnd_max (bestCWND)
 * alpha = alpha_scale * cwnd_total * ------------------------------------
 *                                   (SUM ((rtt_max * cwnd_i) / rtt_i))^2
 */


    fprintf(stderr,"%i =  * nenner %i * bestCWND %i\n",(this->conn->flow->totalCMTCwnd * bestCWND),this->conn->flow->totalCMTCwnd,bestCWND);
    denominator = totalCwndBasedBandwidth * totalCwndBasedBandwidth;
    fprintf(stderr,"sum %f quad*(%f)\n",denominator, totalCwndBasedBandwidth);
    conn->flow->cmtCC_alpha =  (double)(conn->flow->totalCMTCwnd * bestCWND) / denominator;

}


void MPTCP_RFC6356::increaseCWND(uint32 ackedBytes){

// cite RFC6356
/**
 * For each ACK in CA received on subflow i, increase cwnd_i by
 *
 *               alpha * bytes_acked * MSS_i   bytes_acked * MSS_i
 *         min ( --------------------------- , ------------------- )  (1)
 *                        cwnd_total                   cwnd_i
 */
    uint32 increase = ackedBytes;
    double numerator   = 0.0;
    double denominator = 0.0;
    if ((!(state->snd_cwnd < state->ssthresh)) && (!this->conn->getState()->lossRecovery) && ackedBytes){
        // in CA
        recalculateMPTCPCCBasis();
        numerator =  conn->flow->cmtCC_alpha * std::min(acked, conn->getState()->snd_mss) * conn->getState()->snd_mss;
        denominator = conn->flow->totalCMTCwnd;
        double term1 = numerator / denominator;
        fprintf(stderr,"All term1 %i alpha %.2f  tatal cwnd %i  acked %i\n", (uint32)ceil(term1), conn->flow->cmtCC_alpha, conn->flow->totalCMTCwnd,acked);

        numerator = conn->getState()->snd_mss * std::min(acked, conn->getState()->snd_mss);
        denominator = state->snd_cwnd;
        double term2 = numerator / denominator;
        fprintf(stderr,"ONE term2 %i cwnd %i \n", (uint32)(term2), state->snd_cwnd);

        increase = std::max((uint32)1,
                std::min((uint32)term1,(uint32)term2));
        fprintf(stderr,"increase %i \n", increase);
    }

    state->snd_cwnd += increase;
    if (cwndVector)
        cwndVector->record(state->snd_cwnd);

    return;
}

//void MPTCP_RFC6356::decreaseCWND(uint32 decrease){
//    state->snd_cwnd -= decrease;
//    if (cwndVector)
//        cwndVector->record(state->snd_cwnd);
//    return;
//}
//void MPTCP_RFC6356::setCWND(uint32 newCWND){
//    state->snd_cwnd = newCWND;
//    if (cwndVector)
//        cwndVector->record(state->snd_cwnd);
//    return;
//}
//
//void MPTCP_RFC6356::updateCWND(uint32 firstSeqAcked){
//    // Perform slow start and congestion avoidance.
//   if (state->snd_cwnd < state->ssthresh){
//       tcpEV << "cwnd <= ssthresh: Slow Start: increasing cwnd by SMSS bytes to ";
//
//       // perform Slow Start.
//       increaseCWND(state->snd_mss);
//
//       tcpEV << "cwnd=" << state->snd_cwnd << "\n";
//   }
//   else{
//       // perform Congestion Avoidance (RFC 2581)
//       double adder = static_cast<double> (state->snd_mss * state->snd_mss) / state->snd_cwnd;
//       adder = std::max (1.0, adder);
//       increaseCWND(static_cast<uint32>(adder));
//
//       tcpEV << "cwnd > ssthresh: Congestion Avoidance: increasing cwnd linearly, to " << state->snd_cwnd << "\n";
//   }
//}
//// ############################## New Reno Stuff #################################
//void MPTCP_RFC6356::receivedDataAck(uint32 firstSeqAcked)
//{
//
//     TCPTahoeRenoFamily::receivedDataAck(firstSeqAcked);
//
//    // If we above
//    if(state->lossRecovery){
//        if (seqGE(state->snd_una , state->recover)){
//            setCWND(std::min(state->ssthresh, bytesInFlight() + state->snd_mss));
//            state->lossRecovery = false;
//            state->firstPartialACK = false;
//
//            tcpEV << "End Loss Recovery\n";
//        }
//        else{
//            tcpEV << "Fast Recovery - Partial ACK received: retransmitting the first unacknowledged segment\n";
//
//            // deflate cwnd by amount of new data acknowledged by cumulative acknowledgement field
//            // FIXME deflate ?? -> Try a probe
//            if(state->snd_una < firstSeqAcked)
//                throw cRuntimeError("This is not possible");
//             decreaseCWND(std::min(state->snd_una - firstSeqAcked,state->snd_mss)); // Fixe ME -> How to do deflating
//            tcpEV << "Fast Recovery: deflating cwnd by amount of new data acknowledged, new cwnd=" << state->snd_cwnd << "\n";
//
//            // if the partial ACK acknowledges at least one SMSS of new data, then add back SMSS bytes to the cwnd
//            increaseCWND(state->snd_mss); // Is this correct ?
//            conn->sendAck();
//            // Retranmist
//            conn->retransmitOneSegment(false); // we send an retransmit, so we are out
//            return;
//        }
//    }else{
//        updateCWND(firstSeqAcked);
//    }
//
//
//    // Retransmit Timer
//    if ( state->lossRecovery && (!state->firstPartialACK) && (!state->fin_rcvd))    // TODO Unacked date => Correct? ... overwork check Fin state
//    {
//        restartRexmitTimer();
//    }
//    sendData(true);
//}
//
//
//void MPTCP_RFC6356::receivedDuplicateAck()
//{
//    // Overworked....
//    TCPTahoeRenoFamily::receivedDuplicateAck();
//
//    if (state->lossRecovery)
//    {
//        increaseCWND(state->snd_mss);
//        tcpEV << "NewReno on dupAcks > DUPTHRESH(=3): Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";
//        //conn->sendOneNewSegment(false, state->snd_cwnd);
//        //conn->sendData(false, state->snd_cwnd);
//        sendData(true); // is this pending data?
//    }
//    else if (state->dupacks == DUPTHRESH && (!state->lossRecovery)) // DUPTHRESH = 3
//    {
//                tcpEV << "NewReno on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";
//                state->lossRecovery = true;
//                state->recover = (state->snd_nxt);
//                tcpEV << " set recover=" << state->recover;
//                recalculateSlowStartThreshold();
//                conn->retransmitOneSegment(false);
//                state->firstPartialACK = false;
//                setCWND(state->ssthresh + (3 * state->snd_mss));
//                tcpEV << " , cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";
//    }
//    else if((!state->lossRecovery) && (state->limited_transmit_enabled)){
//        increaseCWND(0);    // Just for Debug
//        conn->sendOneNewSegment(false, state->snd_cwnd);
//    }
//    else{
//        increaseCWND(0);    // Just for Debug
//    }
//
//}
//
//void MPTCP_RFC6356::processRexmitTimer(TCPEventCode& event)
//{
//    TCPTahoeRenoFamily::processRexmitTimer(event);
//
//    if (event == TCP_E_ABORT)
//        return;
//
//    // RFC 3782, page 6:
//    // "6)  Retransmit timeouts:
//    // After a retransmit timeout, record the highest sequence number
//    // transmitted in the variable "recover" and exit the Fast Recovery
//    // procedure if applicable."
//    state->recover = 0;
//    tcpEV << "recover=" << state->recover << "\n";
//
//    state->lossRecovery = false;
//    state->firstPartialACK = false;
//    tcpEV << "Loss Recovery terminated.\n";
//
//    // After REXMIT timeout TCP NewReno should start slow start with snd_cwnd = snd_mss.
//    //
//    // If calling "retransmitData();" there is no rexmit limitation (bytesToSend > snd_cwnd)
//    // therefore "sendData();" has been modified and is called to rexmit outstanding data.
//    //
//    // RFC 2581, page 5:
//    // "Furthermore, upon a timeout cwnd MUST be set to no more than the loss
//    // window, LW, which equals 1 full-sized segment (regardless of the
//    // value of IW).  Therefore, after retransmitting the dropped segment
//    // the TCP sender uses the slow start algorithm to increase the window
//    // from 1 full-sized segment to the new value of ssthresh, at which
//    // point congestion avoidance again takes over."
//
//    // begin Slow Start (RFC 2581)
//    recalculateSlowStartThreshold();
//    setCWND(state->snd_mss);
//
//    tcpEV << "Begin Slow Start: resetting cwnd to " << state->snd_cwnd
//          << ", ssthresh=" << state->ssthresh << "\n";
//    state->afterRto = true;
//    conn->retransmitOneSegment(true);
//}
//
//
//
//
//
