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
    //fprintf(stderr,"\n");
    // conn->flow->totalCwndBasedBandwidth = 0;
    for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++, cnt++) {
        if(!conn->isQueueAble) continue;
        TCPConnection* tmp = (*it)->subflow;
        TCPTahoeRenoFamilyStateVariables* another_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (tmp->getTcpAlgorithm()->getStateVariables());

        ASSERT(flowID==tmp->flow->ID);
        tmp->flow->totalCMTCwnd     +=  (tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd;

        maxCwndBasedBandwidth = (double)((tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd) /
                                         (GET_SRTT(another_state->srtt.dbl())*GET_SRTT(another_state->srtt.dbl()));
        if(oldMaxCwndBasedBandwidth < maxCwndBasedBandwidth){
            oldMaxCwndBasedBandwidth = maxCwndBasedBandwidth;
            bestCWND = (tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd;
            bestSRTT = GET_SRTT(another_state->srtt.dbl());
        }
    }

    for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++) {
           if(!conn->isQueueAble) continue;
           TCPConnection* tmp = (*it)->subflow;
           TCPTahoeRenoFamilyStateVariables* another_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (tmp->getTcpAlgorithm()->getStateVariables());
           totalCwndBasedBandwidth += bestSRTT * ((tmp->getState()->lossRecovery)?another_state->ssthresh:another_state->snd_cwnd) / GET_SRTT(another_state->srtt.dbl());
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

    denominator = totalCwndBasedBandwidth * totalCwndBasedBandwidth;
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

        numerator = conn->getState()->snd_mss * std::min(acked, conn->getState()->snd_mss);
        denominator = state->snd_cwnd;
        double term2 = numerator / denominator;

        increase = std::max((uint32)1,
                std::min((uint32)term1,(uint32)term2));
    }

    state->snd_cwnd += increase;
    if (cwndVector)
        cwndVector->record(state->snd_cwnd);

    return;
}

