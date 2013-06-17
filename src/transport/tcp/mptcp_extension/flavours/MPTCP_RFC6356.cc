//
// Copyright (C) 2009 Thomas Reschka
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

#include <algorithm>   // min,max
#include "MPTCP_RFC6356.h"
#include "TCP.h"


Register_Class(MPTCP_RFC6356);


MPTCP_RFC6356::MPTCP_RFC6356() : TCPTahoeRenoFamily(),
  state((MPTCP_RFC6356StateVariables *&)TCPAlgorithm::state)
{
}

void MPTCP_RFC6356::initialize(){
    TCPTahoeRenoFamily::initialize(); // call super
    state->lossRecovery = false;
    state->firstPartialACK = false;
    state->recover = 0;
    state->ssthresh = state->rcv_wnd; //Todo ..should be size of sendqueue
    initilazeCWND();
}

void MPTCP_RFC6356::initilazeCWND(){
    this->setCWND(std::max((int)(2*state->snd_mss), 4380));
}



//############################# helper ##############################################

void MPTCP_RFC6356::recalculateSlowStartThreshold()
{
    // RFC 2581, page 4:
    // "When a TCP sender detects segment loss using the retransmission
    // timer, the value of ssthresh MUST be set to no more than the value
    // given in equation 3:
    //
    //   ssthresh = max (FlightSize / 2, 2*SMSS)            (3)
    //
    // As discussed above, FlightSize is the amount of outstanding data in
    // the network."

    state->ssthresh = std::max(bytesInFlight() / 2, 2 * state->snd_mss);

    if (ssthreshVector)
        ssthreshVector->record(state->ssthresh);
}

void MPTCP_RFC6356::recalculateMPTCPCCBasis(){
//#ifdef PRIVATE
//   // First, calculate per-path values.
//   for (SCTPPathMap::iterator otherPathIterator = sctpPathMap.begin();
//      otherPathIterator != sctpPathMap.end(); otherPathIterator++) {
//      SCTPPathVariables* otherPath = otherPathIterator->second;
//      otherPath->utilizedCwnd      = otherPath->outstandingBytesBeforeUpdate;
//   }
//
//   // Calculate per-path-group values.
//   for (SCTPPathMap::iterator currentPathIterator = sctpPathMap.begin();
//        currentPathIterator != sctpPathMap.end(); currentPathIterator++) {
//      SCTPPathVariables* currentPath = currentPathIterator->second;
//
//      currentPath->cmtGroupPaths                      = 0;
//      currentPath->cmtGroupTotalCwnd                  = 0;
//      currentPath->cmtGroupTotalSsthresh              = 0;
//      currentPath->cmtGroupTotalUtilizedCwnd          = 0;
//      currentPath->cmtGroupTotalCwndBandwidth         = 0.0;
//      currentPath->cmtGroupTotalUtilizedCwndBandwidth = 0.0;
//
//      double qNumerator   = 0.0;
//      double qDenominator = 0.0;
//      for (SCTPPathMap::const_iterator otherPathIterator = sctpPathMap.begin();
//         otherPathIterator != sctpPathMap.end(); otherPathIterator++) {
//         const SCTPPathVariables* otherPath = otherPathIterator->second;
//         if(otherPath->cmtCCGroup == currentPath->cmtCCGroup) {
//            currentPath->cmtGroupPaths++;
//
//            currentPath->cmtGroupTotalCwnd                  += otherPath->cwnd;
//            currentPath->cmtGroupTotalSsthresh              += otherPath->ssthresh;
//            currentPath->cmtGroupTotalCwndBandwidth         += otherPath->cwnd / GET_SRTT(otherPath->srtt.dbl());
//
//            if( (otherPath->blockingTimeout < 0.0) || (otherPath->blockingTimeout < simTime()) ) {
//               currentPath->cmtGroupTotalUtilizedCwnd          += otherPath->utilizedCwnd;
//               currentPath->cmtGroupTotalUtilizedCwndBandwidth += otherPath->utilizedCwnd / GET_SRTT(otherPath->srtt.dbl());
//            }
//
//            qNumerator   = max(qNumerator, otherPath->cwnd / (pow(GET_SRTT(otherPath->srtt.dbl()), 2.0)));
//            qDenominator = qDenominator + (otherPath->cwnd / GET_SRTT(otherPath->srtt.dbl()));
//         }
//      }
//      currentPath->cmtGroupAlpha = currentPath->cmtGroupTotalCwnd * (qNumerator / pow(qDenominator, 2.0));
//
///*
//      printf("alpha(%s)=%1.6f\ttotalCwnd=%u\tcwnd=%u\tpaths=%u\n",
//             currentPath->remoteAddress.str().c_str(),
//             currentPath->cmtGroupAlpha,
//             currentPath->cmtGroupTotalCwnd,
//             currentPath->cwnd,
//             currentPath->cmtGroupPaths);
//*/

}


uint32 MPTCP_RFC6356::bytesInFlight(){
    // FIXME
    // uint32 flight_size = state->snd_max - state->snd_una;
   return std::min(state->snd_cwnd, state->snd_wnd);
}

void MPTCP_RFC6356::increaseCWND(uint32 increase){


//    const uint32 increase =
//          max(1,
//              min( (uint32)ceil((double)w * a * (double)min(ackedBytes, mtu)  / (double)totalW),
//                   (uint32)min(ackedBytes, mtu) ));

    state->snd_cwnd += increase;
    if (cwndVector)
        cwndVector->record(state->snd_cwnd);




    return;
}

void MPTCP_RFC6356::decreaseCWND(uint32 decrease){
    state->snd_cwnd -= decrease;
    if (cwndVector)
        cwndVector->record(state->snd_cwnd);
    return;
}
void MPTCP_RFC6356::setCWND(uint32 newCWND){
    state->snd_cwnd = newCWND;
    if (cwndVector)
        cwndVector->record(state->snd_cwnd);
    return;
}

void MPTCP_RFC6356::updateCWND(uint32 firstSeqAcked){
    // Perform slow start and congestion avoidance.
   if (state->snd_cwnd < state->ssthresh){
       tcpEV << "cwnd <= ssthresh: Slow Start: increasing cwnd by SMSS bytes to ";

       // perform Slow Start.
       increaseCWND(state->snd_mss);

       tcpEV << "cwnd=" << state->snd_cwnd << "\n";
   }
   else{
       // perform Congestion Avoidance (RFC 2581)
       double adder = static_cast<double> (state->snd_mss * state->snd_mss) / state->snd_cwnd;
       adder = std::max (1.0, adder);
       increaseCWND(static_cast<uint32>(adder));

       tcpEV << "cwnd > ssthresh: Congestion Avoidance: increasing cwnd linearly, to " << state->snd_cwnd << "\n";
   }
}
// ############################## New Reno Stuff #################################
void MPTCP_RFC6356::receivedDataAck(uint32 firstSeqAcked)
{

     TCPTahoeRenoFamily::receivedDataAck(firstSeqAcked);

    // If we above
    if(state->lossRecovery){
        if (seqGE(state->snd_una , state->recover)){
            setCWND(std::min(state->ssthresh, bytesInFlight() + state->snd_mss));
            state->lossRecovery = false;
            state->firstPartialACK = false;

            tcpEV << "End Loss Recovery\n";
        }
        else{
            tcpEV << "Fast Recovery - Partial ACK received: retransmitting the first unacknowledged segment\n";

            // deflate cwnd by amount of new data acknowledged by cumulative acknowledgement field
            // FIXME deflate ?? -> Try a probe
            if(state->snd_una < firstSeqAcked)
                throw cRuntimeError("This is not possible");
             decreaseCWND(std::min(state->snd_una - firstSeqAcked,state->snd_mss)); // Fixe ME -> How to do deflating
            tcpEV << "Fast Recovery: deflating cwnd by amount of new data acknowledged, new cwnd=" << state->snd_cwnd << "\n";

            // if the partial ACK acknowledges at least one SMSS of new data, then add back SMSS bytes to the cwnd
            increaseCWND(state->snd_mss); // Is this correct ?
            conn->sendAck();
            // Retranmist
            conn->retransmitOneSegment(false); // we send an retransmit, so we are out
            return;
        }
    }else{
        updateCWND(firstSeqAcked);
    }


    // Retransmit Timer
    if ( state->lossRecovery && (!state->firstPartialACK) && (!state->fin_rcvd))    // TODO Unacked date => Correct? ... overwork check Fin state
    {
        restartRexmitTimer();
    }
    sendData(true);
}


void MPTCP_RFC6356::receivedDuplicateAck()
{
    // Overworked....
    TCPTahoeRenoFamily::receivedDuplicateAck();

    if (state->lossRecovery)
    {
        increaseCWND(state->snd_mss);
        tcpEV << "NewReno on dupAcks > DUPTHRESH(=3): Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";
        //conn->sendOneNewSegment(false, state->snd_cwnd);
        //conn->sendData(false, state->snd_cwnd);
        sendData(true); // is this pending data?
    }
    else if (state->dupacks == DUPTHRESH && (!state->lossRecovery)) // DUPTHRESH = 3
    {
                tcpEV << "NewReno on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";
                state->lossRecovery = true;
                state->recover = (state->snd_nxt);
                tcpEV << " set recover=" << state->recover;
                recalculateSlowStartThreshold();
                conn->retransmitOneSegment(false);
                state->firstPartialACK = false;
                setCWND(state->ssthresh + (3 * state->snd_mss));
                tcpEV << " , cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";
    }
    else if((!state->lossRecovery) && (state->limited_transmit_enabled)){
        increaseCWND(0);    // Just for Debug
        conn->sendOneNewSegment(false, state->snd_cwnd);
    }
    else{
        increaseCWND(0);    // Just for Debug
    }

}

void MPTCP_RFC6356::processRexmitTimer(TCPEventCode& event)
{
    TCPTahoeRenoFamily::processRexmitTimer(event);

    if (event == TCP_E_ABORT)
        return;

    // RFC 3782, page 6:
    // "6)  Retransmit timeouts:
    // After a retransmit timeout, record the highest sequence number
    // transmitted in the variable "recover" and exit the Fast Recovery
    // procedure if applicable."
    state->recover = 0;
    tcpEV << "recover=" << state->recover << "\n";

    state->lossRecovery = false;
    state->firstPartialACK = false;
    tcpEV << "Loss Recovery terminated.\n";

    // After REXMIT timeout TCP NewReno should start slow start with snd_cwnd = snd_mss.
    //
    // If calling "retransmitData();" there is no rexmit limitation (bytesToSend > snd_cwnd)
    // therefore "sendData();" has been modified and is called to rexmit outstanding data.
    //
    // RFC 2581, page 5:
    // "Furthermore, upon a timeout cwnd MUST be set to no more than the loss
    // window, LW, which equals 1 full-sized segment (regardless of the
    // value of IW).  Therefore, after retransmitting the dropped segment
    // the TCP sender uses the slow start algorithm to increase the window
    // from 1 full-sized segment to the new value of ssthresh, at which
    // point congestion avoidance again takes over."

    // begin Slow Start (RFC 2581)
    recalculateSlowStartThreshold();
    setCWND(state->snd_mss);

    tcpEV << "Begin Slow Start: resetting cwnd to " << state->snd_cwnd
          << ", ssthresh=" << state->ssthresh << "\n";
    state->afterRto = true;
    conn->retransmitOneSegment(true);
}





