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
#include "TCPNewReno.h"
#include "TCP.h"


Register_Class(TCPNewReno);


TCPNewReno::TCPNewReno() : TCPTahoeRenoFamily(),
  state((TCPNewRenoStateVariables *&)TCPAlgorithm::state)
{
}

void TCPNewReno::initialize(){
    TCPTahoeRenoFamily::initialize(); // call super
    state->lossRecovery = false;
    state->firstPartialACK = false;
    state->recover = 0;
    state->ssthresh = state->rcv_wnd; //Todo ..should be size of sendqueue
    initilazeCWND();
}

void TCPNewReno::initilazeCWND(){
    this->setCWND(std::max((int)(2*state->snd_mss), 4380));
}
//############################# helper ##############################################

void TCPNewReno::recalculateSlowStartThreshold()
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
uint32 TCPNewReno::bytesInFlight(){
    // FIXME
    // uint32 flight_size = state->snd_max - state->snd_una;
   return std::min(state->snd_cwnd, state->snd_wnd);
}

void TCPNewReno::increaseCWND(uint32 increase){
    state->snd_cwnd += increase;
    if (cwndVector)
        cwndVector->record(state->snd_cwnd);
    if(state->snd_cwnd > (65535 + state->snd_mss))
        tcpEV << " wow what big" << endl;
    if(state->snd_cwnd == 0)
        tcpEV << " not possible" << endl;
    return;
}

void TCPNewReno::decreaseCWND(uint32 decrease){
    state->snd_cwnd -= decrease;
    if (cwndVector)
        cwndVector->record(state->snd_cwnd);
    if(state->snd_cwnd > (65535 + state->snd_mss))
           tcpEV << " wow what big" << endl;
    if(state->snd_cwnd == 0)
        tcpEV << " not possible" << endl;
    return;
}
void TCPNewReno::setCWND(uint32 newCWND){
    state->snd_cwnd = newCWND;
    if (cwndVector)
        cwndVector->record(state->snd_cwnd);
    if(state->snd_cwnd > (65535 + state->snd_mss))
        tcpEV << " wow what big" << endl;
    if(state->snd_cwnd == 0)
        tcpEV << " not possible" << endl;
    return;
}

void TCPNewReno::updateCWND(uint32 firstSeqAcked){
    // Perform slow start and congestion avoidance.
   if (state->snd_cwnd < state->ssthresh){
       tcpEV << "cwnd <= ssthresh: Slow Start: increasing cwnd by SMSS bytes to ";

       // perform Slow Start. RFC 2581: "During slow start, a TCP increments cwnd
       // by at most SMSS bytes for each ACK received that acknowledges new data."
       increaseCWND(state->snd_mss);
       // Note: we could increase cwnd based on the number of bytes being
       // acknowledged by each arriving ACK, rather than by the number of ACKs
       // that arrive. This is called "Appropriate Byte Counting" (ABC) and is
       // described in RFC 3465. This RFC is experimental and probably not
       // implemented in real-life TCPs, hence it's commented out. Also, the ABC
       // RFC would require other modifications as well in addition to the
       // two lines below.

       tcpEV << "cwnd=" << state->snd_cwnd << "\n";
   }
   else{
       // perform Congestion Avoidance (RFC 2581)
       double adder = static_cast<double> (state->snd_mss * state->snd_mss) / state->snd_cwnd;
       adder = std::max (1.0, adder);
       increaseCWND(static_cast<uint32>(adder));

       //
       // Note: some implementations use extra additive constant mss / 8 here
       // which is known to be incorrect (RFC 2581 p5)
       //
       // Note 2: RFC 3465 (experimental) "Appropriate Byte Counting" (ABC)
       // would require maintaining a bytes_acked variable here which we don't do
       //
       tcpEV << "cwnd > ssthresh: Congestion Avoidance: increasing cwnd linearly, to " << state->snd_cwnd << "\n";
   }
}
// ############################## New Reno Stuff #################################
void TCPNewReno::receivedDataAck(uint32 firstSeqAcked)
{

     TCPTahoeRenoFamily::receivedDataAck(firstSeqAcked);

    // If we above
    if(state->lossRecovery){
        if (seqGE(state->snd_una , state->recover)){
            setCWND(std::min(state->ssthresh, bytesInFlight() + state->snd_mss));
            state->lossRecovery = false;
            state->firstPartialACK = false;
            if (rexmitTimer->isScheduled())
                 cancelEvent(rexmitTimer);   // Todo ...is here the best point
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
            conn->sendAck();    // Fixme ...needed?
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
    sendData(false);
}


void TCPNewReno::receivedDuplicateAck()
{
    // Overworked....
    TCPTahoeRenoFamily::receivedDuplicateAck();

    if (state->lossRecovery)
    {
        increaseCWND(state->snd_mss);
        tcpEV << "NewReno on dupAcks > DUPTHRESH(=3): Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";
        //conn->sendOneNewSegment(false, state->snd_cwnd);
        //conn->sendData(false, state->snd_cwnd);
        sendData(false); // is this pending data?
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

void TCPNewReno::processRexmitTimer(TCPEventCode& event)
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





