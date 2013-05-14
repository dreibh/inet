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
    if(state->snd_cwnd > 5000001)
        tcpEV << " wow what big" << endl;
    if(state->snd_cwnd == 0)
        tcpEV << " not possible" << endl;
    return;
}

void TCPNewReno::decreaseCWND(uint32 decrease){
    state->snd_cwnd -= decrease;
//    if (cwndVector)
//        cwndVector->record(state->snd_cwnd);
    if(state->snd_cwnd > 5000001)
           tcpEV << " wow what big" << endl;
    if(state->snd_cwnd == 0)
        tcpEV << " not possible" << endl;
    return;
}
void TCPNewReno::setCWND(uint32 newCWND){
    state->snd_cwnd = newCWND;
    if (cwndVector)
        cwndVector->record(state->snd_cwnd);
    if(state->snd_cwnd > 5000001)
        tcpEV << " wow what big" << endl;
    if(state->snd_cwnd == 0)
        tcpEV << " not possible" << endl;
    return;
}
// ############################## New Reno Stuff #################################
void TCPNewReno::receivedDataAck(uint32 firstSeqAcked)
{
     uint32 old_snd_una = firstSeqAcked;
     TCPTahoeRenoFamily::receivedDataAck(firstSeqAcked);

    // RFC 3782, page 5:
    // "5) When an ACK arrives that acknowledges new data, this ACK could be
    // the acknowledgment elicited by the retransmission from step 2, or
    // elicited by a later retransmission.

    if (state->lossRecovery)    // In Fast Recovery
    {
        if (seqGE(state->snd_una , state->recover))
        {
            // Full acknowledgements:
            // If this ACK acknowledges all of the data up to and including
            // "recover", then the ACK acknowledges all the intermediate
            // segments sent between the original transmission of the lost
            // segment and the receipt of the third duplicate ACK.  Set cwnd to
            // either (1) min (ssthresh, FlightSize + SMSS) or (2) ssthresh,
            // where ssthresh is the value set in step 1; this is termed
            // "deflating" the window.  (We note that "FlightSize" in step 1
            // referred to the amount of data outstanding in step 1, when Fast
            // Recovery was entered, while "FlightSize" in step 5 refers to the
            // amount of data outstanding in step 5, when Fast Recovery is
            // exited.)  If the second option is selected, the implementation is
            // encouraged to take measures to avoid a possible burst of data, in
            // case the amount of data outstanding in the network is much less
            // than the new congestion window allows.  A simple mechanism is to
            // limit the number of data packets that can be sent in response to
            // a single acknowledgement; this is known as "maxburst_" in the NS
            // simulator.  Exit the Fast Recovery procedure."
            setCWND(std::min(state->ssthresh, bytesInFlight() + state->snd_mss));
            state->lossRecovery = false;
            state->firstPartialACK = false;
            tcpEV << "End Loss Recovery\n";
            // Otherwise we fall in retransmission timeout every time
            cancelEvent(rexmitTimer);
        }
        else
        {
            // RFC 3782, page 5:
            // "Partial acknowledgements:
            // If this ACK does *not* acknowledge all of the data up to and
            // including "recover", then this is a partial ACK.  In this case,
            // retransmit the first unacknowledged segment.  Deflate the
            // congestion window by the amount of new data acknowledged by the
            // cumulative acknowledgement field.  If the partial ACK
            // acknowledges at least one SMSS of new data, then add back SMSS
            // bytes to the congestion window.  As in Step 3, this artificially
            // inflates the congestion window in order to reflect the additional
            // segment that has left the network.  Send a new segment if
            // permitted by the new value of cwnd.  This "partial window
            // deflation" attempts to ensure that, when Fast Recovery eventually
            // ends, approximately ssthresh amount of data will be outstanding
            // in the network.  Do not exit the Fast Recovery procedure (i.e.,
            // if any duplicate ACKs subsequently arrive, execute Steps 3 and 4
            // above).
            //


            tcpEV << "Fast Recovery - Partial ACK received: retransmitting the first unacknowledged segment\n";

            // deflate cwnd by amount of new data acknowledged by cumulative acknowledgement field
            // FIXME deflate
            if(state->snd_una < old_snd_una)
                throw cRuntimeError("This is not possible");

            decreaseCWND(std::min(state->snd_una - old_snd_una,state->snd_mss)); // Fixed
            tcpEV << "Fast Recovery: deflating cwnd by amount of new data acknowledged, new cwnd=" << state->snd_cwnd << "\n";

            // if the partial ACK acknowledges at least one SMSS of new data, then add back SMSS bytes to the cwnd
            increaseCWND(state->snd_mss);


            // try to send a new segment if permitted by the new value of cwnd
            // TODO why sendData(false);
            // retransmit first unacknowledged segment
            conn->retransmitOneSegment(false);

            // For the first partial ACK that arrives during Fast Recovery, also
            // reset the retransmit timer.  Timer management is discussed in
            // more detail in Section 4."
            if (state->lossRecovery)
            {
                if (!state->firstPartialACK)
                {
                    state->firstPartialACK = true;
                    tcpEV << "First partial ACK arrived during recovery, restarting REXMIT timer.\n";
                    restartRexmitTimer();
                }
            }
            return;
        }
    }

    //
    // Perform slow start and congestion avoidance.
    //
    if (state->snd_cwnd < state->ssthresh)
    {
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
    else
    {
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

    // RFC 3782, page 13:
    // "When not in Fast Recovery, the value of the state variable "recover"
    // should be pulled along with the value of the state variable for
    // acknowledgments (typically, "snd_una") so that, when large amounts of
    // data have been sent and acked, the sequence space does not wrap and
    // falsely indicate that Fast Recovery should not be entered (Section 3,
    // step 1, last paragraph)."
    if (!state->lossRecovery)
        state->recover = (state->snd_una-1);

    // ack may have freed up some room in the window, try sending
    sendData(false);
}

void TCPNewReno::receivedDuplicateAck()
{
    // Overworked....
    // Note: MBe Doing thinks described in 3042
    TCPTahoeRenoFamily::receivedDuplicateAck();
    if (state->dupacks == DUPTHRESH && (!state->lossRecovery)) // DUPTHRESH = 3
    {
            // RFC 3782, page 4:
            // "1) Three duplicate ACKs:
            // When the third duplicate ACK is received and the sender is not
            // already in the Fast Recovery procedure, check to see if the
            // Cumulative Acknowledgement field covers more than "recover".  If
            // so, go to Step 1A.  Otherwise, go to Step 1B."
            //
            // RFC 3782, page 6:
            // "Step 1 specifies a check that the Cumulative Acknowledgement field
            // covers more than "recover".  Because the acknowledgement field
            // contains the sequence number that the sender next expects to receive,
            // the acknowledgement "ack_number" covers more than "recover" when:
            //      ack_number - 1 > recover;"
            if (state->snd_una  > state->recover)
            {
                tcpEV << "NewReno on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";

                // RFC 3782, page 4:
                // "1A) Invoking Fast Retransmit:
                // If so, then set ssthresh to no more than the value given in
                // equation 1 below.  (This is equation 3 from [RFC2581]).
                //      ssthresh = max (FlightSize / 2, 2*SMSS)           (1)
                // In addition, record the highest sequence number transmitted in
                // the variable "recover", and go to Step 2."

                recalculateSlowStartThreshold();

                state->recover = (state->snd_nxt);
                state->firstPartialACK = false;
                state->lossRecovery = true;
                tcpEV << " set recover=" << state->recover;

                // RFC 3782, page 4:
                // "2) Entering Fast Retransmit:
                // Retransmit the lost segment and set cwnd to ssthresh plus 3 * SMSS.
                // This artificially "inflates" the congestion window by the number
                // of segments (three) that have left the network and the receiver
                // has buffered."

                setCWND(state->ssthresh + (3 * state->snd_mss));

                tcpEV << " , cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";
                conn->retransmitOneSegment(false);
            }
            else{
                // 1B Not invoking Fast Retransmit:
                tcpEV << "Does this happen?" << endl;
                increaseCWND(0); // Just for debug ... print a point
            }

    }
    else if (state->lossRecovery)
    {
        // RFC 3782, page 4:
        // "3) Fast Recovery:
        // For each additional duplicate ACK received while in Fast
        // Recovery, increment cwnd by SMSS.  This artificially inflates the
        // congestion window in order to reflect the additional segment that
        // has left the network."

        increaseCWND(state->snd_mss);
        tcpEV << "NewReno on dupAcks > DUPTHRESH(=3): Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";

        // RFC 3782, page 5:
        // "4) Fast Recovery, continued:
        // Transmit a segment, if allowed by the new value of cwnd and the
        // receiver's advertised window."

        // TODO sendData(false);
        // Pending data
    }

    sendData(false);
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
    state->recover = (state->snd_max);
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





