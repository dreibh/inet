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

#include "MPTCP_OLIA.h"

Register_Class(MPTCP_OLIA);

MPTCP_OLIA::MPTCP_OLIA(): TCPNewReno() {

}

void MPTCP_OLIA::initialize(){
    TCPNewReno::initialize();
    state->new_olia_counting_start = state->snd_una;
    best_paths.clear();
    max_w_paths.clear();
}

MPTCP_OLIA::~MPTCP_OLIA() {

}

void MPTCP_OLIA::recalculateMPTCPCCBasis(){
    // it is necessary to calculate all flow information
    double best_paths_l_rXl_r__rtt_r = 0.0;
    uint32 max_w = 0;
    uint32 max_w_paths_cnt = 0;
    uint32 best_paths_cnt =0;
    TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)(conn->flow->getSubflows());
    // Create the sets
    int cnt = 0;
    collected_paths.clear();
    best_paths.clear();
    max_w_paths.clear();
    for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++, cnt++) {
           if(!conn->isQueueAble) continue;
           TCPConnection *r = (*it)->subflow;
           TCPTahoeRenoFamilyStateVariables* r_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (r->getTcpAlgorithm()->getStateVariables());
           double r_sRTT = GET_SRTT(r_state->srtt.dbl());
           double r_l_rXl_r__rtt_r = ((state->s_olia_sent_bytes * state->s_olia_sent_bytes) / r_sRTT);
           if(best_paths.empty()){
               best_paths_l_rXl_r__rtt_r = r_l_rXl_r__rtt_r;
               best_paths.insert(std::make_pair(cnt,r));
           }
           if(max_w_paths.empty()){
               max_w = r_state->snd_cwnd;
               max_w_paths.insert(std::make_pair(cnt,r));
           }
           if(cnt == 0) continue;
           // set up the sets
           if(r_l_rXl_r__rtt_r > best_paths_l_rXl_r__rtt_r){
               best_paths_l_rXl_r__rtt_r = r_l_rXl_r__rtt_r;
               best_paths.insert(std::make_pair(cnt,r));
               best_paths.erase(best_paths_cnt);
               best_paths_cnt = cnt;
           }
           if(r_state->snd_cwnd > max_w){
               max_w = r_state->snd_cwnd;
               max_w_paths.insert(std::make_pair(cnt,r));
               max_w_paths.erase(best_paths_cnt);
               max_w_paths_cnt = cnt;
           }

           if((max_w_paths.find(cnt) == max_w_paths.end()) && (max_w_paths.find(cnt) == max_w_paths.end()) )
                collected_paths.insert(std::make_pair(cnt,r));
    }
}

void MPTCP_OLIA::increaseCWND(uint32 ackedBytes, bool print){
    bool is_in_collected_path = false;
    bool is_max_w_paths = false;
    if ((!(state->snd_cwnd < state->ssthresh)) && (!this->conn->getState()->lossRecovery) && ackedBytes){
        // in CA
        recalculateMPTCPCCBasis();

        int cnt = 0;
        for (Path_Collection::iterator it =collected_paths.begin(); it != collected_paths.end(); it++, cnt++) {
          if(it->second == conn){
              is_in_collected_path = true;
              break;
          }
        }
        cnt = 0;
        for (Path_Collection::iterator it =max_w_paths.begin(); it != max_w_paths.end(); it++, cnt++) {
          if(it->second == conn){
              is_max_w_paths = true;
              break;
          }
        }

        TCPTahoeRenoFamilyStateVariables* r_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (conn->getTcpAlgorithm()->getStateVariables());
        double r_sRTT = GET_SRTT(r_state->srtt.dbl());

        double numerator_1 = r_state->snd_cwnd/(r_sRTT * r_sRTT);
        double denominator_1 = 0;
        TCP_SubFlowVector_t* subflow_list = (TCP_SubFlowVector_t*)(conn->flow->getSubflows());
        for (TCP_SubFlowVector_t::iterator it =subflow_list->begin(); it != subflow_list->end(); it++) {
               if(!conn->isQueueAble) continue;
               TCPConnection *p = (*it)->subflow;
               TCPTahoeRenoFamilyStateVariables* p_state = check_and_cast<TCPTahoeRenoFamilyStateVariables*> (p->getTcpAlgorithm()->getStateVariables());
               double p_sRTT = GET_SRTT(p_state->srtt.dbl());
               denominator_1 += (p_state->snd_cwnd/p_sRTT);
        }
        denominator_1 =  denominator_1 *  denominator_1;
        double term1 = numerator_1/ denominator_1;

       if(is_in_collected_path){
          /*
          For each ACK on the path r:
           - If r is in collected_paths, increase w_r by

                w_r/rtt_r^2                          1
            -------------------    +     -----------------------       (2)
           (SUM (w_p/rtt_p))^2    w_r * number_of_paths * |collected_paths|

           multiplied by MSS_r * bytes_acked.
           */

          double numerator_2 = 1;
          double denominator_2 = r_state->snd_wnd * subflow_list->size() * collected_paths.size();
          double term2 = 0.0;
          if(denominator_2 > 0.0){
              term2 = numerator_2 / denominator_2;
          }
          state->snd_cwnd += (term1 + term2) * (conn->getState()->snd_mss * std::min(acked, conn->getState()->snd_mss));
        }
        else if((is_max_w_paths) && (!collected_paths.empty())){
            /*
            - If r is in max_w_paths and if collected_paths is not empty,
             increase w_r by

                   w_r/rtt_r^2                         1
              --------------------    -     ------------------------     (3)
              (SUM (w_r/rtt_r))^2     w_r * number_of_paths * |max_w_paths|

             multiplied by MSS_r * bytes_acked.
             */
            double numerator_2 = 1;
            double denominator_2 = r_state->snd_wnd * subflow_list->size() * max_w_paths.size();
            double term2 = 0.0;
            if(denominator_2 > 0.0){
                term2 = numerator_2 / denominator_2;
            }
            state->snd_cwnd += (term1 + term2) * (conn->getState()->snd_mss * std::min(acked, conn->getState()->snd_mss));
        }
        else{
            /*
            - Otherwise, increase w_r by

                                     (w_r/rtt_r^2)
                             ----------------------------------           (4)
                                    (SUM (w_r/rtt_r))^2

              multiplied by MSS_r * bytes_acked.
              */
            state->snd_cwnd += term1 * (conn->getState()->snd_mss * std::min(acked, conn->getState()->snd_mss));

        }
    }
    else
        state->snd_cwnd += ackedBytes;

    if(print)
    if (cwndVector)
      cwndVector->record(state->snd_cwnd);
    return;
}


void MPTCP_OLIA::receivedDataAck(uint32 firstSeqAcked){
    TCPNewReno::receivedDataAck(firstSeqAcked);
//    if(state->lossRecovery){
//        if(state->new_olia_counting_start != state->snd_una){
//            state->s_olia_sent_bytes = std::max(state->snd_una - state->new_olia_counting_start,state->olia_sent_bytes);
//            state->olia_sent_bytes = state->snd_una - state->new_olia_counting_start;
//            state->new_olia_counting_start = state->snd_una;
//        }
//    }
}

void MPTCP_OLIA::receivedDuplicateAck(){
    TCPNewReno::receivedDuplicateAck();
    if(state->lossRecovery){
        if(state->new_olia_counting_start != state->snd_una){
            state->s_olia_sent_bytes = std::max(state->snd_una - state->new_olia_counting_start,state->olia_sent_bytes);
            state->olia_sent_bytes = state->snd_una - state->new_olia_counting_start;
            state->new_olia_counting_start = state->snd_una;
        }

    }
}

void MPTCP_OLIA::processRexmitTimer(TCPEventCode& event){
    TCPNewReno::processRexmitTimer(event);
    if(state->new_olia_counting_start != state->snd_una){
        state->s_olia_sent_bytes = std::max(state->snd_una - state->new_olia_counting_start,state->olia_sent_bytes);
        state->olia_sent_bytes = state->snd_una - state->new_olia_counting_start;
        state->new_olia_counting_start = state->snd_una;
    }
}

