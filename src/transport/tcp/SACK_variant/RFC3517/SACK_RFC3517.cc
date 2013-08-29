/*
 * SACK_RFC3517.cpp
 *
 *  Created on: Aug 28, 2013
 *      Author: becke
 */

#include "SACK_RFC3517.h"

SACK_RFC3517::SACK_RFC3517(TCPConnection *conn): SACKHandler(conn->getState()){
   ASSERT(state!=NULL);
   // create SACK retransmit queue
   this->con = conn;
   // rexmitQueue = new TCPNewSACKRexmitQueue();
   updateStatus();
//   rexmitQueue->setConnection(conn);
}

SACK_RFC3517::~SACK_RFC3517() {
    // TODO Auto-generated destructor stub
}

void SACK_RFC3517::initial(){
    updateStatus();
    sb.high_rtx  = state->snd_una;
    sb.recoveryPoint = 0;
}

// RFC 3517, page 3: ""HighRxt" is the highest sequence number which has been retransmitted during the current loss recovery phase."
uint32 SACK_RFC3517::getHighRxt(){
    return this->sb.high_rtx;
}


void SACK_RFC3517::updateStatus() {
    sb.high_acked = state->snd_una - 1;
    sb.high_data = state->snd_max;
    discardUpTo(state->snd_una);
}

uint32 SACK_RFC3517::do_forward(){
    uint32 forward = 0;
    updateStatus();
    sb.recoveryPoint =  sb.high_data;
    return forward;
}

uint32 SACK_RFC3517::getSizeOfRtxPkt(){
    // Do we know packet?
//    if(state->snd_nxt < rexmitQueue->getHighestSackedSeqNum()){
        // we know this
//        uint32 end = rexmitQueue->getEndOfRegion(state->snd_nxt);
//        return (end - state->snd_nxt);
//    }
//    sb.map.
    return 0;
}

void SACK_RFC3517::enqueueSACKSenderSide(uint32 bytes){
//    if((!state->fin_rcvd) && (!state->send_fin) && (!state->isRTX))
//            rexmitQueue->enqueueSentData(state->snd_nxt, state->snd_nxt + bytes);
    //?????
}

bool SACK_RFC3517::statusChanged(){
    return false; //(state->sackedBytes_old != state->sackedBytes);
}

void SACK_RFC3517::discardUpTo(uint32 to){
    SACK_MAP::iterator i;
    for(i = sb.map.begin();i != sb.map.end();i++){
               if(to > i->second->end){
                   delete i->second;
                   sb.map.erase(i->first);
                   continue;
               }
               // if we are here it could only be partial
               if((i->first < to) && (to < i->second->end)){
                   sb.map.insert(std::make_pair(to+1,i->second));
                   sb.map.erase(i->first);
               }
               else
                   break;
    }
}

void SACK_RFC3517::flush(){

}

void SACK_RFC3517::reset(){
    //rexmitQueue->resetSackedBit();

    //rexmitQueue->resetRexmittedBit();
}

void SACK_RFC3517::setNewRecoveryPoint(uint32 r){
    sb.recoveryPoint = r;
}
uint32 SACK_RFC3517::getRecoveryPoint(){
    return sb.recoveryPoint;
}

uint32 SACK_RFC3517::sendUnsackedSegment(uint32 wnd){
    uint32 offset = 0;
    if(sb.map.empty()) return 0; // No Sack no nee to work
    _setPipe();

    while(wnd - (sb.pipe + offset)>= state->snd_mss){
        uint32 new_nxt = _nextSeg(offset);
        uint32 old_nxt = state->snd_nxt;
        if(new_nxt == 0)
            return offset;
        state->snd_nxt = new_nxt;
        con->sendSegment(state->snd_mss);
        // std::cerr << "RTX on SACK base: [" << new_nxt << "..." << state->snd_nxt - 1 << "]"  << "Expect " << state->snd_una << std::endl;
        sb.high_rtx = state->snd_nxt -1;
        offset += state->snd_nxt - new_nxt;
        state->snd_nxt = old_nxt;
        if(sb.pipe+offset > wnd)
            break;
    }
    return offset;
}

uint32 SACK_RFC3517::_nextSeg(uint32 offset){
    SACK_MAP::iterator i = sb.map.end();
    uint32 s2 = sb.high_acked + 1;
    if(offset){
        s2 = sb.high_rtx + 1;
    }
    if(s2 < state->snd_nxt){
    // check if it is not in a SACK Block
        SACK_MAP::iterator i2 = sb.map.begin();
        i2++;
        for(i = sb.map.begin();i != sb.map.end();i++,i2++){
            if(i2 == sb.map.end()){
                if((s2 > i->second->end) && (s2 < state->snd_nxt)){
                    return s2;
                }
                // i is last segment, we have to go to rule 2
                goto rule2;
            }
            if((s2 > i->second->end) && (s2 < i2->first)){  // it is between two SACK Blocks, so we use it for retransmit
                    // found relating SACK
                    return s2;
            }
         }

        if( (s2 > sb.high_rtx) &&
            (s2 < (--i)->second->end) &&
            (_isLost(s2)->lost)){
        }
    }
rule2:
    sb.high_rtx = sb.high_acked;
    return 0; // sb.high_acked + 1;
// TODO Rule 3 und Rule 4
}
void SACK_RFC3517::_setPipe(){
    _createIsLostTag();
    sb.pipe = 0;
    for(int seg = sb.high_acked; seg <= sb.high_data; seg++){
        // a)
        SACK_REGION* sack = _isLost(seg);
        if(sack==NULL) return; // no SACKs
        if(!sack->lost){
            sb.pipe += sack->end - seg;
        }
        if(seg <= sb.high_rtx){
            sb.pipe += sack->end - seg;
        }

    }
}

void SACK_RFC3517::_createIsLostTag(){

    if(sb.map.empty()) return;
    SACK_MAP::iterator i = (sb.map.end());

    sb.total_sacked = 0;
    do{
        i--;
        uint32 start = i->first;
        uint32 end = i->second->end;
        i->second->len = end - start;
        sb.total_sacked += i->second->len ;
        i->second->sacked_above = sb.total_sacked;
        // Set lost element
        if((i->second->dup) >= DUPTHRESH || (i->second->sacked_above >= DUPTHRESH*state->snd_mss)){
            i->second->lost = true;
        }
        else{
            i->second->lost = false;
        }
    }while(i != sb.map.begin());

}


SACK_REGION* SACK_RFC3517::_isLost(uint32 seg){

    // Perhaps we have a direct access
    SACK_MAP::iterator i = sb.map.find(seg);
    if(i!=sb.map.end())
        return i->second;
    // No direct access, we have to count
    for(i = sb.map.begin();i != sb.map.end();i++){
        if(seg <= i->second->end){
            // found relating SACK
                return i->second;
        }
    }
    return NULL;
}

void SACK_RFC3517::_cntDup(uint32 start, uint32 end){
    // Full known DUP
    // We know exact this Sack
    SACK_MAP::iterator i;
    bool know_start = false;

    if((!sb.map.empty()) ){

        if((i =sb.map.find(start)) != sb.map.end()){
            know_start = true;
            if(i->second->end == end){
                know_end = true;
                i->second->dup++;
                return;
            }
        }
        if(know_start){
            // Partial DUP less
            SACK_REGION *par = new SACK_REGION();
            par->end = end;
            par->lost = 1;
            sb.map.insert(std::make_pair(i->second->end + 1,par));
            i->second->dup += 1;
            return;
        }
        for(i = sb.map.begin();i != sb.map.end();i++){
            if(i->second->end <= end){
                if(i->second->end == end){
                    SACK_REGION *par = new SACK_REGION();
                    par->end = i->first - 1 ;
                    par->dup = 1;
                    i->second->dup += 1;
                    sb.map.insert(std::make_pair(start,par));
                    return;
                }
                // worst case
                // insert the second element
                SACK_REGION *pre = new SACK_REGION();
                pre->end = end;
                pre->dup = i->second->dup + 1;
                sb.map.insert(std::make_pair(start,pre));

                // insert the third element
                SACK_REGION *post = new SACK_REGION();
                pre->end = i->second->end;
                pre->dup = 1;
                sb.map.insert(std::make_pair(end + 1,post));

                // correct the first element
                i->second->end = start -1;
                return;
            }

        }
    }
    // New Dup
    SACK_REGION *pre = new SACK_REGION();
    pre->end = end;
    pre->dup = 1;
    sb.map.insert(std::make_pair(start,pre));
    return;
}
TCPSegment *SACK_RFC3517::addSACK(TCPSegment *tcpseg){

    TCPOption option;
    uint options_len = 0;
    uint used_options_len = tcpseg->getOptionsArrayLength();
    bool dsack_inserted = false; // set if dsack is subsets of a bigger sack block recently reported

    uint32 start = state->start_seqno;
    uint32 end = state->end_seqno;

    // delete old sacks (below rcv_nxt), delete duplicates and print previous status of sacks_array:
    SackMap::iterator it = state->sack_map.begin();
    while(it!=state->sack_map.end()){
        if(state->rcv_nxt > it->first){
            if(state->rcv_nxt < it->second){
                state->sack_map.insert(std::make_pair(state->rcv_nxt+1,it->second));
            }
            state->sack_map.erase(it->first);
            it++;
            continue;
        }
        break;
    }


    if (used_options_len > TCP_OPTIONS_MAX_SIZE - TCP_OPTION_SACK_MIN_SIZE)
    {
         tcpEV << "ERROR: Failed to addSacks - at least 10 free bytes needed for SACK - used_options_len=" << used_options_len << endl;
         //reset flags:
         state->snd_sack = false;
         state->snd_dsack = false;
         state->start_seqno = 0;
         state->end_seqno = 0;
         ASSERT(false && "Not enough space for ACKS");
         return tcpseg;
    }
    uint key = 0;
    if (start != end)
    {
        if (state->snd_dsack) // SequenceNo < rcv_nxt
        {
            // RFC 2883, page 3:
            // "(3) The left edge of the D-SACK block specifies the first sequence
            // number of the duplicate contiguous sequence, and the right edge of
            // the D-SACK block specifies the sequence number immediately following
            // the last sequence in the duplicate contiguous sequence."
            if (seqLess(start, state->rcv_nxt) && seqLess(state->rcv_nxt, end))
                end = state->rcv_nxt;
            key = start;
            dsack_inserted = true;
        }
        else
        {
            start = con->getReceiveQueue()->getLE(start);
            end = con->getReceiveQueue()->getRE(end);
        }


        // RFC 2883, page 3:
        // "(3) The left edge of the D-SACK block specifies the first sequence
        // number of the duplicate contiguous sequence, and the right edge of
        // the D-SACK block specifies the sequence number immediately following
        // the last sequence in the duplicate contiguous sequence."

        // RFC 2018, page 4:
        // "* The first SACK block (i.e., the one immediately following the
        // kind and length fields in the option) MUST specify the contiguous
        // block of data containing the segment which triggered this ACK,
        // unless that segment advanced the Acknowledgment Number field in
        // the header.  This assures that the ACK with the SACK option
        // reflects the most recent change in the data receiver's buffer
        // queue."

        // RFC 2018, page 4:
        // "* The first SACK block (i.e., the one immediately following the
        // kind and length fields in the option) MUST specify the contiguous
        // block of data containing the segment which triggered this ACK,"

        // RFC 2883, page 3:
        // "(4) If the D-SACK block reports a duplicate contiguous sequence from
        // a (possibly larger) block of data in the receiver's data queue above
        // the cumulative acknowledgement, then the second SACK block in that
        // SACK option should specify that (possibly larger) block of data.
        //
        // (5) Following the SACK blocks described above for reporting duplicate
        // segments, additional SACK blocks can be used for reporting additional
        // blocks of data, as specified in RFC 2018."

        // RFC 2018, page 4:
        // "* The SACK option SHOULD be filled out by repeating the most
        // recently reported SACK blocks (based on first SACK blocks in
        // previous SACK options) that are not subsets of a SACK block
        // already included in the SACK option being constructed."



        for (SackMap::iterator it2 = state->sack_map.begin(); it2 != state->sack_map.end(); it2++)
        {
            if(start <= it2->first){
                // OK this is the smallest we know
                if(end< it2->first){
                    break; // NEW smallest sack
                }

                // there is a overlapping...we have to check how far
                bool found_end = false;
                while(it2 != state->sack_map.end()){
                    if(end <= it2->second){
                        found_end = true;
                        break;
                    }
                 // it2 is overlapped ....delete
                 state->sack_map.erase(it2->first);
                 it2++;
                }
                if(found_end){
                    end = it2->second;
                    state->sack_map.erase(it2->first);
                    break;
                }
                else{
                 // nothing to do... overlapped are erased above
                    break;
                }
            }
        }
        std::pair<SackMap::iterator, bool> pair = state->sack_map.insert(std::make_pair(start,end));
        ASSERT(pair.second && "Could not insert SACK");
        it = pair.first;
    }
    uint n = state->sack_map.size();
    uint maxnode = ((TCP_OPTIONS_MAX_SIZE - used_options_len) - 2) / 8;    // 2: option header, 8: size of one sack entry

    if (n > maxnode)
     n = maxnode;

    if (n == 0)
    {

// FIXME Delayed SACK
//     if (dsack_inserted)
//         state->sacks_array.pop_front(); // delete DSACK entry

     // reset flags:
     state->snd_sack = false;
     state->snd_dsack = false;
     state->start_seqno = 0;
     state->end_seqno = 0;

     return tcpseg;
    }

    uint optArrSize = tcpseg->getOptionsArraySize();
    uint optArrSizeAligned = optArrSize;

    while (used_options_len % 4 != 2)
    {
     used_options_len++;
     optArrSizeAligned++;
    }

    tcpseg->setOptionsArraySize(optArrSizeAligned + 1);

    if (optArrSizeAligned > optArrSize)
    {
     option.setKind(TCPOPTION_NO_OPERATION); // NOP
     option.setLength(1);
     option.setValuesArraySize(0);

     while (optArrSize < optArrSizeAligned)
         tcpseg->setOptions(optArrSize++, option);
    }

    ASSERT(used_options_len % 4 == 2);

    option.setKind(TCPOPTION_SACK);
    option.setLength(8 * n + 2);
    option.setValuesArraySize(2 * n);

    // write sacks from sacks_array to options
    uint counter = 0;
    for (SackMap::iterator it2 = state->sack_map.begin(); it2 != state->sack_map.end() && counter < 2 * n; it2++)
    {
     ASSERT(it2->first != it2->second);
     option.setValues(counter++, it2->first);
     option.setValues(counter++, it2->second);
    }

    // independent of "n" we always need 2 padding bytes (NOP) to make: (used_options_len % 4 == 0)
    options_len = used_options_len + 8 * n + 2; // 8 bytes for each SACK (n) + 2 bytes for kind&length
    ASSERT(options_len <= TCP_OPTIONS_MAX_SIZE); // Options length allowed? - maximum: 40 Bytes
    tcpseg->setOptions(optArrSizeAligned, option);

    // update number of sent sacks
    state->snd_sacks += n;

    if (con->sndSacksVector)
     con->sndSacksVector->record(state->snd_sacks);

    counter = 0;
    tcpEV << n << " SACK(s) added to header:\n";

    for (uint t = 0; t < (n * 2); t += 2)
    {
     counter++;
     tcpEV << counter << ". SACK:" << " [" << option.getValues(t) << ".." << option.getValues(t + 1) << ")";

     if (t == 1)
     {
         if (state->snd_dsack)
             tcpEV << " (D-SACK)";
         else if (seqLE(option.getValues(t + 1), state->rcv_nxt))
         {
             tcpEV << " (received segment filled out a gap)";
             state->snd_dsack = true; // Note: Set snd_dsack to delete first sack from sacks_array
         }
     }

     tcpEV << endl;
    }

    // RFC 2883, page 3:
    // "(1) A D-SACK block is only used to report a duplicate contiguous
    // sequence of data received by the receiver in the most recent packet.
    //
    // (2) Each duplicate contiguous sequence of data received is reported
    // in at most one D-SACK block.  (I.e., the receiver sends two identical
    // D-SACK blocks in subsequent packets only if the receiver receives two
    // duplicate segments.)//
    //
    // In case of d-sack: delete first sack (d-sack) and move old sacks by one to the left
//     TODO FIXME Delayed SACK
//    if (dsack_inserted)
//     state->sacks_array.pop_front(); // delete DSACK entry

    // reset flags:
    state->snd_sack = false;
    state->snd_dsack = false;
    state->start_seqno = 0;
    state->end_seqno = 0;

    return tcpseg;
}

bool SACK_RFC3517::processSACKOption(TCPSegment *tcpseg, const TCPOption& option){

    if (option.getLength() % 8 != 2)
      {
          tcpEV << "ERROR: option length incorrect\n";
          return false;
      }

      uint n = option.getValuesArraySize()/2;

      if (!state->sack_enabled)
      {
          tcpEV << "ERROR: " << n << " SACK(s) received, but sack_enabled is set to false\n";
          ASSERT(false && "SACKS NOT ENABLED I");
          return false;
      }

      if (con->getFsmState() != TCP_S_SYN_RCVD && con->getFsmState()  != TCP_S_ESTABLISHED
              && con->getFsmState()  != TCP_S_FIN_WAIT_1 && con->getFsmState()  != TCP_S_FIN_WAIT_2)
      {
          tcpEV << "ERROR: TCP Header Option SACK received, but in unexpected state\n";
          ASSERT(false && "SACKS NOT IN THIS STATE");
          return false;
      }

      if (n > 0) // sacks present?
      {
          tcpEV << n << " SACK(s) received:\n";
          uint count = 0;

          for (uint i = 0; i < n; i++)
          {
              uint32 start = option.getValues(count++);
              uint32 end = option.getValues(count++);

              if (seqGreater(end, tcpseg->getAckNo()) && seqGreater(end, state->snd_una))
                  this->_cntDup(start,end);
              else{
                  //ASSERT(false && "Received SACK below total cumulative ACK snd_una");
              }
          }
          state->rcv_sacks += n; // total counter, no current number

          if (con->rcvSacksVector)
              con->rcvSacksVector->record(state->rcv_sacks);

          if (con->sackedBytesVector)
              con->sackedBytesVector->record(sb.total_sacked);
      }
      return true;

}
