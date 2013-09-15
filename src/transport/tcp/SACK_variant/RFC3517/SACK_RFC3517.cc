/*
 * SACK_RFC3517.cpp
 *
 *  Created on: Aug 28, 2013
 *      Author: becke
 */

#include "SACK_RFC3517.h"


int SACK_RFC3517::ID_COUNTER = 0;

SACK_RFC3517::SACK_RFC3517(TCPConnection *conn): SACKHandler(conn->getState()){
   ASSERT(state!=NULL);
   ID =ID_COUNTER++;
   // create SACK retransmit queue
   this->con = conn;
   // rexmitQueue = new TCPNewSACKRexmitQueue();
   updateStatus();
   sb.high_rtx = 0;
   sb.recoveryPoint = 0;
//   rexmitQueue->setConnection(conn);
}

SACK_RFC3517::~SACK_RFC3517() {
    // TODO Auto-generated destructor stub
    SACK_MAP::iterator i;
       for(i = sb.map.begin();i != sb.map.end();i++){
                  delete i->second;
       }
}

void SACK_RFC3517::initial(){
    updateStatus();
    sb.high_rtx = 0;
    sb.recoveryPoint = 0;
}

// RFC 3517, page 3: ""HighRxt" is the highest sequence number which has been retransmitted during the current loss recovery phase."
uint32 SACK_RFC3517::getHighRxt(){
    return this->sb.high_rtx;
}


void SACK_RFC3517::updateStatus() {
    sb.high_acked = state->snd_una - 1;
    sb.high_data = state->getSndNxt();
    discardUpTo(state->snd_una);
}

uint32 SACK_RFC3517::do_forward(){
    uint32 forward = 0;
    updateStatus();
    sb.recoveryPoint =  sb.high_data;
    return forward;
}

bool SACK_RFC3517::statusChanged(){
    return false; //(state->sackedBytes_old != state->sackedBytes);
}

void SACK_RFC3517::discardUpTo(uint32 to){
    SACK_MAP::iterator i;
    int pos = 1;
    for(i = sb.map.begin();i != sb.map.end();i++){
               int map_size = sb.map.size();
               if(to >= i->second->end){
                   delete i->second;
                   sb.map.erase(i->first);
               }
               // if we are here it could only be partial
               else if((i->first <= to) && (to <= i->second->end)){
                   sb.map.insert(std::make_pair(to+1,i->second));
                   sb.map.erase(i->first);
               }
               else
                   break;

               if(sb.map.size() != map_size){
                    i = sb.map.begin();
                    for(int pos_c = 0; pos_c < pos; pos_c++){
                        if(i==sb.map.end()) return;
                        i++;
                    }
                }
               if(sb.map.empty()) return;
               pos++;
    }
}

void SACK_RFC3517::flush(){

}

void SACK_RFC3517::reset(){
    //rexmitQueue->resetSackedBit();

    //rexmitQueue->resetRexmittedBit();
    SACK_MAP::iterator i = sb.map.begin();
    while(i != sb.map.end()){
        delete i->second;
        sb.map.erase(i->first);
        i++;
    }
    this->updateStatus();
}

void SACK_RFC3517::setNewRecoveryPoint(uint32 r){
    sb.recoveryPoint = r;
}
uint32 SACK_RFC3517::getRecoveryPoint(){
    return sb.recoveryPoint;
}

uint32 SACK_RFC3517::sendUnsackedSegment(uint32 wnd){
    static int counter = 0;
    counter++; // for debug
    uint32 offset = 0;

    // FIXME HOw to set high rtx?
    this->discardUpTo(state->snd_una);
    sb.high_rtx =  state->highRxt;
//    std::cerr << "ID: " << ID << std::endl;
//    std::cerr << "Conn ID: " << con->connId << std::endl;
//    std::cerr << "############ IF GAPS SEND SACK ####################" << std::endl;
//    std::cerr << "Round "  << counter << std::endl;
//    std::cerr << "snd_una: " << state->snd_una << std::endl;
//    std::cerr << "snd_nxt: " << state->getSndNxt() << std::endl;
//    std::cerr << "highest rtx: " << sb.high_rtx << std::endl;

    // _print_and_check_sb();

     _setPipe();
//    std::cerr << "pipe" << sb.pipe << "wnd" << wnd << std::endl;
//    std::cerr << "######################## <> ##################" << std::endl;
        sb.old_nxt = state->getSndNxt();
        if(sb.pipe > wnd)
            return 0;
        while( uint32 new_nxt = _nextSeg()){

            state->setSndNxt(new_nxt);
            con->sendOneNewSegment(false, wnd - (sb.pipe+offset));

            if((state->getSndNxt() - new_nxt) == 0)
                break;
            offset += state->getSndNxt() - new_nxt;
            sb.high_rtx = state->getSndNxt() - 1;


            if(state->getSndNxt() == new_nxt)
                break;
//            std::cerr << "RTX on SACK base: [" << new_nxt << "..." <<  state->getSndNxt() - 1 << "]"  << "Window From: " << state->snd_una << " to " << sb.old_nxt << std::endl;

            if(state->getSndNxt() < sb.old_nxt){

                state->setSndNxt(sb.old_nxt);
            }
            if(((sb.pipe+offset) > wnd)){
                break;
            }

        }
    state->setSndNxt(sb.old_nxt);
    con->sendOneNewSegment(false, wnd - (sb.pipe+offset));

    return 0;
}

uint32 SACK_RFC3517::_nextSeg(){
// 1)
    SACK_MAP::iterator it = sb.map.begin();
    for(SACK_MAP::iterator i = sb.map.begin();i != sb.map.end();i++){
        if((sb.high_rtx + 1) >= i->first){
            if((sb.high_rtx + 1) < i->second->end)
                sb.high_rtx = i->second->end;
            continue;
        }
        if(((sb.high_rtx + 1) < (--sb.map.end())->second->end) &&
           (_isLost(&it,(sb.high_rtx + 1))->lost))
            return (sb.high_rtx + 1);
    }
    // no more in SACK lists
    return state->getSndNxt();
}
#ifndef PRIVATE
uint32 SACK_RFC3517::_nextSeg(uint32 *offset){
    SACK_MAP::iterator i = sb.map.end();
    int rule = 2;

    if(sb.map.empty()) return 0;
    uint32 s2 = sb.high_rtx;

    SACK_MAP::iterator i2 = sb.map.begin();
    if(s2 < state->getSndNxt()){
    // check if it is not in a SACK Block
        i2++;
        for(i = sb.map.begin();i != sb.map.end();i++,i2++){
            while((s2 >= i->first) && (i != sb.map.end())){
                i++;
            }
            if(i2 == sb.map.end()){
                // NOT in SACK BLOCKS
                if((s2 > (--(sb.map.end()))->first) && (s2 < state->getSndNxt())){
                    rule = 1;
                    break;
                }
                rule = 2;
                break;
            }
            rule = 1;
            break;
         }

    }
    switch(rule){
    case 1:{
        SACK_MAP::iterator it = sb.map.begin();

        for(;;){
            i = sb.map.end();
            if( (s2 > sb.high_rtx) &&
                (s2 < (--i)->second->end) &&
                (_isLost(&it,s2)->lost)){
                if(i2 != sb.map.end())
                    *offset =  it->first - (s2);
                else
                    *offset =  (sb.old_nxt - 1) - s2;
                return s2;
            }

            // possible cap
            bool tryAgain = false;
            while(it!=sb.map.end()){
                SACK_MAP::iterator tmp = it;
                tmp++;
                if(tmp == sb.map.end()) break;
                if((it->second->end + 1) == tmp->first){
                    it++;
                    continue; // still the block
                }
                if(s2 < it->first){
                    s2 = it->second->end + 1;
                    tryAgain = true;
                    break;
                }
                it++;
            }
            if(tryAgain){
                it++;
                if(it == sb.map.end())
                    break;
                continue;
            }
            return 0;
            }
    }break;
    case 2:{
            sb.high_rtx = sb.high_acked;
             *offset =  1;
            return sb.high_acked + 1;
    }break;
// TODO Rule 3 und Rule 4
    case 3:
    default:
        return 0;
    }
    ASSERT(false && "Should never be reached");
    return 0;
}
#endif

void SACK_RFC3517::_setPipe(){
    _createIsLostTag();
    SACK_MAP::iterator i = sb.map.begin();
    sb.pipe = 0;
    for(uint32 seg = sb.high_acked + 1; seg <= sb.high_data; seg++){
        if(seg > i->first) {
            if(i == sb.map.end()) break;
            seg  = i->second->end;
            i++;
            continue;
        }
        // a)
        if(_isLost(&i, seg)==NULL)
            break;; // no SACKs

        if(!(i->second->lost)){
            // not sacked not lost
            sb.pipe +=  i->first  - seg;
        }
        if(seg <= sb.high_rtx){
            sb.pipe += i->first - seg;
        }
        seg = i->second->end;
        i++;
    }
    if(!sb.map.empty())
        sb.pipe +=  sb.high_data -  (--sb.map.end())->second->end;
    else
        sb.pipe = state->getSndNxt() - state->snd_una;
    //_print_and_check_sb();
    //std::cerr << "PIPE: " << sb.pipe << std::endl;
    //std::cerr << "#############################" << std::endl;
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
        if((i->second->dup) >= DUPTHRESH ){ // TODO || (i->second->sacked_above >= DUPTHRESH*state->snd_mss)){
            i->second->lost = true;
        }
        else{
            i->second->lost = false;
        }
    }while(i != sb.map.begin());

}


SACK_REGION* SACK_RFC3517::_isLost(SACK_MAP::iterator *it, uint32 seg){


    // Perhaps we have a direct access
    if(sb.map.empty())
        return NULL;

    for(;(*it) != sb.map.end();(*it)++){
        if(seg <= (*it)->second->end){
            // found relating SACK
            return (*it)->second;
        }
    }
    return NULL;
}

void SACK_RFC3517::_cntDup(uint32 start, uint32 end){
    // Full known DUP
    // We know exact this Sack

    SACK_MAP::iterator i;
    bool know_start = false;
    discardUpTo(state->snd_una);

    if((!sb.map.empty()) ){

        if((i =sb.map.find(start)) != sb.map.end()){
            know_start = true;
            if(i->second->end == end){
                i->second->dup++;

                return;
            }
        }
        if(know_start){
            // Partial DUP less
            SACK_REGION *ent = (SACK_REGION *) malloc(sizeof(SACK_REGION));
            ent->end = end;
            ent->dup = 1;


            uint32 new_start = i->second->end + 1;
            while(i != sb.map.end()){
                if((start< i->second->end) && (end >= i->second->end)){
                    i->second->dup++;
                    new_start = i->second->end + 1;
                }
                else break;
                i++;
            }
            if(new_start - 1 == end){
                // we don t need a new pair... everything is known
                delete ent;
            }
            else
                sb.map.insert(std::make_pair(new_start,ent));
            return;
        }

        for(i = sb.map.begin();i != sb.map.end();i++){
            SACK_MAP::iterator l = i;

            SACK_REGION *par = NULL;
            while(i != sb.map.end()){
                if(!i->second->end >= start){
                    if(par != NULL)
                        sb.map.insert(std::make_pair(start,par));
                    i = l;
                    break;
                }

                if(i->first > start){
                    // we have a diff
                    if(par == NULL)
                       par = (SACK_REGION *) malloc(sizeof(SACK_REGION));
                    par->dup =1;
                    par->end = i->first - 1;
                }


                l = i;
                i++;
            }
            if(i == sb.map.end()) break; // new
            bool create_new_entry = false;
            while(i != sb.map.end()){
                if(i->second->end < end){
                    create_new_entry = true;
                    break;
                }
                i->second->dup += 1;
                l = i;
                i++;
            }
            if(create_new_entry){
                uint32 new_s = sb.map.begin()->second->end + 1;
                if(i != sb.map.begin()){
                    // we are somewhere in the middle
                    new_s = (--i)->second->end + 1;
                }
                par = (SACK_REGION *) malloc(sizeof(SACK_REGION));
                par->dup =1;
                par->end = end;
                sb.map.insert(std::make_pair(new_s,par));
            }

            return;
        }


//
//            if(i->second->end <= end){
//                if(i->second->end == end){
//                    SACK_REGION *par = (SACK_REGION *) malloc(sizeof(SACK_REGION));
//                    par->end = i->first - 1 ;
//                    par->dup = 1;
//                    i->second->dup += 1;
//                    sb.map.insert(std::make_pair(start,par));
//                    _print_and_check_sb();
//                    return;
//                }
//                if(i->second->end < start){
//                    // it is a new above
//                    break;
//                }
//                // worst case
//                // overlapping element; we have to split
//                SACK_REGION *pre = new SACK_REGION();
//                pre->end = end;
//                pre->dup = i->second->dup + 1;
//
//                // insert the third element
//                SACK_REGION *post = (SACK_REGION *) malloc(sizeof(SACK_REGION));
//                post->end = i->second->end;
//                post->dup = 1;
//
//                uint32 new_start = i->second->end + 1;
//                while(i != sb.map.end()){
//                  if((start< i->second->end) && (end >= i->second->end)){
//                      i->second->dup++;
//                      new_start = i->second->end + 1;
//                  }
//                  else break;
//                  i++;
//                }
//                sb.map.insert(std::make_pair(start,pre));
//                sb.map.insert(std::make_pair(new_start,post));
//
//                // correct the first element
//                i->second->end = start -1;
//                _print_and_check_sb();
//                return;
//            }

 //       }
    }

    // New Dup
    SACK_REGION *pre = (SACK_REGION *) malloc(sizeof(SACK_REGION));
    pre->end = end;
    pre->dup = 1;
    sb.map.insert(std::make_pair(start,pre));

    return;
}
void SACK_RFC3517::_print_and_check_sb(){
    return;
    uint32 last_end = state->snd_una;
    std::cerr << "========================================" << std::endl;
    for(SACK_MAP::iterator i = sb.map.begin();i != sb.map.end();i++){
        if(i->first < state->snd_una)
            ASSERT(false && "Start to small");
//        if(i->second->end > state->getSndNxt())
//            ASSERT(false && "End to big");
// FIXME
//        if(last_end > i->first)
//            ASSERT(false && "Not in Order");
        last_end =  i->second->end;
        std::cerr << "SACKed " << i->second->dup << "times : [" <<  i->first << ".." << i->second->end << "]" << std::endl;
    }
    std::cerr << "========================================" << std::endl;
}

TCPSegment *SACK_RFC3517::addSACK(TCPSegment *tcpseg){

    TCPOption option;
    uint options_len = 0;
    uint used_options_len = tcpseg->getOptionsArrayLength();
//    TODO DSACK
    bool dsack_inserted = false; // set if dsack is subsets of a bigger sack block recently reported

    uint32 start = state->start_seqno;
    uint32 end = state->end_seqno;

    // delete old sacks (below rcv_nxt), delete duplicates and print previous status of sacks_array:
    SackMap::iterator it = state->sack_map.begin();
    int pos = 1;
    while(it!=state->sack_map.end()){
        int map_size = state->sack_map.size();
        if(state->rcv_nxt > it->first){
            if(state->rcv_nxt < it->second){
                state->sack_map.insert(std::make_pair(state->rcv_nxt+1,it->second));
            }
            state->sack_map.erase(it->first);
            if(state->sack_map.size() != map_size){
                it = state->sack_map.begin();
                for(int pos_c = 0; pos_c < pos; pos_c++){
                    if(it==state->sack_map.end()) break;
                    it++;
                }
                if(it==state->sack_map.end()) break;
            }

            it++;
            pos++;
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


        int pos = 1;
        for (SackMap::iterator it2 = state->sack_map.begin(); it2 != state->sack_map.end(); it2++)
        {
            int map_size = state->sack_map.size();
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
                 if(state->sack_map.size() != map_size){
                      it = state->sack_map.begin();
                      for(int pos_c = 0; pos_c < pos; pos_c++){
                          if(it==state->sack_map.end()) break;
                          it++;
                      }
                      if(it==state->sack_map.end()) break;
                  }
                 pos++;
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
                pos++;
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
