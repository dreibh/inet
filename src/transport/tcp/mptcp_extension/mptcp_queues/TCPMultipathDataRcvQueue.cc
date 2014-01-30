//
// Copyright (C) 2004 Andras Varga
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


#include "TCPMultipathDataRcvQueue.h"
#include <map>

Register_Class(TCPMultipathDataRcvQueue);


TCPMultipathDataRcvQueue::TCPMultipathDataRcvQueue() : TCPMultipathReceiveQueue()
{
}

TCPMultipathDataRcvQueue::~TCPMultipathDataRcvQueue()
{
    clear();
}

void TCPMultipathDataRcvQueue::clear(){
    if(data.empty()){
        std::cerr << "Queue is empty" << std::endl;
        return;
    }
    std::cerr <<  "Stop with filled queue" << std::endl;
    for(MPTCP_DataMap::iterator i = data.begin(); i != data.end(); i++){
        std::cerr << "Base: " << virtual_start << "Small: " << (uint32) virtual_start << " -> " << i->second->begin << ".."<< i->first
                       << " - send " << (uint32) i->second->begin << ".." << (uint32) i->first  << std::endl;
      }
    std::cerr << "Occupied Memory" << getOccupiedMemory() << std::endl;
    data.clear();
}

void TCPMultipathDataRcvQueue::init(uint64 startSeq)
{
    virtual_start = startSeq + 1;
    clear();
    data.clear();
}

void TCPMultipathDataRcvQueue::info()
{
    std::cerr << "#################" << std::endl;
    for(MPTCP_DataMap::const_iterator i = data.begin(); i != data.end(); i++){
           std::cerr << "Base: " << virtual_start << " Small: " << (uint32) virtual_start << " -> " << i->second->begin << ".."<< i->first
            << " - send " << (uint32) i->second->begin << ".." << (uint32) i->first  << std::endl;
    }
    // std::cerr << "Occupied Memory" << getOccupiedMemory() << " complete up to " << (uint32) virtual_start << " On Time " <<  simTime() << std::endl;
}

uint64 TCPMultipathDataRcvQueue::insertBytesFromSegment(uint64 dss_start_seq, uint32 data_len)
{
    MPTCP_DataMap::iterator i = data.begin();
    Data_Pair *p = (Data_Pair *) malloc(sizeof(Data_Pair));
    p->begin = dss_start_seq;
    p->len = data_len;
    //info();
    //std::cerr << "Last DSS " << dss_start_seq <<" len "   << data_len<< std::endl;
    // check for old
    if(dss_start_seq < (virtual_start + 1)){
        // old one
        // perhaps we coudl use part of this data
        if(dss_start_seq + data_len < (virtual_start + 1))
            return virtual_start; // No that is not valid any more
        dss_start_seq = (virtual_start);
        data_len = (dss_start_seq + data_len) - (virtual_start);
        p->begin = virtual_start;
        p->len = data_len;
    }

    std::pair<MPTCP_DataMap::iterator, bool> res = data.insert(std::make_pair(dss_start_seq + data_len,p));
    const bool result = res.second;
    if(!result){
        // we still know this element
        // TODO create a vector for double messages
        // check if the length is OK
        i = data.find(dss_start_seq + data_len);
        ASSERT(i!=data.end() && "Something else is wrong with our map");

        if(i->second->len < p->len){
            i->second->len =  p->len;
            i->second->begin = p->begin;
        }
        delete p;
        return virtual_start;
    }

    uint64 next_start= virtual_start; + 1;
    uint64 highest_in_order = virtual_start;
    bool in_order = true;

    // Now check the queue for Overlapping
    for(i = data.begin();i != data.end();i++){

        uint64 start = std::min(i->second->begin, highest_in_order);
        MPTCP_DataMap::iterator j = i;
        // find start of next element
        j++;
        if(j != data.end()){
            next_start = j->second->begin;
        }
        else{
            next_start = i->first + 1; //simulate last element
        }

        if(next_start < start){
            // we have a bigger sequence
            // New begin is next start - The end is later
            // we remove the new entry and adapt the second
            j->second->begin = ((res.first))->second->begin;
            j->second->len   = j->first - j->second->begin;

            // we correct the length on delivery
            data.erase((res.first)->first);

            // restart loop;
            i = data.begin();
            continue;
        }
        // Just to be sure
        ASSERT((i->first - i->second->begin)  == i->second->len);

        if(in_order && (highest_in_order + 1  >= i->second->begin)){
            highest_in_order  = std::max(i->first,highest_in_order);
            in_order = true;
        }
        else in_order = false;
     }

    virtual_start = highest_in_order;
    //info();
    return virtual_start;
}


cPacket *TCPMultipathDataRcvQueue::extractBytesUpTo(uint64 seq)
{
    if(data.empty())
        return NULL;
    uint64 first_in_queue = data.begin()->first;
    if( first_in_queue <= seq){
        cPacket *pkt = new cPacket("MPTCP Data");
        pkt->setByteLength(data.begin()->second->len);
        delete data.begin()->second;
        data.erase((data.begin())->first);
        return (pkt);
    }
    uint64 new_start = (--(data.end()))->first;

    return NULL;
}

void TCPMultipathDataRcvQueue::printInfo(){
#ifndef DEBUG
    std::cerr << "#########" << std::endl;
    info();
#endif
}

uint64 TCPMultipathDataRcvQueue::getOccupiedMemory(){
#ifndef Relativ
   if(data.empty()){
       return 0;
   }
   //info();
   return (--(data.end()))->first - virtual_start;
#else
   uint32 len = 0;
   for(MPTCP_DataMap::iterator i = data.begin(); i != data.end(); i++){
       len += i->second->len;
   }
   return len;
#endif
}

uint64 TCPMultipathDataRcvQueue::getAmountOfBufferedBytes()
{
    uint32 bytes = 0;
    for(MPTCP_DataMap::iterator i = data.begin(); i != data.end(); i++){
        bytes += i->first - i->second->begin;
    }
    return bytes;
}

uint64 TCPMultipathDataRcvQueue::getAmountOfFreeBytes(uint64 maxRcvBuffer)
{

    return maxRcvBuffer - getOccupiedMemory();
}

uint64 TCPMultipathDataRcvQueue::getQueueLength()
{
    return data.size();
}

void TCPMultipathDataRcvQueue::getQueueStatus()
{
    //tcpEV << "receiveQLength=" << data.size() << " " << info() << "\n";
}
