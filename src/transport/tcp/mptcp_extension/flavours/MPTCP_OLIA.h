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

#ifndef MPTCPOLIA_H_
#define MPTCPOLIA_H_

#include "INETDefs.h"
#include "TCPNewReno.h"
#include <map>
/**
   This class implements the mechanism of OLIA, the "opportunistic
   linked increases algorithm". OLIA is a congestion control algorithm
   for MPTCP. The current congestion control algorithm of MPTCP, LIA,
   forces a tradeoff between optimal congestion balancing and
   responsiveness. OLIA's design departs from this tradeoff and provide
   these properties simultaneously.
*/

typedef std::map<uint32,TCPConnection*> Path_Collection;
// simtime_t
// max_mms
class INET_API MPTCP_OLIA : public TCPNewReno{

private:
    Path_Collection best_paths;
    Path_Collection max_w_paths;
    Path_Collection collected_paths;
public:
    MPTCP_OLIA();
    virtual ~MPTCP_OLIA();
    virtual void recalculateMPTCPCCBasis();
    void increaseCWND(uint32 ackedBytes, bool print);

    /** Redefine what should happen when data got acked, to add congestion window management */
    virtual void receivedDataAck(uint32 firstSeqAcked);

    /** Redefine what should happen when dupAck was received, to add congestion window management */
    virtual void receivedDuplicateAck();

    virtual void processRexmitTimer(TCPEventCode& event);

    virtual void initialize();
};

#endif /* MPTCPOLIA_H_ */
