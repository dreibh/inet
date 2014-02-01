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

#ifndef MPTCP_RPMPV2_H_
#define MPTCP_RPMPV2_H_

#include "INETDefs.h"
#include "TCPNewReno.h"


class INET_API  MPTCP_RPMPv2 : public TCPNewReno{
public:
    MPTCP_RPMPv2();
    virtual ~MPTCP_RPMPv2();

    void increaseCWND(uint32 ackedBytes, bool print);

    /** Redefine what should happen when data got acked, to add congestion window management */
    virtual void receivedDataAck(uint32 firstSeqAcked);

    /** Redefine what should happen when dupAck was received, to add congestion window management */
    virtual void receivedDuplicateAck();

    virtual void processRexmitTimer(TCPEventCode& event);

    virtual void processRexmitTimerSetCWND();
    virtual void receivedDuplicateAckSetCWND();

    virtual void initialize();
};

#endif /* MPTCPRPMPV2_H_ */
