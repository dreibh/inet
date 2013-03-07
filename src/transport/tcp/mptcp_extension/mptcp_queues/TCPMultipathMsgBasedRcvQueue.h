//
// Copyright (C) 2004 Andras Varga
// Copyright (C) 2014 Martin Becke
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

#ifndef __INET_TCPMULTIPATHMESSAGERCVQUEUE_H
#define __INET_TCPMULTIPATHMESSAGERCVQUEUE_H

#include <map>
#include <string>
#include <omnetpp.h>
#include "TCPSegment.h"
#include "TCPMultipathVirtualDataRcvQueue.h"

/**
 * FIXME
 *
 * @see TCPMsgBasedSendQueue
 */
class INET_API TCPMultipathMsgBasedRcvQueue : public TCPMultipathVirtualDataRcvQueue
{
  protected:
    typedef std::map<uint64, cPacket *> PayloadList;
    PayloadList payloadList;

  public:
    /**
     * Ctor.
     */
    TCPMultipathMsgBasedRcvQueue();

    /**
     * Virtual dtor.
     */
    virtual ~TCPMultipathMsgBasedRcvQueue();

    /**
     * Set initial receive sequence number.
     */
    virtual void init(uint64 startSeq);

    /**
     * Returns a string with region stored.
     */
    virtual std::string info() const;

    /**
     * Called when a TCP segment arrives. Returns sequence number for ACK.
     */
    virtual uint64 insertBytesFromSegment(TCPSegment *tcpseg);

    /**
     *
     */
    virtual cPacket *extractBytesUpTo(uint64 seq);

};

#endif

