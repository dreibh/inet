//
// Copyright (C) 2015 Irene Ruengeler
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

#ifndef __INET_TUNLOOPBACKAPP_H
#define __INET_TUNLOOPBACKAPP_H

#include "inet/linklayer/tun/TunSocket.h"

namespace inet {

class INET_API TunLoopbackApp : public cSimpleModule
{
    protected:
        const char *tunInterface;

        unsigned int packetsSent;
        unsigned int packetsReceived;

        static simsignal_t sentPkSignal;
        static simsignal_t rcvdPkSignal;

        TunSocket tunSocket;

    public:
        TunLoopbackApp();
        virtual ~TunLoopbackApp();

    protected:
        void initialize(int stage) override;
        void handleMessage(cMessage *msg) override;
        void finish() override;
};

} // namespace inet

# endif

