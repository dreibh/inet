//
// Copyright (C) 2013 OpenSim Ltd.
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

#ifndef __INET_RADIO_H_
#define __INET_RADIO_H_

#include "IRadioChannel.h"
#include "IRadioAntenna.h"
#include "IRadioDecider.h"
#include "IRadioSignalModulator.h"
#include "RadioBase.h"

// TODO: merge with RadioFrame
class INET_API RadioFrame : public cPacket, public IRadioFrame
{
    protected:
        const IRadioSignalTransmission *transmission;

    public:
        RadioFrame(const IRadioSignalTransmission *transmission) :
            transmission(transmission)
        {}

        virtual const IRadioSignalTransmission *getTransmission() const { return transmission; }
};

// TODO: merge with RadioBase
class INET_API Radio : public RadioBase, public IRadio
{
    protected:
        static unsigned int nextId;

    protected:
        const unsigned int id;
        const IRadioSignalModulator *modulator;
        // TODO: split into receiver and transmitter antenna
        const IRadioAntenna *antenna;
        const IRadioDecider *decider;
        IRadioChannel *channel;

    public:
        Radio() :
            id(nextId++),
            modulator(NULL),
            antenna(NULL),
            decider(NULL),
            channel(NULL)
        {}

        Radio(RadioMode radioMode, const IRadioSignalModulator *modulator, const IRadioAntenna *antenna, const IRadioDecider *decider, IRadioChannel *channel) :
            id(nextId++),
            modulator(modulator),
            antenna(antenna),
            decider(decider),
            channel(channel)
        {
            channel->addRadio(this);
        }

        virtual unsigned int getId() const { return id; }

        virtual const IRadioSignalModulator *getModulator() const { return modulator; }
        virtual const IRadioAntenna *getReceiverAntenna() const { return antenna; }
        virtual const IRadioAntenna *getTransmitterAntenna() const { return antenna; }
        virtual const IRadioDecider *getDecider() const { return decider; }
        virtual const IRadioChannel *getXRadioChannel() const { return channel; }

        virtual IRadioFrame *transmitPacket(cPacket *packet, simtime_t startTime);
        virtual cPacket *receivePacket(IRadioFrame *frame);

        // TODO: delme
        virtual void handleMessageWhenUp(cMessage *msg) {}
};

#endif
