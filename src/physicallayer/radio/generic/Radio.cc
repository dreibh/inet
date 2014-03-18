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

#include "Radio.h"
#include "ImplementationBase.h"
#include "PhyControlInfo_m.h"
#include "Ieee80211RadioDecider.h"

unsigned int Radio::nextId = 0;

IRadioFrame *Radio::transmitPacket(cPacket *packet, simtime_t startTime)
{
    // TODO: bare minimum
    // 1. FEC coding
    // 2. modulation (bit -> symbol)
    // 3. pulse shaping filter



    const IRadioSignalTransmission *transmission = modulator->createTransmission(this, packet, startTime);
    channel->transmitToChannel(this, transmission);
    RadioFrame *radioFrame = new RadioFrame(transmission);
    radioFrame->setDuration(transmission->getDuration());
    radioFrame->encapsulate(packet);
    return radioFrame;
}

cPacket *Radio::receivePacket(IRadioFrame *frame)
{
    // TODO: bare minimum
    // 1. pulse matching filter
    // 2. demodulation (symbol -> bit)
    // 3. FEC decoding


    const IRadioSignalTransmission *transmission = frame->getTransmission();
    const IRadioSignalListening *listening = modulator->createListening(this, transmission->getStartTime(), transmission->getEndTime(), transmission->getStartPosition(), transmission->getEndPosition());
    const IRadioSignalReceptionDecision *radioDecision = channel->receiveFromChannel(this, listening, transmission);
    cPacket *packet = check_and_cast<cPacket *>(frame)->decapsulate();
    if (!radioDecision->isReceptionSuccessful())
        packet->setKind(COLLISION);
    else
    {
        // KLUDGE: move
        const Ieee80211RadioDecider *ieee80211Decider = dynamic_cast<const Ieee80211RadioDecider *>(decider);
        if (ieee80211Decider)
        {
            const ScalarRadioSignalReceptionDecision *scalarRadioDecision = check_and_cast<const ScalarRadioSignalReceptionDecision *>(radioDecision);
            const ScalarRadioSignalTransmission *scalarTransmission = check_and_cast<const ScalarRadioSignalTransmission *>(frame->getTransmission());
            // KLUDGE: bitrate
            if (!ieee80211Decider->isPacketOK(scalarRadioDecision->getSNRMinimum(), packet->getBitLength(), scalarTransmission->getBitrate()))
            // TODO: if (!ieee80211Decider->isPacketOK(scalarRadioDecision->getSNRMinimum(), radioFrame->getEncapsulatedPacket()->getBitLength(), radioFrame->getBitrate()))
                packet->setKind(BITERROR);
        }
    }
// TODO: decide how do we communicate collisions
// TODO: fix LMac and BMac to not use kind to pass information to the other node?
// packet->setKind(radioDecision->isReceptionSuccessful() ? 0 : COLLISION);
    packet->setControlInfo(const_cast<cObject *>(check_and_cast<const cObject *>(check_and_cast<const RadioSignalReceptionDecision *>(radioDecision))));
    return packet;
}
