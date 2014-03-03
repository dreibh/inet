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

#ifndef __INET_RADIOCHANNEL_H_
#define __INET_RADIOCHANNEL_H_

#include <vector>
#include <algorithm>
#include "RadioChannelBase.h"
#include "IRadioBackgroundNoise.h"
#include "IRadioSignalAttenuation.h"

class INET_API RadioChannel : public RadioChannelBase, public IRadioChannel
{
    protected:
        const double propagationSpeed;
        const double maximumCommunicationRange;
        // TODO: compute from longest frame duration, maximum mobility speed and signal propagation time
        const simtime_t minimumOverlappingTime;
        const int mobilityApproximationCount;
        const IRadioBackgroundNoise *backgroundNoise;
        const IRadioSignalAttenuation *attenuation;
        std::vector<const IRadio *> radios;
        std::vector<const IRadioSignalTransmission *> transmissions;

    protected:

        virtual simtime_t computeArrivalTime(simtime_t time, Coord position, IMobility *mobility) const;
        virtual bool isOverlappingTransmission(const IRadioSignalTransmission *transmission, const IRadioSignalListening *listening) const;
        virtual bool isOverlappingTransmission(const IRadioSignalTransmission *transmission, const IRadioSignalReception *reception) const;

        virtual void eraseAllExpiredTransmissions();

        virtual const std::vector<const IRadioSignalTransmission *> *computeOverlappingTransmissions(const IRadioSignalListening *listening, const std::vector<const IRadioSignalTransmission *> *transmissions) const;
        virtual const std::vector<const IRadioSignalTransmission *> *computeOverlappingTransmissions(const IRadioSignalReception *reception, const std::vector<const IRadioSignalTransmission *> *transmissions) const;
        virtual const std::vector<const IRadioSignalReception *> *computeOverlappingReceptions(const IRadioSignalListening *listening, const std::vector<const IRadioSignalTransmission *> *transmissions) const;
        virtual const std::vector<const IRadioSignalReception *> *computeOverlappingReceptions(const IRadioSignalReception *reception, const std::vector<const IRadioSignalTransmission *> *transmissions) const;
        virtual const IRadioSignalReceptionDecision *computeReceptionDecision(const IRadio *radio, const IRadioSignalTransmission *transmission, const std::vector<const IRadioSignalTransmission *> *transmissions) const;
        virtual const IRadioSignalListeningDecision *computeListeningDecision(const IRadio *radio, const IRadioSignalListening *listening, const std::vector<const IRadioSignalTransmission *> *transmissions) const;

    public:
        RadioChannel() :
            propagationSpeed(SPEED_OF_LIGHT),
            maximumCommunicationRange(-1),
            minimumOverlappingTime(1E-10),
            mobilityApproximationCount(0),
            backgroundNoise(NULL),
            attenuation(NULL)
        {}

        RadioChannel(const IRadioBackgroundNoise *backgroundNoise, const IRadioSignalAttenuation *attenuation) :
            propagationSpeed(SPEED_OF_LIGHT),
            maximumCommunicationRange(-1),
            minimumOverlappingTime(1E-10),
            mobilityApproximationCount(0),
            backgroundNoise(backgroundNoise),
            attenuation(attenuation)
        {}

        virtual ~RadioChannel();

        virtual void addRadio(const IRadio *radio) { radios.push_back(radio); }
        virtual void removeRadio(const IRadio *radio) { radios.erase(std::remove(radios.begin(), radios.end(), radio)); }

        virtual double getPropagationSpeed() const { return propagationSpeed; }
        virtual simtime_t computeTransmissionStartArrivalTime(const IRadioSignalTransmission *transmission, IMobility *mobility) const;
        virtual simtime_t computeTransmissionEndArrivalTime(const IRadioSignalTransmission *transmission, IMobility *mobility) const;

        virtual void transmitToChannel(const IRadio *radio, const IRadioSignalTransmission *transmission);
        virtual void sendToChannel(IRadio *radio, const IRadioFrame *frame);

        virtual const IRadioSignalReceptionDecision *receiveFromChannel(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
        virtual const IRadioSignalListeningDecision *listenOnChannel(const IRadio *radio, const IRadioSignalListening *listening) const;
        virtual bool isPotentialReceiver(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
};

#endif
