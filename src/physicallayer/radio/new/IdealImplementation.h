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

#ifndef __INET_IDEALIMPLEMENTATION_H_
#define __INET_IDEALIMPLEMENTATION_H_

#include "ImplementationBase.h"

class INET_API IdealRadioSignalTransmission : public RadioSignalTransmissionBase
{
    protected:
        const double maximumCommunicationRange;
        const double maximumInterferenceRange;

    public:
        IdealRadioSignalTransmission(const IRadio *radio, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition, double maximumCommunicationRange, double maximumInterferenceRange) :
            RadioSignalTransmissionBase(radio, startTime, endTime, startPosition, endPosition),
            maximumCommunicationRange(maximumCommunicationRange),
            maximumInterferenceRange(maximumInterferenceRange)
        {}

        virtual double getMaximumCommunicationRange() const { return maximumCommunicationRange; }
        virtual double getMaximumInterferenceRange() const { return maximumInterferenceRange; }
};

class INET_API IdealRadioSignalLoss : public IRadioSignalLoss
{
    public:
        enum Factor
        {
            FACTOR_WITHIN_COMMUNICATION_RANGE,
            FACTOR_WITHIN_INTERFERENCE_RANGE,
            FACTOR_OUT_OF_INTERFERENCE_RANGE
        };

    protected:
        const Factor factor;

    public:
        IdealRadioSignalLoss(Factor factor) :
            factor(factor)
        {}

        virtual Factor getFactor() const { return factor; }
};

class INET_API IdealRadioSignalReception : public RadioSignalReceptionBase
{
    public:
        enum Power
        {
            POWER_RECEIVABLE,
            POWER_INTERFERING,
            POWER_UNDETECTABLE
        };

    protected:
        const Power power;

    public:
        IdealRadioSignalReception(const IRadio *radio, const IRadioSignalTransmission *transmission, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition, Power power) :
            RadioSignalReceptionBase(radio, transmission, startTime, endTime, startPosition, endPosition),
            power(power)
        {}

        virtual Power getPower() const { return power; }
};

class INET_API IdealRadioSignalAttenuationBase : public IRadioSignalAttenuation
{
    public:
        virtual const IRadioSignalReception *computeReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
};

class INET_API IdealRadioSignalFreeSpaceAttenuation : public IdealRadioSignalAttenuationBase, public cCompoundModule
{
    public:
        IdealRadioSignalFreeSpaceAttenuation() {}

        virtual const IRadioSignalLoss *computeLoss(const IRadio *radio, const IRadioSignalTransmission *transmission, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition) const;
};

class INET_API IdealRadioDecider : public IRadioDecider, public cCompoundModule
{
    protected:
        bool ignoreInterference;

    protected:
        virtual void initialize(int stage);

    public:
        IdealRadioDecider() :
            ignoreInterference(true)
        {}

        IdealRadioDecider(bool ignoreInterference) :
            ignoreInterference(ignoreInterference)
        {}

        virtual const IRadioSignalReceptionDecision *computeReceptionDecision(const IRadioSignalReception *reception, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const;
        virtual const IRadioSignalListeningDecision *computeListeningDecision(const IRadioSignalListening *listening, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const;
};

class INET_API IdealRadioSignalModulator : public IRadioSignalModulator, public cCompoundModule
{
    protected:
        double bitrate;
        double maximumCommunicationRange;
        double maximumInterferenceRange;

    protected:
        virtual void initialize(int stage);

    public:
        IdealRadioSignalModulator() :
            bitrate(-1),
            maximumCommunicationRange(-1),
            maximumInterferenceRange(-1)
        {}

        IdealRadioSignalModulator(double bitrate, double maximumCommunicationRange, double maximumInterferenceRange) :
            bitrate(bitrate),
            maximumCommunicationRange(maximumCommunicationRange),
            maximumInterferenceRange(maximumInterferenceRange)
        {}

        virtual const IRadioSignalTransmission *createTransmission(const IRadio *radio, const cPacket *packet, simtime_t startTime) const;
};

#endif
