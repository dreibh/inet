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

#ifndef __INET_DIMENSIONALIMPLEMENTATION_H_
#define __INET_DIMENSIONALIMPLEMENTATION_H_

#include "ImplementationBase.h"
#include "Mapping.h"

class INET_API DimensionalRadioSignalTransmission : public RadioSignalTransmissionBase
{
    protected:
        const Mapping *power;
        const double carrierFrequency; // TODO: shouldn't be here

    public:
        DimensionalRadioSignalTransmission(const IRadio *radio, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition, const Mapping *power, double carrierFrequency) :
            RadioSignalTransmissionBase(radio, startTime, endTime, startPosition, endPosition),
            power(power),
            carrierFrequency(carrierFrequency)
        {}

        virtual const Mapping *getPower() const { return power; }
        virtual double getCarrierFrequency() const { return carrierFrequency; }
};

class INET_API DimensionalRadioSignalLoss : public IRadioSignalLoss
{
    protected:
        const ConstMapping *factor;

    public:
        DimensionalRadioSignalLoss(const ConstMapping *factor) :
            factor(factor)
        {}

        virtual const ConstMapping *getFactor() const { return factor; }
};

class INET_API DimensionalRadioSignalReception : public RadioSignalReceptionBase
{
    protected:
        const Mapping *power;
        const double carrierFrequency; // TODO: shouldn't be here

    public:
        DimensionalRadioSignalReception(const IRadio *radio, const IRadioSignalTransmission *transmission, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition, const Mapping *power, double carrierFrequency) :
            RadioSignalReceptionBase(radio, transmission, startTime, endTime, startPosition, endPosition),
            power(power),
            carrierFrequency(carrierFrequency)
        {}

        virtual const Mapping *getPower() const { return power; }
        virtual double getCarrierFrequency() const { return carrierFrequency; }
};

class INET_API DimensionalRadioSignalAttenuationBase : public virtual IRadioSignalAttenuation
{
    protected:
        class INET_API LossConstMapping : public SimpleConstMapping
        {
            private:
                LossConstMapping &operator=(const LossConstMapping&);

            protected:
                const double factor;

            public:
                LossConstMapping(const DimensionSet &dimensions, double factor) :
                    SimpleConstMapping(dimensions),
                    factor(factor)
                {}

                LossConstMapping(const LossConstMapping &other) :
                    SimpleConstMapping(other),
                    factor(other.factor)
                {}

                virtual double getValue(const Argument &position) const { return factor; }

                virtual ConstMapping *constClone() const { return new LossConstMapping(*this); }
        };

    public:
        virtual const IRadioSignalReception *computeReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
};


class INET_API DimensionalRadioSignalFreeSpaceAttenuation : public RadioSignalFreeSpaceAttenuationBase, public DimensionalRadioSignalAttenuationBase
{
    public:
        DimensionalRadioSignalFreeSpaceAttenuation(double alpha) :
            RadioSignalFreeSpaceAttenuationBase(alpha)
        {}

        virtual const IRadioSignalLoss *computeLoss(const IRadio *radio, const IRadioSignalTransmission *transmission, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition) const;
};

class INET_API DimensionalRadioBackgroundNoise : public IRadioBackgroundNoise
{
    protected:
        const double power;

    public:
        DimensionalRadioBackgroundNoise(double power) :
            power(power)
        {}

    public:
        virtual const IRadioSignalNoise *computeNoise(const IRadioSignalListening *listening) const;
        virtual const IRadioSignalNoise *computeNoise(const IRadioSignalReception *reception) const;
};

class INET_API DimensionalSNRRadioDecider : public SNRRadioDecider
{
    protected:
        virtual bool isReceptionPossible(const IRadioSignalReception *reception) const;
        virtual const IRadioSignalNoise *computeNoise(const std::vector<const IRadioSignalReception *> *receptions, const IRadioSignalNoise *backgroundNoise) const;
        virtual double computeSNRMinimum(const IRadioSignalReception *reception, const IRadioSignalNoise *noise) const;

    public:
        DimensionalSNRRadioDecider(double sensitivity, double snrThreshold) :
            SNRRadioDecider(sensitivity, snrThreshold)
        {}

        virtual const IRadioSignalListeningDecision *computeListeningDecision(const IRadioSignalListening *listening, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const;
};

class INET_API DimensionalRadioSignalModulator : public IRadioSignalModulator
{
    protected:
        double bitrate;
        double power;
        double carrierFrequency;
        double bandwidth;

    public:
        DimensionalRadioSignalModulator(double bitrate, double power, double carrierFrequency, double bandwidth) :
            bitrate(bitrate),
            power(power),
            carrierFrequency(carrierFrequency),
            bandwidth(bandwidth)
        {}

        virtual const IRadioSignalTransmission *createTransmission(const IRadio *radio, const cPacket *packet, simtime_t startTime) const;
};

#endif
