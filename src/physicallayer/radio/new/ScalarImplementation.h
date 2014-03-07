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

#ifndef __INET_SCALARIMPLEMENTATION_H_
#define __INET_SCALARIMPLEMENTATION_H_

#include "ImplementationBase.h"

class INET_API ScalarRadioSignalTransmission : public RadioSignalTransmissionBase
{
    protected:
        const double power;
        const double carrierFrequency;
        const double bandwidth;

    public:
        ScalarRadioSignalTransmission(const IRadio *radio, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition, double power, double carrierFrequency, double bandwidth) :
            RadioSignalTransmissionBase(radio, startTime, endTime, startPosition, endPosition),
            power(power),
            carrierFrequency(carrierFrequency),
            bandwidth(bandwidth)
        {}

        virtual void printToStream(std::ostream &stream) const;

        virtual double getPower() const { return power; }
        virtual double getCarrierFrequency() const { return carrierFrequency; }
        virtual double getBandwidth() const { return bandwidth; }
};

class INET_API ScalarRadioSignalLoss : public IRadioSignalLoss
{
    protected:
        const double factor;

    public:
        ScalarRadioSignalLoss(double factor) :
            factor(factor)
        {}

        virtual double getFactor() const { return factor; }
};

class INET_API ScalarRadioSignalListening : public RadioSignalListeningBase
{
    protected:
        const double carrierFrequency;
        const double bandwidth;

    public:
        ScalarRadioSignalListening(const IRadio *radio, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition, double carrierFrequency, double bandwidth) :
            RadioSignalListeningBase(radio, startTime, endTime, startPosition, endPosition),
            carrierFrequency(carrierFrequency),
            bandwidth(bandwidth)
        {}

        virtual double getCarrierFrequency() const { return carrierFrequency; }
        virtual double getBandwidth() const { return bandwidth; }
};

class INET_API ScalarRadioSignalReception : public RadioSignalReceptionBase
{
    protected:
        const double power;
        const double carrierFrequency;
        const double bandwidth;

    public:
        ScalarRadioSignalReception(const IRadio *radio, const IRadioSignalTransmission *transmission, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition, double power, double carrierFrequency, double bandwidth) :
            RadioSignalReceptionBase(radio, transmission, startTime, endTime, startPosition, endPosition),
            power(power),
            carrierFrequency(carrierFrequency),
            bandwidth(bandwidth)
        {}

        virtual void printToStream(std::ostream &stream) const;

        virtual double getPower() const { return power; }
        virtual double getCarrierFrequency() const { return carrierFrequency; }
        virtual double getBandwidth() const { return bandwidth; }
};

class INET_API ScalarRadioSignalNoise : public RadioSignalNoiseBase
{
    protected:
        const std::map<simtime_t, double> *powerChanges;
        // TODO: where's carrierFrequency and bandwidth

    public:
        ScalarRadioSignalNoise(simtime_t startTime, simtime_t endTime, const std::map<simtime_t, double> *powerChanges) :
            RadioSignalNoiseBase(startTime, endTime),
            powerChanges(powerChanges)
        {}

        virtual const std::map<simtime_t, double> *getPowerChanges() const { return powerChanges; }
        virtual double computeMaximumPower(simtime_t startTime, simtime_t endTime) const;
};

class INET_API ScalarRadioSignalAttenuationBase : public virtual IRadioSignalAttenuation
{
    public:
        virtual const IRadioSignalReception *computeReception(const IRadio *radio, const IRadioSignalTransmission *transmission) const;
};

class INET_API ScalarRadioSignalFreeSpaceAttenuation : public RadioSignalFreeSpaceAttenuationBase, public ScalarRadioSignalAttenuationBase
{
    public:
        ScalarRadioSignalFreeSpaceAttenuation() :
            RadioSignalFreeSpaceAttenuationBase()
        {}

        ScalarRadioSignalFreeSpaceAttenuation(double alpha) :
            RadioSignalFreeSpaceAttenuationBase(alpha)
        {}

        virtual const IRadioSignalLoss *computeLoss(const IRadio *radio, const IRadioSignalTransmission *transmission, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition) const;
};

class INET_API ScalarRadioSignalCompoundAttenuation : public CompoundAttenuationBase, public ScalarRadioSignalAttenuationBase
{
    public:
        ScalarRadioSignalCompoundAttenuation(const std::vector<const IRadioSignalAttenuation *> *elements) :
            CompoundAttenuationBase(elements)
        {}

        virtual const IRadioSignalLoss *computeLoss(const IRadio *radio, const IRadioSignalTransmission *transmission, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition) const;
};

class INET_API ScalarRadioBackgroundNoise : public IRadioBackgroundNoise, public cCompoundModule
{
    protected:
        double power;

    protected:
        virtual void initialize(int stage);

    public:
        ScalarRadioBackgroundNoise() :
            power(-1)
        {}

        ScalarRadioBackgroundNoise(double power) :
            power(power)
        {}

    public:
        virtual double getPower() const { return power; }

        virtual const IRadioSignalNoise *computeNoise(const IRadioSignalListening *listening) const;
        virtual const IRadioSignalNoise *computeNoise(const IRadioSignalReception *reception) const;
};

class INET_API ScalarRadioSignalListeningDecision : public RadioSignalListeningDecision
{
    protected:
        const double powerMaximum;

    public:
        ScalarRadioSignalListeningDecision(const IRadioSignalListening *listening, double isListeningPossible, double powerMaximum) :
            RadioSignalListeningDecision(listening, isListeningPossible),
            powerMaximum(powerMaximum)
        {}

        virtual void printToStream(std::ostream &stream) const;

        virtual double getPowerMaximum() const { return powerMaximum; }
};

class INET_API ScalarRadioSignalReceptionDecision : public RadioSignalReceptionDecision
{
    protected:
        const double snrMinimum;
        // TODO: rssi, lqi, snr

    public:
        ScalarRadioSignalReceptionDecision(const IRadioSignalReception *reception, bool isReceptionPossible, bool isReceptionSuccessful, double snrMinimum) :
            RadioSignalReceptionDecision(reception, isReceptionPossible, isReceptionSuccessful),
            snrMinimum(snrMinimum)
        {}

        virtual void printToStream(std::ostream &stream) const;

        virtual double getSNRMinimum() const { return snrMinimum; }
};

class INET_API ScalarSNRRadioDecider : public SNRRadioDecider
{
    protected:
        virtual bool isReceptionPossible(const IRadioSignalReception *reception) const;
        virtual const IRadioSignalNoise *computeNoise(const std::vector<const IRadioSignalReception *> *receptions, const IRadioSignalNoise *backgroundNoise) const;
        virtual double computeSNRMinimum(const IRadioSignalReception *reception, const IRadioSignalNoise *noise) const;

    public:
        ScalarSNRRadioDecider() :
            SNRRadioDecider(-1, -1)
        {}

        ScalarSNRRadioDecider(double sensitivity, double snrThreshold) :
            SNRRadioDecider(sensitivity, snrThreshold)
        {}

        virtual const IRadioSignalListeningDecision *computeListeningDecision(const IRadioSignalListening *listening, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const;
        virtual const IRadioSignalReceptionDecision *computeReceptionDecision(const IRadioSignalReception *reception, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const;
};

class INET_API ScalarRadioSignalModulator : public IRadioSignalModulator, public cCompoundModule
{
    protected:
        double bitrate;
        // TODO: is it the preamble duration?
        double headerBitLength;
        double power;
        double carrierFrequency;
        double bandwidth;

    protected:
        virtual void initialize(int stage);

        virtual simtime_t computeDuration(const cPacket *packet) const;

    public:
        ScalarRadioSignalModulator() :
            bitrate(-1),
            headerBitLength(-1),
            power(-1),
            carrierFrequency(-1),
            bandwidth(-1)
        {}

        ScalarRadioSignalModulator(double bitrate, double headerBitLength, double power, double carrierFrequency, double bandwidth) :
            bitrate(bitrate),
            headerBitLength(headerBitLength),
            power(power),
            carrierFrequency(carrierFrequency),
            bandwidth(bandwidth)
        {}

        virtual const IRadioSignalTransmission *createTransmission(const IRadio *radio, const cPacket *packet, simtime_t startTime) const;
};

#endif
