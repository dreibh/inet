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

#ifndef __INET_IMPLEMENTATIONBASE_H_
#define __INET_IMPLEMENTATIONBASE_H_

#include "IRadioSignalLoss.h"
#include "IRadioBackgroundNoise.h"
#include "IRadioSignalAttenuation.h"
#include "IRadioSignalModulator.h"

// TODO: revise all names here and also in contract.h
// TODO: optimize interface in terms of constness, use of references, etc.
// TODO: add proper destructors with freeing resources
// TODO: add delete operator calls where appropriate and do proper memory management
// TODO: !!! extend radio decider interface to allow a separate decision for the detection of preambles during synchronization
// TODO: !!! extend radio decider interface to provide reception state for listeners? and support for carrier sensing for MACs
// TODO: avoid the need for subclassing radio and radio channel to be able to have only one parameterizable radio and radio channel NED types
// TODO: add classification of radios into grid cells to be able provide an approximation of the list of radios within communication range quickly
// DONE: extend attenuation model with obstacles, is it a separate model or just another attenuation model?
// TODO: add computation for maximum communication range, using computation for maximum transmission signal power and minimum reception power?
// TODO: refactor optimizing radio channel to allow turning on and off optimization via runtime parameters instead of subclassing
// TODO: extend interface to allow CUDA optimizations e.g. with adding Pi(x, y, z, t, f, b) and SNRi, etc. multiple nested loops to compute the minimum SNR for all transmissions at all receiver radios at once
// TODO: add a skeleton for sampled radio signals or maybe support for GNU radio?
// TODO: add NED modules to provide compound parameters for radio and radio channel
// TODO: how do we combine attenuation and antenna models, do we miss something?
// TODO: who is converting receptions to packets as opposed to signal producer?

class INET_API RadioSignalTransmissionBase : public IRadioSignalTransmission
{
    protected:
        static unsigned int nextId;

    protected:
        const unsigned int id;

        const IRadio *radio;

        const simtime_t startTime;
        const simtime_t endTime;

        const Coord startPosition;
        const Coord endPosition;
//        const Coord startAngularPosition;
//        const Coord endAngularPosition;

        double propagationSpeed;

    public:
        RadioSignalTransmissionBase(const IRadio *radio, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition) :
            id(nextId++),
            radio(radio),
            startTime(startTime),
            endTime(endTime),
            startPosition(startPosition),
            endPosition(endPosition),
            propagationSpeed(SPEED_OF_LIGHT)
        {}

        virtual unsigned int getId() const { return id; }

        virtual simtime_t getStartTime() const { return startTime; }
        virtual simtime_t getEndTime() const { return endTime; }
        virtual simtime_t getDuration() const { return endTime - startTime; }

        virtual Coord getStartPosition() const { return startPosition; }
        virtual Coord getEndPosition() const { return endPosition; }

        virtual double getPropagationSpeed() const { return propagationSpeed; }

        virtual const IRadio *getRadio() const { return radio; }
};

class INET_API RadioSignalListeningBase : public IRadioSignalListening
{
    protected:
        const IRadio *radio;

        const simtime_t startTime;
        const simtime_t endTime;

        const Coord startPosition;
        const Coord endPosition;

    public:
        RadioSignalListeningBase(const IRadio *radio, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition) :
            radio(radio),
            startTime(startTime),
            endTime(endTime),
            startPosition(startPosition),
            endPosition(endPosition)
        {}

        virtual simtime_t getStartTime() const { return startTime; }
        virtual simtime_t getEndTime() const { return endTime; }
        virtual simtime_t getDuration() const { return endTime - startTime; }

        virtual Coord getStartPosition() const { return startPosition; }
        virtual Coord getEndPosition() const { return endPosition; }

        virtual const IRadio *getRadio() const { return radio; }
};

class INET_API RadioSignalReceptionBase : public IRadioSignalReception
{
    protected:
        const IRadio *radio;
        const IRadioSignalTransmission *transmission;

        const simtime_t startTime;
        const simtime_t endTime;

        const Coord startPosition;
        const Coord endPosition;

    public:
        RadioSignalReceptionBase(const IRadio *radio, const IRadioSignalTransmission *transmission, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition) :
            radio(radio),
            transmission(transmission),
            startTime(startTime),
            endTime(endTime),
            startPosition(startPosition),
            endPosition(endPosition)
        {}

        virtual simtime_t getStartTime() const { return startTime; }
        virtual simtime_t getEndTime() const { return endTime; }
        virtual simtime_t getDuration() const { return endTime - startTime; }

        virtual Coord getStartPosition() const { return startPosition; }
        virtual Coord getEndPosition() const { return endPosition; }

        virtual const IRadio *getRadio() const { return radio; }
        virtual const IRadioSignalTransmission *getTransmission() const { return transmission; }
};

class INET_API RadioSignalNoiseBase : public IRadioSignalNoise
{
    protected:
        const simtime_t startTime;
        const simtime_t endTime;

    public:
        RadioSignalNoiseBase(simtime_t startTime, simtime_t endTime) :
            startTime(startTime),
            endTime(endTime)
        {}

        virtual simtime_t getStartTime() const { return startTime; }
        virtual simtime_t getEndTime() const { return endTime; }
        virtual simtime_t getDuration() const { return endTime - startTime; }
};

class INET_API RadioAntennaBase : public IRadioAntenna, public cCompoundModule
{
    protected:
        IMobility *mobility;

    protected:
        virtual void initialize(int stage);

    public:
        RadioAntennaBase(IMobility *mobility) :
            mobility(mobility)
        {}

        virtual IMobility *getMobility() const { return mobility; }
};

class INET_API IsotropicRadioAntenna : public RadioAntennaBase
{
    public:
        IsotropicRadioAntenna() :
            RadioAntennaBase(NULL)
        {}

        IsotropicRadioAntenna(IMobility *mobility) :
            RadioAntennaBase(mobility)
        {}

        virtual double getGain(Coord direction) const { return 1; }
};

class INET_API DipoleRadioAntenna : public RadioAntennaBase
{
    protected:
        const double length;

    public:
        DipoleRadioAntenna(IMobility *mobility, double length) :
            RadioAntennaBase(mobility),
            length(length)
        {}

        virtual double getLength() const { return length; }
        virtual double getGain(Coord direction) const { return 1; }
};

class INET_API RadioSignalFreeSpaceAttenuationBase : public virtual IRadioSignalAttenuation, public cCompoundModule
{
    protected:
        double alpha;

    protected:
        virtual void initialize(int stage);

        virtual double computePathLoss(const IRadioSignalTransmission *transmission, simtime_t receptionStartTime, simtime_t receptionEndTime, Coord receptionStartPosition, Coord receptionEndPosition, double carrierFrequency) const;

    public:
        RadioSignalFreeSpaceAttenuationBase() :
            alpha(-1)
        {}

        RadioSignalFreeSpaceAttenuationBase(double alpha) :
            alpha(alpha)
        {}

        virtual double getAlpha() const { return alpha; }
};

class INET_API CompoundAttenuationBase : public IRadioSignalAttenuation
{
    protected:
        const std::vector<const IRadioSignalAttenuation *> *elements;

    public:
        CompoundAttenuationBase(const std::vector<const IRadioSignalAttenuation *> *elements) :
            elements(elements)
        {}
};

class INET_API RadioSignalListeningDecision : public IRadioSignalListeningDecision, public cObject
{
    protected:
        const IRadioSignalListening *listening;
        const bool isListeningPossible_;

    public:
        RadioSignalListeningDecision(const IRadioSignalListening *listening, bool isListeningPossible_) :
            listening(listening),
            isListeningPossible_(isListeningPossible_)
        {}

        virtual const IRadioSignalListening *getListening() const { return listening; }

        virtual bool isListeningPossible() const { return isListeningPossible_; }
};

class INET_API RadioSignalReceptionDecision : public IRadioSignalReceptionDecision, public cObject
{
    protected:
        const IRadioSignalReception *reception;
        const bool isReceptionPossible_;
        const bool isReceptionSuccessful_;

    public:
        RadioSignalReceptionDecision(const IRadioSignalReception *reception, bool isReceptionPossible, bool isReceptionSuccessful) :
            reception(reception),
            isReceptionPossible_(isReceptionPossible),
            isReceptionSuccessful_(isReceptionSuccessful)
        {}

        virtual const IRadioSignalReception *getReception() const { return reception; }

        virtual bool isReceptionPossible() const { return isReceptionPossible_; }
        virtual bool isReceptionSuccessful() const { return isReceptionSuccessful_; }
};

class INET_API RadioDeciderBase : public IRadioDecider, public cCompoundModule
{
    protected:
        double sensitivity;

    protected:
        virtual void initialize(int stage);

        virtual bool isReceptionPossible(const IRadioSignalReception *reception) const = 0;
        virtual bool computeIsReceptionPossible(const IRadioSignalReception *reception, const std::vector<const IRadioSignalReception *> *overlappingReceptions) const;

    public:
        RadioDeciderBase(double sensitivity) :
            sensitivity(sensitivity)
        {}
};

class INET_API SNRRadioDecider : public RadioDeciderBase
{
    protected:
        double snrThreshold;

    protected:
        virtual void initialize(int stage);

        virtual const IRadioSignalNoise *computeNoise(const std::vector<const IRadioSignalReception *> *receptions, const IRadioSignalNoise *backgroundNoise) const = 0;
        virtual double computeSNRMinimum(const IRadioSignalReception *reception, const IRadioSignalNoise *noise) const = 0;

    public:
        SNRRadioDecider(double sensitivity, double snrThreshold) :
            RadioDeciderBase(sensitivity),
            snrThreshold(snrThreshold)
        {}

        virtual double getSNRThreshold() const { return snrThreshold; }
        virtual const IRadioSignalReceptionDecision *computeReceptionDecision(const IRadioSignalReception *reception, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const;
};

#endif
