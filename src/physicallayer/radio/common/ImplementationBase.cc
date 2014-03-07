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

#include "ImplementationBase.h"
#include "ModuleAccess.h"

Define_Module(IsotropicRadioAntenna);

unsigned int RadioSignalTransmissionBase::nextId = 0;

void RadioSignalTransmissionBase::printToStream(std::ostream &stream) const
{
    // TODO: members
    stream << "transmission";
}

void RadioSignalListeningBase::printToStream(std::ostream &stream) const
{
    // TODO: members
    stream << "listening";
}

void RadioSignalReceptionBase::printToStream(std::ostream &stream) const
{
    // TODO: members
    stream << "reception";
}

void RadioAntennaBase::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL)
    {
        mobility = check_and_cast<IMobility *>(getContainingNode(this)->getSubmodule("mobility"));
    }
}

void RadioSignalFreeSpaceAttenuationBase::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL)
    {
        alpha = par("alpha");
    }
}

double RadioSignalFreeSpaceAttenuationBase::computePathLoss(const IRadioSignalTransmission *transmission, simtime_t receptionStartTime, simtime_t receptionEndTime, Coord receptionStartPosition, Coord receptionEndPosition, double carrierFrequency) const
{
    /** @brief
     *       waveLength ^ 2
     *   -----------------------
     *   16 * pi ^ 2 * d ^ alpha
     */
//    TODO: add parameter to use more precise distance approximation?
//    double startDistance = transmission->getStartPosition().distance(receptionStartPosition);
//    double endDistance = transmission->getEndPosition().distance(receptionEndPosition);
//    double distance = (startDistance + endDistance) / 2;
    double distance = transmission->getStartPosition().distance(receptionStartPosition);
    double waveLength = transmission->getPropagationSpeed() / carrierFrequency;
    // NOTE: this check allows to get the same result from the GPU and the CPU when the alpha is exactly 2
    double raisedDistance = alpha == 2.0 ? distance * distance : pow(distance, alpha);
    return distance == 0.0 ? 1.0 : waveLength * waveLength / (16.0 * M_PI * M_PI * raisedDistance);
}

void RadioSignalListeningDecision::printToStream(std::ostream &stream) const
{
    stream << "listening " << (isListeningPossible_ ? "possible" : "impossible");
}

void RadioSignalReceptionDecision::printToStream(std::ostream &stream) const
{
    stream << "reception " << (isReceptionPossible_ ? "possible" : "impossible");
    stream << " and " << (isReceptionSuccessful_ ? "successful" : "unsuccessful");
}

void RadioDeciderBase::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL)
    {
        sensitivity = par("sensitivity");
    }
}

bool RadioDeciderBase::computeIsReceptionPossible(const IRadioSignalReception *reception, const std::vector<const IRadioSignalReception *> *overlappingReceptions) const
{
    if (!isReceptionPossible(reception))
        return false;
    else
    {
        for (std::vector<const IRadioSignalReception *>::const_iterator it = overlappingReceptions->begin(); it != overlappingReceptions->end(); it++)
        {
            const IRadioSignalReception *overlappingReception = *it;
            if (overlappingReception->getStartTime() < reception->getStartTime() && isReceptionPossible(overlappingReception))
                return false;
        }
        return true;
    }
}

void SNRRadioDecider::initialize(int stage)
{
    RadioDeciderBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL)
    {
        snrThreshold = par("snrThreshold");
    }
}

const IRadioSignalReceptionDecision *SNRRadioDecider::computeReceptionDecision(const IRadioSignalReception *reception, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const
{
    const IRadioSignalNoise *noise = computeNoise(overlappingReceptions, backgroundNoise);
    double snrMinimum = computeSNRMinimum(reception, noise);
    bool isReceptionPossible = computeIsReceptionPossible(reception, overlappingReceptions);
    bool isReceptionSuccessful = isReceptionPossible && snrMinimum > snrThreshold;
    return new RadioSignalReceptionDecision(reception, isReceptionPossible, isReceptionSuccessful);
}
