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

#include "DimensionalImplementation.h"
#include "IRadioChannel.h"

const IRadioSignalReception *DimensionalRadioSignalAttenuationBase::computeReception(const IRadio *receiverRadio, const IRadioSignalTransmission *transmission) const
{
    const IRadioChannel *radioChannel = receiverRadio->getXRadioChannel();
    const IRadio *transmitterRadio = transmission->getRadio();
    const IRadioAntenna *receiverAntenna = receiverRadio->getReceiverAntenna();
    const IRadioAntenna *transmitterAntenna = transmitterRadio->getTransmitterAntenna();
    const DimensionalRadioSignalTransmission *dimensionalTransmission = check_and_cast<const DimensionalRadioSignalTransmission *>(transmission);
    IMobility *receiverAntennaMobility = receiverAntenna->getMobility();
    simtime_t receptionStartTime = radioChannel->computeTransmissionStartArrivalTime(transmission, receiverAntennaMobility);
    simtime_t receptionEndTime = radioChannel->computeTransmissionEndArrivalTime(transmission, receiverAntennaMobility);
    Coord receptionStartPosition = receiverAntennaMobility->getPosition(receptionStartTime);
    Coord receptionEndPosition = receiverAntennaMobility->getPosition(receptionEndTime);
    Coord direction = receptionStartPosition - transmission->getStartPosition();
    // TODO: use antenna gains
    double transmitterAntennaGain = transmitterAntenna->getGain(direction);
    double receiverAntennaGain = receiverAntenna->getGain(direction);
    const ConstMapping *attenuationFactor = check_and_cast<const DimensionalRadioSignalLoss *>(computeLoss(receiverRadio, transmission, receptionStartTime, receptionEndTime, receptionStartPosition, receptionEndPosition))->getFactor();
    const Mapping *transmissionPower = dimensionalTransmission->getPower();
    const Mapping *receptionPower = MappingUtils::multiply(*transmissionPower, *attenuationFactor, Argument::MappedZero);
    return new DimensionalRadioSignalReception(receiverRadio, transmission, receptionStartTime, receptionEndTime, receptionStartPosition, receptionEndPosition, receptionPower, dimensionalTransmission->getCarrierFrequency());
}

const IRadioSignalLoss *DimensionalRadioSignalFreeSpaceAttenuation::computeLoss(const IRadio *radio, const IRadioSignalTransmission *transmission, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition) const
{
    const DimensionalRadioSignalTransmission *dimensionalTransmission = check_and_cast<const DimensionalRadioSignalTransmission *>(transmission);
    // TODO: iterate over frequencies in power mapping
    LossConstMapping *pathLoss = new LossConstMapping(DimensionSet::timeFreqDomain, computePathLoss(transmission, startTime, endTime, startPosition, endPosition, dimensionalTransmission->getCarrierFrequency()));
    return new DimensionalRadioSignalLoss(pathLoss);
}

const IRadioSignalNoise *DimensionalRadioBackgroundNoise::computeNoise(const IRadioSignalListening *listening) const
{
    // TODO:
    throw cRuntimeError("Not yet implemented");
}

const IRadioSignalNoise *DimensionalRadioBackgroundNoise::computeNoise(const IRadioSignalReception *reception) const
{
    // TODO:
    throw cRuntimeError("Not yet implemented");
}

bool DimensionalSNRRadioDecider::isReceptionPossible(const IRadioSignalReception *reception) const
{
    // TODO:
    throw cRuntimeError("Not yet implemented");
}

const IRadioSignalNoise *DimensionalSNRRadioDecider::computeNoise(const std::vector<const IRadioSignalReception *> *receptions, const IRadioSignalNoise *backgroundNoise) const
{
    // TODO:
    throw cRuntimeError("Not yet implemented");
}

double DimensionalSNRRadioDecider::computeSNRMinimum(const IRadioSignalReception *reception, const IRadioSignalNoise *noise) const
{
    // TODO:
    throw cRuntimeError("Not yet implemented");
}

const IRadioSignalListeningDecision *DimensionalSNRRadioDecider::computeListeningDecision(const IRadioSignalListening *listening, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const
{
    // TODO:
    throw cRuntimeError("Not yet implemented");
}

const IRadioSignalTransmission *DimensionalRadioSignalModulator::createTransmission(const IRadio *radio, const cPacket *packet, simtime_t startTime) const
{
    simtime_t duration = packet->getBitLength() / bitrate;
    simtime_t endTime = startTime + duration;
    IMobility *mobility = radio->getTransmitterAntenna()->getMobility();
    Coord startPosition = mobility->getPosition(startTime);
    Coord endPosition = mobility->getPosition(endTime);
    Mapping *powerMapping = MappingUtils::createMapping(Argument::MappedZero, DimensionSet::timeFreqDomain, Mapping::LINEAR);
    Argument position(DimensionSet::timeFreqDomain);
    position.setArgValue(Dimension::frequency, carrierFrequency - bandwidth / 2);
    position.setTime(startTime);
    powerMapping->setValue(position, power);
    position.setTime(endTime);
    powerMapping->setValue(position, power);
    position.setArgValue(Dimension::frequency, carrierFrequency + bandwidth / 2);
    position.setTime(startTime);
    powerMapping->setValue(position, power);
    position.setTime(endTime);
    powerMapping->setValue(position, power);
    return new DimensionalRadioSignalTransmission(radio, startTime, endTime, startPosition, endPosition, powerMapping, carrierFrequency);
}

const IRadioSignalListening *DimensionalRadioSignalModulator::createListening(const IRadio *radio, simtime_t startTime, simtime_t endTime, Coord startPosition, Coord endPosition) const
{
    // TODO:
    throw cRuntimeError("Not yet implemented");
}
