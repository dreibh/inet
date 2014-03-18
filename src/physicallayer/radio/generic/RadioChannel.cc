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
#include "RadioChannel.h"
// TODO: should not be here
#include "ScalarImplementation.h"

RadioChannel::~RadioChannel()
{
    delete backgroundNoise;
    delete attenuation;
}

simtime_t RadioChannel::computeArrivalTime(simtime_t time, Coord position, IMobility *mobility) const
{
    double distance;
    switch (mobilityApproximationCount)
    {
        case 0:
        {
            distance = position.distance(mobility->getCurrentPosition());
            break;
        }
        case 1:
            distance = position.distance(mobility->getPosition(time));
            break;
        case 2:
            // NOTE: repeat once again to approximate the movement during propagation
            distance = position.distance(mobility->getPosition(time));
            simtime_t propagationTime = distance / propagationSpeed;
            distance = position.distance(mobility->getPosition(time + propagationTime));
            break;
    }
    simtime_t propagationTime = distance / propagationSpeed;
    return time + propagationTime;
}

simtime_t RadioChannel::computeTransmissionStartArrivalTime(const IRadioSignalTransmission *transmission, IMobility *mobility) const
{
    return computeArrivalTime(transmission->getStartTime(), transmission->getStartPosition(), mobility);
}

simtime_t RadioChannel::computeTransmissionEndArrivalTime(const IRadioSignalTransmission *transmission, IMobility *mobility) const
{
    return computeArrivalTime(transmission->getEndTime(), transmission->getEndPosition(), mobility);
}

// TODO: factor out common part
bool RadioChannel::isOverlappingTransmission(const IRadioSignalTransmission *transmission, const IRadioSignalListening *listening) const
{
    double propagationSpeed = getPropagationSpeed();
    simtime_t propagationStartTime = transmission->getStartPosition().distance(listening->getStartPosition()) / propagationSpeed;
    simtime_t propagationEndTime = transmission->getEndPosition().distance(listening->getEndPosition()) / propagationSpeed;
    simtime_t arrivalStartTime = transmission->getStartTime() + propagationStartTime;
    simtime_t arrivalEndTime = transmission->getEndTime() + propagationEndTime;
    return arrivalEndTime > listening->getStartTime() + minimumOverlappingTime && arrivalStartTime < listening->getEndTime() - minimumOverlappingTime;
}

// TODO: factor out common part
bool RadioChannel::isOverlappingTransmission(const IRadioSignalTransmission *transmission, const IRadioSignalReception *reception) const
{
    double propagationSpeed = getPropagationSpeed();
    simtime_t propagationStartTime = transmission->getStartPosition().distance(reception->getStartPosition()) / propagationSpeed;
    simtime_t propagationEndTime = transmission->getEndPosition().distance(reception->getEndPosition()) / propagationSpeed;
    simtime_t arrivalStartTime = transmission->getStartTime() + propagationStartTime;
    simtime_t arrivalEndTime = transmission->getEndTime() + propagationEndTime;
    return arrivalEndTime > reception->getStartTime() + minimumOverlappingTime && arrivalStartTime < reception->getEndTime() - minimumOverlappingTime;
}

void RadioChannel::eraseAllExpiredTransmissions()
{
    // TODO: consider interfering with other not yet received signals (use maximum signal duration?)
    double xMinimum = DBL_MAX;
    double xMaximum = DBL_MIN;
    double yMinimum = DBL_MAX;
    double yMaximum = DBL_MIN;
    for (std::vector<const IRadio *>::const_iterator it = radios.begin(); it != radios.end(); it++)
    {
        const IRadio *radio = *it;
        IMobility *mobility = radio->getTransmitterAntenna()->getMobility();
        Coord position = mobility->getCurrentPosition();
        if (position.x < xMinimum)
            xMinimum = position.x;
        if (position.x > xMaximum)
            xMaximum = position.x;
        if (position.y < yMinimum)
            yMinimum = position.y;
        if (position.y > yMaximum)
            yMaximum = position.y;
    }
    double distanceMaximum = Coord(xMinimum, yMinimum).distance(Coord(xMaximum, yMaximum));
    double propagationTimeMaximum = distanceMaximum / getPropagationSpeed();
    simtime_t transmissionEndTimeMinimum = simTime() - propagationTimeMaximum;
    for (std::vector<const IRadioSignalTransmission *>::iterator it = transmissions.begin(); it != transmissions.end();)
    {
        const IRadioSignalTransmission *transmission = *it;
        if (transmission->getEndTime() < transmissionEndTimeMinimum) {
            transmissions.erase(it);
        }
        else
            it++;
    }
}

// TODO: factor out common part
const std::vector<const IRadioSignalTransmission *> *RadioChannel::computeOverlappingTransmissions(const IRadioSignalListening *listening, const std::vector<const IRadioSignalTransmission *> *transmissions) const
{
    std::vector<const IRadioSignalTransmission *> *overlappingTransmissions = new std::vector<const IRadioSignalTransmission *>();
    for (std::vector<const IRadioSignalTransmission *>::const_iterator it = transmissions->begin(); it != transmissions->end(); it++)
    {
        const IRadioSignalTransmission *transmission = *it;
        if (isOverlappingTransmission(transmission, listening))
            overlappingTransmissions->push_back(transmission);
    }
    return overlappingTransmissions;
}

// TODO: factor out common part
const std::vector<const IRadioSignalTransmission *> *RadioChannel::computeOverlappingTransmissions(const IRadioSignalReception *reception, const std::vector<const IRadioSignalTransmission *> *transmissions) const
{
    std::vector<const IRadioSignalTransmission *> *overlappingTransmissions = new std::vector<const IRadioSignalTransmission *>();
    for (std::vector<const IRadioSignalTransmission *>::const_iterator it = transmissions->begin(); it != transmissions->end(); it++)
    {
        const IRadioSignalTransmission *transmission = *it;
        if (isOverlappingTransmission(transmission, reception))
            overlappingTransmissions->push_back(transmission);
    }
    return overlappingTransmissions;
}

// TODO: factor out common part
const std::vector<const IRadioSignalReception *> *RadioChannel::computeOverlappingReceptions(const IRadioSignalListening *listening, const std::vector<const IRadioSignalTransmission *> *transmissions) const
{
    const IRadio *radio = listening->getRadio();
    std::vector<const IRadioSignalReception *> *overlappingReceptions = new std::vector<const IRadioSignalReception *>();
    const std::vector<const IRadioSignalTransmission *> *overlappingTransmissions = computeOverlappingTransmissions(listening, transmissions);
    for (std::vector<const IRadioSignalTransmission *>::const_iterator it = overlappingTransmissions->begin(); it != overlappingTransmissions->end(); it++)
    {
        const IRadioSignalTransmission *overlappingTransmission = *it;
        if (overlappingTransmission->getRadio() != radio)
            overlappingReceptions->push_back(attenuation->computeReception(radio, overlappingTransmission));
    }
    return overlappingReceptions;
}

// TODO: factor out common part
const std::vector<const IRadioSignalReception *> *RadioChannel::computeOverlappingReceptions(const IRadioSignalReception *reception, const std::vector<const IRadioSignalTransmission *> *transmissions) const
{
    const IRadio *radio = reception->getRadio();
    const IRadioSignalTransmission *transmission = reception->getTransmission();
    std::vector<const IRadioSignalReception *> *overlappingReceptions = new std::vector<const IRadioSignalReception *>();
    const std::vector<const IRadioSignalTransmission *> *overlappingTransmissions = computeOverlappingTransmissions(reception, transmissions);
    for (std::vector<const IRadioSignalTransmission *>::const_iterator it = overlappingTransmissions->begin(); it != overlappingTransmissions->end(); it++)
    {
        const IRadioSignalTransmission *overlappingTransmission = *it;
        if (overlappingTransmission != transmission)
            overlappingReceptions->push_back(attenuation->computeReception(radio, overlappingTransmission));
    }
    return overlappingReceptions;
}

const IRadioSignalReceptionDecision *RadioChannel::computeReceptionDecision(const IRadio *radio, const IRadioSignalListening *listening, const IRadioSignalTransmission *transmission, const std::vector<const IRadioSignalTransmission *> *transmissions) const
{
    const IRadioSignalReception *reception = attenuation->computeReception(radio, transmission);
    const std::vector<const IRadioSignalReception *> *overlappingReceptions = computeOverlappingReceptions(reception, transmissions);
    const IRadioSignalNoise *noise = backgroundNoise ? backgroundNoise->computeNoise(reception) : NULL;
    return radio->getDecider()->computeReceptionDecision(listening, reception, overlappingReceptions, noise);
}

const IRadioSignalListeningDecision *RadioChannel::computeListeningDecision(const IRadio *radio, const IRadioSignalListening *listening, const std::vector<const IRadioSignalTransmission *> *transmissions) const
{
    const std::vector<const IRadioSignalReception *> *overlappingReceptions = computeOverlappingReceptions(listening, transmissions);
    const IRadioSignalNoise *noise = backgroundNoise ? backgroundNoise->computeNoise(listening) : NULL;
    return radio->getDecider()->computeListeningDecision(listening, overlappingReceptions, noise);
}

void RadioChannel::transmitToChannel(const IRadio *radio, const IRadioSignalTransmission *transmission)
{
    transmissions.push_back(transmission);
    eraseAllExpiredTransmissions();
}

void RadioChannel::sendToChannel(IRadio *radio, const IRadioFrame *frame)
{
    const Radio *transmitterRadio = check_and_cast<Radio *>(radio);
    const RadioFrame *radioFrame = check_and_cast<const RadioFrame *>(frame);
    const IRadioSignalTransmission *transmission = frame->getTransmission();
    EV_DEBUG << "Sending " << radioFrame << " with " << radioFrame->getBitLength() << " bits in " << radioFrame->getDuration() * 1E+6 << " us transmission duration"
             << " from " << transmitterRadio << " to " << this << "." << endl;
    for (std::vector<const IRadio *>::const_iterator it = radios.begin(); it != radios.end(); it++)
    {
        const Radio *receiverRadio = check_and_cast<const Radio *>(*it);
        if (receiverRadio != transmitterRadio && isPotentialReceiver(receiverRadio, transmission))
        {
            cGate *gate = receiverRadio->RadioBase::getRadioGate()->getPathStartGate();
            IMobility *receiverAntennaMobility = receiverRadio->getReceiverAntenna()->getMobility();
            simtime_t startArrivalTime = computeTransmissionStartArrivalTime(transmission, receiverAntennaMobility);
            simtime_t propagationTime = startArrivalTime - simTime();
            EV_DEBUG << "Sending " << radioFrame
                     << " from " << transmitterRadio << " at " << transmission->getStartPosition()
                     << " to " << receiverRadio << " at " << receiverAntennaMobility->getPosition(startArrivalTime)
                     << " in " << propagationTime * 1E+6 << " us propagation time." << endl;
            RadioFrame *frameCopy = new RadioFrame(radioFrame->getTransmission());
            frameCopy->encapsulate(radioFrame->getEncapsulatedPacket()->dup());
            const_cast<Radio *>(transmitterRadio)->sendDirect(frameCopy, propagationTime, radioFrame->getDuration(), gate);
        }
    }
}

const IRadioSignalReceptionDecision *RadioChannel::receiveFromChannel(const IRadio *radio, const IRadioSignalListening *listening, const IRadioSignalTransmission *transmission) const
{
    const IRadioSignalReceptionDecision *decision = computeReceptionDecision(radio, listening, transmission, const_cast<const std::vector<const IRadioSignalTransmission *> *>(&transmissions));
    EV_DEBUG << "Receiving " << transmission << " from channel by " << radio << " arrives as " << decision->getReception() << " and results in " << decision << endl;
    return decision;
}

const IRadioSignalListeningDecision *RadioChannel::listenOnChannel(const IRadio *radio, const IRadioSignalListening *listening) const
{
    const IRadioSignalListeningDecision *decision = computeListeningDecision(radio, listening, const_cast<const std::vector<const IRadioSignalTransmission *> *>(&transmissions));
    EV_DEBUG << "Listening " << listening << " on channel by " << radio << " results in " << decision << endl;
    return decision;
}

bool RadioChannel::isPotentialReceiver(const IRadio *radio, const IRadioSignalTransmission *transmission) const
{
    // KLUDGE: fingerprint
    const ScalarRadioSignalModulator *scalarModulator = dynamic_cast<const ScalarRadioSignalModulator *>(radio->getModulator());
    const ScalarRadioSignalTransmission *scalarTransmission = dynamic_cast<const ScalarRadioSignalTransmission *>(transmission);
    if (scalarModulator && scalarTransmission && scalarTransmission->getCarrierFrequency() != scalarModulator->getCarrierFrequency())
        return false;
    else if (maximumCommunicationRange == -1)
        return true;
    else
    {
        const IRadioAntenna *antenna = radio->getReceiverAntenna();
        IMobility *mobility = antenna->getMobility();
        simtime_t receptionStartTime = computeTransmissionStartArrivalTime(transmission, mobility);
        simtime_t receptionEndTime = computeTransmissionEndArrivalTime(transmission, mobility);
        Coord receptionStartPosition = mobility->getPosition(receptionStartTime);
        Coord receptionEndPosition = mobility->getPosition(receptionEndTime);
        double maxiumCommunicationRange = maximumCommunicationRange; // TODO: ???->computeMaximumCommunicationRange();
        return transmission->getStartPosition().distance(receptionStartPosition) < maxiumCommunicationRange ||
               transmission->getEndPosition().distance(receptionEndPosition) < maxiumCommunicationRange;
    }
}
