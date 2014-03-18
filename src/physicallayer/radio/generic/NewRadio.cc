//
// Copyright (C) 2013 OpenSim Ltd
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

#include "NewRadio.h"
#include "NewRadioChannel.h"
#include "ModuleAccess.h"
#include "NodeOperations.h"
#include "NodeStatus.h"
// TODO: should not be here
#include "ScalarImplementation.h"
// TODO: should not be here
#include "PhyControlInfo_m.h"
// TODO: should not be here
#include "Ieee80211Consts.h"

Define_Module(NewRadio);

NewRadio::NewRadio()
{
    endTransmissionTimer = NULL;
}

NewRadio::~NewRadio()
{
    cancelAndDelete(endTransmissionTimer);
    cancelAndDeleteEndReceptionTimers();
}

void NewRadio::initialize(int stage)
{
    Radio::initialize(stage);
    if (stage == INITSTAGE_LOCAL)
    {
        endTransmissionTimer = new cMessage("endTransmission");
        channel = check_and_cast<IRadioChannel *>(simulation.getModuleByPath("radioChannel"));
        channel->addRadio(this);
        modulator = check_and_cast<IRadioSignalModulator *>(getSubmodule("modulator"));
        antenna = check_and_cast<IRadioAntenna *>(getSubmodule("antenna"));
        decider = check_and_cast<IRadioDecider *>(getSubmodule("decider"));
        // KLUDGE:
        if (hasPar("channelNumber"))
            setRadioChannel(par("channelNumber"));
    }
}

void NewRadio::setRadioMode(RadioMode newRadioMode)
{
    Enter_Method_Silent();
    if (radioMode != newRadioMode)
    {
        // KLUDGE: to keep fingerprint
        if (newRadioMode == OldIRadio::RADIO_MODE_RECEIVER)
        {
            for (EndReceptionTimers::iterator it = endReceptionTimers.begin(); it != endReceptionTimers.end(); it++)
            {
                cMessage *timer = *it;
                RadioFrame *radioFrame = check_and_cast<RadioFrame*>(timer->getControlInfo());
                const IRadioSignalTransmission *transmission = radioFrame->getTransmission();
                double distance = antenna->getMobility()->getCurrentPosition().distance(transmission->getStartPosition());
                simtime_t propagationTime = distance / SPEED_OF_LIGHT;
                simtime_t endArrivalTime = transmission->getStartTime() + radioFrame->getDuration() + propagationTime;
//                if (transmission->getStartTime() + propagationTime > simTime())
//                    TODO:
                if (endArrivalTime > simTime())
                    scheduleAt(endArrivalTime, timer);
            }
        }
        else
            cancelAndDeleteEndReceptionTimers();
        EV << "Changing radio mode from " << getRadioModeName(radioMode) << " to " << getRadioModeName(newRadioMode) << ".\n";
        radioMode = newRadioMode;
        emit(radioModeChangedSignal, newRadioMode);
        updateTransceiverState();
    }
}

void NewRadio::handleMessageWhenUp(cMessage *message)
{
    if (message->isSelfMessage())
        handleSelfMessage(message);
    else if (message->getArrivalGate() == upperLayerIn)
    {
        if (!message->isPacket())
            handleUpperCommand(message);
        else if (radioMode == RADIO_MODE_TRANSMITTER || radioMode == RADIO_MODE_TRANSCEIVER)
            handleUpperFrame(check_and_cast<cPacket *>(message));
        else
        {
            EV << "Radio is not in transmitter or transceiver mode, dropping frame.\n";
            delete message;
        }
    }
    else if (message->getArrivalGate() == radioIn)
    {
        if (!message->isPacket())
            handleLowerCommand(message);
        else if (radioMode == RADIO_MODE_RECEIVER || radioMode == RADIO_MODE_TRANSCEIVER)
            handleLowerFrame(check_and_cast<RadioFrame*>(message));
        else
        {
            // KLUDGE: fingerprint
            {
                cMessage *endReceptionTimer = new cMessage("endReception");
                endReceptionTimer->setControlInfo(message);
                endReceptionTimer->setKind(false);
                endReceptionTimers.push_back(endReceptionTimer);
            }
            EV << "Radio is not in receiver or transceiver mode, dropping frame.\n";
//            delete message;
        }
    }
    else
    {
        throw cRuntimeError("Unknown arrival gate '%s'.", message->getArrivalGate()->getFullName());
        delete message;
    }
}

void NewRadio::handleSelfMessage(cMessage *message)
{
    if (message == endTransmissionTimer) {
        EV << "Transmission successfully completed.\n";
        updateTransceiverState();
    }
    else
    {
        EV << "Frame is completely received now.\n";
        for (EndReceptionTimers::iterator it = endReceptionTimers.begin(); it != endReceptionTimers.end(); it++)
        {
            if (*it == message)
            {
                endReceptionTimers.erase(it);
                RadioFrame *radioFrame = check_and_cast<RadioFrame *>(message->removeControlInfo());
                if (message->getKind())
                {
                    cPacket *macFrame = receivePacket(radioFrame);
                    EV << "Sending up " << macFrame << ".\n";
                    send(macFrame, upperLayerOut);
                }
                updateTransceiverState();
                delete radioFrame;
                delete message;
                return;
            }
        }
        throw cRuntimeError("Self message not found in endReceptionTimers.");
    }
}

void NewRadio::handleUpperCommand(cMessage *message)
{
    // TODO: revise interface
    if (message->getKind() == PHY_C_CONFIGURERADIO)
    {
        PhyControlInfo *phyControlInfo = check_and_cast<PhyControlInfo *>(message->getControlInfo());
        int newChannelNumber = phyControlInfo->getChannelNumber();
        double newBitrate = phyControlInfo->getBitrate();
        delete phyControlInfo;

        // KLUDGE: scalar
        ScalarRadioSignalModulator *scalarModulator = const_cast<ScalarRadioSignalModulator *>(check_and_cast<const ScalarRadioSignalModulator *>(modulator));
        if (newChannelNumber != -1)
        {
            scalarModulator->setCarrierFrequency(CENTER_FREQUENCIES[newChannelNumber]);
            // KLUDGE: channel
            setRadioChannel(newChannelNumber);
        }
        else if (newBitrate != -1)
        {
            scalarModulator->setBitrate(newBitrate);
        }
    }
    else
        throw cRuntimeError("Unsupported command");
}

void NewRadio::handleLowerCommand(cMessage *message)
{
    throw cRuntimeError("Unsupported command");
}

void NewRadio::handleUpperFrame(cPacket *packet)
{
    if (endTransmissionTimer->isScheduled())
        throw cRuntimeError("Received frame from upper layer while already transmitting.");
    const RadioFrame *radioFrame = check_and_cast<const RadioFrame *>(transmitPacket(packet, simTime()));
    channel->sendToChannel(this, radioFrame);
    EV << "Transmission of " << packet << " started\n";
    ASSERT(radioFrame->getDuration() != 0);
    scheduleAt(simTime() + radioFrame->getDuration(), endTransmissionTimer);
    updateTransceiverState();
    delete radioFrame;
}

void NewRadio::handleLowerFrame(RadioFrame *radioFrame)
{
    EV << "Reception of " << radioFrame << " started.\n";
    cMessage *endReceptionTimer = new cMessage("endReception");
    endReceptionTimer->setControlInfo(radioFrame);
    const IRadioSignalTransmission *transmission = radioFrame->getTransmission();
    const IRadioSignalListening *listening = modulator->createListening(this, transmission->getStartTime(), transmission->getEndTime(), transmission->getStartPosition(), transmission->getEndPosition());
    const IRadioSignalReceptionDecision *receptionDecision = channel->receiveFromChannel(this, listening, transmission);
    endReceptionTimer->setKind(receptionDecision->isReceptionPossible());
    endReceptionTimers.push_back(endReceptionTimer);
// TODO:   scheduleAt(receptionDecision->getReception()->getEndTime(), endReceptionTimer);
    scheduleAt(simTime() + radioFrame->getDuration(), endReceptionTimer);
    updateTransceiverState();
}

bool NewRadio::handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback)
{
    Enter_Method_Silent();
    if (dynamic_cast<NodeStartOperation *>(operation)) {
        if (stage == NodeStartOperation::STAGE_PHYSICAL_LAYER)
            setRadioMode(RADIO_MODE_OFF);
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation)) {
        if (stage == NodeStartOperation::STAGE_PHYSICAL_LAYER)
            setRadioMode(RADIO_MODE_OFF);
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation)) {
        if (stage == NodeStartOperation::STAGE_LOCAL)
            setRadioMode(RADIO_MODE_OFF);
    }
    return true;
}

void NewRadio::cancelAndDeleteEndReceptionTimers()
{
    for (EndReceptionTimers::iterator it = endReceptionTimers.begin(); it != endReceptionTimers.end(); it++)
        cancelAndDelete(*it);
    endReceptionTimers.clear();
}

void NewRadio::updateTransceiverState()
{
    // reception state
    ReceptionState newRadioReceptionState;
    simtime_t now = simTime();
    Coord position = antenna->getMobility()->getCurrentPosition();
    bool isReceiving = false;
    for (EndReceptionTimers::iterator it = endReceptionTimers.begin(); it != endReceptionTimers.end(); it++)
        isReceiving |= (*it)->getKind();
    // TODO: use the demodulator to create a listening? use 2 * minimumOverlappingTime for lookahead?
    const IRadioSignalListeningDecision *listeningDecision = channel->listenOnChannel(this, modulator->createListening(this, now, now + 1E-9, position, position));
    if (radioMode == RADIO_MODE_OFF || radioMode == RADIO_MODE_SLEEP || radioMode == RADIO_MODE_TRANSMITTER)
        newRadioReceptionState = RECEPTION_STATE_UNDEFINED;
    else if (isReceiving)
        newRadioReceptionState = RECEPTION_STATE_RECEIVING;
    else if (false) // NOTE: synchronization is not modeled in New radio
        newRadioReceptionState = RECEPTION_STATE_SYNCHRONIZING;
    else if (listeningDecision->isListeningPossible())
        newRadioReceptionState = RECEPTION_STATE_BUSY;
    else
        newRadioReceptionState = RECEPTION_STATE_IDLE;
    if (receptionState != newRadioReceptionState)
    {
        EV << "Changing radio reception state from " << getRadioReceptionStateName(receptionState) << " to " << getRadioReceptionStateName(newRadioReceptionState) << ".\n";
        receptionState = newRadioReceptionState;
        emit(receptionStateChangedSignal, newRadioReceptionState);
    }
    // transmission state
    TransmissionState newRadioTransmissionState;
    if (radioMode == RADIO_MODE_OFF || radioMode == RADIO_MODE_SLEEP || radioMode == RADIO_MODE_RECEIVER)
        newRadioTransmissionState = TRANSMISSION_STATE_UNDEFINED;
    else if (endTransmissionTimer->isScheduled())
        newRadioTransmissionState = TRANSMISSION_STATE_TRANSMITTING;
    else
        newRadioTransmissionState = TRANSMISSION_STATE_IDLE;
    if (transmissionState != newRadioTransmissionState)
    {
        EV << "Changing radio transmission state from " << getRadioTransmissionStateName(transmissionState) << " to " << getRadioTransmissionStateName(newRadioTransmissionState) << ".\n";
        transmissionState = newRadioTransmissionState;
        emit(transmissionStateChangedSignal, newRadioTransmissionState);
    }
}
