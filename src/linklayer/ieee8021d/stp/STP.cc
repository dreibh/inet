// Copyright (C) 2013 OpenSim Ltd.
// Copyright (C) ANSA Team
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//
// Authors: ANSA Team, Benjamin Martin Seregi

#include "EtherFrame.h"
#include "STP.h"
#include "STPMACCompare.h"
#include "InterfaceTableAccess.h"
#include "InterfaceEntry.h"
#include "STPTester.h"

Define_Module(SpanningTree);

void SpanningTree::initialize(int stage)
{
    if (stage == 0)
    {
        portCount = this->getParentModule()->gate("ethg$o", 0)->getVectorSize();
        tick = new cMessage("STP_TICK", 0);

        // Connection to MACAddressTable for faster aging
        cModule * tmpMacTable = getParentModule()->getSubmodule("macTable");
        macTable = check_and_cast<MACAddressTable *>(tmpMacTable);
        WATCH(bridgeAddress);
    }
    else if (stage == 1)
    {
        NodeStatus * nodeStatus = dynamic_cast<NodeStatus *>(findContainingNode(this)->getSubmodule("status"));
        isOperational = (!nodeStatus) || nodeStatus->getState() == NodeStatus::UP;

        // Obtain a bridge address from InterfaceTable
        ifTable = InterfaceTableAccess().get();
        InterfaceEntry * ifEntry = ifTable->getInterface(0);

        if (ifEntry != NULL)
            bridgeAddress = ifEntry->getMacAddress();

        initPortTable();
        helloTime = 2;
        maxAge = 20;
        fwdDelay = 15;
        bridgePriority = 32768;
        ubridgePriority = bridgePriority;

        isRoot = true;
        topologyChange = 0;
        topologyChangeNotification = false;
        topologyChangeRecvd = false;

        rootPriority = bridgePriority;
        rootAddress = bridgeAddress;
        rootPathCost = 0;
        rootPort = 0;
        cHelloTime = helloTime;
        cMaxAge = maxAge;
        cFwdDelay = fwdDelay;

        helloTimer = 0;
        allDesignated();
        scheduleAt(simTime() + 1, tick);
    }
}

SpanningTree::~SpanningTree()
{
    cancelAndDelete(tick);
}

// Default port information for the InterfaceTable
void SpanningTree::initPortTable()
{
    for (unsigned int i = 0; i < portCount; i++)
    {
        IEEE8021DInterfaceData * port = getPortInterfaceData(i);
        port->setDefaultStpPortInfoData();
    }
}

void SpanningTree::handleMessage(cMessage * msg)
{
    if (!isOperational)
    {
        EV<< "Message '" << msg << "' arrived when module status is down, dropped it\n";
        delete msg;
        return;
    }

    cMessage * tmp = msg;

    if (!msg->isSelfMessage())
    {
        if (dynamic_cast<BPDU *>(tmp))
        {
            BPDU * bpdu = (BPDU *) tmp;

            if(bpdu->getBpduType() == 0) // Configuration BPDU
                handleBPDU(bpdu);
            else if(bpdu->getBpduType() == 1) // TCN BPDU
                handleTCN(bpdu);
        }
        else
            delete msg;
    }
    else
    {
        if(msg == tick)
        {
            handleTick();
            colorTree();
            scheduleAt(simTime() + 1, tick);
        }
        else
            delete msg;
    }
}

void SpanningTree::colorTree()
{
    IEEE8021DInterfaceData * port;
    for (unsigned int i = 0; i < portCount; i++)
    {
        port = getPortInterfaceData(i);
        cGate * outGate = getParentModule()->gate("ethg$o", i);
        cGate * inputGate = getParentModule()->gate("ethg$i", i);
        cGate * outGateNext = outGate->getNextGate();
        cGate * inputGatePrev = inputGate->getPreviousGate();

        if(outGate && inputGate && inputGatePrev && outGateNext)
        {
            if (port->isForwarding())
            {
                outGate->getDisplayString().setTagArg("ls", 0, "#458B00");
                outGate->getDisplayString().setTagArg("ls", 1, 3);

                inputGate->getDisplayString().setTagArg("ls", 0, "#458B00");
                inputGate->getDisplayString().setTagArg("ls", 1, 3);

                outGateNext->getDisplayString().setTagArg("ls", 0, "#458B00");
                outGateNext->getDisplayString().setTagArg("ls", 1, 3);

                inputGatePrev->getDisplayString().setTagArg("ls", 0, "#458B00");
                inputGatePrev->getDisplayString().setTagArg("ls", 1, 3);
            }
            else
            {
                outGate->getDisplayString().setTagArg("ls", 0, "#000000");
                outGate->getDisplayString().setTagArg("ls", 1, 1);

                inputGate->getDisplayString().setTagArg("ls", 0, "#000000");
                inputGate->getDisplayString().setTagArg("ls", 1, 1);

                outGateNext->getDisplayString().setTagArg("ls", 0, "#000000");
                outGateNext->getDisplayString().setTagArg("ls", 1, 1);

                inputGatePrev->getDisplayString().setTagArg("ls", 0, "#000000");
                inputGatePrev->getDisplayString().setTagArg("ls", 1, 1);
            }
        }
    }
}

void SpanningTree::handleBPDU(BPDU * bpdu)
{
    Ieee802Ctrl * controlInfo = check_and_cast<Ieee802Ctrl *>(bpdu->getControlInfo());
    int arrivalGate = controlInfo->getInterfaceId();
    IEEE8021DInterfaceData * port = getPortInterfaceData(arrivalGate);

    // Get inferior BPDU, reply with superior
    if (!superiorBPDU(arrivalGate, bpdu))
    {
        if (port->getRole() == IEEE8021DInterfaceData::DESIGNATED)
            generateBPDU(arrivalGate);
    }

    // BPDU from root
    else if (port->getRole() == IEEE8021DInterfaceData::ROOT)
    {

        if (bpdu->getTcaFlag())
            topologyChangeNotification = false;

        // If the topology changes you may need faster aging
        if (bpdu->getTcFlag())
        {
            topologyChange++;
            macTable->setAgingTime(5);
        }
        else
            macTable->resetDefaultAging();

        // BPDUs are sent on all designated ports
        for (unsigned int i = 0; i < desPorts.size(); i++)
            generateBPDU(desPorts.at(i));

        // BPDU with TCA
        if (topologyChangeRecvd)
            topologyChangeRecvd = false;

        if (topologyChange > 0)
            topologyChange--; // TODO:
    }

    tryRoot();
    delete bpdu;
}

void SpanningTree::handleTCN(BPDU * tcn)
{
    topologyChangeNotification = true;
    topologyChangeRecvd = true;

    Ieee802Ctrl * controlInfo = check_and_cast<Ieee802Ctrl *>(tcn->getControlInfo());
    int arrivalGate = controlInfo->getInterfaceId();
    MACAddress address = controlInfo->getSrc();

    // Send ACK to the sender
    generateBPDU(arrivalGate,address);

    controlInfo->setInterfaceId(rootPort); // Send TCN to the Root Switch

    if (!isRoot)
        send(tcn, "STPGate$o");
    else
        delete tcn;

}

void SpanningTree::generateBPDU(int port, const MACAddress& address)
{
    BPDU * bpdu = new BPDU();
    Ieee802Ctrl * controlInfo = new Ieee802Ctrl();
    controlInfo->setDest(address);
    controlInfo->setInterfaceId(port);

    bpdu->setProtocolIdentifier(0);
    bpdu->setProtocolVersionIdentifier(0);
    bpdu->setBpduType(0); // 0 if configuration BPDU

    bpdu->setBridgeAddress(bridgeAddress);
    bpdu->setBridgePriority(bridgePriority);
    bpdu->setRootPathCost(rootPathCost);
    bpdu->setRootAddress(rootAddress);
    bpdu->setRootPriority(rootPriority);
    bpdu->setPortNum(port);
    bpdu->setPortPriority(getPortInterfaceData(port)->getPriority());
    bpdu->setMessageAge(0);
    bpdu->setMaxAge(cMaxAge);
    bpdu->setHelloTime(cHelloTime);
    bpdu->setForwardDelay(cFwdDelay);

    if (topologyChangeRecvd)
        bpdu->setTcaFlag(true);
    else
        bpdu->setTcaFlag(false);

    if (isRoot)
    {
        if (topologyChange > 0)
            bpdu->setTcFlag(true);
        else
            bpdu->setTcFlag(false);
    }


    bpdu->setControlInfo(controlInfo);

    send(bpdu, "STPGate$o");
}

void SpanningTree::generateTCN()
{
    // There is something to notify
    if (topologyChangeNotification)
    {
        if (getPortInterfaceData(rootPort)->getRole() == IEEE8021DInterfaceData::ROOT)
        {
            // Exist root port to notifying

            BPDU * tcn = new BPDU();
            tcn->setProtocolIdentifier(0);
            tcn->setProtocolVersionIdentifier(0);

            // 1 if Topology Change Notification BPDU
            tcn->setBpduType(1);

            Ieee802Ctrl * controlInfo = new Ieee802Ctrl();
            controlInfo->setDest(MACAddress::STP_MULTICAST_ADDRESS);
            controlInfo->setInterfaceId(rootPort);
            tcn->setControlInfo(controlInfo);

            send(tcn, "STPGate$o");
        }
    }
}

// Check of the received BPDU is superior to port information from InterfaceTable
bool SpanningTree::superiorBPDU(int portNum, BPDU * bpdu)
{
    IEEE8021DInterfaceData * port = getPortInterfaceData(portNum);
    IEEE8021DInterfaceData * xBpdu = new IEEE8021DInterfaceData();

    int result;

    xBpdu->setRootPriority(bpdu->getRootPriority());
    xBpdu->setRootAddress(bpdu->getRootAddress());
    xBpdu->setRootPathCost(bpdu->getRootPathCost() + port->getLinkCost());
    xBpdu->setBridgePriority(bpdu->getBridgePriority());
    xBpdu->setBridgeAddress(bpdu->getBridgeAddress());
    xBpdu->setPortPriority(bpdu->getPortPriority());
    xBpdu->setPortNum(bpdu->getPortNum());

    result = superiorTPort(port, xBpdu);

    // Port is superior
    if (result > 0)
        return false;

    if (result < 0)
    {
        // BPDU is superior
        port->setFdWhile(0); // renew info
        port->setState(IEEE8021DInterfaceData::DISCARDING);
        setSuperiorBPDU(portNum, bpdu); // renew information
        return true;
    }

    setSuperiorBPDU(portNum, bpdu); // renew information
    delete xBpdu;
    return true;
}

void SpanningTree::setSuperiorBPDU(int portNum, BPDU * bpdu)
{
    // BDPU is out-of-date
    if (bpdu->getMessageAge() >= bpdu->getMaxAge())
        return;

    IEEE8021DInterfaceData * portData = getPortInterfaceData(portNum);

    portData->setRootPriority(bpdu->getRootPriority());
    portData->setRootAddress(bpdu->getRootAddress());
    portData->setRootPathCost(bpdu->getRootPathCost() + portData->getLinkCost());
    portData->setBridgePriority(bpdu->getBridgePriority());
    portData->setBridgeAddress(bpdu->getBridgeAddress());
    portData->setPortPriority(bpdu->getPortPriority());
    portData->setPortNum(bpdu->getPortNum());
    portData->setMaxAge(bpdu->getMaxAge());
    portData->setFwdDelay(bpdu->getForwardDelay());
    portData->setHelloTime(bpdu->getHelloTime());

    // We just set new port info so reset the age timer
    portData->setAge(0);

}

void SpanningTree::generator()
{
    // Only the root switch can generate Hello BPDUs
    if (!isRoot)
        return;

    // Send BDPUs on all ports
    for (unsigned int i = 0; i < portCount; i++)
        generateBPDU(i);

    if (topologyChangeRecvd)
        topologyChangeRecvd = false;

    // If the topology changed, then we turn faster aging on
    if (topologyChange > 0)
    {
        macTable->setAgingTime(5);
        topologyChange--;
    }
    else
        macTable->resetDefaultAging();
}

void SpanningTree::handleTick()
{
    // Bridge timers
    convergenceTime++;

    // Hello BDPU timer
    if (isRoot)
        helloTimer = helloTimer + 1;
    else
        helloTimer = 0;

    for (unsigned int i = 0; i < portCount; i++)
    {
        IEEE8021DInterfaceData * port = getPortInterfaceData(i);

        // Disabled ports don't count
        if (port->getRole() == IEEE8021DInterfaceData::DISABLED)
            continue;

        // Increment the MessageAge and FdWhile timers
        if (port->getRole() != IEEE8021DInterfaceData::DESIGNATED)
            port->setAge(port->getAge() + 1);

        if (port->getRole() == IEEE8021DInterfaceData::ROOT || port->getRole() == IEEE8021DInterfaceData::DESIGNATED)
            port->setFdWhile(port->getFdWhile() + 1);

    }
    checkTimers();
    checkParametersChange();
    generateTCN();
}

void SpanningTree::checkTimers()
{
    IEEE8021DInterfaceData * port;

    // Hello timer check
    if (helloTimer >= cHelloTime)
    {
        generator();
        helloTimer = 0;
    }

    // Information age check
    for (unsigned int i = 0; i < portCount; i++)
    {
        port = getPortInterfaceData(i);

        if (port->getAge() >= cMaxAge)
        {
            if (port->getRole() == IEEE8021DInterfaceData::ROOT)
            {
                port->setDefaultStpPortInfoData();
                lostRoot();
            }
            else
            {
                port->setDefaultStpPortInfoData();
                lostAlternate(i);
            }
        }
    }

    // fdWhile timer
    for (unsigned int i = 0; i < portCount; i++)
    {
        port = getPortInterfaceData(i);

        // ROOT / DESIGNATED, can transition
        if (port->getRole() == IEEE8021DInterfaceData::ROOT || port->getRole() == IEEE8021DInterfaceData::DESIGNATED)
        {
            if (port->getFdWhile() >= cFwdDelay)
            {
                switch (port->getState())
                {
                    case IEEE8021DInterfaceData::DISCARDING:
                        port->setState(IEEE8021DInterfaceData::LEARNING);
                        port->setFdWhile(0);
                        break;
                    case IEEE8021DInterfaceData::LEARNING:
                        port->setState(IEEE8021DInterfaceData::FORWARDING);
                        port->setFdWhile(0);
                        break;
                    default:
                        port->setFdWhile(0);
                        break;
                }

            }
        }
        else
        {
            port->setFdWhile(0);
            port->setState(IEEE8021DInterfaceData::DISCARDING);
        }
    }

    // Topology change handling
    if (topologyChangeNotification)
    {
        if (isRoot)
        {
            topologyChange = 5; // todo: what's this??
            topologyChangeNotification = false;
        }
    }

}

void SpanningTree::checkParametersChange()
{
    if (isRoot)
    {
        cHelloTime = helloTime;
        cMaxAge = maxAge;
        cFwdDelay = fwdDelay;
    }
    if (ubridgePriority != bridgePriority)
    {
        ubridgePriority = bridgePriority;
        reset();
    }
}

IEEE8021DInterfaceData * SpanningTree::getPortInterfaceData(unsigned int portNum)
{
    cGate * gate = this->getParentModule()->gate("ethg$o", portNum);
    InterfaceEntry * gateIfEntry = ifTable->getInterfaceByNodeOutputGateId(gate->getId());
    IEEE8021DInterfaceData * portData = gateIfEntry->ieee8021DData();

    if (!portData)
        error("IEEE8021DInterfaceData not found!");

    return portData;
}

bool SpanningTree::checkRootEligibility()
{
    IEEE8021DInterfaceData * port;

    for (unsigned int i = 0; i < portCount; i++)
    {
        port = getPortInterfaceData(i);

        if (superiorID(port->getRootPriority(), port->getRootAddress(), bridgePriority, bridgeAddress) > 0)
            return false;
    }

    return true;
}

void SpanningTree::tryRoot()
{
    if (checkRootEligibility())
    {
        isRoot = true;
        allDesignated();
        rootPriority = bridgePriority;
        rootAddress = bridgeAddress;
        rootPathCost = 0;
        cHelloTime = helloTime;
        cMaxAge = maxAge;
        cFwdDelay = fwdDelay;
    }
    else
    {
        isRoot = false;
        selectRootPort();
        selectDesignatedPorts();
    }

}

int SpanningTree::superiorID(unsigned int aPriority, MACAddress aAddress, unsigned int bPriority, MACAddress bAddress) // todo paraméter nevek
{
    if (aPriority < bPriority)
        return 1; // A is superior
    else if (aPriority > bPriority)
        return -1;

    // APR == BPR
    if (aAddress < bAddress)
        return 1; // A is superior
    else if (aAddress > bAddress)
        return -1;

    // A==B
    // (can happen if bridge have two port connected to one not bridged lan,
    // "cable loopback"
    return 0;
}

int SpanningTree::superiorPort(unsigned int aPriority, unsigned int aNum, unsigned int bPriority, unsigned int bNum)
{
    if (aPriority < bPriority)
        return 1; // A is superior

    else if (aPriority > bPriority)
        return -1;

    // APR == BPR
    if (aNum < bNum)
        return 1; // A is superior

    else if (aNum > bNum)
        return -1;

    // A==B
    return 0;
}

int SpanningTree::superiorTPort(IEEE8021DInterfaceData * portA, IEEE8021DInterfaceData * portB)
{
    int result;

    result = superiorID(portA->getRootPriority(), portA->getRootAddress(), portB->getRootPriority(),
            portB->getRootAddress());

    // not same, so pass result
    if (result != 0)
        return result;

    if (portA->getRootPathCost() < portB->getRootPathCost())
        return 1;

    if (portA->getRootPathCost() > portB->getRootPathCost())
        return -1;

    // Designated bridge
    result = superiorID(portA->getBridgePriority(), portA->getBridgeAddress(), portB->getBridgePriority(),
            portB->getBridgeAddress());

    // not same, so pass result
    if (result != 0)
        return result;

    // Designated port of Designated Bridge
    result = superiorPort(portA->getPortPriority(), portA->getPortNum(), portB->getPortPriority(), portB->getPortNum());

    // not same, so pass result
    if (result != 0)
        return result;

    return 0; // same
}

void SpanningTree::selectRootPort()
{
    unsigned int xRootPort = 0;
    int result;
    IEEE8021DInterfaceData * best = getPortInterfaceData(0);
    IEEE8021DInterfaceData * currentPort;

    for (unsigned int i = 0; i < portCount; i++)
    {
        currentPort = getPortInterfaceData(i);
        currentPort->setRole(IEEE8021DInterfaceData::NOTASSIGNED);
        result = superiorTPort(currentPort, best);
        if (result > 0)
        {
            xRootPort = i;
            best = currentPort;
            continue;
        }
        if (result < 0)
        {
            continue;
        }
        if (currentPort->getPriority() < best->getPriority())
        {
            xRootPort = i;
            best = currentPort;
            continue;
        }
        if (currentPort->getPriority() > best->getPriority())
            continue;
    }

    if (rootPort != xRootPort)
        topologyChangeNotification = true;

    rootPort = xRootPort;
    getPortInterfaceData(rootPort)->setRole(IEEE8021DInterfaceData::ROOT);
    rootPathCost = best->getRootPathCost();
    rootAddress = best->getRootAddress();
    rootPriority = best->getRootPriority();

    cMaxAge = best->getMaxAge();
    cFwdDelay = best->getFwdDelay();
    cHelloTime = best->getHelloTime();

}

void SpanningTree::selectDesignatedPorts()
{
    // Select designated ports
    desPorts.clear();
    IEEE8021DInterfaceData * port;
    IEEE8021DInterfaceData * bridgeGlobal = new IEEE8021DInterfaceData();
    int result;

    bridgeGlobal->setBridgePriority(bridgePriority);
    bridgeGlobal->setBridgeAddress(bridgeAddress);
    bridgeGlobal->setRootAddress(rootAddress);
    bridgeGlobal->setRootPriority(rootPriority);

    for (unsigned int i = 0; i < portCount; i++)
    {
        port = getPortInterfaceData(i);

        if (port->getRole() == IEEE8021DInterfaceData::ROOT || port->getRole() == IEEE8021DInterfaceData::DISABLED)
            continue;

        bridgeGlobal->setPortPriority(port->getPriority());
        bridgeGlobal->setPortNum(i);

        bridgeGlobal->setRootPathCost(rootPathCost + port->getLinkCost());

        result = superiorTPort(bridgeGlobal, port);

        if (result > 0)
        {
            desPorts.push_back(i);
            port->setRole(IEEE8021DInterfaceData::DESIGNATED);
            continue;
        }
        if (result < 0)
        {
            port->setRole(IEEE8021DInterfaceData::ALTERNATE);
            continue;
        }
    }
    delete bridgeGlobal;
}

void SpanningTree::allDesignated()
{
    // All ports of the root switch are designated ports

    IEEE8021DInterfaceData * port;
    desPorts.clear();
    for (unsigned int i = 0; i < portCount; i++)
    {
        port = getPortInterfaceData(i);
        if (port->getRole() == IEEE8021DInterfaceData::DISABLED)
            continue;

        port->setRole(IEEE8021DInterfaceData::DESIGNATED);
        desPorts.push_back(i);
    }
}

void SpanningTree::lostRoot()
{
    topologyChangeNotification = true;
    tryRoot();
}

void SpanningTree::lostAlternate(int port)
{
    selectDesignatedPorts();
    topologyChangeNotification = true;
}

void SpanningTree::reset()
{
    // Upon booting all switches believe themselves to be the root

    isRoot = true;
    rootPriority = bridgePriority;
    rootAddress = bridgeAddress;
    rootPathCost = 0;
    cHelloTime = helloTime;
    cMaxAge = maxAge;
    cFwdDelay = fwdDelay;
    allDesignated();

    for (unsigned int i = 0; i < portCount; i++)
    {
        IEEE8021DInterfaceData * port = getPortInterfaceData(i);
        port->setDefaultStpPortInfoData();
    }
}

void SpanningTree::start()
{
    // Obtain a bridge address from InterfaceTable
    ifTable = InterfaceTableAccess().get();
    InterfaceEntry * ifEntry = ifTable->getInterface(0);

    if (ifEntry != NULL)
        bridgeAddress = ifEntry->getMacAddress();

    this->getParentModule()->getDisplayString().removeTag("i2");
    isOperational = true;
    initPortTable();
    helloTime = 2;
    maxAge = 20;
    fwdDelay = 15;
    bridgePriority = 32768;
    ubridgePriority = bridgePriority;

    isRoot = true;
    topologyChange = 0;
    topologyChangeNotification = false;
    topologyChangeRecvd = false;

    rootPriority = bridgePriority;
    rootAddress = bridgeAddress;
    rootPathCost = 0;
    rootPort = 0;
    cHelloTime = helloTime;
    cMaxAge = maxAge;
    cFwdDelay = fwdDelay;
    helloTimer = 0;
    allDesignated();

    scheduleAt(simTime() + 1, tick);
}

void SpanningTree::stop()
{
    isOperational = false;

    for (unsigned int i = 0; i < portCount; i++)
    {
        cGate * outGate = getParentModule()->gate("ethg$o", i);
        cGate * inputGate = getParentModule()->gate("ethg$i", i);
        cGate * outGateNext = outGate->getNextGate();
        cGate * inputGatePrev = inputGate->getPreviousGate();

        if(outGate && inputGate && inputGatePrev && outGateNext)
        {
            outGate->getDisplayString().setTagArg("ls", 0, "#000000");
            outGate->getDisplayString().setTagArg("ls", 1, 1);

            inputGate->getDisplayString().setTagArg("ls", 0, "#000000");
            inputGate->getDisplayString().setTagArg("ls", 1, 1);

            outGateNext->getDisplayString().setTagArg("ls", 0, "#000000");
            outGateNext->getDisplayString().setTagArg("ls", 1, 1);

            inputGatePrev->getDisplayString().setTagArg("ls", 0, "#000000");
            inputGatePrev->getDisplayString().setTagArg("ls", 1, 1);
        }
    }

    this->getParentModule()->getDisplayString().setTagArg("i2", 0, "status/stop");
    cancelEvent(tick);
}

bool SpanningTree::handleOperationStage(LifecycleOperation * operation, int stage, IDoneCallback * doneCallback)
{
    Enter_Method_Silent();

    if (dynamic_cast<NodeStartOperation *>(operation))
    {
        if (stage == NodeStartOperation::STAGE_LINK_LAYER)
        {
            start();
        }
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation))
    {
        if (stage == NodeShutdownOperation::STAGE_LINK_LAYER)
        {
            stop();
        }
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation))
    {
        if (stage == NodeCrashOperation::STAGE_CRASH)
        {
            stop();
        }
    }
    else
    {
        throw cRuntimeError("Unsupported operation '%s'", operation->getClassName());
    }
    return true;
}
