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

#include "Ieee80211Implementation.h"
#include "WifiMode.h"
#include "ModulationType.h"
#include "PhyControlInfo_m.h"

Define_Module(Ieee80211ScalarRadioSignalModulator);

void Ieee80211ScalarRadioSignalModulator::initialize(int stage)
{
    ScalarRadioSignalModulator::initialize(stage);
    if (stage == INITSTAGE_LOCAL)
    {
        const char *preambleModeString = par("preambleMode");
        if (!strcmp("short", preambleModeString))
            preambleMode = WIFI_PREAMBLE_SHORT;
        else if (!strcmp("long", preambleModeString))
            preambleMode = WIFI_PREAMBLE_LONG;
        else
            throw cRuntimeError("Unknown preamble mode");
    }
}

simtime_t Ieee80211ScalarRadioSignalModulator::computeDuration(const cPacket *packet) const
{
    PhyControlInfo *controlInfo = dynamic_cast<PhyControlInfo *>(packet->getControlInfo());
    // TODO: operation mode
    ModulationType modulationType = WifiModulationType::getModulationType('g', controlInfo ? controlInfo->getBitrate() : bitrate);
    return SIMTIME_DBL(WifiModulationType::calculateTxDuration(packet->getBitLength(), modulationType, preambleMode));
}
