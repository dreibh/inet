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

#include "Ieee80211RadioDecider.h"
#include "ModulationType.h"
#include "WifiMode.h"
#include "Ieee80211Consts.h"
#include "yans-error-rate-model.h"
#include "nist-error-rate-model.h"

Define_Module(Ieee80211RadioDecider);

void Ieee80211RadioDecider::initialize(int stage)
{
    ScalarSNRRadioDecider::initialize(stage);
    if (stage == INITSTAGE_LOCAL)
    {
        const char *opModeString = par("opMode");
        if (!strcmp("b", opModeString))
            opMode = 'b';
        else if (!strcmp("g", opModeString))
            opMode = 'g';
        else if (!strcmp("a", opModeString))
            opMode = 'a';
        else if (!strcmp("p", opModeString))
            opMode = 'p';
        else
            opMode = 'g';

        wifiPreamble = WIFI_PREAMBLE_LONG;

        const char *errorModelString = par("errorModel");
        if (!strcmp("yans", errorModelString))
            errorModel = new YansErrorRateModel();
        else if (!strcmp("nist", errorModelString))
            errorModel = new NistErrorRateModel();
        else
            opp_error("Error %s model is not valid",errorModelString);
        autoHeaderSize = par("autoHeaderSize");
        parseTable = NULL;
//        const char *fname = radioModule->par("berTableFile");
//        std::string name(fname);
//        if (!name.empty())
//        {
//            parseTable = new BerParseFile(opMode);
//            parseTable->parseFile(fname);
//        }
    }
}

bool Ieee80211RadioDecider::isPacketOK(double snirMin, int lengthMPDU, double bitrate) const
{
    ModulationType modeBody;
    ModulationType modeHeader;

    WifiPreamble preambleUsed = wifiPreamble;
    double headerNoError;
    uint32_t headerSize;
    if (opMode=='b')
        headerSize = HEADER_WITHOUT_PREAMBLE;
    else
        headerSize = 24;

    modeBody = WifiModulationType::getModulationType(opMode, bitrate);
    modeHeader = WifiModulationType::getPlcpHeaderMode(modeBody, preambleUsed);
    if (opMode=='g')
    {
        if (autoHeaderSize)
        {
           ModulationType modeBodyA = WifiModulationType::getModulationType('a', bitrate);
           headerSize = ceil(SIMTIME_DBL(WifiModulationType::getPlcpHeaderDuration(modeBodyA, preambleUsed))*modeHeader.getDataRate());
        }
    }
    else if (opMode=='b' || opMode=='a' || opMode=='p')
    {
        if (autoHeaderSize)
             headerSize = ceil(SIMTIME_DBL(WifiModulationType::getPlcpHeaderDuration(modeBody, preambleUsed))*modeHeader.getDataRate());
    }
    else
    {
        opp_error("Radio model not supported yet, must be a,b,g or p");
    }

    headerNoError = errorModel->GetChunkSuccessRate(modeHeader, snirMin, headerSize);
    // probability of no bit error in the MPDU
    double MpduNoError;
    if (parseTable)
        MpduNoError = 1 - parseTable->getPer(bitrate, snirMin, lengthMPDU / 8);
    else
        MpduNoError = errorModel->GetChunkSuccessRate(modeBody, snirMin, lengthMPDU);

    EV << "lengthMPDU: " << lengthMPDU << " PER: " << 1 - MpduNoError << " headerNoError: " << headerNoError << endl;
    if (MpduNoError >= 1 && headerNoError >= 1)
        return true;
    double rand = dblrand();

    if (rand > headerNoError)
        return false; // error in header
    else if (dblrand() > MpduNoError)
        return false;  // error in MPDU
    else
        return true; // no error
}
