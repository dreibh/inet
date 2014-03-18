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

#ifndef __INET_IEEE80211RADIODECIDER_H_
#define __INET_IEEE80211RADIODECIDER_H_

#include "ScalarImplementation.h"
#include "WifiPreambleType.h"
#include "IErrorModel.h"
#include "BerParseFile.h"

class INET_API Ieee80211RadioDecider : public ScalarSNRRadioDecider
{
    protected:
        char opMode;
        IErrorModel *errorModel;
        WifiPreamble wifiPreamble;
        bool autoHeaderSize;
        BerParseFile *parseTable;

    protected:
        virtual void initialize(int stage);

    public:
        Ieee80211RadioDecider() :
            ScalarSNRRadioDecider()
        {}

        Ieee80211RadioDecider(double sensitivity, double snrThreshold) :
            ScalarSNRRadioDecider(sensitivity, snrThreshold)
        {}

        virtual bool isPacketOK(double snirMin, int lengthMPDU, double bitrate) const;
};

#endif
