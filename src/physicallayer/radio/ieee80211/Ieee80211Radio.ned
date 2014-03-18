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

package inet.physicallayer.radio.ieee80211;

import inet.physicallayer.radio.scalar.ScalarRadio;

simple Ieee80211Radio extends ScalarRadio
{
    parameters:
//        string errorModel @enum("YansModel", "NistModel") = default("NistModel");
        int channelNumber = default(0);
        modulatorType = default("Ieee80211ScalarRadioSignalModulator");
        modulator.bitrate = default(11Mbps);
        modulator.headerBitLength = default(192b);
        modulator.carrierFrequency = default(2.4GHz);
        modulator.bandwidth = default(2MHz);
        modulator.preambleMode = default("long");
        deciderType = default("Ieee80211RadioDecider");
        decider.sensitivity = default(3.1622776602e-12W); // TODO: -85dBm
        decider.snrThreshold = default(2.51188643151); // TODO: 4dB
        modulator.power = default(20mW);
        **.channelNumber = channelNumber;
}
