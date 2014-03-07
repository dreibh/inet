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

package inet.physicallayer.radio.new;

simple Ieee80211Radio extends ScalarRadio
{
    parameters:
        modulatorType = default("Ieee80211ScalarRadioSignalModulator");
        modulator.bitrate = default(2Mbps);
        // TODO: meaningless, factor and delete
        modulator.headerBitLength = default(192b);
        modulator.carrierFrequency = default(2.4GHz);
        modulator.bandwidth = default(2MHz);
        modulator.preambleMode = default("long");
        decider.sensitivity = default(1E-11W);
        decider.snrThreshold = default(10);
        modulator.power = default(100mW);
}
