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

package inet.physicallayer.radio.generic;

import inet.physicallayer.radio.common.RadioBase;
import inet.physicallayer.radio.contract.IRadioAntenna;
import inet.physicallayer.radio.contract.IRadioDecider;
import inet.physicallayer.radio.contract.IRadioSignalModulator;

simple NewRadio extends RadioBase
{
    parameters:
        string modulatorType;
        string antennaType;
        string deciderType;
        @class(NewRadio);

    submodules:
        modulator: <modulatorType> like IRadioSignalModulator;
        antenna: <antennaType> like IRadioAntenna;
        decider: <deciderType> like IRadioDecider;
        
        // TODO:
        // codec or coder
        // modem or modulator
        // shaper/filter
        // preamble/synchronizer
        // decider -> snir
}
