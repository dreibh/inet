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

#ifndef __INET_IRADIOSIGNALBITMODEL_H_
#define __INET_IRADIOSIGNALBITMODEL_H_

#include "INETDefs.h"

/**
 * This purely virtual interface provides an abstraction for different radio
 * signal models in the bit domain.
 */
class INET_API IRadioSignalBitModel
{
    public:
        virtual ~IRadioSignalBitModel() {}

        // TODO: return type
        virtual void getCRC() const = 0;

        // TODO: return type
        virtual void getFEC() const = 0;

        virtual const std::vector<bool> *getBits() const = 0;
};

class INET_API SimpleRadioSignalBitModel : public IRadioSignalBitModel
{
    public:
        SimpleRadioSignalBitModel()
        {}

        // TODO: return type
        virtual void getCRC() const { return; }

        // TODO: return type
        virtual void getFEC() const { return; }

        virtual const std::vector<bool> *getBits() const
        { throw cRuntimeError("This radio signal bit model doesn't provide the actual bits"); }
};

#endif
