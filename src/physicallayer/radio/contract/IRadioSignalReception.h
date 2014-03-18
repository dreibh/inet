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

#ifndef __INET_IRADIOSIGNALRECEPTION_H_
#define __INET_IRADIOSIGNALRECEPTION_H_

#include "IPrintableObject.h"
#include "IRadioSignalTransmission.h"

class INET_API IRadioSignalReception : public IPrintableObject
{
    public:
        virtual ~IRadioSignalReception() {}

        virtual simtime_t getStartTime() const = 0;
        virtual simtime_t getEndTime() const = 0;
        virtual simtime_t getDuration() const = 0;

        virtual Coord getStartPosition() const = 0;
        virtual Coord getEndPosition() const = 0;

        // TODO: should not be needed
        virtual const IRadio *getRadio() const = 0;
        virtual const IRadioSignalTransmission *getTransmission() const = 0;
};

#endif
