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

#ifndef __INET_IRADIODECIDER_H_
#define __INET_IRADIODECIDER_H_

#include "IRadioSignalReception.h"
#include "IRadioSignalListening.h"
#include "IRadioSignalNoise.h"
#include "IRadioSignalReceptionDecision.h"
#include "IRadioSignalListeningDecision.h"

// TODO: add support for synchronization
// TODO: add support for reception state
class INET_API IRadioDecider
{
    public:
        virtual ~IRadioDecider() {}

        // TODO: extract reception, totalNoise interface
        // TODO: virtual const IRadioDecision *computeDecision(const IRadioSignalReception *reception, const IRadioSignalNoise *noise) const = 0;
        virtual const IRadioSignalReceptionDecision *computeReceptionDecision(const IRadioSignalReception *reception, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const = 0;
        virtual const IRadioSignalListeningDecision *computeListeningDecision(const IRadioSignalListening *listening, const std::vector<const IRadioSignalReception *> *overlappingReceptions, const IRadioSignalNoise *backgroundNoise) const = 0;
};

#endif
