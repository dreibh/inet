//
// Copyright (C) 2011 Martin Becke
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

// Include the MPTCP FLOW
// Include the MPTCP PCB
#ifdef PRIVATE

#ifndef TCPCCFUNKTIONS_H_
#define TCPCCFUNKTIONS_H_

#include <omnetpp.h>
#include "INETDefs.h"

class INET_API TCPCCFunktions : public cPolymorphic
{
public:
	TCPCCFunktions();
	virtual ~TCPCCFunktions();
};

#endif /* TCPCCFUNKTIONS_H_ */

#endif
