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

#ifdef PRIVATE

#ifndef TCPMULTIPATHQUEUEMNGMT_H_
#define TCPMULTIPATHQUEUEMNGMT_H_

#include <omnetpp.h>
#include "INETDefs.h"

class INET_API  TCPMultipathQueueMngmt : public cPolymorphic {
public:
	TCPMultipathQueueMngmt();
	virtual ~TCPMultipathQueueMngmt();
};

#endif /* TCPMULTIPATHQUEUEMNGMT_H_ */

#endif
