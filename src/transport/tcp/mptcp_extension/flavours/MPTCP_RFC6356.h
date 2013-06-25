//
// Copyright (C) 2013 Martin Becke
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

#ifndef __INET_MPTCP_RFC6356
#define __INET_MPTCP_RFC6356

#include "INETDefs.h"
#include "TCPNewReno.h"


/**
 * State variables for MPTCP_RFC6356.
 */
//typedef TCPTahoeRenoFamilyStateVariables MPTCP_RFC6356StateVariables;


/**
 * Implements TCP MPTCP_RFC6356.
 */
class INET_API MPTCP_RFC6356 : public TCPNewReno
{
  private:
    bool isCA;

    virtual void increaseCWND(uint32 increase);
    /** Utility function to recalculate path variables */
    virtual void recalculateMPTCPCCBasis();

  public:
//    /** Ctor */
    MPTCP_RFC6356();
};

#endif
