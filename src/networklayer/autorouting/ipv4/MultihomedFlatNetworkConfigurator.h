// * --------------------------------------------------------------------------
// *
// *     //====//  //===== <===//===>  //====//
// *    //        //          //      //    //    SCTP Optimization Project
// *   //=====   //          //      //====//   ==============================
// *        //  //          //      //           University of Duisburg-Essen
// *  =====//  //=====     //      //
// *
// * --------------------------------------------------------------------------
// *
// *   Copyright (C) 2009-2012 by Thomas Dreibholz
// *
// *   This program is free software: you can redistribute it and/or modify
// *   it under the terms of the GNU General Public License as published by
// *   the Free Software Foundation, either version 3 of the License, or
// *   (at your option) any later version.
// *
// *   This program is distributed in the hope that it will be useful,
// *   but WITHOUT ANY WARRANTY; without even the implied warranty of
// *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// *   GNU General Public License for more details.
// *
// *   You should have received a copy of the GNU General Public License
// *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
// *
// *   Contact: dreibh@iem.uni-due.de

#ifndef __INET_MULTIHOMEDFLATNETWORKCONFIGURATOR_H
#define __INET_MULTIHOMEDFLATNETWORKCONFIGURATOR_H

#include <omnetpp.h>
#include <set>
#include "FlatNetworkConfigurator.h"


class INET_API MultihomedFlatNetworkConfigurator : public cSimpleModule
{
   protected:
   struct NodeInfo {
      NodeInfo() {
         isIPNode         = false;
         interfaceTable   = NULL;
         routingTable     = NULL;
         usesDefaultRoute = false; }
      bool             isIPNode;
      IInterfaceTable* interfaceTable;
      IRoutingTable*   routingTable;
      bool             usesDefaultRoute;
   };
   typedef std::vector<NodeInfo> NodeInfoVector;


   protected:
   virtual int numInitStages() const { return(3); }
   virtual void initialize(int stage);
   virtual void extractTopology(cTopology&         topology,
                                NodeInfoVector&    nodeInfo,
                                const bool         fullTopology,
                                const bool         allNetworks,
                                const unsigned int networkID);
   virtual std::set<unsigned int> assignAddresses(cTopology&      topology,
                                                  NodeInfoVector& nodeInfo);
   virtual void computeRouting(cTopology&         topology,
                               NodeInfoVector&    nodeInfo,
                               const unsigned int networkID);
   virtual void setDisplayString(cTopology&      topology,
                                 NodeInfoVector& nodeInfo);


   private:
   typedef std::set<IPv4Address> HostSet;
   unsigned int                  TotalNumberOfInterfaces;

   void dumpConfiguration(cTopology&      topo,
                          NodeInfoVector& nodeInfo,
                          const bool      intermediateVersion = false);
};

#endif
