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

#include <algorithm>
#include "IRoutingTable.h"
#include "IInterfaceTable.h"
#include "IPAddressResolver.h"
#include "MultihomedFlatNetworkConfigurator.h"
#include "InterfaceEntry.h"
#include "IPv4InterfaceData.h"


Define_Module(MultihomedFlatNetworkConfigurator);


// ###### Initialize: perform autorouting ###################################
void MultihomedFlatNetworkConfigurator::initialize(int stage)
{
   if(stage == 2) {
      cTopology      fullTopology;
      NodeInfoVector fullNodeInfoVector;
      extractTopology(fullTopology, fullNodeInfoVector, true, true, 0);

      // Assign addresses to all nodes
      std::set<unsigned int> networkSet = assignAddresses(fullTopology, fullNodeInfoVector);

      // Compute routing tables for each network ID
      for(std::set<unsigned int>::iterator iterator = networkSet.begin();
         iterator != networkSet.end(); iterator++) {
         const unsigned int networkID = *iterator;
         EV << "###### Computing routing table for network ID " << networkID << " ... ######" << endl;

         cTopology      fullTopologyForNetwork;
         NodeInfoVector fullNodeInfoVectorForNetwork;
         extractTopology(fullTopologyForNetwork, fullNodeInfoVectorForNetwork, true, false, networkID);

         computeRouting(fullTopologyForNetwork, fullNodeInfoVectorForNetwork, networkID);      
         // dumpConfiguration(fullTopologyForNetwork, fullNodeInfoVectorForNetwork, true);
      }
      
      dumpConfiguration(fullTopology, fullNodeInfoVector);
      setDisplayString(fullTopology, fullNodeInfoVector);
   }
}


// ###### Update route if new one has a better metric #######################
static void updateIfMetricIsBetter(IRoutingTable* routingTable,
                                   IPRoute*       newRoute)
{
   const IPRoute* oldRoute = routingTable->findRoute(newRoute->getHost(), newRoute->getNetmask(), IPAddress());
   if(oldRoute) {
      if(oldRoute->getMetric() <= newRoute->getMetric()) {
         // Old route is better or equal -> keep it and ignore new one.
         delete newRoute;
         return;
      }
      else {
         // New route is better -> get rid of the old one.
         routingTable->deleteRoute(oldRoute);
      }
   }
      
   std::vector<IPAddress> ownAddresses = routingTable->gatherAddresses();
   for(std::vector<IPAddress>::iterator iterator = ownAddresses.begin();
       iterator != ownAddresses.end(); iterator++) {
      if(newRoute->getHost() == *iterator) {
          // New route is a loop to myself -> ignore it.
         delete newRoute;
         return;
      }
   }
   
   routingTable->addRoute(newRoute);
}


// ###### Get Network ID from gate ##########################################
static unsigned int getNetworkID(cChannel* channel)
{
   unsigned int networkID = 0;
   if(channel) {
      if(channel->hasPar("netID")) {
         networkID = channel->par("netID");
      }
   }
   return(networkID);
}

// ###### Get Network ID from gate ##########################################
static unsigned int getNetworkID(cModule*        module,
                                 InterfaceEntry* interfaceEntry)
{
   int          outputGateID = interfaceEntry->getNodeOutputGateId();
   cGate*       outputGate   = module->gate(outputGateID);
   cChannel*    channel      = outputGate->getChannel();
   return(getNetworkID(channel));
}


// ###### Get Network ID from gate ##########################################
static unsigned int getNetworkID(cModule*            module,
                                 cTopology::LinkOut* link)
{
   int          outputGateID = link->getLocalGateId();
   cGate*       outputGate   = module->gate(outputGateID);
   cChannel*    channel      = outputGate->getChannel();
   return(getNetworkID(channel));
}



// ###### Search filter to find nodes or routers only #######################
struct NodeFilterParameters
{
   bool         AllNetworks;
   bool         FullTopology;
   unsigned int NetworkID;
};

static bool nodeFilter(cModule* module, void* userData)
{
   const NodeFilterParameters* parameters = (const NodeFilterParameters*)userData;

   cProperty* nodeProperty = module->getProperties()->get("node");
   if(nodeProperty) {
      // ====== Check whether this is a router ==============================
      IRoutingTable* routingTable = IPAddressResolver().routingTableOf(module);
      if(routingTable) {
         if( (parameters->FullTopology) || (routingTable->isIPForwardingEnabled()) ) {
            // ====== Are nodes in arbitrary networks requested? ============
            if(parameters->AllNetworks) {
               return(true);
            }

            // ====== Is there an interface in the right network? ===========
            IInterfaceTable* interfaceTable = IPAddressResolver().interfaceTableOf(module);
            if(interfaceTable) {
               bool foundNetwork = false;
               for(int k = 0;k < interfaceTable->getNumInterfaces(); k++) {
                  InterfaceEntry*    interfaceEntry     = interfaceTable->getInterface(k);
                  if(!interfaceEntry->isLoopback()) {
                     const unsigned int interfaceNetworkID = getNetworkID(module, interfaceEntry);
                     if( (interfaceNetworkID == 0) ||
                         (interfaceNetworkID == parameters->NetworkID) ) {
                        foundNetwork = true;
                        break;
                     }
                  }
               }
               if(foundNetwork) {
                  return(true);
               }
            }
         }
      }
   }
   return(false);
}


// ###### Extract the topology (full or routers only) #######################
void MultihomedFlatNetworkConfigurator::extractTopology(cTopology&      topology,
                                                        NodeInfoVector& nodeInfo,
                                                        const bool      fullTopology,
                                                        const bool      allNetworks,
                                                        unsigned int    networkID)
{
   NodeFilterParameters parameters;
   parameters.FullTopology = fullTopology;
   parameters.AllNetworks  = allNetworks;
   parameters.NetworkID    = networkID;

   topology.extractFromNetwork(nodeFilter, &parameters);
   EV << "cTopology found " << topology.getNumNodes() << " nodes for network "
      << networkID << endl;

   nodeInfo.resize(topology.getNumNodes());
   for(int i = 0; i < topology.getNumNodes(); i++) {
      // ====== Cache pointers to interface and routing tables ==============
      cTopology::Node* node   = topology.getNode(i);
      cModule*         module = node->getModule();
      nodeInfo[i].isIPNode = (IPAddressResolver().findInterfaceTableOf(module) != NULL);
      if(nodeInfo[i].isIPNode) {
         nodeInfo[i].interfaceTable = IPAddressResolver().interfaceTableOf(module);
         nodeInfo[i].routingTable   = IPAddressResolver().routingTableOf(module);
      }

      // ====== Prune links having the wrong network ID =====================
      for(int j = 0; j < node->getNumOutLinks(); j++) {
         cTopology::LinkOut* link          = node->getLinkOut(j);
         const unsigned int  linkNetworkID = getNetworkID(module, link);
         if( (linkNetworkID != networkID) && (linkNetworkID != 0) ) {
            link->disable();
         }
      }
   }
}


#define MAX_HOSTS_SHIFT    16
#define MAX_NETWORKS_SHIFT (32 - MAX_HOSTS_SHIFT - 2)

// ###### Assign addresses to all nodes #####################################
std::set<unsigned int> MultihomedFlatNetworkConfigurator::assignAddresses(cTopology&      topology,
                                                                          NodeInfoVector& nodeInfo)
{
   // ====== Initialize per-network node counters ===========================
   unsigned int hostsOfNetwork[1 << MAX_NETWORKS_SHIFT];
   for(unsigned int i = 0;i < (1 << MAX_NETWORKS_SHIFT);i++) {
      hostsOfNetwork[i] = 0;
   }
   std::set<unsigned int> networkSet;

   TotalNumberOfInterfaces = 0;
   for(int i=0; i<topology.getNumNodes(); i++) {
      // ====== Skip bus types ==============================================
      if (!nodeInfo[i].isIPNode) {
          continue;
      }

      // ====== Assign address to each IP interface =========================
      IInterfaceTable* interfaceTable = nodeInfo[i].interfaceTable;
      cTopology::Node* atNode         = topology.getNode(i);
      EV << "Node " << atNode->getModule()->getFullName() << ":" << endl;
      for(int k = 0; k < interfaceTable->getNumInterfaces(); k++) {
         InterfaceEntry* interfaceEntry = interfaceTable->getInterface(k);
         if(!interfaceEntry->isLoopback()) {
            const unsigned int networkID = getNetworkID(atNode->getModule(), interfaceEntry);
            networkSet.insert(networkID);

            if(networkID >= (1 << MAX_NETWORKS_SHIFT) - 1) {
               error("Network ID %u is too large!", networkID);
            }

            const uint32 address =
               0x80000000                     |   // beginning with binary 10 (i.e. 128.0.0.0 .. 191.255.255.255)
               (networkID << MAX_HOSTS_SHIFT) |
               (++hostsOfNetwork[networkID]);
            TotalNumberOfInterfaces++;

            if(hostsOfNetwork[networkID] >= (1 << (32 - 2 - MAX_NETWORKS_SHIFT)) - 1) {
               error("Too many hosts (%u) for network ID %u!", hostsOfNetwork[networkID], networkID);
            }

            EV << "   Interface " << interfaceEntry->getName() << ": "
               << IPAddress(address).str().c_str() << endl;
            interfaceEntry->ipv4Data()->setIPAddress(IPAddress(address));
            interfaceEntry->ipv4Data()->setNetmask(IPAddress::ALLONES_ADDRESS);
         }
      }
   }
   return(networkSet);
}


// ###### Print configuration computed ######################################
void MultihomedFlatNetworkConfigurator::dumpConfiguration(cTopology&      topology,
                                                          NodeInfoVector& nodeInfo,
                                                          const bool      intermediateVersion)
{
   EV << "Routing Configuration by MultihomedFlatNetworkConfigurator: --------------" << endl;
   for(int n = 0; n < topology.getNumNodes(); n++) {
      cTopology::Node* node               = topology.getNode(n);
      cModule*         nodeModule         = node->getModule();
      IRoutingTable*   nodeRoutingTable   = nodeInfo[n].routingTable;
      IInterfaceTable* nodeInterfaceTable = nodeInfo[n].interfaceTable;
      
      EV << "Node " << nodeModule->getFullPath() << ":" << endl;
      EV << "   Forwarding: " << (nodeRoutingTable->isIPForwardingEnabled() ? "yes" : "no") << endl;

/*
      for(int k = 0;k < nodeInterfaceTable->getNumInterfaces();k++) {
         InterfaceEntry* interfaceEntry = nodeInterfaceTable->getInterface(k);
         EV << "   Interface " << interfaceEntry->getName() << ":\t"
            << interfaceEntry->ipv4Data()->getIPAddress().str().c_str() << endl;
      }
*/

      unsigned int num = 0;
      for(int j = 0; j < node->getNumOutLinks(); j++) {
         cTopology::Node* neighbourNode               = node->getLinkOut(j)->getRemoteNode();
         IInterfaceTable* neighbourNodeInterfaceTable = IPAddressResolver().interfaceTableOf(neighbourNode->getModule());
         const int        neighbourGateID             = node->getLinkOut(j)->getRemoteGate()->getId();
         InterfaceEntry*  neighbourInterfaceEntry     = neighbourNodeInterfaceTable->getInterfaceByNodeInputGateId(neighbourGateID);
         const int        outputGateID                = node->getLinkOut(j)->getLocalGate()->getId();
         InterfaceEntry*  outputInterfaceEntry        = nodeInterfaceTable->getInterfaceByNodeOutputGateId(outputGateID);
         unsigned int     outputInterfaceNetworkID    = getNetworkID(node->getModule(), outputInterfaceEntry);

         EV << ++num << "   Interface "
               << outputInterfaceEntry->getName() << ":\t"
               << outputInterfaceEntry->ipv4Data()->getIPAddress().str().c_str()
            << "\t<-->\t"
               << neighbourNode->getModule()->getFullPath() << " Interface "
               << neighbourInterfaceEntry->getName() << ":\t"
               << neighbourInterfaceEntry->ipv4Data()->getIPAddress().str().c_str()
            << "\tNetID: " << outputInterfaceNetworkID
            << endl;
      }

      if(nodeInfo[n].usesDefaultRoute) {
         EV << "   Using default route" << endl;
      }
      else {
         for (int r = 0;r< nodeRoutingTable->getNumRoutes();r++) {
            const IPRoute* route = nodeRoutingTable->getRoute(r);
            ev << ++num << "   Route to "
               << route->getHost().str().c_str() << " via "
               << route->getInterface()->getName() << ", metric "
               << route->getMetric() << endl;
         }
         if( ((unsigned int)nodeRoutingTable->getNumRoutes() > TotalNumberOfInterfaces) &&
             (!intermediateVersion) ) {
            error("Routing table has more routes (%u) than interfaces in the network (%u)!",
                  (unsigned int)nodeRoutingTable->getNumRoutes(), TotalNumberOfInterfaces);
         }
      }
   }
   EV << "--------------------------------------------------------------------------" << endl;
}


// ###### Set MultihomedFlatNetworkConfigurator description text ############
void MultihomedFlatNetworkConfigurator::setDisplayString(cTopology&      topology,
                                                         NodeInfoVector& nodeInfo)
{
   int numIPNodes = 0;
   for(int i = 0; i < topology.getNumNodes(); i++) {
      if(nodeInfo[i].isIPNode) {
         numIPNodes++;
      }
   }

   char buffer[80];
   snprintf(buffer, sizeof(buffer), "%d IP nodes\n%d non-IP nodes",
            numIPNodes, topology.getNumNodes() - numIPNodes);
   getDisplayString().setTagArg("t", 0, buffer);
}


// ###### Compute the routing tables for given network ID ###################
void MultihomedFlatNetworkConfigurator::computeRouting(cTopology&         topology,
                                                       NodeInfoVector&    nodeInfo,
                                                       const unsigned int networkID)
{
   for(int i = 0;i < topology.getNumNodes();i++) {
      // ====== Get destination router data =================================
      cTopology::Node* destinationNode = topology.getNode(i);
      // skip bus types
      if(!nodeInfo[i].isIPNode) {
         continue;
      }
      IInterfaceTable* destinationNodeInterfaceTable = nodeInfo[i].interfaceTable;

      // ====== Calculate shortest paths ====================================
      topology.calculateUnweightedSingleShortestPathsTo(destinationNode);

      
      // ====== Update routing tables of all nodes with shortest paths ======
      for (int j = 0; j < topology.getNumNodes(); j++) {
         // ====== Is this node useful? =====================================
         cTopology::Node* atNode = topology.getNode(j);
         if( (i == j) || (!nodeInfo[j].isIPNode) ) {
            continue;   // same node or bus type
         }
         if(atNode->getNumPaths() == 0) {
            continue;   // not connected
         }

         // ====== Get output interface at node "atNode" ====================
         IInterfaceTable* sourceNodeInterfaceTable = nodeInfo[j].interfaceTable;
         const int        outputGateId             = atNode->getPath(0)->getLocalGate()->getId();
         InterfaceEntry*  outputInterfaceEntry     = sourceNodeInterfaceTable->getInterfaceByNodeOutputGateId(outputGateId);
         if(outputInterfaceEntry == NULL) {
            error("%s has no interface for output gate id %d",
                  sourceNodeInterfaceTable->getFullPath().c_str(), outputGateId);
         }
         
         // ====== Get input interface at node "destinationNode" ============
         cTopology::LinkOut* path = atNode->getPath(0);
         while(path->getRemoteNode() != destinationNode) {
            cTopology::Node* nextRouter = path->getRemoteNode();
            path = nextRouter->getPath(0);
         }
         
         // ====== Add routing table entries for the destination router =====
         IRoutingTable* routingTable = nodeInfo[j].routingTable;
         for(int k = 0;k < destinationNodeInterfaceTable->getNumInterfaces();k++) {
            // Add a routing table entry for each interface of the destination ...
            InterfaceEntry* interfaceEntry = destinationNodeInterfaceTable->getInterface(k);
            if(interfaceEntry->isLoopback()) {
               continue;   // ... except for its loopback address
            }
            const unsigned int destinationNetworkID = getNetworkID(destinationNode->getModule(), interfaceEntry);
            if( (destinationNetworkID != networkID) && (destinationNetworkID != 0) ) {
               continue;   // ... except for links belonging to the wrong network
            }
            const IPAddress destinationAddress = interfaceEntry->ipv4Data()->getIPAddress();

            IPRoute* route = new IPRoute();
            route->setHost(destinationAddress);
            route->setNetmask(IPAddress(255,255,255,255));      // full match needed
            route->setInterface(outputInterfaceEntry);
            route->setType(IPRoute::DIRECT);
            route->setSource(IPRoute::MANUAL);
            route->setMetric(atNode->getDistanceToTarget());    // hop count metric
            updateIfMetricIsBetter(routingTable, route);
         }
      }
   }
}
