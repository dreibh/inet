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
// *   Copyright (C) 2009-2015 by Thomas Dreibholz
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

package inet.examples.sctp.cmttest4;

import inet.applications.netperfmeter.NetPerfMeterHost;
import inet.common.queue.FIFOQueue;
import inet.common.queue.IOutputQueue;
import inet.common.queue.REDDropper;
import inet.networklayer.configurator.ipv4.IPv4NetworkConfigurator;
import inet.node.inet.Router;
import ned.DatarateChannel;
import ned.IdealChannel;


module REDQueue like IOutputQueue
{
   gates:
      input in;
      output out;

   submodules:
      red: REDDropper {
         numGates = 1;
         wq = default(0.002);
         minths = default("30");
         maxths = default("90");
         maxps = default("0.10");
         pkrates = default("8333.333");
      }
      fifo: FIFOQueue;

   connections:
      in --> red.in[0];
      red.out[0] --> fifo.in++;
      fifo.out --> out;
}


channel coreChannel extends DatarateChannel
{
   int netID = default(0);        // NOTE: nedID==0 => shared by all networks!
   datarate  = default(1 Mbps);
   delay     = default(0ms);
   ber       = default(0);
   per       = default(0);
   @display("ls=black,3;t=NetID=$netID");
}

channel accessChannel extends DatarateChannel
{
   int netID = default(1);        // NOTE: nedID>0 => separate network!
   datarate  = default(1 Gbps);   // NOTE: 1 Gbit/s access channel!
   delay     = default(0.1ms);
   ber       = default(0);
   per       = default(0);
   @display("ls=blue,5;t=NetID=$netID");
}

channel connectorChannel extends IdealChannel
{
   int netID = default(1);
   @display("ls=darkgray,5;t=NetID=$netID");
}


module Core
{
   // ====== System Parameters ==============================================
   parameters:
      @display("bgi=maps/world,s");
      int    netIDBase        = default(2048);
      int    systemsMain      = default(1);
      int    systemsReference = default(0);
      int    disjointTrails   = default(2);
      int    bottleneckTrails = default(0);
      int    uplinkTrails     = default(0);
      int    downlinkTrails   = default(0);

   // ====== Gates ==========================================================
   gates:
      inout westernDownlink[downlinkTrails] @loose;
      inout easternDownlink[downlinkTrails] @loose;
      inout westernUplink[uplinkTrails] @loose;
      inout easternUplink[uplinkTrails] @loose;

   // ====== Network Components =============================================
   submodules:
      // ------ Routers -----------------------------------------------------
      westernBorderRouter[disjointTrails * (1 + bottleneckTrails)] : Router {
         parameters:
            @display("p=500,150,c,150;i=abstract/router_l,gold");
         gates:
            pppg[1 + systemsMain + systemsReference + (downlinkTrails > 0 ? 1 : 0)];
      }
      westernCoreRouter[disjointTrails] : NetPerfMeterHost {   // NOTE: may have background traffic generators!
         parameters:
            forwarding = true;
            @display("p=700,150,c,150;i=abstract/router_l,gold");
         gates:
            pppg[1 + (1 + bottleneckTrails)];
      }
      easternCoreRouter[disjointTrails] : NetPerfMeterHost {   // NOTE: may have background traffic generators!
         parameters:
            forwarding = true;
            @display("p=1000,150,c,150;i=abstract/router_l,gold");
         gates:
            pppg[1 + (1 + bottleneckTrails)];
      }
      easternBorderRouter[disjointTrails * (1 + bottleneckTrails)] : Router {
         parameters:
            @display("p=1200,150,c,150;i=abstract/router_l,gold");
         gates:
            pppg[1 + systemsMain + systemsReference + (downlinkTrails > 0 ? 1 : 0)];
      }

      westernUplinkRouter[uplinkTrails] : Router {
         parameters:
            @display("p=350,50,r,150;i=abstract/router_l,gray");
         gates:
            pppg[1 + systemsMain + systemsReference];
      }
      easternUplinkRouter[uplinkTrails] : Router {
         parameters:
            @display("p=1250,50,r,150;i=abstract/router_l,gray");
         gates:
            pppg[1 + systemsMain + systemsReference];
      }

      // ------ Systems -----------------------------------------------------
      clientMain[systemsMain] : NetPerfMeterHost {
         parameters:
            forwarding = false;
            @display("p=50,50,c,200;i=device/laptop_l,green");
         gates:
            pppg[disjointTrails * (1 + bottleneckTrails) + uplinkTrails];
      }
      clientReference[systemsReference] : NetPerfMeterHost {
         parameters:
            forwarding = false;
            @display("p=150,150,c,200;i=device/laptop_l,red");
         gates:
            pppg[disjointTrails * (1 + bottleneckTrails) + uplinkTrails];
      }
      serverMain[systemsMain] : NetPerfMeterHost {
         parameters:
            forwarding = false;
            @display("p=1650,50,c,200;i=device/server_l,green");
         gates:
            pppg[disjointTrails * (1 + bottleneckTrails) + uplinkTrails];
      }
      serverReference[systemsReference] : NetPerfMeterHost {
         parameters:
            forwarding = false;
            @display("p=1550,150,c,200;i=device/server_l,red");
         gates:
            pppg[disjointTrails * (1 + bottleneckTrails) + uplinkTrails];
      }

   // ====== Connections ====================================================
   connections:

      // Core Router [disjointTrails]:
      // ppp0 <--> other core router
      // ppp1 <--> disjoint path to border router
      // pppx <--> shared paths to border routers; x=2+b

      // Border Router [disjointTrails * (1 + bottleneckTrails) + uplinkTrails]:
      // ppp0 <--> core router OR uplink router
      // pppX <--> system; x=1+s (main); X=1+systemsMain+s (reference)
      // pppY <--> downlink router; Y=2+systemsMain+systemsReference

      // System
      // pppX <--> border router of path X
      //   ppp0: disjoint path #1
      //      ppp(1-bottleneckTrails): corresponding bottleneck path

      // ------ Disjoint Links ----------------------------------------------
      for d=0..disjointTrails-1 {
         // NOTE: These connections MUST be the first ones, since the
         //       simulation script assumes the bottleneck interface to be ppp0!
         westernCoreRouter[d].pppg[0]
            <--> coreChannel { netID = 0; @display("ls=blue,3"); }
            <--> easternCoreRouter[d].pppg[0];

         westernBorderRouter[d].pppg[0]
            <--> accessChannel { netID = netIDBase + d * (1 + bottleneckTrails); @display("ls=blue,5"); }
            <--> westernCoreRouter[d].pppg[1];
         easternBorderRouter[d].pppg[0]
            <--> accessChannel { netID = netIDBase + d * (1 + bottleneckTrails); @display("ls=blue,5"); }
            <--> easternCoreRouter[d].pppg[1];
      }

      for d=0..disjointTrails-1,
         for s=0..max(systemsMain, systemsReference)-1 {
            clientMain[s].pppg[d * (1 + bottleneckTrails) + 0]
               <--> accessChannel { netID = 0; @display("ls=green,5"); }
               <--> westernBorderRouter[d].pppg[1 + s]
               if (s < systemsMain);
            serverMain[s].pppg[d * (1 + bottleneckTrails) + 0]
               <--> accessChannel { netID = 0; @display("ls=green,5"); }
               <--> easternBorderRouter[d].pppg[1 + s]
               if (s < systemsMain);

            clientReference[s].pppg[d * (1 + bottleneckTrails) + 0]
               <--> accessChannel { netID = 0; @display("ls=red,5"); }
               <--> westernBorderRouter[d].pppg[1 + systemsMain + s]
               if (s < systemsReference);
            serverReference[s].pppg[d * (1 + bottleneckTrails) + 0]
               <--> accessChannel { netID = 0; @display("ls=red,5"); }
               <--> easternBorderRouter[d].pppg[1 + systemsMain + s]
               if (s < systemsReference);
      }

      // ------ Shared Bottleneck Links -------------------------------------
      for d=0..disjointTrails-1,
         for b=0..bottleneckTrails-1 {
            westernBorderRouter[disjointTrails + (d * bottleneckTrails) + b].pppg++
               <--> accessChannel { netID = 0; @display("ls=blue,5"); }
               <--> westernCoreRouter[d].pppg[2 + b];
            easternBorderRouter[disjointTrails + (d * bottleneckTrails) + b].pppg++
               <--> accessChannel { netID = 0; @display("ls=blue,5"); }
               <--> easternCoreRouter[d].pppg[2 + b];
      }

      for d=0..disjointTrails-1,
         for b=0..bottleneckTrails-1,
            for s=0..max(systemsMain, systemsReference)-1 {
               clientMain[s].pppg[d * (1 + bottleneckTrails) + (b + 1)]
                  <--> accessChannel { netID = 0; @display("ls=green,5,da"); }
                  <--> westernBorderRouter[disjointTrails + (d * bottleneckTrails) + b].pppg[1 + s]
                  if (s < systemsMain);
               serverMain[s].pppg[d * (1 + bottleneckTrails) + (b + 1)]
                  <--> accessChannel { netID = 0; @display("ls=green,5,da"); }
                  <--> easternBorderRouter[disjointTrails + (d * bottleneckTrails) + b].pppg[1 + s]
                  if (s < systemsMain);

               clientReference[s].pppg[d * (1 + bottleneckTrails) + (b + 1)]
                  <--> accessChannel { netID = 0; @display("ls=red,5,d"); }
                  <--> westernBorderRouter[disjointTrails + (d * bottleneckTrails) + b].pppg[1 + systemsMain + s]
                  if (s < systemsReference);
               serverReference[s].pppg[d * (1 + bottleneckTrails) + (b + 1)]
                  <--> accessChannel { netID = 0; @display("ls=red,5,d"); }
                  <--> easternBorderRouter[disjointTrails + (d * bottleneckTrails) + b].pppg[1 + systemsMain + s]
                  if (s < systemsReference);
      }

      // ------ Downlinks -----------------------------------------------------
      for w=0..min(downlinkTrails, (disjointTrails * (1 + bottleneckTrails)))-1 {
         westernBorderRouter[w].pppg[1 + systemsMain + systemsReference]
            <--> connectorChannel { netID = 0;  @display("ls=darkgray,5"); }
            <--> westernDownlink[w];
         easternBorderRouter[w].pppg[1 + systemsMain + systemsReference]
            <--> connectorChannel { netID = 0;  @display("ls=darkgray,5"); }
            <--> easternDownlink[w];
      }

      // ------ Uplinks -----------------------------------------------------
      for u=0..uplinkTrails-1 {
         westernUplinkRouter[u].pppg[0]
            <--> connectorChannel { netID = 0;  @display("ls=darkgray,5"); }
            <--> westernUplink[u];
         easternUplinkRouter[u].pppg[0]
            <--> connectorChannel { netID = 0;  @display("ls=darkgray,5"); }
            <--> easternUplink[u];
      }
      for u=0..uplinkTrails-1,
         for s=0..max(systemsMain, systemsReference)-1 {
            clientMain[s].pppg[disjointTrails * (1 + bottleneckTrails) + u]
               <--> accessChannel { netID = 0;  @display("ls=darkgray,5"); }
               <--> westernUplinkRouter[u].pppg[1 + s]
               if (s < systemsMain);
            serverMain[s].pppg[disjointTrails * (1 + bottleneckTrails) + u]
               <--> accessChannel { netID = 0;  @display("ls=darkgray,5"); }
               <--> easternUplinkRouter[u].pppg[1 + s]
               if (s < systemsMain);

            clientReference[s].pppg[disjointTrails * (1 + bottleneckTrails) + u]
               <--> accessChannel { netID = 0;  @display("ls=darkgray,5"); }
               <--> westernUplinkRouter[u].pppg[1 + systemsMain + s]
               if (s < systemsReference);
            serverReference[s].pppg[disjointTrails * (1 + bottleneckTrails) + u]
               <--> accessChannel { netID = 0;  @display("ls=darkgray,5"); }
               <--> easternUplinkRouter[u].pppg[1 + systemsMain + s]
               if (s < systemsReference);
      }
}


network cmttest4
{
    // ====== System Parameters =============================================
    parameters:
        double testTimeout @unit(s) = default(0s);
        bool   testing              = default(false);
        int    cores                = default(3);
    @display("bgi=maps/europe,s");

    // ====== Network Components ============================================
    submodules:
        // ------ Routing Auto-Configuration --------------------------------
        configurator: IPv4NetworkConfigurator {
            parameters:
               @display("p=600,250;i=abstract/penguin_vl,gold");
        }

        core[cores] : Core {
           parameters:
              netIDBase = 1024 + (index * 1024);
              @display("p=150,150,c,200;i=block/network2_vl,blue");
        }

   // ====== Connections ====================================================
   connections:
   for c=1..cores-1,
      for t=0..core[c-1].downlinkTrails-1 {
         core[c-1].westernDownlink[t]
            <--> accessChannel { netID = core[c].netIDBase + core[c].disjointTrails * (1 + core[c].bottleneckTrails) + t; }
            <--> core[c].westernUplink[t]
            if (t < core[c].uplinkTrails);
         core[c-1].easternDownlink[t]
            <--> accessChannel { netID = core[c].netIDBase + core[c].disjointTrails * (1 + core[c].bottleneckTrails) + t; }
            <--> core[c].easternUplink[t]
            if (t < core[c].uplinkTrails);
   }
}
