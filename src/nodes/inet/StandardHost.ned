//
// Copyright (C) 2009-2012 Thomas Dreibholz
// Copyright (C) 2004 Andras Varga
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//


package inet.nodes.inet;

import inet.applications.netperfmeter.NetPerfMeter;
import inet.applications.pingapp.PingApp;
import inet.applications.tcpapp.TCPApp;
import inet.applications.udpapp.UDPApp;
import inet.applications.sctpapp.SCTPApp;   //I.R.
import inet.base.NotificationBoard;
import inet.linklayer.ethernet.EthernetInterface;
import inet.linklayer.ppp.PPPInterface;
import inet.linklayer.ext.ExtInterface; //I.R.
import inet.networklayer.common.InterfaceTable;
import inet.networklayer.ipv4.RoutingTable;
import inet.transport.tcp.TCP;
import inet.transport.udp.UDP;
import inet.transport.sctp.SCTP;    //I.R.
import inet.util.TCPDump;   //I.R.
import inet.util.NAMTraceWriter;


//
// \IP host with TCP, UDP layers and applications.
//
module StandardHost
{
    parameters:
        @node();
        int numNetPerfMeters = default(0);   // T.D. 17.11.09
        int numTcpApps = default(0);
        int numUdpApps = default(0);
        int numSctpApps = default(0);   //I.R.
        string tcpAppType = default("n/a");
        string udpAppType = default("n/a");
        string sctpAppType = default("n/a");    //I.R.
        bool IPForward = default(false);
        int namid = default(-1);
        string routingFile = default("");
        @display("i=device/pc2");
    gates:
        inout pppg[];
        inout ethg[];
        inout extg[];
    submodules:
        notificationBoard: NotificationBoard {
            parameters:
                @display("p=60,60");
        }
        interfaceTable: InterfaceTable {
            parameters:
                @display("p=60,160");
        }
        routingTable: RoutingTable {
            parameters:
                IPForward = IPForward;
                routerId = "";
                routingFile = routingFile;
                @display("p=60,260");
        }
        namTrace: NAMTraceWriter {
            parameters:
                namid = namid;
                @display("p=60,360");
        }

        netPerfMeter[numNetPerfMeters]: NetPerfMeter {  // T.D. 17.11.09
            parameters:
                @display("p=280,60;i=block/timer");
        }
        tcpApp[numTcpApps]: <tcpAppType> like TCPApp {
            parameters:
                @display("p=180,60");
        }
        udpApp[numUdpApps]: <udpAppType> like UDPApp {
            parameters:
                @display("p=280,60");
        }
        sctpApp[numSctpApps]: <sctpAppType> like SCTPApp {  //I.R.
            parameters:
                @display("p=380,60");
        }
        pingApp: PingApp {
            parameters:
                @display("p=360,230");
        }

        tcp: TCP {
            parameters:
                @display("p=180,160");
        }
        udp: UDP {
            parameters:
                @display("p=280,160");
        }
        sctp: SCTP {    //I.R.
            @display("p=380,160;i=block/wheelbarrow");
        }

        networkLayer: NetworkLayer {
            parameters:
                proxyARP = false;
                @display("p=280,250;q=queue");
            gates:
                ifIn[sizeof(pppg)+sizeof(ethg)+sizeof(extg)];
                ifOut[sizeof(pppg)+sizeof(ethg)+sizeof(extg)];
        }
        ppp[sizeof(pppg)]: PPPInterface {
            parameters:
                @display("p=235,360,row,90;q=txQueue;i=block/ifcard");
        }
        eth[sizeof(ethg)]: EthernetInterface {
            parameters:
                @display("p=335,360,row,90;q=txQueue;i=block/ifcard");
        }
        ext[sizeof(extg)]: ExtInterface {   //I.R.
            parameters:
                @display("p=400,390,row,90;q=txQueue;i=block/ifcard");
        }
        tcpdump: TCPDump {  //I.R.
            parameters:
                @display("p=280,310;i=abstract/cache_s");
            gates:
                ifIn[sizeof(pppg)+sizeof(ethg)+sizeof(extg)];
                in2[sizeof(pppg)+sizeof(ethg)+sizeof(extg)];
                ifOut[sizeof(pppg)+sizeof(ethg)+sizeof(extg)];
                out2[sizeof(pppg)+sizeof(ethg)+sizeof(extg)];
        }
    connections allowunconnected:
        for i=0..numNetPerfMeters-1 {
            netPerfMeter[i].tcpOut --> tcp.appIn++;
            netPerfMeter[i].tcpIn <-- tcp.appOut++;
            netPerfMeter[i].sctpOut --> sctp.from_appl++;
            netPerfMeter[i].sctpIn <-- sctp.to_appl++;
            netPerfMeter[i].udpOut --> udp.appIn++;
            netPerfMeter[i].udpIn <-- udp.appOut++;
        }

        for i=0..numTcpApps-1 {
            tcpApp[i].tcpOut --> tcp.appIn++;
            tcpApp[i].tcpIn <-- tcp.appOut++;
        }

        tcp.ipOut --> networkLayer.tcpIn;
        tcp.ipIn <-- networkLayer.tcpOut;

        for i=0..numUdpApps-1 {
            udpApp[i].udpOut --> udp.appIn++;
            udpApp[i].udpIn <-- udp.appOut++;
        }

        udp.ipOut --> networkLayer.udpIn;
        udp.ipIn <-- networkLayer.udpOut;

        for i=0..numSctpApps-1 {    //I.R.
            sctpApp[i].sctpOut --> sctp.from_appl++;
            sctp.to_appl++ --> sctpApp[i].sctpIn;
        }

        sctp.to_ip --> networkLayer.sctpIn;
        networkLayer.sctpOut --> sctp.from_ip;

        networkLayer.pingOut --> pingApp.pingIn;
        networkLayer.pingIn <-- pingApp.pingOut;

        // connections to network outside
        for i=0..sizeof(pppg)-1 {
            pppg[i] <--> ppp[i].phys;
            ppp[i].netwOut --> tcpdump.ifIn[i];
            tcpdump.out2[i] --> networkLayer.ifIn[i];
            ppp[i].netwIn <-- tcpdump.ifOut[i];
            tcpdump.in2[i] <-- networkLayer.ifOut[i];
        }

        for i=0..sizeof(ethg)-1 {
            ethg[i] <--> eth[i].phys;
            eth[i].netwOut --> tcpdump.ifIn[sizeof(pppg)+i];
            tcpdump.out2[sizeof(pppg)+i] --> networkLayer.ifIn[sizeof(pppg)+i];
            eth[i].netwIn <-- tcpdump.ifOut[sizeof(pppg)+i];
            tcpdump.in2[sizeof(pppg)+i] <-- networkLayer.ifOut[sizeof(pppg)+i];
        }

        for i=0..sizeof(extg)-1 {
            ext[i].netwOut --> tcpdump.ifIn[sizeof(pppg)+sizeof(ethg)+i];
            tcpdump.out2[sizeof(pppg)+sizeof(ethg)+i] --> networkLayer.ifIn[sizeof(pppg)+sizeof(ethg)+i];
            ext[i].netwIn <-- tcpdump.ifOut[sizeof(pppg)+sizeof(ethg)+i];
            tcpdump.in2[sizeof(pppg)+sizeof(ethg)+i] <-- networkLayer.ifOut[sizeof(pppg)+sizeof(ethg)+i];
        }
}
