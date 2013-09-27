package inet.examples.mptcp.disjointbottleneck;

import inet.networklayer.autorouting.ipv4.FlatNetworkConfigurator;
import inet.nodes.inet.StandardHost;
import ned.DatarateChannel;

import inet.nodes.inet.Router;

network bottleneck
{
    @display("bgb=833,441");
    types:
        channel C1 extends DatarateChannel
        {
            datarate = 10 Mbps;
        }
        channel C2 extends DatarateChannel
        {
            datarate = 10 Mbps;
            delay = 10 ms;
            per = 0;
        }
    submodules:
        pc1: StandardHost {
            parameters:
                @display("p=72,47;i=device/pc3");
                routingFile = "pc1.mrt";
            gates:
                pppg[1];
        }
        pc2: StandardHost {
            parameters:
                @display("p=72,206;i=device/pc3");
                routingFile = "pc2.mrt";
            gates:
                pppg[2];
        }
        server1: StandardHost {
            parameters:
                @display("p=670,206;i=device/pc2");
                routingFile = "server1.mrt";
            gates:
                pppg[2];
        }
        server2: StandardHost {
            parameters:
                @display("p=670,47;i=device/pc3");
                routingFile = "server2.mrt";
            gates:
                pppg[1];
        }
        router1: Router {
            parameters:
                routingFile = "router1.mrt";
                @display("p=362,107;i=abstract/router");
            gates:
                pppg[3];
        }
        router2: Router {
            parameters:
                routingFile = "router2.mrt";
                @display("p=362,255;i=abstract/router");
            gates:
                pppg[2];
        }
        router3: Router {
            parameters:
                routingFile = "router3.mrt";
                @display("p=503,107;i=abstract/router");
            gates:
                pppg[3];
        }
        router4: Router {
            parameters:
                routingFile = "router4.mrt";
                @display("p=503,255;i=abstract/router");
            gates:
                pppg[2];
        }                

    connections:
		// Subflow 1
        pc2.pppg[0] <--> C1 <--> router1.pppg[0];
        router3.pppg[1] <--> C1 <--> server1.pppg[0];
        // Subflow 2
        pc2.pppg[1] <--> C1 <--> router2.pppg[0];
        router4.pppg[1] <--> C1 <--> server1.pppg[1];
		// Default network        
        pc1.pppg[0] <--> C1 <--> router1.pppg[2];
        router3.pppg[2] <--> C1 <--> server2.pppg[0];
        // Router Connection        
        router1.pppg[1] <--> C2 <--> router3.pppg[0];
        router2.pppg[1] <--> C2 <--> router4.pppg[0];
}

