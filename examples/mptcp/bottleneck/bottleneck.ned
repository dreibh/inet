package inet.examples.mptcp.bottleneck;

import inet.networklayer.autorouting.FlatNetworkConfigurator;
import inet.nodes.inet.StandardHost;
import ned.DatarateChannel;

import inet.nodes.inet.Router;

network bottleneck
{
    @display("bgb=833,441");
    types:
        channel C1 extends DatarateChannel
        {
            datarate = 1Mbps;
            delay = 1 ms;
        }
        channel C2 extends DatarateChannel
        {
            datarate = 1Mbps;
            delay = 1 ms;
        }
    submodules:
        client1: StandardHost {
            parameters:
                @display("p=50,206;i=device/pc3");
                routingFile = "client1.mrt";
            gates:
                pppg[2];
        }
        server: StandardHost {
            parameters:
                @display("p=670,193;i=device/pc2");
                routingFile = "server1.mrt";
            gates:
                pppg[2];
        }
        router1: Router {
            parameters:
                routingFile = "router1.mrt";
                @display("p=362,107;i=abstract/router");
            gates:
                pppg[2];
        }
        router2: Router {
            parameters:
                routingFile = "router2.mrt";
                @display("p=362,328;i=abstract/router");
            gates:
                pppg[2];
        }
        router3: Router {
            parameters:
                routingFile = "router1.mrt";
                @display("p=503,107;i=abstract/router");
            gates:
                pppg[2];
        }
        router4: Router {
            parameters:
                routingFile = "router2.mrt";
                @display("p=503,328;i=abstract/router");
            gates:
                pppg[2];
        }
    //        configurator: FlatNetworkConfigurator {
    //            parameters:
    //                @display("p=109,142");
    //        }
    connections:
        client1.pppg++ <--> C1 <--> router1.pppg++;
//        router1.pppg++ <--> C2 <--> router3.pppg++;
       router1.pppg++ <--> C2 {  per = 0.01; } <--> router3.pppg++;
        router3.pppg++ <--> C1 <--> server.pppg++;
        client1.pppg++ <--> C1 <--> router2.pppg++;
//        router2.pppg++ <--> C2  <--> router4.pppg++;
        router2.pppg++ <--> C2  {  per = 0.01; }<--> router4.pppg++;
        router4.pppg++ <--> C1 <--> server.pppg++;
}

