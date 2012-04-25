package inet.examples.mptcp.basic;

import inet.networklayer.autorouting.FlatNetworkConfigurator;
import inet.nodes.inet.StandardHost;
import ned.DatarateChannel;

import inet.nodes.inet.Router;

network mptcpnetwork
{
    @display("bgb=384,206");
    types:
        channel C1 extends DatarateChannel
        {
            datarate = 1Mbps;
            delay = 0.1us;
        }
        channel C2 extends DatarateChannel
        {
            datarate = 1Mbps;
            delay = 0.1us;
        }
    submodules:
        client1: StandardHost {
            parameters:
                @display("p=53,67;i=device/pc3");
                routingFile = "client1.mrt";
            gates:
                pppg[2];
        }
        server: StandardHost {
            parameters:
                @display("p=200,67;i=device/pc2");
                routingFile = "server1.mrt";
            gates:
                pppg[2];
        }
        router1: Router {
            parameters:
                routingFile = "router1.mrt";
                @display("p=130,32,37;i=abstract/router");
            gates:
                pppg[2];
        }
        router2: Router {
            parameters:
                routingFile = "router2.mrt";
                @display("p=130,116;i=abstract/router");
            gates:
                pppg[2];
        }
    //        configurator: FlatNetworkConfigurator {
    //            parameters:
    //                @display("p=109,142");
    //        }
    connections:
        client1.pppg++ <--> C1 <--> router1.pppg++;
        router1.pppg++ <--> C1 <--> server.pppg++;
        client1.pppg++ <--> C2 <--> router2.pppg++;
        router2.pppg++ <--> C2 <--> server.pppg++;
}

