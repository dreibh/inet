package inet.examples.mptcp.full_bottleneck;

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
            //delay = 1 ms;
        }
        channel C2 extends DatarateChannel
        {
            datarate = 10 Mbps;
            // delay = 1 ms;
        }
    submodules:
        mptcp1: StandardHost {
            parameters:
                @display("p=72,241;i=device/pc3");
                routingFile = "mptcp1.mrt";
            gates:
                pppg[2];
        }
        server1: StandardHost {
            parameters:
                @display("p=685,255;i=device/pc2");
                routingFile = "server1.mrt";
            gates:
                pppg[2];
        }
        router1: Router {
            parameters:
                routingFile = "router1.mrt";
                @display("p=280,138;i=abstract/router");
            gates:
                pppg[3];
        }
        router2: Router {
            parameters:
                routingFile = "router2.mrt";
                @display("p=280,330;i=abstract/router");
            gates:
                pppg[2];
        }
        router3: Router {
            parameters:
                routingFile = "router3.mrt";
                @display("p=564,154;i=abstract/router");
            gates:
                pppg[3];
        }
        router4: Router {
            parameters:
                routingFile = "router4.mrt";
                @display("p=564,338;i=abstract/router");
            gates:
                pppg[2];
        }
        default1: StandardHost {
            parameters:
                @display("p=72,47;i=device/pc3");
                routingFile = "default1.mrt";
            gates:
                pppg[1];
        }
        server2: StandardHost {
            parameters:
                @display("p=670,47;i=device/pc3");
                routingFile = "server2.mrt";
            gates:
                pppg[1];
        }
        router5: Router {
            parameters:
                routingFile = "router5.mrt";
                @display("p=373,251;i=abstract/router");
            gates:
                pppg[3];
        }
        router6: Router {
            parameters:
                routingFile = "router6.mrt";
                @display("p=474,251;i=abstract/router");
            gates:
                pppg[3];
        }
    //        configurator: FlatNetworkConfigurator {
    //            parameters:
    //                @display("p=109,142");
    //        }
    connections:
// MPTCP Network 
		// Subflow 1
        mptcp1.pppg[0] <--> C1 <--> router1.pppg[0];
        router2.pppg[1] <--> C1 <--> router5.pppg[0];
        default1.pppg[0] <--> C1 <--> router1.pppg[2];

        mptcp1.pppg[1] <--> C1 <--> router2.pppg[0];

        server2.pppg[0] <--> C1 <--> router3.pppg[2];
        server1.pppg[0] <--> C1 <--> router3.pppg[1];
        router6.pppg[0] <--> C1 <--> router3.pppg[0];
        server1.pppg[1] <--> C1 <--> router4.pppg[1];


        router5.pppg[2] <--> C2 {  delay = 1 ms; per = 0; } <--> router6.pppg[2];

        router6.pppg[1] <--> C1 <--> router4.pppg[0];
        router5.pppg[1] <--> C1 <--> router1.pppg[1];
}

