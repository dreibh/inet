package inet.examples.mptcp.basic;

import inet.networklayer.autorouting.ipv4.FlatNetworkConfigurator;
import inet.nodes.inet.StandardHost;
import ned.DatarateChannel;

import inet.nodes.inet.Router;

network basic
{
    @display("bgb=833,441");
    types:
        channel C1 extends DatarateChannel
        {
            datarate = 10 Mbps;
            delay = 1 ms;
            per = 0.01;
        }
     
    submodules:
        mptcp1: StandardHost {
            parameters:
                @display("p=72,206;i=device/pc3");
                routingFile = "mptcp1.mrt";
            gates:
                pppg[1];
        }
        server1: StandardHost {
            parameters:
                @display("p=670,206;i=device/pc2");
                routingFile = "server1.mrt";
            gates:
                pppg[1];
        }
    connections:
		// simple MPTCP Network 
		// Subflow 1
        mptcp1.pppg[0] <--> C1 <--> server1.pppg[0];
}

