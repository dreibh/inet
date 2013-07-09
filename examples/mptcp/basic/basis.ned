package inet.examples.mptcp.basic;

import inet.networklayer.autorouting.ipv4.FlatNetworkConfigurator;
import inet.nodes.inet.StandardHost;
import ned.DatarateChannel;

import inet.nodes.inet.Router;



import inet.linklayer.IOutputQueue;
import inet.linklayer.queue.DropTailQueue;
import inet.linklayer.queue.FIFOQueue;
import inet.linklayer.queue.REDDropper;


network basic
{
    @display("bgb=833,441");
    types:
        channel C1 extends DatarateChannel
        {
            datarate = 10 Mbps;
            delay = 0.1 ms;
            per = 0;
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
        router: Router {
            @display("p=404,130");
            routingFile = "router.mrt";
            gates:
                pppg[2];
        }
    connections:
		// simple MPTCP Network 
		// Subflow 1
        mptcp1.pppg[0] <--> C1 <--> router.pppg[0];
        router.pppg[1] <--> C1 <--> server1.pppg[0];
}

