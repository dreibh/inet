#
# OMNeT++/OMNEST Makefile for inet
#
# This file was generated with the command:
#  opp_makemake -f --deep -lpcap -lssl -lcrypto -DPRIVATE -DPRIVATE_DEBUG -DHAVE_PCAP -DUSE_TF -Xapplications/voipstream -Xtransport/tcp_lwip -Xtransport/tcp_nsc -DWITH_TCP_COMMON -DWITH_TCP_INET -DWITH_IPv4 -DWITH_xMIPv6 -DWITH_UDP -DWITH_RTP -DWITH_SCTP -DWITH_DHCP -DWITH_ETHERNET -DWITH_PPP -DWITH_EXT_IF -DWITH_MPLS -DWITH_OSPFv2 -DWITH_BGPv4 -DWITH_TRACI -DWITH_MANET -O0 -o inet
#

# Name of target to be created (-o option)
TARGET = inet$(EXE_SUFFIX)

# User interface (uncomment one) (-u option)
USERIF_LIBS = $(ALL_ENV_LIBS) # that is, $(TKENV_LIBS) $(CMDENV_LIBS)
#USERIF_LIBS = $(CMDENV_LIBS)
#USERIF_LIBS = $(TKENV_LIBS)

# C++ include paths (with -I)
INCLUDE_PATH = \
    -I. \
    -Iapplications \
    -Iapplications/dhcp \
    -Iapplications/ethernet \
    -Iapplications/generic \
    -Iapplications/httptools \
    -Iapplications/netperfmeter \
    -Iapplications/pingapp \
    -Iapplications/rtpapp \
    -Iapplications/sctpapp \
    -Iapplications/tcpapp \
    -Iapplications/traci \
    -Iapplications/udpapp \
    -Iapplications/voip \
    -Ibase \
    -Ibattery \
    -Ibattery/models \
    -Ilinklayer \
    -Ilinklayer/common \
    -Ilinklayer/contract \
    -Ilinklayer/ethernet \
    -Ilinklayer/ethernet/switch \
    -Ilinklayer/etherswitch \
    -Ilinklayer/ext \
    -Ilinklayer/idealwireless \
    -Ilinklayer/ieee80211 \
    -Ilinklayer/ieee80211/mac \
    -Ilinklayer/ieee80211/mgmt \
    -Ilinklayer/ieee80211/radio \
    -Ilinklayer/ieee80211/radio/errormodel \
    -Ilinklayer/ppp \
    -Ilinklayer/queue \
    -Ilinklayer/radio \
    -Ilinklayer/radio/propagation \
    -Imobility \
    -Imobility/models \
    -Inetworklayer \
    -Inetworklayer/arp \
    -Inetworklayer/autorouting \
    -Inetworklayer/autorouting/ipv4 \
    -Inetworklayer/autorouting/ipv6 \
    -Inetworklayer/bgpv4 \
    -Inetworklayer/bgpv4/BGPMessage \
    -Inetworklayer/common \
    -Inetworklayer/contract \
    -Inetworklayer/diffserv \
    -Inetworklayer/extras \
    -Inetworklayer/icmpv6 \
    -Inetworklayer/internetcloud \
    -Inetworklayer/ipv4 \
    -Inetworklayer/ipv6 \
    -Inetworklayer/ipv6tunneling \
    -Inetworklayer/ldp \
    -Inetworklayer/manetrouting \
    -Inetworklayer/manetrouting/aodv \
    -Inetworklayer/manetrouting/aodv/aodv-uu \
    -Inetworklayer/manetrouting/base \
    -Inetworklayer/manetrouting/batman \
    -Inetworklayer/manetrouting/batman/batmand \
    -Inetworklayer/manetrouting/batman/batmand/orig \
    -Inetworklayer/manetrouting/dsdv \
    -Inetworklayer/manetrouting/dsr \
    -Inetworklayer/manetrouting/dsr/dsr-uu \
    -Inetworklayer/manetrouting/dymo \
    -Inetworklayer/manetrouting/dymo/dymoum \
    -Inetworklayer/manetrouting/dymo_fau \
    -Inetworklayer/manetrouting/olsr \
    -Inetworklayer/mpls \
    -Inetworklayer/ospfv2 \
    -Inetworklayer/ospfv2/interface \
    -Inetworklayer/ospfv2/messagehandler \
    -Inetworklayer/ospfv2/neighbor \
    -Inetworklayer/ospfv2/router \
    -Inetworklayer/rsvp_te \
    -Inetworklayer/ted \
    -Inetworklayer/xmipv6 \
    -Inodes \
    -Inodes/bgp \
    -Inodes/ethernet \
    -Inodes/httptools \
    -Inodes/inet \
    -Inodes/internetcloud \
    -Inodes/ipv6 \
    -Inodes/mpls \
    -Inodes/ospfv2 \
    -Inodes/wireless \
    -Inodes/xmipv6 \
    -Itransport \
    -Itransport/contract \
    -Itransport/rtp \
    -Itransport/rtp/profiles \
    -Itransport/rtp/profiles/avprofile \
    -Itransport/sctp \
    -Itransport/tcp \
    -Itransport/tcp/flavours \
    -Itransport/tcp/mptcp_extension \
    -Itransport/tcp/mptcp_extension/flavours \
    -Itransport/tcp/mptcp_extension/mptcp_queues \
    -Itransport/tcp/mptcp_extension/mptcp_scheduler \
    -Itransport/tcp/queues \
    -Itransport/tcp_common \
    -Itransport/udp \
    -Iutil \
    -Iutil/headerserializers \
    -Iutil/headerserializers/headers \
    -Iutil/headerserializers/ipv4 \
    -Iutil/headerserializers/ipv4/headers \
    -Iutil/headerserializers/sctp \
    -Iutil/headerserializers/sctp/headers \
    -Iutil/headerserializers/tcp \
    -Iutil/headerserializers/tcp/headers \
    -Iutil/headerserializers/udp \
    -Iutil/headerserializers/udp/headers \
    -Iworld \
    -Iworld/annotations \
    -Iworld/httptools \
    -Iworld/obstacles \
    -Iworld/powercontrol \
    -Iworld/radio \
    -Iworld/scenario \
    -Iworld/traci

# Additional object and library files to link with
EXTRA_OBJS =

# Additional libraries (-L, -l options)
LIBS =  -lpcap -lssl -lcrypto

# Output directory
PROJECT_OUTPUT_DIR = ../0
PROJECTRELATIVE_PATH = /src
O = $(PROJECT_OUTPUT_DIR)/$(CONFIGNAME)/$(PROJECTRELATIVE_PATH)

# Object files for local .cc and .msg files
OBJS = \
    $O/applications/dhcp/DHCPClient.o \
    $O/applications/dhcp/DHCPServer.o \
    $O/applications/ethernet/EtherAppCli.o \
    $O/applications/ethernet/EtherAppSrv.o \
    $O/applications/ethernet/EtherTrafGen.o \
    $O/applications/generic/IPvXTrafGen.o \
    $O/applications/generic/IPvXTrafSink.o \
    $O/applications/httptools/HttpBrowser.o \
    $O/applications/httptools/HttpBrowserBase.o \
    $O/applications/httptools/HttpBrowserDirect.o \
    $O/applications/httptools/HttpNodeBase.o \
    $O/applications/httptools/HttpRandom.o \
    $O/applications/httptools/HttpServer.o \
    $O/applications/httptools/HttpServerBase.o \
    $O/applications/httptools/HttpServerDirect.o \
    $O/applications/httptools/HttpServerDirectEvilA.o \
    $O/applications/httptools/HttpServerDirectEvilB.o \
    $O/applications/httptools/HttpServerEvilA.o \
    $O/applications/httptools/HttpServerEvilB.o \
    $O/applications/httptools/HttpUtils.o \
    $O/applications/netperfmeter/NetPerfMeter.o \
    $O/applications/pingapp/PingApp.o \
    $O/applications/pingapp/PingTestApp.o \
    $O/applications/rtpapp/RTPApplication.o \
    $O/applications/sctpapp/SCTPClient.o \
    $O/applications/sctpapp/SCTPNatPeer.o \
    $O/applications/sctpapp/SCTPNatServer.o \
    $O/applications/sctpapp/SCTPPeer.o \
    $O/applications/sctpapp/SCTPServer.o \
    $O/applications/tcpapp/TCPBasicClientApp.o \
    $O/applications/tcpapp/TCPEchoApp.o \
    $O/applications/tcpapp/TCPGenericCliAppBase.o \
    $O/applications/tcpapp/TCPGenericSrvApp.o \
    $O/applications/tcpapp/TCPGenericSrvThread.o \
    $O/applications/tcpapp/TCPSessionApp.o \
    $O/applications/tcpapp/TCPSinkApp.o \
    $O/applications/tcpapp/TCPSrvHostApp.o \
    $O/applications/tcpapp/TelnetApp.o \
    $O/applications/traci/TraCIDemo.o \
    $O/applications/traci/TraCITestApp.o \
    $O/applications/udpapp/UDPBasicApp.o \
    $O/applications/udpapp/UDPBasicBurst.o \
    $O/applications/udpapp/UDPEchoApp.o \
    $O/applications/udpapp/UDPSink.o \
    $O/applications/udpapp/UDPVideoStreamCli.o \
    $O/applications/udpapp/UDPVideoStreamSvr.o \
    $O/applications/voip/SimpleVoIPReceiver.o \
    $O/applications/voip/SimpleVoIPSender.o \
    $O/base/AbstractQueue.o \
    $O/base/BasicModule.o \
    $O/base/ByteArray.o \
    $O/base/ByteArrayBuffer.o \
    $O/base/ByteArrayMessage.o \
    $O/base/Coord.o \
    $O/base/erfc.o \
    $O/base/Join.o \
    $O/base/ModuleAccess.o \
    $O/base/NedFunctions.o \
    $O/base/NotificationBoard.o \
    $O/base/NotifierConsts.o \
    $O/base/PassiveQueueBase.o \
    $O/base/ProtocolMap.o \
    $O/base/QueueBase.o \
    $O/base/QueueWithQoS.o \
    $O/base/ReassemblyBuffer.o \
    $O/base/ResultFilters.o \
    $O/base/Sink.o \
    $O/base/Topology.o \
    $O/base/UnimplementedModule.o \
    $O/base/WeightedTopology.o \
    $O/battery/models/BasicBattery.o \
    $O/battery/models/InetSimpleBattery.o \
    $O/linklayer/common/WirelessMacBase.o \
    $O/linklayer/contract/MACAddress.o \
    $O/linklayer/ethernet/EtherBus.o \
    $O/linklayer/ethernet/EtherEncap.o \
    $O/linklayer/ethernet/EtherFrameClassifier.o \
    $O/linklayer/ethernet/EtherHub.o \
    $O/linklayer/ethernet/EtherLLC.o \
    $O/linklayer/ethernet/EtherMAC.o \
    $O/linklayer/ethernet/EtherMACBase.o \
    $O/linklayer/ethernet/EtherMACFullDuplex.o \
    $O/linklayer/ethernet/switch/MACRelayUnitBase.o \
    $O/linklayer/ethernet/switch/MACRelayUnitNP.o \
    $O/linklayer/ethernet/switch/MACRelayUnitPP.o \
    $O/linklayer/ext/cSocketRTScheduler.o \
    $O/linklayer/ext/ExtInterface.o \
    $O/linklayer/idealwireless/IdealWirelessMac.o \
    $O/linklayer/ieee80211/mac/Ieee80211DataRate.o \
    $O/linklayer/ieee80211/mac/Ieee80211eClassifier.o \
    $O/linklayer/ieee80211/mac/Ieee80211Mac.o \
    $O/linklayer/ieee80211/mac/WifiMode.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211AgentSTA.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211Etx.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211MgmtAdhoc.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211MgmtAdhocWithEtx.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211MgmtAP.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211MgmtAPBase.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211MgmtAPSimplified.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211MgmtBase.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211MgmtSTA.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211MgmtSTASimplified.o \
    $O/linklayer/ieee80211/radio/BerParseFile.o \
    $O/linklayer/ieee80211/radio/Ieee80211RadioModel.o \
    $O/linklayer/ieee80211/radio/errormodel/dsss-error-rate-model.o \
    $O/linklayer/ieee80211/radio/errormodel/nist-error-rate-model.o \
    $O/linklayer/ieee80211/radio/errormodel/yans-error-rate-model.o \
    $O/linklayer/ppp/PPP.o \
    $O/linklayer/queue/AlgorithmicDropperBase.o \
    $O/linklayer/queue/DropTailQueue.o \
    $O/linklayer/queue/FIFOQueue.o \
    $O/linklayer/queue/PriorityScheduler.o \
    $O/linklayer/queue/REDDropper.o \
    $O/linklayer/queue/SchedulerBase.o \
    $O/linklayer/queue/ThresholdDropper.o \
    $O/linklayer/queue/WRRScheduler.o \
    $O/linklayer/radio/GenericRadioModel.o \
    $O/linklayer/radio/IdealRadio.o \
    $O/linklayer/radio/Modulation.o \
    $O/linklayer/radio/Radio.o \
    $O/linklayer/radio/propagation/FreeSpaceModel.o \
    $O/linklayer/radio/propagation/LogNormalShadowingModel.o \
    $O/linklayer/radio/propagation/NakagamiModel.o \
    $O/linklayer/radio/propagation/RayleighModel.o \
    $O/linklayer/radio/propagation/RiceModel.o \
    $O/linklayer/radio/propagation/TwoRayGroundModel.o \
    $O/mobility/models/ANSimMobility.o \
    $O/mobility/models/BonnMotionFileCache.o \
    $O/mobility/models/BonnMotionMobility.o \
    $O/mobility/models/ChiangMobility.o \
    $O/mobility/models/CircleMobility.o \
    $O/mobility/models/ConstSpeedMobility.o \
    $O/mobility/models/GaussMarkovMobility.o \
    $O/mobility/models/LinearMobility.o \
    $O/mobility/models/LinearNodeDistributionMobility.o \
    $O/mobility/models/LineSegmentsMobilityBase.o \
    $O/mobility/models/MassMobility.o \
    $O/mobility/models/MoBANCoordinator.o \
    $O/mobility/models/MoBANLocal.o \
    $O/mobility/models/MobilityAccess.o \
    $O/mobility/models/MobilityBase.o \
    $O/mobility/models/MovingMobilityBase.o \
    $O/mobility/models/Ns2MotionMobility.o \
    $O/mobility/models/Posture.o \
    $O/mobility/models/PostureTransition.o \
    $O/mobility/models/RandomWPMobility.o \
    $O/mobility/models/RectangleMobility.o \
    $O/mobility/models/StaticGridMobility.o \
    $O/mobility/models/StationaryMobility.o \
    $O/mobility/models/TraCIMobility.o \
    $O/mobility/models/TractorMobility.o \
    $O/mobility/models/TurtleMobility.o \
    $O/networklayer/arp/ARP.o \
    $O/networklayer/autorouting/ipv4/FlatNetworkConfigurator.o \
    $O/networklayer/autorouting/ipv4/HostAutoConfigurator.o \
    $O/networklayer/autorouting/ipv4/IPv4NetworkConfigurator.o \
    $O/networklayer/autorouting/ipv4/MultihomedFlatNetworkConfigurator.o \
    $O/networklayer/autorouting/ipv6/FlatNetworkConfigurator6.o \
    $O/networklayer/bgpv4/BGPFSM.o \
    $O/networklayer/bgpv4/BGPRouting.o \
    $O/networklayer/bgpv4/BGPSession.o \
    $O/networklayer/bgpv4/BGPMessage/BGPUpdate.o \
    $O/networklayer/common/InterfaceEntry.o \
    $O/networklayer/common/InterfaceTable.o \
    $O/networklayer/contract/IPv4Address.o \
    $O/networklayer/contract/IPv4ControlInfo.o \
    $O/networklayer/contract/IPv6Address.o \
    $O/networklayer/contract/IPv6ControlInfo.o \
    $O/networklayer/contract/IPvXAddress.o \
    $O/networklayer/contract/IPvXAddressResolver.o \
    $O/networklayer/diffserv/BehaviorAggregateClassifier.o \
    $O/networklayer/diffserv/DiffservUtil.o \
    $O/networklayer/diffserv/DSCPMarker.o \
    $O/networklayer/diffserv/MultiFieldClassifier.o \
    $O/networklayer/diffserv/SingleRateThreeColorMeter.o \
    $O/networklayer/diffserv/TokenBucketMeter.o \
    $O/networklayer/diffserv/TwoRateThreeColorMeter.o \
    $O/networklayer/extras/Dummy.o \
    $O/networklayer/extras/FailureManager.o \
    $O/networklayer/icmpv6/ICMPv6.o \
    $O/networklayer/icmpv6/IPv6NeighbourCache.o \
    $O/networklayer/icmpv6/IPv6NeighbourDiscovery.o \
    $O/networklayer/internetcloud/CloudDelayerBase.o \
    $O/networklayer/internetcloud/InternetCloudTaggerChannel.o \
    $O/networklayer/internetcloud/MatrixCloudDelayer.o \
    $O/networklayer/ipv4/ErrorHandling.o \
    $O/networklayer/ipv4/ICMP.o \
    $O/networklayer/ipv4/IGMPv2.o \
    $O/networklayer/ipv4/IPv4.o \
    $O/networklayer/ipv4/IPv4FragBuf.o \
    $O/networklayer/ipv4/IPv4InterfaceData.o \
    $O/networklayer/ipv4/IPv4Route.o \
    $O/networklayer/ipv4/NetworkInfo.o \
    $O/networklayer/ipv4/RoutingTable.o \
    $O/networklayer/ipv4/RoutingTableParser.o \
    $O/networklayer/ipv4/RoutingTableRecorder.o \
    $O/networklayer/ipv6/IPv6.o \
    $O/networklayer/ipv6/IPv6Datagram.o \
    $O/networklayer/ipv6/IPv6ErrorHandling.o \
    $O/networklayer/ipv6/IPv6ExtensionHeaders.o \
    $O/networklayer/ipv6/IPv6FragBuf.o \
    $O/networklayer/ipv6/IPv6InterfaceData.o \
    $O/networklayer/ipv6/RoutingTable6.o \
    $O/networklayer/ipv6tunneling/IPv6Tunneling.o \
    $O/networklayer/ldp/LDP.o \
    $O/networklayer/manetrouting/aodv/aodv_msg_struct.o \
    $O/networklayer/manetrouting/aodv/aodv_uu_omnet.o \
    $O/networklayer/manetrouting/aodv/packet_queue_omnet.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/aodv_hello.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/aodv_socket.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/debug_aodv.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/list.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/locality.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/routing_table.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/seek_list.o \
    $O/networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.o \
    $O/networklayer/manetrouting/base/ManetAddress.o \
    $O/networklayer/manetrouting/base/ManetRoutingBase.o \
    $O/networklayer/manetrouting/batman/BatmanMain.o \
    $O/networklayer/manetrouting/batman/batmand/batman.o \
    $O/networklayer/manetrouting/batman/batmand/bitarray.o \
    $O/networklayer/manetrouting/batman/batmand/hna.o \
    $O/networklayer/manetrouting/batman/batmand/originator.o \
    $O/networklayer/manetrouting/batman/batmand/os.o \
    $O/networklayer/manetrouting/batman/batmand/ring_buffer.o \
    $O/networklayer/manetrouting/batman/batmand/schedule.o \
    $O/networklayer/manetrouting/dsdv/DSDV_2.o \
    $O/networklayer/manetrouting/dsr/dsr-pkt_omnet.o \
    $O/networklayer/manetrouting/dsr/dsr-uu-omnetpp.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/dsr-ack.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/dsr-io.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/dsr-opt.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/dsr-srt.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/link-cache.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/maint-buf.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/neigh.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/path-cache.o \
    $O/networklayer/manetrouting/dsr/dsr-uu/send-buf.o \
    $O/networklayer/manetrouting/dymo/dymo_msg_struct.o \
    $O/networklayer/manetrouting/dymo/dymo_packet_queue_omnet.o \
    $O/networklayer/manetrouting/dymo/dymo_um_omnet.o \
    $O/networklayer/manetrouting/dymo/dymoum/blacklist.o \
    $O/networklayer/manetrouting/dymo/dymoum/debug_dymo.o \
    $O/networklayer/manetrouting/dymo/dymoum/dymo_generic.o \
    $O/networklayer/manetrouting/dymo/dymoum/dymo_hello.o \
    $O/networklayer/manetrouting/dymo/dymoum/dymo_nb.o \
    $O/networklayer/manetrouting/dymo/dymoum/dymo_re.o \
    $O/networklayer/manetrouting/dymo/dymoum/dymo_rerr.o \
    $O/networklayer/manetrouting/dymo/dymoum/dymo_socket.o \
    $O/networklayer/manetrouting/dymo/dymoum/dymo_timeout.o \
    $O/networklayer/manetrouting/dymo/dymoum/dymo_uerr.o \
    $O/networklayer/manetrouting/dymo/dymoum/icmp_socket.o \
    $O/networklayer/manetrouting/dymo/dymoum/pending_rreq.o \
    $O/networklayer/manetrouting/dymo/dymoum/rtable.o \
    $O/networklayer/manetrouting/dymo/dymoum/timer_queue.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_DataQueue.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_OutstandingRREQList.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_RoutingEntry.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_RoutingTable.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_Timer.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_TokenBucket.o \
    $O/networklayer/manetrouting/dymo_fau/InspectorHelpers.o \
    $O/networklayer/manetrouting/olsr/OLSR.o \
    $O/networklayer/manetrouting/olsr/OLSR_ETX.o \
    $O/networklayer/manetrouting/olsr/OLSR_ETX_dijkstra.o \
    $O/networklayer/manetrouting/olsr/OLSR_ETX_state.o \
    $O/networklayer/manetrouting/olsr/OLSR_rtable.o \
    $O/networklayer/manetrouting/olsr/OLSR_state.o \
    $O/networklayer/manetrouting/olsr/OLSROPT.o \
    $O/networklayer/mpls/LIBTable.o \
    $O/networklayer/mpls/MPLS.o \
    $O/networklayer/mpls/MPLSPacket.o \
    $O/networklayer/ospfv2/OSPFRouting.o \
    $O/networklayer/ospfv2/interface/OSPFInterface.o \
    $O/networklayer/ospfv2/interface/OSPFInterfaceState.o \
    $O/networklayer/ospfv2/interface/OSPFInterfaceStateBackup.o \
    $O/networklayer/ospfv2/interface/OSPFInterfaceStateDesignatedRouter.o \
    $O/networklayer/ospfv2/interface/OSPFInterfaceStateDown.o \
    $O/networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.o \
    $O/networklayer/ospfv2/interface/OSPFInterfaceStateNotDesignatedRouter.o \
    $O/networklayer/ospfv2/interface/OSPFInterfaceStatePointToPoint.o \
    $O/networklayer/ospfv2/interface/OSPFInterfaceStateWaiting.o \
    $O/networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.o \
    $O/networklayer/ospfv2/messagehandler/HelloHandler.o \
    $O/networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.o \
    $O/networklayer/ospfv2/messagehandler/LinkStateRequestHandler.o \
    $O/networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.o \
    $O/networklayer/ospfv2/messagehandler/MessageHandler.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighbor.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighborState.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighborStateAttempt.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighborStateDown.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighborStateExchange.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighborStateExchangeStart.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighborStateFull.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighborStateInit.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighborStateLoading.o \
    $O/networklayer/ospfv2/neighbor/OSPFNeighborStateTwoWay.o \
    $O/networklayer/ospfv2/router/ASExternalLSA.o \
    $O/networklayer/ospfv2/router/LSA.o \
    $O/networklayer/ospfv2/router/NetworkLSA.o \
    $O/networklayer/ospfv2/router/OSPFArea.o \
    $O/networklayer/ospfv2/router/OSPFRouter.o \
    $O/networklayer/ospfv2/router/OSPFRoutingTableEntry.o \
    $O/networklayer/ospfv2/router/RouterLSA.o \
    $O/networklayer/ospfv2/router/SummaryLSA.o \
    $O/networklayer/rsvp_te/RSVP.o \
    $O/networklayer/rsvp_te/SimpleClassifier.o \
    $O/networklayer/rsvp_te/Utils.o \
    $O/networklayer/ted/LinkStateRouting.o \
    $O/networklayer/ted/TED.o \
    $O/networklayer/xmipv6/BindingCache.o \
    $O/networklayer/xmipv6/BindingUpdateList.o \
    $O/networklayer/xmipv6/MobilityHeader.o \
    $O/networklayer/xmipv6/xMIPv6.o \
    $O/transport/contract/SCTPSocket.o \
    $O/transport/contract/TCPSocket.o \
    $O/transport/contract/TCPSocketMap.o \
    $O/transport/contract/UDPSocket.o \
    $O/transport/rtp/reports.o \
    $O/transport/rtp/RTCP.o \
    $O/transport/rtp/RTCPPacket.o \
    $O/transport/rtp/RTP.o \
    $O/transport/rtp/RTPInnerPacket.o \
    $O/transport/rtp/RTPPacket.o \
    $O/transport/rtp/RTPParticipantInfo.o \
    $O/transport/rtp/RTPPayloadReceiver.o \
    $O/transport/rtp/RTPPayloadSender.o \
    $O/transport/rtp/RTPProfile.o \
    $O/transport/rtp/RTPReceiverInfo.o \
    $O/transport/rtp/RTPSenderInfo.o \
    $O/transport/rtp/sdes.o \
    $O/transport/rtp/profiles/avprofile/RTPAVProfile.o \
    $O/transport/rtp/profiles/avprofile/RTPAVProfilePayload32Receiver.o \
    $O/transport/rtp/profiles/avprofile/RTPAVProfilePayload32Sender.o \
    $O/transport/sctp/ChunkMap.o \
    $O/transport/sctp/GapList.o \
    $O/transport/sctp/QoSStatsCollector.o \
    $O/transport/sctp/SCTP.o \
    $O/transport/sctp/SCTPAlg.o \
    $O/transport/sctp/SCTPAssociationAddIP.o \
    $O/transport/sctp/SCTPAssociationBase.o \
    $O/transport/sctp/SCTPAssociationEventProc.o \
    $O/transport/sctp/SCTPAssociationRcvMessage.o \
    $O/transport/sctp/SCTPAssociationSendAll.o \
    $O/transport/sctp/SCTPAssociationStreamReset.o \
    $O/transport/sctp/SCTPAssociationUtil.o \
    $O/transport/sctp/SCTPCCFunctions.o \
    $O/transport/sctp/SCTPMessage.o \
    $O/transport/sctp/SCTPNatTable.o \
    $O/transport/sctp/SCTPQueue.o \
    $O/transport/sctp/SCTPReceiveStream.o \
    $O/transport/sctp/SCTPSendStream.o \
    $O/transport/sctp/SCTPSSFunctions.o \
    $O/transport/sctp/TimeStatsCollector.o \
    $O/transport/tcp/TCP.o \
    $O/transport/tcp/TCPConnectionBase.o \
    $O/transport/tcp/TCPConnectionEventProc.o \
    $O/transport/tcp/TCPConnectionRcvSegment.o \
    $O/transport/tcp/TCPConnectionSackUtil.o \
    $O/transport/tcp/TCPConnectionUtil.o \
    $O/transport/tcp/TCPSACKRexmitQueue.o \
    $O/transport/tcp/flavours/DumbTCP.o \
    $O/transport/tcp/flavours/TCPBaseAlg.o \
    $O/transport/tcp/flavours/TCPNewReno.o \
    $O/transport/tcp/flavours/TCPNoCongestionControl.o \
    $O/transport/tcp/flavours/TCPReno.o \
    $O/transport/tcp/flavours/TCPTahoe.o \
    $O/transport/tcp/flavours/TCPTahoeRenoFamily.o \
    $O/transport/tcp/mptcp_extension/TCPMultipathFlow.o \
    $O/transport/tcp/mptcp_extension/TCPMultipathPCB.o \
    $O/transport/tcp/mptcp_extension/flavours/MPTCP_RFC6356.o \
    $O/transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathMsgBasedRcvQueue.o \
    $O/transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathVirtualDataRcvQueue.o \
    $O/transport/tcp/mptcp_extension/mptcp_scheduler/TCPMultipathRoundRobinScheduler.o \
    $O/transport/tcp/mptcp_extension/mptcp_scheduler/TCPSchedulerManager.o \
    $O/transport/tcp/queues/TCPByteStreamRcvQueue.o \
    $O/transport/tcp/queues/TCPByteStreamSendQueue.o \
    $O/transport/tcp/queues/TCPMsgBasedRcvQueue.o \
    $O/transport/tcp/queues/TCPMsgBasedSendQueue.o \
    $O/transport/tcp/queues/TCPVirtualDataRcvQueue.o \
    $O/transport/tcp/queues/TCPVirtualDataSendQueue.o \
    $O/transport/tcp_common/TCPSegment.o \
    $O/transport/tcp_common/TCPSpoof.o \
    $O/transport/udp/UDP.o \
    $O/util/common.o \
    $O/util/Delayer.o \
    $O/util/int128.o \
    $O/util/Macho.o \
    $O/util/MessageChecker.o \
    $O/util/NetAnimTrace.o \
    $O/util/opp_utils.o \
    $O/util/OrdinalBasedDropper.o \
    $O/util/OrdinalBasedDuplicator.o \
    $O/util/PacketDump.o \
    $O/util/PatternMatcher.o \
    $O/util/PcapDump.o \
    $O/util/PcapRecorder.o \
    $O/util/TCPDump.o \
    $O/util/ThruputMeter.o \
    $O/util/ThruputMeteringChannel.o \
    $O/util/XMLUtils.o \
    $O/util/headerserializers/TCPIPchecksum.o \
    $O/util/headerserializers/ipv4/ICMPSerializer.o \
    $O/util/headerserializers/ipv4/IGMPSerializer.o \
    $O/util/headerserializers/ipv4/IPv4Serializer.o \
    $O/util/headerserializers/sctp/SCTPSerializer.o \
    $O/util/headerserializers/tcp/TCPSerializer.o \
    $O/util/headerserializers/udp/UDPSerializer.o \
    $O/world/annotations/AnnotationDummy.o \
    $O/world/annotations/AnnotationManager.o \
    $O/world/httptools/HttpController.o \
    $O/world/obstacles/Obstacle.o \
    $O/world/obstacles/ObstacleControl.o \
    $O/world/powercontrol/PowerControlManager.o \
    $O/world/radio/ChannelAccess.o \
    $O/world/radio/ChannelControl.o \
    $O/world/radio/IdealChannelModel.o \
    $O/world/radio/IdealChannelModelAccess.o \
    $O/world/scenario/ScenarioManager.o \
    $O/world/traci/TraCIScenarioManager.o \
    $O/world/traci/TraCIScenarioManagerLaunchd.o \
    $O/applications/dhcp/DHCP_m.o \
    $O/applications/ethernet/EtherApp_m.o \
    $O/applications/httptools/HttpEventMessages_m.o \
    $O/applications/httptools/HttpMessages_m.o \
    $O/applications/netperfmeter/NetPerfMeter_m.o \
    $O/applications/pingapp/PingPayload_m.o \
    $O/applications/tcpapp/GenericAppMsg_m.o \
    $O/applications/voip/SimpleVoIPPacket_m.o \
    $O/base/ByteArray_m.o \
    $O/base/ByteArrayMessage_m.o \
    $O/linklayer/contract/Ieee802Ctrl_m.o \
    $O/linklayer/contract/PhyControlInfo_m.o \
    $O/linklayer/ethernet/EtherFrame_m.o \
    $O/linklayer/ext/ExtFrame_m.o \
    $O/linklayer/idealwireless/IdealWirelessFrame_m.o \
    $O/linklayer/ieee80211/mac/Ieee80211Frame_m.o \
    $O/linklayer/ieee80211/mgmt/ETXPacket_m.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.o \
    $O/linklayer/ieee80211/mgmt/Ieee80211Primitives_m.o \
    $O/linklayer/ppp/PPPFrame_m.o \
    $O/linklayer/radio/AirFrame_m.o \
    $O/linklayer/radio/IdealAirFrame_m.o \
    $O/linklayer/radio/Radio80211aControlInfo_m.o \
    $O/networklayer/arp/ARPPacket_m.o \
    $O/networklayer/bgpv4/BGPMessage/BGPASPathSegment_m.o \
    $O/networklayer/bgpv4/BGPMessage/BGPHeader_m.o \
    $O/networklayer/bgpv4/BGPMessage/BGPKeepAlive_m.o \
    $O/networklayer/bgpv4/BGPMessage/BGPOpen_m.o \
    $O/networklayer/bgpv4/BGPMessage/BGPUpdate_m.o \
    $O/networklayer/bgpv4/BGPMessage/BGPUpdatePathAttributes_m.o \
    $O/networklayer/contract/IPProtocolId_m.o \
    $O/networklayer/contract/IPv4ControlInfo_m.o \
    $O/networklayer/contract/IPv6ControlInfo_m.o \
    $O/networklayer/diffserv/DSCP_m.o \
    $O/networklayer/icmpv6/ICMPv6Message_m.o \
    $O/networklayer/icmpv6/IPv6NDMessage_m.o \
    $O/networklayer/ipv4/ICMPMessage_m.o \
    $O/networklayer/ipv4/IGMPMessage_m.o \
    $O/networklayer/ipv4/IPv4Datagram_m.o \
    $O/networklayer/ipv6/IPv6Datagram_m.o \
    $O/networklayer/ipv6/IPv6ExtensionHeaders_m.o \
    $O/networklayer/ldp/LDPPacket_m.o \
    $O/networklayer/manetrouting/aodv/aodv_msg_struct_m.o \
    $O/networklayer/manetrouting/base/ControlInfoBreakLink_m.o \
    $O/networklayer/manetrouting/base/ControlManetRouting_m.o \
    $O/networklayer/manetrouting/base/MeshControlInfo_m.o \
    $O/networklayer/manetrouting/batman/BatmanMsg_m.o \
    $O/networklayer/manetrouting/dsdv/DSDVhello_m.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_Packet_m.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_PacketBBMessage_m.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_RERR_m.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_RM_m.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_RREP_m.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_RREQ_m.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_Timeout_m.o \
    $O/networklayer/manetrouting/dymo_fau/DYMO_UERR_m.o \
    $O/networklayer/manetrouting/olsr/OLSRpkt_m.o \
    $O/networklayer/ospfv2/OSPFPacket_m.o \
    $O/networklayer/ospfv2/OSPFTimer_m.o \
    $O/networklayer/rsvp_te/IntServ_m.o \
    $O/networklayer/rsvp_te/RSVPHello_m.o \
    $O/networklayer/rsvp_te/RSVPPacket_m.o \
    $O/networklayer/rsvp_te/RSVPPathMsg_m.o \
    $O/networklayer/rsvp_te/RSVPResvMsg_m.o \
    $O/networklayer/rsvp_te/SignallingMsg_m.o \
    $O/networklayer/ted/LinkStatePacket_m.o \
    $O/networklayer/ted/TED_m.o \
    $O/networklayer/xmipv6/MobilityHeader_m.o \
    $O/transport/contract/SCTPCommand_m.o \
    $O/transport/contract/TCPCommand_m.o \
    $O/transport/contract/UDPControlInfo_m.o \
    $O/transport/rtp/reports_m.o \
    $O/transport/rtp/RTCPPacket1_m.o \
    $O/transport/rtp/RTCPPacket2_m.o \
    $O/transport/rtp/RTCPPacket3_m.o \
    $O/transport/rtp/RTPInnerPacket_m.o \
    $O/transport/rtp/RTPInterfacePacket_m.o \
    $O/transport/rtp/RTPPacket_m.o \
    $O/transport/rtp/RTPParticipantInfo_m.o \
    $O/transport/rtp/RTPSenderControlMessage_m.o \
    $O/transport/rtp/RTPSenderStatusMessage_m.o \
    $O/transport/rtp/profiles/avprofile/RTPMpegPacket_m.o \
    $O/transport/sctp/SCTPMessage_m.o \
    $O/transport/tcp_common/TCPSegment_m.o \
    $O/transport/udp/UDPPacket_m.o \
    $O/world/powercontrol/PowerControlMessages_m.o

# Message files
MSGFILES = \
    applications/dhcp/DHCP.msg \
    applications/ethernet/EtherApp.msg \
    applications/httptools/HttpEventMessages.msg \
    applications/httptools/HttpMessages.msg \
    applications/netperfmeter/NetPerfMeter.msg \
    applications/pingapp/PingPayload.msg \
    applications/tcpapp/GenericAppMsg.msg \
    applications/voip/SimpleVoIPPacket.msg \
    base/ByteArray.msg \
    base/ByteArrayMessage.msg \
    linklayer/contract/Ieee802Ctrl.msg \
    linklayer/contract/PhyControlInfo.msg \
    linklayer/ethernet/EtherFrame.msg \
    linklayer/ext/ExtFrame.msg \
    linklayer/idealwireless/IdealWirelessFrame.msg \
    linklayer/ieee80211/mac/Ieee80211Frame.msg \
    linklayer/ieee80211/mgmt/ETXPacket.msg \
    linklayer/ieee80211/mgmt/Ieee80211MgmtFrames.msg \
    linklayer/ieee80211/mgmt/Ieee80211Primitives.msg \
    linklayer/ppp/PPPFrame.msg \
    linklayer/radio/AirFrame.msg \
    linklayer/radio/IdealAirFrame.msg \
    linklayer/radio/Radio80211aControlInfo.msg \
    networklayer/arp/ARPPacket.msg \
    networklayer/bgpv4/BGPMessage/BGPASPathSegment.msg \
    networklayer/bgpv4/BGPMessage/BGPHeader.msg \
    networklayer/bgpv4/BGPMessage/BGPKeepAlive.msg \
    networklayer/bgpv4/BGPMessage/BGPOpen.msg \
    networklayer/bgpv4/BGPMessage/BGPUpdate.msg \
    networklayer/bgpv4/BGPMessage/BGPUpdatePathAttributes.msg \
    networklayer/contract/IPProtocolId.msg \
    networklayer/contract/IPv4ControlInfo.msg \
    networklayer/contract/IPv6ControlInfo.msg \
    networklayer/diffserv/DSCP.msg \
    networklayer/icmpv6/ICMPv6Message.msg \
    networklayer/icmpv6/IPv6NDMessage.msg \
    networklayer/ipv4/ICMPMessage.msg \
    networklayer/ipv4/IGMPMessage.msg \
    networklayer/ipv4/IPv4Datagram.msg \
    networklayer/ipv6/IPv6Datagram.msg \
    networklayer/ipv6/IPv6ExtensionHeaders.msg \
    networklayer/ldp/LDPPacket.msg \
    networklayer/manetrouting/aodv/aodv_msg_struct.msg \
    networklayer/manetrouting/base/ControlInfoBreakLink.msg \
    networklayer/manetrouting/base/ControlManetRouting.msg \
    networklayer/manetrouting/base/MeshControlInfo.msg \
    networklayer/manetrouting/batman/BatmanMsg.msg \
    networklayer/manetrouting/dsdv/DSDVhello.msg \
    networklayer/manetrouting/dymo_fau/DYMO_Packet.msg \
    networklayer/manetrouting/dymo_fau/DYMO_PacketBBMessage.msg \
    networklayer/manetrouting/dymo_fau/DYMO_RERR.msg \
    networklayer/manetrouting/dymo_fau/DYMO_RM.msg \
    networklayer/manetrouting/dymo_fau/DYMO_RREP.msg \
    networklayer/manetrouting/dymo_fau/DYMO_RREQ.msg \
    networklayer/manetrouting/dymo_fau/DYMO_Timeout.msg \
    networklayer/manetrouting/dymo_fau/DYMO_UERR.msg \
    networklayer/manetrouting/olsr/OLSRpkt.msg \
    networklayer/ospfv2/OSPFPacket.msg \
    networklayer/ospfv2/OSPFTimer.msg \
    networklayer/rsvp_te/IntServ.msg \
    networklayer/rsvp_te/RSVPHello.msg \
    networklayer/rsvp_te/RSVPPacket.msg \
    networklayer/rsvp_te/RSVPPathMsg.msg \
    networklayer/rsvp_te/RSVPResvMsg.msg \
    networklayer/rsvp_te/SignallingMsg.msg \
    networklayer/ted/LinkStatePacket.msg \
    networklayer/ted/TED.msg \
    networklayer/xmipv6/MobilityHeader.msg \
    transport/contract/SCTPCommand.msg \
    transport/contract/TCPCommand.msg \
    transport/contract/UDPControlInfo.msg \
    transport/rtp/reports.msg \
    transport/rtp/RTCPPacket1.msg \
    transport/rtp/RTCPPacket2.msg \
    transport/rtp/RTCPPacket3.msg \
    transport/rtp/RTPInnerPacket.msg \
    transport/rtp/RTPInterfacePacket.msg \
    transport/rtp/RTPPacket.msg \
    transport/rtp/RTPParticipantInfo.msg \
    transport/rtp/RTPSenderControlMessage.msg \
    transport/rtp/RTPSenderStatusMessage.msg \
    transport/rtp/profiles/avprofile/RTPMpegPacket.msg \
    transport/sctp/SCTPMessage.msg \
    transport/tcp_common/TCPSegment.msg \
    transport/udp/UDPPacket.msg \
    world/powercontrol/PowerControlMessages.msg

#------------------------------------------------------------------------------

# Pull in OMNeT++ configuration (Makefile.inc or configuser.vc)

ifneq ("$(OMNETPP_CONFIGFILE)","")
CONFIGFILE = $(OMNETPP_CONFIGFILE)
else
ifneq ("$(OMNETPP_ROOT)","")
CONFIGFILE = $(OMNETPP_ROOT)/Makefile.inc
else
CONFIGFILE = $(shell opp_configfilepath)
endif
endif

ifeq ("$(wildcard $(CONFIGFILE))","")
$(error Config file '$(CONFIGFILE)' does not exist -- add the OMNeT++ bin directory to the path so that opp_configfilepath can be found, or set the OMNETPP_CONFIGFILE variable to point to Makefile.inc)
endif

include $(CONFIGFILE)

# Simulation kernel and user interface libraries
OMNETPP_LIB_SUBDIR = $(OMNETPP_LIB_DIR)/$(TOOLCHAIN_NAME)
OMNETPP_LIBS = -L"$(OMNETPP_LIB_SUBDIR)" -L"$(OMNETPP_LIB_DIR)" -loppmain$D $(USERIF_LIBS) $(KERNEL_LIBS) $(SYS_LIBS)

COPTS = $(CFLAGS) \
    -DPRIVATE \
    -DPRIVATE_DEBUG \
    -DHAVE_PCAP \
    -DUSE_TF \
    -DWITH_TCP_COMMON \
    -DWITH_TCP_INET \
    -DWITH_IPv4 \
    -DWITH_xMIPv6 \
    -DWITH_UDP \
    -DWITH_RTP \
    -DWITH_SCTP \
    -DWITH_DHCP \
    -DWITH_ETHERNET \
    -DWITH_PPP \
    -DWITH_EXT_IF \
    -DWITH_MPLS \
    -DWITH_OSPFv2 \
    -DWITH_BGPv4 \
    -DWITH_TRACI \
    -DWITH_MANET $(INCLUDE_PATH) -I$(OMNETPP_INCL_DIR)
MSGCOPTS = $(INCLUDE_PATH)

# we want to recompile everything if COPTS changes,
# so we store COPTS into $COPTS_FILE and have object
# files depend on it (except when "make depend" was called)
COPTS_FILE = $O/.last-copts
ifneq ($(MAKECMDGOALS),depend)
ifneq ("$(COPTS)","$(shell cat $(COPTS_FILE) 2>/dev/null || echo '')")
$(shell $(MKPATH) "$O" && echo "$(COPTS)" >$(COPTS_FILE))
endif
endif

#------------------------------------------------------------------------------
# User-supplied makefile fragment(s)
# >>>
# inserted from file 'makefrag':
# if you want to use external interfaces with inet, you should install
# winpcap (on windows) or libpcap-dev (on linux) and re-run ./configure in
# the omnetpp root directory and comment out the following line:
HAVE_PCAP=no

ifeq ($(HAVE_PCAP),yes)
  # link with PCAP libs too
  LIBS += $(PCAP_LIBS)
else
  # remove the HAVE_PCAP define if we do not need PCAP
  CFLAGS := $(filter-out -DHAVE_PCAP,$(CFLAGS))
endif

#
# TCP implementaion using the Network Simulation Cradle (TCP_NSC feature)
#
ifneq (,$(findstring -DWITH_TCP_NSC,$(COPTS)))
  NSC_VERSION= $(shell ls -d ../3rdparty/nsc* 2>/dev/null | sed 's/^.*-//')
  ifneq ($(NSC_VERSION),)
    CFLAGS += -I../3rdparty/nsc-$(NSC_VERSION)/sim -DHAVE_NSC
    LIBS += -Wl,-rpath,`abspath ../3rdparty/nsc-$(NSC_VERSION)`
  endif
endif

#
# pkg-config:
#
HAVE_PKGCFG := $(shell pkg-config --version 2>/dev/null)
ifeq ($(strip $(HAVE_PKGCFG)),)
  HAVE_PKGCFG := no
else
  HAVE_PKGCFG := yes
  PKGCFG := $(shell which pkg-config)
endif

#
# VoipStream feature:
#
ifneq (,$(findstring -DWITH_VOIPSTREAM,$(COPTS)))
  ifeq ($(HAVE_PKGCFG), yes)
    HAVE_FFMPEG := $(shell $(PKGCFG) --exists libavcodec libavformat libavutil && echo yes || echo no)
    ifeq ($(HAVE_FFMPEG), yes)
      LIBS += $(shell $(PKGCFG) --libs libavcodec libavformat libavutil)
      CFLAGS += $(shell $(PKGCFG) --cflags libavcodec libavformat libavutil) -DHAVE_FFMPEG
    endif
  endif
endif

# <<<
#------------------------------------------------------------------------------

# Main target
all: $O/$(TARGET)
	$(Q)$(LN) $O/$(TARGET) .

$O/$(TARGET): $(OBJS)  $(wildcard $(EXTRA_OBJS)) Makefile
	@$(MKPATH) $O
	@echo Creating executable: $@
	$(Q)$(CXX) $(LDFLAGS) -o $O/$(TARGET)  $(OBJS) $(EXTRA_OBJS) $(AS_NEEDED_OFF) $(WHOLE_ARCHIVE_ON) $(LIBS) $(WHOLE_ARCHIVE_OFF) $(OMNETPP_LIBS)

.PHONY: all clean cleanall depend msgheaders

.SUFFIXES: .cc

$O/%.o: %.cc $(COPTS_FILE)
	@$(MKPATH) $(dir $@)
	$(qecho) "$<"
	$(Q)$(CXX) -c $(COPTS) -o $@ $<

%_m.cc %_m.h: %.msg
	$(qecho) MSGC: $<
	$(Q)$(MSGC) -s _m.cc $(MSGCOPTS) $?

msgheaders: $(MSGFILES:.msg=_m.h)

clean:
	$(qecho) Cleaning...
	$(Q)-rm -rf $O
	$(Q)-rm -f inet inet.exe libinet.so libinet.a libinet.dll libinet.dylib
	$(Q)-rm -f ./*_m.cc ./*_m.h
	$(Q)-rm -f applications/*_m.cc applications/*_m.h
	$(Q)-rm -f applications/dhcp/*_m.cc applications/dhcp/*_m.h
	$(Q)-rm -f applications/ethernet/*_m.cc applications/ethernet/*_m.h
	$(Q)-rm -f applications/generic/*_m.cc applications/generic/*_m.h
	$(Q)-rm -f applications/httptools/*_m.cc applications/httptools/*_m.h
	$(Q)-rm -f applications/netperfmeter/*_m.cc applications/netperfmeter/*_m.h
	$(Q)-rm -f applications/pingapp/*_m.cc applications/pingapp/*_m.h
	$(Q)-rm -f applications/rtpapp/*_m.cc applications/rtpapp/*_m.h
	$(Q)-rm -f applications/sctpapp/*_m.cc applications/sctpapp/*_m.h
	$(Q)-rm -f applications/tcpapp/*_m.cc applications/tcpapp/*_m.h
	$(Q)-rm -f applications/traci/*_m.cc applications/traci/*_m.h
	$(Q)-rm -f applications/udpapp/*_m.cc applications/udpapp/*_m.h
	$(Q)-rm -f applications/voip/*_m.cc applications/voip/*_m.h
	$(Q)-rm -f base/*_m.cc base/*_m.h
	$(Q)-rm -f battery/*_m.cc battery/*_m.h
	$(Q)-rm -f battery/models/*_m.cc battery/models/*_m.h
	$(Q)-rm -f linklayer/*_m.cc linklayer/*_m.h
	$(Q)-rm -f linklayer/common/*_m.cc linklayer/common/*_m.h
	$(Q)-rm -f linklayer/contract/*_m.cc linklayer/contract/*_m.h
	$(Q)-rm -f linklayer/ethernet/*_m.cc linklayer/ethernet/*_m.h
	$(Q)-rm -f linklayer/ethernet/switch/*_m.cc linklayer/ethernet/switch/*_m.h
	$(Q)-rm -f linklayer/etherswitch/*_m.cc linklayer/etherswitch/*_m.h
	$(Q)-rm -f linklayer/ext/*_m.cc linklayer/ext/*_m.h
	$(Q)-rm -f linklayer/idealwireless/*_m.cc linklayer/idealwireless/*_m.h
	$(Q)-rm -f linklayer/ieee80211/*_m.cc linklayer/ieee80211/*_m.h
	$(Q)-rm -f linklayer/ieee80211/mac/*_m.cc linklayer/ieee80211/mac/*_m.h
	$(Q)-rm -f linklayer/ieee80211/mgmt/*_m.cc linklayer/ieee80211/mgmt/*_m.h
	$(Q)-rm -f linklayer/ieee80211/radio/*_m.cc linklayer/ieee80211/radio/*_m.h
	$(Q)-rm -f linklayer/ieee80211/radio/errormodel/*_m.cc linklayer/ieee80211/radio/errormodel/*_m.h
	$(Q)-rm -f linklayer/ppp/*_m.cc linklayer/ppp/*_m.h
	$(Q)-rm -f linklayer/queue/*_m.cc linklayer/queue/*_m.h
	$(Q)-rm -f linklayer/radio/*_m.cc linklayer/radio/*_m.h
	$(Q)-rm -f linklayer/radio/propagation/*_m.cc linklayer/radio/propagation/*_m.h
	$(Q)-rm -f mobility/*_m.cc mobility/*_m.h
	$(Q)-rm -f mobility/models/*_m.cc mobility/models/*_m.h
	$(Q)-rm -f networklayer/*_m.cc networklayer/*_m.h
	$(Q)-rm -f networklayer/arp/*_m.cc networklayer/arp/*_m.h
	$(Q)-rm -f networklayer/autorouting/*_m.cc networklayer/autorouting/*_m.h
	$(Q)-rm -f networklayer/autorouting/ipv4/*_m.cc networklayer/autorouting/ipv4/*_m.h
	$(Q)-rm -f networklayer/autorouting/ipv6/*_m.cc networklayer/autorouting/ipv6/*_m.h
	$(Q)-rm -f networklayer/bgpv4/*_m.cc networklayer/bgpv4/*_m.h
	$(Q)-rm -f networklayer/bgpv4/BGPMessage/*_m.cc networklayer/bgpv4/BGPMessage/*_m.h
	$(Q)-rm -f networklayer/common/*_m.cc networklayer/common/*_m.h
	$(Q)-rm -f networklayer/contract/*_m.cc networklayer/contract/*_m.h
	$(Q)-rm -f networklayer/diffserv/*_m.cc networklayer/diffserv/*_m.h
	$(Q)-rm -f networklayer/extras/*_m.cc networklayer/extras/*_m.h
	$(Q)-rm -f networklayer/icmpv6/*_m.cc networklayer/icmpv6/*_m.h
	$(Q)-rm -f networklayer/internetcloud/*_m.cc networklayer/internetcloud/*_m.h
	$(Q)-rm -f networklayer/ipv4/*_m.cc networklayer/ipv4/*_m.h
	$(Q)-rm -f networklayer/ipv6/*_m.cc networklayer/ipv6/*_m.h
	$(Q)-rm -f networklayer/ipv6tunneling/*_m.cc networklayer/ipv6tunneling/*_m.h
	$(Q)-rm -f networklayer/ldp/*_m.cc networklayer/ldp/*_m.h
	$(Q)-rm -f networklayer/manetrouting/*_m.cc networklayer/manetrouting/*_m.h
	$(Q)-rm -f networklayer/manetrouting/aodv/*_m.cc networklayer/manetrouting/aodv/*_m.h
	$(Q)-rm -f networklayer/manetrouting/aodv/aodv-uu/*_m.cc networklayer/manetrouting/aodv/aodv-uu/*_m.h
	$(Q)-rm -f networklayer/manetrouting/base/*_m.cc networklayer/manetrouting/base/*_m.h
	$(Q)-rm -f networklayer/manetrouting/batman/*_m.cc networklayer/manetrouting/batman/*_m.h
	$(Q)-rm -f networklayer/manetrouting/batman/batmand/*_m.cc networklayer/manetrouting/batman/batmand/*_m.h
	$(Q)-rm -f networklayer/manetrouting/batman/batmand/orig/*_m.cc networklayer/manetrouting/batman/batmand/orig/*_m.h
	$(Q)-rm -f networklayer/manetrouting/dsdv/*_m.cc networklayer/manetrouting/dsdv/*_m.h
	$(Q)-rm -f networklayer/manetrouting/dsr/*_m.cc networklayer/manetrouting/dsr/*_m.h
	$(Q)-rm -f networklayer/manetrouting/dsr/dsr-uu/*_m.cc networklayer/manetrouting/dsr/dsr-uu/*_m.h
	$(Q)-rm -f networklayer/manetrouting/dymo/*_m.cc networklayer/manetrouting/dymo/*_m.h
	$(Q)-rm -f networklayer/manetrouting/dymo/dymoum/*_m.cc networklayer/manetrouting/dymo/dymoum/*_m.h
	$(Q)-rm -f networklayer/manetrouting/dymo_fau/*_m.cc networklayer/manetrouting/dymo_fau/*_m.h
	$(Q)-rm -f networklayer/manetrouting/olsr/*_m.cc networklayer/manetrouting/olsr/*_m.h
	$(Q)-rm -f networklayer/mpls/*_m.cc networklayer/mpls/*_m.h
	$(Q)-rm -f networklayer/ospfv2/*_m.cc networklayer/ospfv2/*_m.h
	$(Q)-rm -f networklayer/ospfv2/interface/*_m.cc networklayer/ospfv2/interface/*_m.h
	$(Q)-rm -f networklayer/ospfv2/messagehandler/*_m.cc networklayer/ospfv2/messagehandler/*_m.h
	$(Q)-rm -f networklayer/ospfv2/neighbor/*_m.cc networklayer/ospfv2/neighbor/*_m.h
	$(Q)-rm -f networklayer/ospfv2/router/*_m.cc networklayer/ospfv2/router/*_m.h
	$(Q)-rm -f networklayer/rsvp_te/*_m.cc networklayer/rsvp_te/*_m.h
	$(Q)-rm -f networklayer/ted/*_m.cc networklayer/ted/*_m.h
	$(Q)-rm -f networklayer/xmipv6/*_m.cc networklayer/xmipv6/*_m.h
	$(Q)-rm -f nodes/*_m.cc nodes/*_m.h
	$(Q)-rm -f nodes/bgp/*_m.cc nodes/bgp/*_m.h
	$(Q)-rm -f nodes/ethernet/*_m.cc nodes/ethernet/*_m.h
	$(Q)-rm -f nodes/httptools/*_m.cc nodes/httptools/*_m.h
	$(Q)-rm -f nodes/inet/*_m.cc nodes/inet/*_m.h
	$(Q)-rm -f nodes/internetcloud/*_m.cc nodes/internetcloud/*_m.h
	$(Q)-rm -f nodes/ipv6/*_m.cc nodes/ipv6/*_m.h
	$(Q)-rm -f nodes/mpls/*_m.cc nodes/mpls/*_m.h
	$(Q)-rm -f nodes/ospfv2/*_m.cc nodes/ospfv2/*_m.h
	$(Q)-rm -f nodes/wireless/*_m.cc nodes/wireless/*_m.h
	$(Q)-rm -f nodes/xmipv6/*_m.cc nodes/xmipv6/*_m.h
	$(Q)-rm -f transport/*_m.cc transport/*_m.h
	$(Q)-rm -f transport/contract/*_m.cc transport/contract/*_m.h
	$(Q)-rm -f transport/rtp/*_m.cc transport/rtp/*_m.h
	$(Q)-rm -f transport/rtp/profiles/*_m.cc transport/rtp/profiles/*_m.h
	$(Q)-rm -f transport/rtp/profiles/avprofile/*_m.cc transport/rtp/profiles/avprofile/*_m.h
	$(Q)-rm -f transport/sctp/*_m.cc transport/sctp/*_m.h
	$(Q)-rm -f transport/tcp/*_m.cc transport/tcp/*_m.h
	$(Q)-rm -f transport/tcp/flavours/*_m.cc transport/tcp/flavours/*_m.h
	$(Q)-rm -f transport/tcp/mptcp_extension/*_m.cc transport/tcp/mptcp_extension/*_m.h
	$(Q)-rm -f transport/tcp/mptcp_extension/flavours/*_m.cc transport/tcp/mptcp_extension/flavours/*_m.h
	$(Q)-rm -f transport/tcp/mptcp_extension/mptcp_queues/*_m.cc transport/tcp/mptcp_extension/mptcp_queues/*_m.h
	$(Q)-rm -f transport/tcp/mptcp_extension/mptcp_scheduler/*_m.cc transport/tcp/mptcp_extension/mptcp_scheduler/*_m.h
	$(Q)-rm -f transport/tcp/queues/*_m.cc transport/tcp/queues/*_m.h
	$(Q)-rm -f transport/tcp_common/*_m.cc transport/tcp_common/*_m.h
	$(Q)-rm -f transport/udp/*_m.cc transport/udp/*_m.h
	$(Q)-rm -f util/*_m.cc util/*_m.h
	$(Q)-rm -f util/headerserializers/*_m.cc util/headerserializers/*_m.h
	$(Q)-rm -f util/headerserializers/headers/*_m.cc util/headerserializers/headers/*_m.h
	$(Q)-rm -f util/headerserializers/ipv4/*_m.cc util/headerserializers/ipv4/*_m.h
	$(Q)-rm -f util/headerserializers/ipv4/headers/*_m.cc util/headerserializers/ipv4/headers/*_m.h
	$(Q)-rm -f util/headerserializers/sctp/*_m.cc util/headerserializers/sctp/*_m.h
	$(Q)-rm -f util/headerserializers/sctp/headers/*_m.cc util/headerserializers/sctp/headers/*_m.h
	$(Q)-rm -f util/headerserializers/tcp/*_m.cc util/headerserializers/tcp/*_m.h
	$(Q)-rm -f util/headerserializers/tcp/headers/*_m.cc util/headerserializers/tcp/headers/*_m.h
	$(Q)-rm -f util/headerserializers/udp/*_m.cc util/headerserializers/udp/*_m.h
	$(Q)-rm -f util/headerserializers/udp/headers/*_m.cc util/headerserializers/udp/headers/*_m.h
	$(Q)-rm -f world/*_m.cc world/*_m.h
	$(Q)-rm -f world/annotations/*_m.cc world/annotations/*_m.h
	$(Q)-rm -f world/httptools/*_m.cc world/httptools/*_m.h
	$(Q)-rm -f world/obstacles/*_m.cc world/obstacles/*_m.h
	$(Q)-rm -f world/powercontrol/*_m.cc world/powercontrol/*_m.h
	$(Q)-rm -f world/radio/*_m.cc world/radio/*_m.h
	$(Q)-rm -f world/scenario/*_m.cc world/scenario/*_m.h
	$(Q)-rm -f world/traci/*_m.cc world/traci/*_m.h

cleanall: clean
	$(Q)-rm -rf $(PROJECT_OUTPUT_DIR)

depend:
	$(qecho) Creating dependencies...
	$(Q)$(MAKEDEPEND) $(INCLUDE_PATH) -f Makefile -P\$$O/ -- $(MSG_CC_FILES)  ./*.cc applications/*.cc applications/dhcp/*.cc applications/ethernet/*.cc applications/generic/*.cc applications/httptools/*.cc applications/netperfmeter/*.cc applications/pingapp/*.cc applications/rtpapp/*.cc applications/sctpapp/*.cc applications/tcpapp/*.cc applications/traci/*.cc applications/udpapp/*.cc applications/voip/*.cc base/*.cc battery/*.cc battery/models/*.cc linklayer/*.cc linklayer/common/*.cc linklayer/contract/*.cc linklayer/ethernet/*.cc linklayer/ethernet/switch/*.cc linklayer/etherswitch/*.cc linklayer/ext/*.cc linklayer/idealwireless/*.cc linklayer/ieee80211/*.cc linklayer/ieee80211/mac/*.cc linklayer/ieee80211/mgmt/*.cc linklayer/ieee80211/radio/*.cc linklayer/ieee80211/radio/errormodel/*.cc linklayer/ppp/*.cc linklayer/queue/*.cc linklayer/radio/*.cc linklayer/radio/propagation/*.cc mobility/*.cc mobility/models/*.cc networklayer/*.cc networklayer/arp/*.cc networklayer/autorouting/*.cc networklayer/autorouting/ipv4/*.cc networklayer/autorouting/ipv6/*.cc networklayer/bgpv4/*.cc networklayer/bgpv4/BGPMessage/*.cc networklayer/common/*.cc networklayer/contract/*.cc networklayer/diffserv/*.cc networklayer/extras/*.cc networklayer/icmpv6/*.cc networklayer/internetcloud/*.cc networklayer/ipv4/*.cc networklayer/ipv6/*.cc networklayer/ipv6tunneling/*.cc networklayer/ldp/*.cc networklayer/manetrouting/*.cc networklayer/manetrouting/aodv/*.cc networklayer/manetrouting/aodv/aodv-uu/*.cc networklayer/manetrouting/base/*.cc networklayer/manetrouting/batman/*.cc networklayer/manetrouting/batman/batmand/*.cc networklayer/manetrouting/batman/batmand/orig/*.cc networklayer/manetrouting/dsdv/*.cc networklayer/manetrouting/dsr/*.cc networklayer/manetrouting/dsr/dsr-uu/*.cc networklayer/manetrouting/dymo/*.cc networklayer/manetrouting/dymo/dymoum/*.cc networklayer/manetrouting/dymo_fau/*.cc networklayer/manetrouting/olsr/*.cc networklayer/mpls/*.cc networklayer/ospfv2/*.cc networklayer/ospfv2/interface/*.cc networklayer/ospfv2/messagehandler/*.cc networklayer/ospfv2/neighbor/*.cc networklayer/ospfv2/router/*.cc networklayer/rsvp_te/*.cc networklayer/ted/*.cc networklayer/xmipv6/*.cc nodes/*.cc nodes/bgp/*.cc nodes/ethernet/*.cc nodes/httptools/*.cc nodes/inet/*.cc nodes/internetcloud/*.cc nodes/ipv6/*.cc nodes/mpls/*.cc nodes/ospfv2/*.cc nodes/wireless/*.cc nodes/xmipv6/*.cc transport/*.cc transport/contract/*.cc transport/rtp/*.cc transport/rtp/profiles/*.cc transport/rtp/profiles/avprofile/*.cc transport/sctp/*.cc transport/tcp/*.cc transport/tcp/flavours/*.cc transport/tcp/mptcp_extension/*.cc transport/tcp/mptcp_extension/flavours/*.cc transport/tcp/mptcp_extension/mptcp_queues/*.cc transport/tcp/mptcp_extension/mptcp_scheduler/*.cc transport/tcp/queues/*.cc transport/tcp_common/*.cc transport/udp/*.cc util/*.cc util/headerserializers/*.cc util/headerserializers/headers/*.cc util/headerserializers/ipv4/*.cc util/headerserializers/ipv4/headers/*.cc util/headerserializers/sctp/*.cc util/headerserializers/sctp/headers/*.cc util/headerserializers/tcp/*.cc util/headerserializers/tcp/headers/*.cc util/headerserializers/udp/*.cc util/headerserializers/udp/headers/*.cc world/*.cc world/annotations/*.cc world/httptools/*.cc world/obstacles/*.cc world/powercontrol/*.cc world/radio/*.cc world/scenario/*.cc world/traci/*.cc

# DO NOT DELETE THIS LINE -- make depend depends on it.
$O/applications/dhcp/DHCPClient.o: applications/dhcp/DHCPClient.cc \
  applications/dhcp/Byte.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  base/NotifierConsts.h \
  applications/dhcp/DHCPLease.h \
  base/NotificationBoard.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  applications/dhcp/DHCP_m.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/common/InterfaceTableAccess.h \
  base/INETDefs.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  applications/dhcp/DHCPClient.h \
  networklayer/arp/ARP.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  applications/dhcp/DHCPOptions.h \
  base/ModuleAccess.h \
  transport/contract/UDPSocket.h
$O/applications/dhcp/DHCPServer.o: applications/dhcp/DHCPServer.cc \
  transport/contract/UDPControlInfo_m.h \
  applications/dhcp/Byte.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  base/NotifierConsts.h \
  applications/dhcp/DHCPLease.h \
  base/NotificationBoard.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  applications/dhcp/DHCP_m.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  applications/dhcp/DHCPOptions.h \
  base/ModuleAccess.h \
  applications/dhcp/DHCPServer.h \
  transport/contract/UDPSocket.h
$O/applications/ethernet/EtherAppCli.o: applications/ethernet/EtherAppCli.cc \
  applications/ethernet/EtherAppCli.h \
  linklayer/contract/MACAddress.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  applications/ethernet/EtherApp_m.h
$O/applications/ethernet/EtherAppSrv.o: applications/ethernet/EtherAppSrv.cc \
  linklayer/contract/MACAddress.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  applications/ethernet/EtherApp_m.h \
  applications/ethernet/EtherAppSrv.h
$O/applications/ethernet/EtherTrafGen.o: applications/ethernet/EtherTrafGen.cc \
  linklayer/contract/MACAddress.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  applications/ethernet/EtherTrafGen.h
$O/applications/generic/IPvXTrafGen.o: applications/generic/IPvXTrafGen.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  applications/generic/IPvXTrafSink.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/contract/IPvXAddressResolver.h \
  applications/generic/IPvXTrafGen.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h
$O/applications/generic/IPvXTrafSink.o: applications/generic/IPvXTrafSink.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  applications/generic/IPvXTrafSink.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/contract/IPvXAddressResolver.h \
  applications/generic/IPvXTrafGen.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h
$O/applications/httptools/HttpBrowser.o: applications/httptools/HttpBrowser.cc \
  applications/httptools/HttpBrowser.h \
  applications/httptools/HttpEventMessages_m.h \
  networklayer/contract/IPv6Address.h \
  applications/httptools/HttpBrowserBase.h \
  transport/contract/TCPCommand_m.h \
  applications/httptools/HttpLogdefs.h \
  networklayer/contract/IPv4Address.h \
  applications/httptools/HttpNodeBase.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddressResolver.h \
  applications/httptools/HttpRandom.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpMessages_m.h \
  transport/contract/TCPSocketMap.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpBrowserBase.o: applications/httptools/HttpBrowserBase.cc \
  applications/httptools/HttpEventMessages_m.h \
  applications/httptools/HttpBrowserBase.h \
  applications/httptools/HttpLogdefs.h \
  applications/httptools/HttpNodeBase.h \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpBrowserDirect.o: applications/httptools/HttpBrowserDirect.cc \
  applications/httptools/HttpEventMessages_m.h \
  applications/httptools/HttpBrowserBase.h \
  applications/httptools/HttpLogdefs.h \
  applications/httptools/HttpNodeBase.h \
  applications/httptools/HttpServerBase.h \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpBrowserDirect.h \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpNodeBase.o: applications/httptools/HttpNodeBase.cc \
  applications/httptools/HttpEventMessages_m.h \
  applications/httptools/HttpLogdefs.h \
  applications/httptools/HttpNodeBase.h \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpRandom.o: applications/httptools/HttpRandom.cc \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpServer.o: applications/httptools/HttpServer.cc \
  applications/httptools/HttpEventMessages_m.h \
  networklayer/contract/IPv6Address.h \
  transport/contract/TCPCommand_m.h \
  applications/httptools/HttpLogdefs.h \
  networklayer/contract/IPv4Address.h \
  applications/httptools/HttpServer.h \
  applications/httptools/HttpServerBase.h \
  applications/httptools/HttpNodeBase.h \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpMessages_m.h \
  transport/contract/TCPSocketMap.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpServerBase.o: applications/httptools/HttpServerBase.cc \
  applications/httptools/HttpEventMessages_m.h \
  applications/httptools/HttpLogdefs.h \
  applications/httptools/HttpNodeBase.h \
  applications/httptools/HttpServerBase.h \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpServerDirect.o: applications/httptools/HttpServerDirect.cc \
  applications/httptools/HttpEventMessages_m.h \
  applications/httptools/HttpLogdefs.h \
  applications/httptools/HttpServerBase.h \
  applications/httptools/HttpNodeBase.h \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpUtils.h \
  applications/httptools/HttpServerDirect.h
$O/applications/httptools/HttpServerDirectEvilA.o: applications/httptools/HttpServerDirectEvilA.cc \
  applications/httptools/HttpEventMessages_m.h \
  applications/httptools/HttpLogdefs.h \
  applications/httptools/HttpNodeBase.h \
  applications/httptools/HttpServerBase.h \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  applications/httptools/HttpServerDirectEvilA.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpServerDirect.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpServerDirectEvilB.o: applications/httptools/HttpServerDirectEvilB.cc \
  applications/httptools/HttpEventMessages_m.h \
  applications/httptools/HttpLogdefs.h \
  applications/httptools/HttpNodeBase.h \
  applications/httptools/HttpServerBase.h \
  base/INETDefs.h \
  applications/httptools/HttpServerDirectEvilB.h \
  applications/httptools/HttpRandom.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpServerDirect.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpServerEvilA.o: applications/httptools/HttpServerEvilA.cc \
  applications/httptools/HttpEventMessages_m.h \
  networklayer/contract/IPv6Address.h \
  applications/httptools/HttpLogdefs.h \
  transport/contract/TCPCommand_m.h \
  applications/httptools/HttpServer.h \
  networklayer/contract/IPv4Address.h \
  applications/httptools/HttpNodeBase.h \
  applications/httptools/HttpServerBase.h \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  transport/contract/TCPSocket.h \
  applications/httptools/HttpServerEvilA.h \
  world/httptools/HttpController.h \
  networklayer/contract/IPvXAddress.h \
  applications/httptools/HttpMessages_m.h \
  transport/contract/TCPSocketMap.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpServerEvilB.o: applications/httptools/HttpServerEvilB.cc \
  applications/httptools/HttpEventMessages_m.h \
  networklayer/contract/IPv6Address.h \
  applications/httptools/HttpLogdefs.h \
  transport/contract/TCPCommand_m.h \
  applications/httptools/HttpServer.h \
  networklayer/contract/IPv4Address.h \
  applications/httptools/HttpNodeBase.h \
  applications/httptools/HttpServerBase.h \
  base/INETDefs.h \
  applications/httptools/HttpRandom.h \
  transport/contract/TCPSocket.h \
  world/httptools/HttpController.h \
  networklayer/contract/IPvXAddress.h \
  applications/httptools/HttpMessages_m.h \
  transport/contract/TCPSocketMap.h \
  applications/httptools/HttpServerEvilB.h \
  applications/httptools/HttpUtils.h
$O/applications/httptools/HttpUtils.o: applications/httptools/HttpUtils.cc \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpUtils.h
$O/applications/netperfmeter/NetPerfMeter.o: applications/netperfmeter/NetPerfMeter.cc \
  applications/netperfmeter/NetPerfMeter.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  transport/contract/SCTPSocket.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPCommand_m.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  applications/netperfmeter/NetPerfMeter_m.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/QoSStatsCollector.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  util/common.h \
  transport/sctp/ChunkMap.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPReceiveStream.h \
  transport/sctp/SCTPMessage.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  transport/contract/UDPControlInfo_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/contract/TCPSocket.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/pingapp/PingApp.o: applications/pingapp/PingApp.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  applications/pingapp/PingPayload_m.h \
  applications/pingapp/PingApp.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h
$O/applications/pingapp/PingTestApp.o: applications/pingapp/PingTestApp.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  applications/pingapp/PingPayload_m.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/contract/IPv6ControlInfo.h \
  applications/pingapp/PingTestApp.h \
  networklayer/contract/IPvXAddress.h
$O/applications/rtpapp/RTPApplication.o: applications/rtpapp/RTPApplication.cc \
  networklayer/contract/IPv6Address.h \
  transport/rtp/RTPInterfacePacket_m.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  transport/rtp/RTPSenderControlMessage_m.h \
  base/INETDefs.h \
  transport/rtp/RTPSenderStatusMessage_m.h \
  applications/rtpapp/RTPApplication.h \
  networklayer/contract/IPvXAddress.h
$O/applications/sctpapp/SCTPClient.o: applications/sctpapp/SCTPClient.cc \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTP.h \
  networklayer/common/IInterfaceTable.h \
  transport/contract/SCTPSocket.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPCommand_m.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  applications/sctpapp/SCTPClient.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  transport/sctp/SCTPMessage_m.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/sctpapp/SCTPNatPeer.o: applications/sctpapp/SCTPNatPeer.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPSocket.h \
  transport/contract/SCTPCommand_m.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/QoSStatsCollector.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  util/common.h \
  transport/sctp/ChunkMap.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPReceiveStream.h \
  transport/sctp/SCTPMessage.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  applications/sctpapp/SCTPNatPeer.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/sctpapp/SCTPNatServer.o: applications/sctpapp/SCTPNatServer.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPSocket.h \
  transport/contract/SCTPCommand_m.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/QoSStatsCollector.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  util/common.h \
  transport/sctp/ChunkMap.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPReceiveStream.h \
  transport/sctp/SCTPMessage.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  applications/sctpapp/SCTPNatServer.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/sctpapp/SCTPPeer.o: applications/sctpapp/SCTPPeer.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPSocket.h \
  transport/contract/SCTPCommand_m.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/QoSStatsCollector.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  util/common.h \
  transport/sctp/ChunkMap.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPReceiveStream.h \
  transport/sctp/SCTPMessage.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  applications/sctpapp/SCTPPeer.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/sctpapp/SCTPServer.o: applications/sctpapp/SCTPServer.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPSocket.h \
  transport/contract/SCTPCommand_m.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/QoSStatsCollector.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  util/common.h \
  transport/sctp/ChunkMap.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPReceiveStream.h \
  transport/sctp/SCTPMessage.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  applications/sctpapp/SCTPServer.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/tcpapp/TCPBasicClientApp.o: applications/tcpapp/TCPBasicClientApp.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  applications/tcpapp/TCPGenericCliAppBase.h \
  applications/tcpapp/TCPBasicClientApp.h
$O/applications/tcpapp/TCPEchoApp.o: applications/tcpapp/TCPEchoApp.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  base/ByteArray_m.h \
  base/ByteArrayMessage.h \
  base/ByteArrayMessage_m.h \
  base/ByteArray.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  applications/tcpapp/TCPEchoApp.h
$O/applications/tcpapp/TCPGenericCliAppBase.o: applications/tcpapp/TCPGenericCliAppBase.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  applications/tcpapp/GenericAppMsg_m.h \
  networklayer/contract/IPvXAddressResolver.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  applications/tcpapp/TCPGenericCliAppBase.h
$O/applications/tcpapp/TCPGenericSrvApp.o: applications/tcpapp/TCPGenericSrvApp.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  applications/tcpapp/GenericAppMsg_m.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  applications/tcpapp/TCPGenericSrvApp.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h
$O/applications/tcpapp/TCPGenericSrvThread.o: applications/tcpapp/TCPGenericSrvThread.cc \
  applications/tcpapp/TCPSrvHostApp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  applications/tcpapp/GenericAppMsg_m.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  applications/tcpapp/TCPGenericSrvThread.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/TCPSocketMap.h
$O/applications/tcpapp/TCPSessionApp.o: applications/tcpapp/TCPSessionApp.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  applications/tcpapp/GenericAppMsg_m.h \
  base/ByteArray_m.h \
  base/ByteArrayMessage.h \
  networklayer/contract/IPvXAddressResolver.h \
  base/ByteArrayMessage_m.h \
  applications/tcpapp/TCPSessionApp.h \
  base/ByteArray.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h
$O/applications/tcpapp/TCPSinkApp.o: applications/tcpapp/TCPSinkApp.cc \
  applications/tcpapp/TCPSinkApp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h
$O/applications/tcpapp/TCPSrvHostApp.o: applications/tcpapp/TCPSrvHostApp.cc \
  applications/tcpapp/TCPSrvHostApp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/TCPSocketMap.h
$O/applications/tcpapp/TelnetApp.o: applications/tcpapp/TelnetApp.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  applications/tcpapp/TelnetApp.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  applications/tcpapp/TCPGenericCliAppBase.h
$O/applications/traci/TraCIDemo.o: applications/traci/TraCIDemo.cc \
  base/BasicModule.h \
  util/FWMath.h \
  ./mobility/models/MobilityBase.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  base/Coord.h \
  base/INotifiable.h \
  ./applications/traci/TraCIDemo.h \
  ./world/traci/TraCIScenarioManager.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  ./mobility/models/TraCIMobility.h \
  transport/contract/UDPSocket.h
$O/applications/traci/TraCITestApp.o: applications/traci/TraCITestApp.cc \
  base/BasicModule.h \
  util/FWMath.h \
  ./mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  ./world/traci/TraCIScenarioManager.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  ./applications/traci/TraCITestApp.h \
  base/INETDefs.h \
  ./mobility/models/TraCIMobility.h
$O/applications/udpapp/UDPBasicApp.o: applications/udpapp/UDPBasicApp.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/ModuleAccess.h \
  transport/contract/UDPControlInfo_m.h \
  base/NotifierConsts.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  applications/udpapp/UDPBasicApp.h \
  transport/contract/UDPSocket.h
$O/applications/udpapp/UDPBasicBurst.o: applications/udpapp/UDPBasicBurst.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  transport/contract/UDPControlInfo_m.h \
  applications/udpapp/UDPBasicBurst.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/udpapp/UDPEchoApp.o: applications/udpapp/UDPEchoApp.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  applications/udpapp/UDPEchoApp.h \
  transport/contract/UDPControlInfo_m.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/udpapp/UDPSink.o: applications/udpapp/UDPSink.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  applications/udpapp/UDPSink.h \
  transport/contract/UDPControlInfo_m.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/udpapp/UDPVideoStreamCli.o: applications/udpapp/UDPVideoStreamCli.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  transport/contract/UDPControlInfo_m.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  applications/udpapp/UDPVideoStreamCli.h \
  transport/contract/UDPSocket.h
$O/applications/udpapp/UDPVideoStreamSvr.o: applications/udpapp/UDPVideoStreamSvr.cc \
  networklayer/contract/IPv6Address.h \
  applications/udpapp/UDPVideoStreamSvr.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/UDPControlInfo_m.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/voip/SimpleVoIPReceiver.o: applications/voip/SimpleVoIPReceiver.cc \
  networklayer/contract/IPv6Address.h \
  applications/voip/SimpleVoIPPacket_m.h \
  applications/voip/SimpleVoIPReceiver.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/applications/voip/SimpleVoIPSender.o: applications/voip/SimpleVoIPSender.cc \
  applications/voip/SimpleVoIPSender.h \
  networklayer/contract/IPv6Address.h \
  applications/voip/SimpleVoIPPacket_m.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/base/AbstractQueue.o: base/AbstractQueue.cc \
  base/AbstractQueue.h \
  base/INETDefs.h
$O/base/BasicModule.o: base/BasicModule.cc \
  base/BasicModule.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h
$O/base/ByteArray.o: base/ByteArray.cc \
  base/ByteArray_m.h \
  base/ByteArray.h \
  base/INETDefs.h
$O/base/ByteArrayBuffer.o: base/ByteArrayBuffer.cc \
  base/ByteArray_m.h \
  base/ByteArrayBuffer.h \
  base/ByteArray.h \
  base/INETDefs.h
$O/base/ByteArrayMessage.o: base/ByteArrayMessage.cc \
  base/ByteArray_m.h \
  base/ByteArrayMessage.h \
  base/ByteArrayMessage_m.h \
  base/ByteArray.h \
  base/INETDefs.h
$O/base/Coord.o: base/Coord.cc \
  util/FWMath.h \
  base/Coord.h \
  base/INETDefs.h
$O/base/Join.o: base/Join.cc \
  base/INETDefs.h
$O/base/ModuleAccess.o: base/ModuleAccess.cc \
  base/ModuleAccess.h \
  base/INETDefs.h
$O/base/NedFunctions.o: base/NedFunctions.cc \
  base/INETDefs.h
$O/base/NotificationBoard.o: base/NotificationBoard.cc \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h
$O/base/NotifierConsts.o: base/NotifierConsts.cc \
  base/NotifierConsts.h \
  base/INETDefs.h
$O/base/PassiveQueueBase.o: base/PassiveQueueBase.cc \
  base/IPassiveQueue.h \
  base/PassiveQueueBase.h \
  base/INETDefs.h
$O/base/ProtocolMap.o: base/ProtocolMap.cc \
  base/INETDefs.h \
  base/ProtocolMap.h
$O/base/QueueBase.o: base/QueueBase.cc \
  base/AbstractQueue.h \
  base/QueueBase.h \
  base/INETDefs.h
$O/base/QueueWithQoS.o: base/QueueWithQoS.cc \
  base/AbstractQueue.h \
  base/EnqueueHook.h \
  base/INETDefs.h \
  base/QueueWithQoS.h
$O/base/ReassemblyBuffer.o: base/ReassemblyBuffer.cc \
  base/ReassemblyBuffer.h \
  base/INETDefs.h
$O/base/ResultFilters.o: base/ResultFilters.cc \
  util/FWMath.h \
  base/Coord.h \
  base/ResultFilters.h \
  mobility/IMobility.h \
  base/INETDefs.h
$O/base/Sink.o: base/Sink.cc \
  base/Sink.h \
  base/INETDefs.h
$O/base/Topology.o: base/Topology.cc \
  base/Topology.h \
  util/PatternMatcher.h \
  util/stlutils.h \
  base/INETDefs.h
$O/base/UnimplementedModule.o: base/UnimplementedModule.cc \
  base/UnimplementedModule.h \
  base/INETDefs.h
$O/base/WeightedTopology.o: base/WeightedTopology.cc \
  base/WeightedTopology.h \
  base/INETDefs.h
$O/base/erfc.o: base/erfc.cc \
  base/INETDefs.h
$O/battery/models/BasicBattery.o: battery/models/BasicBattery.cc \
  base/INotifiable.h \
  base/ModuleAccess.h \
  battery/models/BasicBattery.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h
$O/battery/models/InetSimpleBattery.o: battery/models/InetSimpleBattery.cc \
  battery/models/InetSimpleBattery.h \
  battery/models/Energy.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  battery/models/BasicBattery.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/contract/RadioState.h \
  base/INETDefs.h
$O/linklayer/common/WirelessMacBase.o: linklayer/common/WirelessMacBase.cc \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  linklayer/common/WirelessMacBase.h
$O/linklayer/contract/MACAddress.o: linklayer/contract/MACAddress.cc \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceToken.h \
  base/INETDefs.h
$O/linklayer/ethernet/EtherBus.o: linklayer/ethernet/EtherBus.cc \
  base/INETDefs.h \
  linklayer/ethernet/EtherBus.h
$O/linklayer/ethernet/EtherEncap.o: linklayer/ethernet/EtherEncap.cc \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  linklayer/ethernet/Ethernet.h \
  linklayer/ethernet/EtherFrame_m.h \
  base/NotifierConsts.h \
  linklayer/ethernet/EtherEncap.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h
$O/linklayer/ethernet/EtherFrameClassifier.o: linklayer/ethernet/EtherFrameClassifier.cc \
  linklayer/ethernet/EtherFrameClassifier.h \
  linklayer/contract/MACAddress.h \
  linklayer/ethernet/Ethernet.h \
  linklayer/ethernet/EtherFrame_m.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h
$O/linklayer/ethernet/EtherHub.o: linklayer/ethernet/EtherHub.cc \
  base/INETDefs.h \
  linklayer/ethernet/EtherHub.h
$O/linklayer/ethernet/EtherLLC.o: linklayer/ethernet/EtherLLC.cc \
  linklayer/contract/MACAddress.h \
  linklayer/ethernet/EtherLLC.h \
  linklayer/ethernet/Ethernet.h \
  linklayer/ethernet/EtherFrame_m.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h
$O/linklayer/ethernet/EtherMAC.o: linklayer/ethernet/EtherMAC.cc \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  linklayer/ethernet/EtherMACBase.h \
  linklayer/ethernet/EtherMAC.h \
  linklayer/ethernet/Ethernet.h \
  linklayer/ethernet/EtherFrame_m.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h
$O/linklayer/ethernet/EtherMACBase.o: linklayer/ethernet/EtherMACBase.cc \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/IPassiveQueue.h \
  networklayer/common/InterfaceEntry.h \
  linklayer/ethernet/EtherMACBase.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ethernet/Ethernet.h \
  base/ModuleAccess.h \
  linklayer/ethernet/EtherFrame_m.h \
  base/NotifierConsts.h \
  util/opp_utils.h \
  base/NotificationBoard.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h
$O/linklayer/ethernet/EtherMACFullDuplex.o: linklayer/ethernet/EtherMACFullDuplex.cc \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  linklayer/ethernet/EtherMACFullDuplex.h \
  linklayer/ethernet/EtherMACBase.h \
  base/INotifiable.h \
  linklayer/ethernet/Ethernet.h \
  base/ModuleAccess.h \
  linklayer/ethernet/EtherFrame_m.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h
$O/linklayer/ethernet/switch/MACRelayUnitBase.o: linklayer/ethernet/switch/MACRelayUnitBase.cc \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  linklayer/ethernet/EtherMACBase.h \
  linklayer/ethernet/Ethernet.h \
  linklayer/ethernet/switch/MACRelayUnitBase.h \
  linklayer/ethernet/EtherFrame_m.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h
$O/linklayer/ethernet/switch/MACRelayUnitNP.o: linklayer/ethernet/switch/MACRelayUnitNP.cc \
  linklayer/contract/MACAddress.h \
  linklayer/ethernet/Ethernet.h \
  linklayer/ethernet/switch/MACRelayUnitBase.h \
  linklayer/ethernet/EtherFrame_m.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h \
  linklayer/ethernet/switch/MACRelayUnitNP.h
$O/linklayer/ethernet/switch/MACRelayUnitPP.o: linklayer/ethernet/switch/MACRelayUnitPP.cc \
  linklayer/contract/MACAddress.h \
  linklayer/ethernet/Ethernet.h \
  linklayer/ethernet/switch/MACRelayUnitBase.h \
  linklayer/ethernet/EtherFrame_m.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h \
  linklayer/ethernet/switch/MACRelayUnitPP.h
$O/linklayer/ext/ExtInterface.o: linklayer/ext/ExtInterface.cc \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/ext/ExtFrame_m.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  base/ModuleAccess.h \
  linklayer/ext/cSocketRTScheduler.h \
  base/NotifierConsts.h \
  util/opp_utils.h \
  base/NotificationBoard.h \
  util/headerserializers/ipv4/IPv4Serializer.h \
  base/INETDefs.h \
  util/headerserializers/headers/bsdint.h \
  networklayer/common/InterfaceTable.h \
  linklayer/ext/ExtInterface.h \
  networklayer/ipv4/IPv4Datagram.h
$O/linklayer/ext/cSocketRTScheduler.o: linklayer/ext/cSocketRTScheduler.cc \
  linklayer/ext/ExtFrame_m.h \
  linklayer/ext/cSocketRTScheduler.h \
  base/INETDefs.h \
  util/headerserializers/headers/bsdint.h \
  util/headerserializers/headers/ethernet.h
$O/linklayer/idealwireless/IdealWirelessMac.o: linklayer/idealwireless/IdealWirelessMac.cc \
  util/FWMath.h \
  base/BasicModule.h \
  world/radio/IdealChannelModel.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/radio/IdealRadio.h \
  networklayer/common/InterfaceEntry.h \
  base/IPassiveQueue.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/idealwireless/IdealWirelessMac.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  util/opp_utils.h \
  base/NotificationBoard.h \
  linklayer/radio/IdealAirFrame_m.h \
  linklayer/contract/RadioState.h \
  world/radio/IdealChannelModelAccess.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/idealwireless/IdealWirelessFrame_m.h \
  world/powercontrol/IPowerControl.h \
  linklayer/common/WirelessMacBase.h
$O/linklayer/ieee80211/mac/Ieee80211DataRate.o: linklayer/ieee80211/mac/Ieee80211DataRate.cc \
  linklayer/ieee80211/radio/WifiPreambleType.h \
  linklayer/ieee80211/mac/Ieee80211DataRate.h \
  base/INETDefs.h \
  linklayer/radio/ModulationType.h \
  linklayer/ieee80211/mac/WifiMode.h
$O/linklayer/ieee80211/mac/Ieee80211Mac.o: linklayer/ieee80211/mac/Ieee80211Mac.cc \
  util/FWMath.h \
  linklayer/ieee80211/radio/WifiPreambleType.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  base/IPassiveQueue.h \
  linklayer/ieee80211/mac/Ieee80211Mac.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/INotifiable.h \
  linklayer/radio/AirFrame_m.h \
  linklayer/ieee80211/mac/Ieee80211DataRate.h \
  base/FSMA.h \
  base/ModuleAccess.h \
  linklayer/ieee80211/mac/WirelessMacBase.h \
  linklayer/ieee80211/mac/Ieee80211eClassifier.h \
  base/NotifierConsts.h \
  linklayer/ieee80211/mac/IQoSClassifier.h \
  base/NotificationBoard.h \
  linklayer/contract/RadioState.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  linklayer/radio/ModulationType.h \
  linklayer/contract/PhyControlInfo_m.h \
  linklayer/radio/Radio80211aControlInfo_m.h \
  linklayer/ieee80211/mac/WifiMode.h
$O/linklayer/ieee80211/mac/Ieee80211eClassifier.o: linklayer/ieee80211/mac/Ieee80211eClassifier.cc \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv6/IPv6Datagram.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  transport/udp/UDPPacket_m.h \
  linklayer/ieee80211/mac/Ieee80211eClassifier.h \
  base/ByteArray.h \
  linklayer/ieee80211/mac/IQoSClassifier.h \
  networklayer/icmpv6/ICMPv6Message_m.h \
  networklayer/ipv4/ICMPMessage_m.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/ipv4/IPv4Datagram.h
$O/linklayer/ieee80211/mac/WifiMode.o: linklayer/ieee80211/mac/WifiMode.cc \
  linklayer/ieee80211/radio/WifiPreambleType.h \
  linklayer/ieee80211/mac/Ieee80211DataRate.h \
  base/INETDefs.h \
  linklayer/radio/ModulationType.h \
  linklayer/ieee80211/mac/WifiMode.h
$O/linklayer/ieee80211/mgmt/Ieee80211AgentSTA.o: linklayer/ieee80211/mgmt/Ieee80211AgentSTA.cc \
  linklayer/ieee80211/mgmt/Ieee80211AgentSTA.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  linklayer/ieee80211/mgmt/Ieee80211Primitives_m.h \
  networklayer/common/InterfaceToken.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/common/InterfaceTable.h
$O/linklayer/ieee80211/mgmt/Ieee80211Etx.o: linklayer/ieee80211/mgmt/Ieee80211Etx.cc \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211Etx.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  linklayer/radio/ModulationType.h \
  linklayer/ieee80211/mgmt/ETXPacket_m.h \
  linklayer/radio/Radio80211aControlInfo_m.h
$O/linklayer/ieee80211/mgmt/Ieee80211MgmtAP.o: linklayer/ieee80211/mgmt/Ieee80211MgmtAP.cc \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAPBase.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  linklayer/ethernet/Ethernet.h \
  base/PassiveQueueBase.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAP.h \
  base/ModuleAccess.h \
  linklayer/ethernet/EtherFrame_m.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtBase.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  linklayer/contract/RadioState.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h
$O/linklayer/ieee80211/mgmt/Ieee80211MgmtAPBase.o: linklayer/ieee80211/mgmt/Ieee80211MgmtAPBase.cc \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAPBase.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/INotifiable.h \
  linklayer/ethernet/Ethernet.h \
  base/PassiveQueueBase.h \
  base/ModuleAccess.h \
  linklayer/ethernet/EtherFrame_m.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtBase.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h
$O/linklayer/ieee80211/mgmt/Ieee80211MgmtAPSimplified.o: linklayer/ieee80211/mgmt/Ieee80211MgmtAPSimplified.cc \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAPBase.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  linklayer/ethernet/Ethernet.h \
  base/PassiveQueueBase.h \
  base/ModuleAccess.h \
  linklayer/ethernet/EtherFrame_m.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtBase.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAPSimplified.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h
$O/linklayer/ieee80211/mgmt/Ieee80211MgmtAdhoc.o: linklayer/ieee80211/mgmt/Ieee80211MgmtAdhoc.cc \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/INotifiable.h \
  base/PassiveQueueBase.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtBase.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAdhoc.h
$O/linklayer/ieee80211/mgmt/Ieee80211MgmtAdhocWithEtx.o: linklayer/ieee80211/mgmt/Ieee80211MgmtAdhocWithEtx.cc \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/PassiveQueueBase.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtBase.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  linklayer/ieee80211/mgmt/Ieee80211Etx.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAdhocWithEtx.h \
  linklayer/ieee80211/mgmt/ETXPacket_m.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAdhoc.h
$O/linklayer/ieee80211/mgmt/Ieee80211MgmtBase.o: linklayer/ieee80211/mgmt/Ieee80211MgmtBase.cc \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/PassiveQueueBase.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtBase.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h
$O/linklayer/ieee80211/mgmt/Ieee80211MgmtSTA.o: linklayer/ieee80211/mgmt/Ieee80211MgmtSTA.cc \
  base/BasicModule.h \
  util/FWMath.h \
  linklayer/contract/MACAddress.h \
  linklayer/ieee80211/mgmt/Ieee80211Primitives_m.h \
  base/IPassiveQueue.h \
  base/Coord.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/INotifiable.h \
  world/radio/ChannelAccess.h \
  base/PassiveQueueBase.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtBase.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  linklayer/contract/RadioState.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  linklayer/radio/ModulationType.h \
  linklayer/contract/PhyControlInfo_m.h \
  linklayer/radio/Radio80211aControlInfo_m.h \
  world/radio/IChannelControl.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtSTA.h
$O/linklayer/ieee80211/mgmt/Ieee80211MgmtSTASimplified.o: linklayer/ieee80211/mgmt/Ieee80211MgmtSTASimplified.cc \
  linklayer/contract/MACAddress.h \
  base/IPassiveQueue.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtSTASimplified.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/INotifiable.h \
  base/PassiveQueueBase.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtBase.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h
$O/linklayer/ieee80211/radio/BerParseFile.o: linklayer/ieee80211/radio/BerParseFile.cc \
  linklayer/ieee80211/radio/BerParseFile.h \
  base/INETDefs.h
$O/linklayer/ieee80211/radio/Ieee80211RadioModel.o: linklayer/ieee80211/radio/Ieee80211RadioModel.cc \
  util/FWMath.h \
  linklayer/ieee80211/radio/WifiPreambleType.h \
  linklayer/radio/IRadioModel.h \
  linklayer/ieee80211/radio/BerParseFile.h \
  linklayer/ieee80211/radio/Ieee80211RadioModel.h \
  linklayer/ieee80211/radio/errormodel/yans-error-rate-model.h \
  base/Coord.h \
  linklayer/radio/AirFrame_m.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  linklayer/ieee80211/radio/errormodel/nist-error-rate-model.h \
  linklayer/ieee80211/radio/errormodel/dsss-error-rate-model.h \
  linklayer/ieee80211/radio/errormodel/IErrorModel.h \
  base/INETDefs.h \
  linklayer/radio/ModulationType.h \
  linklayer/ieee80211/mac/WifiMode.h \
  linklayer/radio/SnrList.h
$O/linklayer/ieee80211/radio/errormodel/dsss-error-rate-model.o: linklayer/ieee80211/radio/errormodel/dsss-error-rate-model.cc \
  linklayer/ieee80211/radio/errormodel/dsss-error-rate-model.h \
  base/INETDefs.h
$O/linklayer/ieee80211/radio/errormodel/nist-error-rate-model.o: linklayer/ieee80211/radio/errormodel/nist-error-rate-model.cc \
  linklayer/ieee80211/radio/WifiPreambleType.h \
  linklayer/ieee80211/radio/errormodel/nist-error-rate-model.h \
  linklayer/ieee80211/radio/errormodel/dsss-error-rate-model.h \
  linklayer/ieee80211/radio/errormodel/IErrorModel.h \
  base/INETDefs.h \
  linklayer/radio/ModulationType.h \
  linklayer/ieee80211/mac/WifiMode.h
$O/linklayer/ieee80211/radio/errormodel/yans-error-rate-model.o: linklayer/ieee80211/radio/errormodel/yans-error-rate-model.cc \
  linklayer/ieee80211/radio/WifiPreambleType.h \
  linklayer/ieee80211/radio/errormodel/yans-error-rate-model.h \
  linklayer/ieee80211/radio/errormodel/dsss-error-rate-model.h \
  linklayer/ieee80211/radio/errormodel/IErrorModel.h \
  base/INETDefs.h \
  linklayer/radio/ModulationType.h \
  linklayer/ieee80211/mac/WifiMode.h
$O/linklayer/ppp/PPP.o: linklayer/ppp/PPP.cc \
  linklayer/contract/TxNotifDetails.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  base/IPassiveQueue.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  util/opp_utils.h \
  base/NotificationBoard.h \
  linklayer/ppp/PPP.h \
  base/INETDefs.h \
  linklayer/ppp/PPPFrame_m.h
$O/linklayer/queue/AlgorithmicDropperBase.o: linklayer/queue/AlgorithmicDropperBase.cc \
  linklayer/queue/AlgorithmicDropperBase.h \
  linklayer/queue/IQueueAccess.h \
  base/INETDefs.h
$O/linklayer/queue/DropTailQueue.o: linklayer/queue/DropTailQueue.cc \
  base/IPassiveQueue.h \
  base/PassiveQueueBase.h \
  linklayer/queue/DropTailQueue.h \
  base/INETDefs.h
$O/linklayer/queue/FIFOQueue.o: linklayer/queue/FIFOQueue.cc \
  linklayer/queue/FIFOQueue.h \
  base/IPassiveQueue.h \
  base/PassiveQueueBase.h \
  linklayer/queue/IQueueAccess.h \
  base/INETDefs.h
$O/linklayer/queue/PriorityScheduler.o: linklayer/queue/PriorityScheduler.cc \
  linklayer/queue/SchedulerBase.h \
  base/IPassiveQueue.h \
  base/INETDefs.h \
  linklayer/queue/PriorityScheduler.h
$O/linklayer/queue/REDDropper.o: linklayer/queue/REDDropper.cc \
  linklayer/queue/AlgorithmicDropperBase.h \
  linklayer/queue/IQueueAccess.h \
  util/opp_utils.h \
  base/INETDefs.h \
  linklayer/queue/REDDropper.h
$O/linklayer/queue/SchedulerBase.o: linklayer/queue/SchedulerBase.cc \
  linklayer/queue/SchedulerBase.h \
  base/IPassiveQueue.h \
  base/INETDefs.h
$O/linklayer/queue/ThresholdDropper.o: linklayer/queue/ThresholdDropper.cc \
  linklayer/queue/AlgorithmicDropperBase.h \
  linklayer/queue/IQueueAccess.h \
  linklayer/queue/ThresholdDropper.h \
  base/INETDefs.h
$O/linklayer/queue/WRRScheduler.o: linklayer/queue/WRRScheduler.cc \
  linklayer/queue/SchedulerBase.h \
  base/IPassiveQueue.h \
  util/opp_utils.h \
  base/INETDefs.h \
  linklayer/queue/WRRScheduler.h
$O/linklayer/radio/GenericRadioModel.o: linklayer/radio/GenericRadioModel.cc \
  util/FWMath.h \
  linklayer/radio/IRadioModel.h \
  linklayer/radio/Modulation.h \
  base/Coord.h \
  linklayer/radio/GenericRadioModel.h \
  linklayer/radio/AirFrame_m.h \
  base/INETDefs.h \
  linklayer/radio/ModulationType.h \
  linklayer/radio/IModulation.h \
  linklayer/radio/SnrList.h
$O/linklayer/radio/IdealRadio.o: linklayer/radio/IdealRadio.cc \
  util/FWMath.h \
  base/BasicModule.h \
  world/radio/IdealChannelModel.h \
  linklayer/radio/IdealRadio.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/radio/IdealAirFrame_m.h \
  linklayer/contract/RadioState.h \
  base/INETDefs.h \
  world/radio/IdealChannelModelAccess.h \
  world/powercontrol/IPowerControl.h
$O/linklayer/radio/Modulation.o: linklayer/radio/Modulation.cc \
  linklayer/radio/Modulation.h \
  base/INETDefs.h \
  linklayer/radio/IModulation.h
$O/linklayer/radio/Radio.o: linklayer/radio/Radio.cc \
  base/BasicModule.h \
  util/FWMath.h \
  ./world/obstacles/Obstacle.h \
  linklayer/radio/IRadioModel.h \
  linklayer/radio/Radio.h \
  base/Coord.h \
  world/radio/ChannelAccess.h \
  linklayer/radio/AirFrame_m.h \
  base/INotifiable.h \
  ./world/annotations/AnnotationManager.h \
  linklayer/radio/INoiseGenerator.h \
  base/ModuleAccess.h \
  linklayer/radio/propagation/IReceptionModel.h \
  battery/models/BasicBattery.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  world/obstacles/ObstacleControl.h \
  linklayer/contract/RadioState.h \
  base/INETDefs.h \
  linklayer/radio/ModulationType.h \
  linklayer/contract/PhyControlInfo_m.h \
  linklayer/radio/Radio80211aControlInfo_m.h \
  world/radio/IChannelControl.h \
  world/powercontrol/IPowerControl.h \
  linklayer/radio/SnrList.h
$O/linklayer/radio/propagation/FreeSpaceModel.o: linklayer/radio/propagation/FreeSpaceModel.cc \
  base/BasicModule.h \
  util/FWMath.h \
  base/Coord.h \
  base/INotifiable.h \
  world/radio/ChannelAccess.h \
  base/ModuleAccess.h \
  linklayer/radio/propagation/IReceptionModel.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  linklayer/radio/propagation/FreeSpaceModel.h \
  world/radio/IChannelControl.h
$O/linklayer/radio/propagation/LogNormalShadowingModel.o: linklayer/radio/propagation/LogNormalShadowingModel.cc \
  util/FWMath.h \
  linklayer/radio/propagation/LogNormalShadowingModel.h \
  linklayer/radio/propagation/IReceptionModel.h \
  base/INETDefs.h \
  linklayer/radio/propagation/FreeSpaceModel.h
$O/linklayer/radio/propagation/NakagamiModel.o: linklayer/radio/propagation/NakagamiModel.cc \
  util/FWMath.h \
  linklayer/radio/propagation/NakagamiModel.h \
  linklayer/radio/propagation/IReceptionModel.h \
  base/INETDefs.h \
  linklayer/radio/propagation/FreeSpaceModel.h
$O/linklayer/radio/propagation/RayleighModel.o: linklayer/radio/propagation/RayleighModel.cc \
  util/FWMath.h \
  linklayer/radio/propagation/IReceptionModel.h \
  base/INETDefs.h \
  linklayer/radio/propagation/FreeSpaceModel.h \
  linklayer/radio/propagation/RayleighModel.h
$O/linklayer/radio/propagation/RiceModel.o: linklayer/radio/propagation/RiceModel.cc \
  util/FWMath.h \
  linklayer/radio/propagation/IReceptionModel.h \
  base/INETDefs.h \
  linklayer/radio/propagation/FreeSpaceModel.h \
  linklayer/radio/propagation/RiceModel.h
$O/linklayer/radio/propagation/TwoRayGroundModel.o: linklayer/radio/propagation/TwoRayGroundModel.cc \
  util/FWMath.h \
  linklayer/radio/propagation/TwoRayGroundModel.h \
  linklayer/radio/propagation/IReceptionModel.h \
  base/INETDefs.h \
  linklayer/radio/propagation/FreeSpaceModel.h
$O/mobility/models/ANSimMobility.o: mobility/models/ANSimMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  mobility/models/ANSimMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h
$O/mobility/models/BonnMotionFileCache.o: mobility/models/BonnMotionFileCache.cc \
  mobility/models/BonnMotionFileCache.h \
  base/INETDefs.h
$O/mobility/models/BonnMotionMobility.o: mobility/models/BonnMotionMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  mobility/models/BonnMotionMobility.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/BonnMotionFileCache.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h
$O/mobility/models/ChiangMobility.o: mobility/models/ChiangMobility.cc \
  util/FWMath.h \
  base/BasicModule.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h \
  mobility/models/ChiangMobility.h
$O/mobility/models/CircleMobility.o: mobility/models/CircleMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/CircleMobility.h
$O/mobility/models/ConstSpeedMobility.o: mobility/models/ConstSpeedMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  mobility/models/ConstSpeedMobility.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h
$O/mobility/models/GaussMarkovMobility.o: mobility/models/GaussMarkovMobility.cc \
  util/FWMath.h \
  base/BasicModule.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/GaussMarkovMobility.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h
$O/mobility/models/LineSegmentsMobilityBase.o: mobility/models/LineSegmentsMobilityBase.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h
$O/mobility/models/LinearMobility.o: mobility/models/LinearMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/LinearMobility.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h
$O/mobility/models/LinearNodeDistributionMobility.o: mobility/models/LinearNodeDistributionMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/models/StationaryMobility.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  mobility/models/LinearNodeDistributionMobility.h
$O/mobility/models/MassMobility.o: mobility/models/MassMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h \
  mobility/models/MassMobility.h
$O/mobility/models/MoBANCoordinator.o: mobility/models/MoBANCoordinator.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  mobility/models/MoBANCoordinator.h \
  mobility/models/Posture.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/models/MobilityAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/PostureTransition.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h \
  mobility/models/MoBANLocal.h
$O/mobility/models/MoBANLocal.o: mobility/models/MoBANLocal.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  mobility/models/MoBANCoordinator.h \
  base/Coord.h \
  mobility/models/Posture.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/PostureTransition.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h \
  mobility/models/MoBANLocal.h
$O/mobility/models/MobilityAccess.o: mobility/models/MobilityAccess.cc \
  util/FWMath.h \
  base/Coord.h \
  base/ModuleAccess.h \
  mobility/models/MobilityAccess.h \
  mobility/IMobility.h \
  base/INETDefs.h
$O/mobility/models/MobilityBase.o: mobility/models/MobilityBase.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h
$O/mobility/models/MovingMobilityBase.o: mobility/models/MovingMobilityBase.cc \
  util/FWMath.h \
  base/BasicModule.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h
$O/mobility/models/Ns2MotionMobility.o: mobility/models/Ns2MotionMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h \
  mobility/models/Ns2MotionMobility.h
$O/mobility/models/Posture.o: mobility/models/Posture.cc \
  util/FWMath.h \
  base/Coord.h \
  mobility/models/Posture.h \
  base/INETDefs.h
$O/mobility/models/PostureTransition.o: mobility/models/PostureTransition.cc \
  util/FWMath.h \
  base/Coord.h \
  mobility/models/PostureTransition.h \
  base/INETDefs.h
$O/mobility/models/RandomWPMobility.o: mobility/models/RandomWPMobility.cc \
  util/FWMath.h \
  base/BasicModule.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/RandomWPMobility.h \
  mobility/models/LineSegmentsMobilityBase.h
$O/mobility/models/RectangleMobility.o: mobility/models/RectangleMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  mobility/models/RectangleMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h
$O/mobility/models/StaticGridMobility.o: mobility/models/StaticGridMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  mobility/models/StaticGridMobility.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/models/StationaryMobility.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h
$O/mobility/models/StationaryMobility.o: mobility/models/StationaryMobility.cc \
  util/FWMath.h \
  base/BasicModule.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  mobility/models/StationaryMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h
$O/mobility/models/TraCIMobility.o: mobility/models/TraCIMobility.cc \
  util/FWMath.h \
  base/BasicModule.h \
  ./mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  ./world/traci/TraCIScenarioManager.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  ./mobility/models/TraCIMobility.h
$O/mobility/models/TractorMobility.o: mobility/models/TractorMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/TractorMobility.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h
$O/mobility/models/TurtleMobility.o: mobility/models/TurtleMobility.cc \
  base/BasicModule.h \
  util/FWMath.h \
  mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  mobility/models/MovingMobilityBase.h \
  base/INETDefs.h \
  mobility/models/LineSegmentsMobilityBase.h \
  mobility/models/TurtleMobility.h
$O/networklayer/arp/ARP.o: networklayer/arp/ARP.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/arp/ARPPacket_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/arp/ARP.h
$O/networklayer/autorouting/ipv4/FlatNetworkConfigurator.o: networklayer/autorouting/ipv4/FlatNetworkConfigurator.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/autorouting/ipv4/FlatNetworkConfigurator.h \
  base/NotifierConsts.h \
  base/WeightedTopology.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/networklayer/autorouting/ipv4/HostAutoConfigurator.o: networklayer/autorouting/ipv4/HostAutoConfigurator.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/autorouting/ipv4/HostAutoConfigurator.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/networklayer/autorouting/ipv4/IPv4NetworkConfigurator.o: networklayer/autorouting/ipv4/IPv4NetworkConfigurator.cc \
  base/Topology.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  util/PatternMatcher.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/autorouting/ipv4/IPv4NetworkConfigurator.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  util/stlutils.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/networklayer/autorouting/ipv4/MultihomedFlatNetworkConfigurator.o: networklayer/autorouting/ipv4/MultihomedFlatNetworkConfigurator.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/autorouting/ipv4/MultihomedFlatNetworkConfigurator.h \
  networklayer/autorouting/ipv4/FlatNetworkConfigurator.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/networklayer/autorouting/ipv6/FlatNetworkConfigurator6.o: networklayer/autorouting/ipv6/FlatNetworkConfigurator6.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/autorouting/ipv6/FlatNetworkConfigurator6.h \
  networklayer/ipv6/RoutingTable6.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/networklayer/bgpv4/BGPFSM.o: networklayer/bgpv4/BGPFSM.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/bgpv4/BGPMessage/BGPKeepAlive.h \
  networklayer/common/IInterfaceTable.h \
  util/Macho.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/OSPFRoutingAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/bgpv4/BGPMessage/BGPUpdatePathAttributes_m.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/bgpv4/BGPSession.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/bgpv4/BGPMessage/BGPUpdate.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/bgpv4/BGPFSM.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/bgpv4/BGPRouting.h \
  networklayer/bgpv4/BGPMessage/BGPHeader_m.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/bgpv4/BGPRoutingTableEntry.h \
  base/NotificationBoard.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  transport/contract/TCPCommand_m.h \
  networklayer/bgpv4/BGPMessage/BGPUpdate_m.h \
  networklayer/bgpv4/BGPMessage/BGPKeepAlive_m.h \
  networklayer/bgpv4/BGPMessage/BGPOpen.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/bgpv4/BGPMessage/BGPOpen_m.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/bgpv4/BGPMessage/BGPASPathSegment_m.h \
  networklayer/ospfv2/OSPFRouting.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h \
  transport/contract/TCPSocketMap.h \
  networklayer/bgpv4/BGPCommon.h
$O/networklayer/bgpv4/BGPRouting.o: networklayer/bgpv4/BGPRouting.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/bgpv4/BGPMessage/BGPKeepAlive.h \
  util/Macho.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/ospfv2/OSPFRoutingAccess.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  networklayer/bgpv4/BGPMessage/BGPUpdatePathAttributes_m.h \
  networklayer/bgpv4/BGPSession.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/bgpv4/BGPMessage/BGPUpdate.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/bgpv4/BGPFSM.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/bgpv4/BGPMessage/BGPHeader_m.h \
  networklayer/bgpv4/BGPRouting.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/bgpv4/BGPRoutingTableEntry.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/bgpv4/BGPMessage/BGPOpen.h \
  networklayer/bgpv4/BGPMessage/BGPKeepAlive_m.h \
  networklayer/bgpv4/BGPMessage/BGPUpdate_m.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  base/INETDefs.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/bgpv4/BGPMessage/BGPOpen_m.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/bgpv4/BGPMessage/BGPASPathSegment_m.h \
  networklayer/ospfv2/OSPFRouting.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  transport/contract/TCPSocketMap.h \
  networklayer/ospfv2/router/OSPFArea.h \
  networklayer/bgpv4/BGPCommon.h
$O/networklayer/bgpv4/BGPSession.o: networklayer/bgpv4/BGPSession.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/bgpv4/BGPMessage/BGPKeepAlive.h \
  networklayer/common/IInterfaceTable.h \
  util/Macho.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/OSPFRoutingAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/bgpv4/BGPMessage/BGPUpdatePathAttributes_m.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/bgpv4/BGPSession.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/bgpv4/BGPMessage/BGPUpdate.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/bgpv4/BGPFSM.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/bgpv4/BGPMessage/BGPHeader_m.h \
  networklayer/bgpv4/BGPRouting.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/bgpv4/BGPRoutingTableEntry.h \
  base/NotificationBoard.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  transport/contract/TCPCommand_m.h \
  networklayer/bgpv4/BGPMessage/BGPUpdate_m.h \
  networklayer/bgpv4/BGPMessage/BGPKeepAlive_m.h \
  networklayer/bgpv4/BGPMessage/BGPOpen.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/bgpv4/BGPMessage/BGPOpen_m.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/bgpv4/BGPMessage/BGPASPathSegment_m.h \
  networklayer/ospfv2/OSPFRouting.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h \
  transport/contract/TCPSocketMap.h \
  networklayer/bgpv4/BGPCommon.h
$O/networklayer/bgpv4/BGPMessage/BGPUpdate.o: networklayer/bgpv4/BGPMessage/BGPUpdate.cc \
  networklayer/contract/IPv4Address.h \
  networklayer/bgpv4/BGPMessage/BGPUpdatePathAttributes_m.h \
  networklayer/bgpv4/BGPMessage/BGPUpdate.h \
  networklayer/bgpv4/BGPMessage/BGPHeader_m.h \
  networklayer/bgpv4/BGPMessage/BGPUpdate_m.h \
  base/INETDefs.h \
  networklayer/bgpv4/BGPMessage/BGPASPathSegment_m.h
$O/networklayer/common/InterfaceEntry.o: networklayer/common/InterfaceEntry.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h
$O/networklayer/common/InterfaceTable.o: networklayer/common/InterfaceTable.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  networklayer/common/InterfaceTable.h
$O/networklayer/contract/IPv4Address.o: networklayer/contract/IPv4Address.cc \
  networklayer/contract/IPv4Address.h \
  base/INETDefs.h
$O/networklayer/contract/IPv4ControlInfo.o: networklayer/contract/IPv4ControlInfo.cc \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ipv4/IPv4Datagram.h
$O/networklayer/contract/IPv6Address.o: networklayer/contract/IPv6Address.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/InterfaceToken.h \
  base/INETDefs.h
$O/networklayer/contract/IPv6ControlInfo.o: networklayer/contract/IPv6ControlInfo.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  base/INETDefs.h \
  networklayer/contract/IPv6ControlInfo.h
$O/networklayer/contract/IPvXAddress.o: networklayer/contract/IPvXAddress.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/networklayer/contract/IPvXAddressResolver.o: networklayer/contract/IPvXAddressResolver.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv6/RoutingTable6.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/networklayer/diffserv/BehaviorAggregateClassifier.o: networklayer/diffserv/BehaviorAggregateClassifier.cc \
  transport/udp/UDPPacket.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  transport/udp/UDPPacket_m.h \
  networklayer/diffserv/DiffservUtil.h \
  base/ByteArray.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/diffserv/BehaviorAggregateClassifier.h
$O/networklayer/diffserv/DSCPMarker.o: networklayer/diffserv/DSCPMarker.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/diffserv/DSCP_m.h \
  networklayer/diffserv/DSCPMarker.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/diffserv/DiffservUtil.h \
  base/INETDefs.h \
  networklayer/ipv4/IPv4Datagram.h
$O/networklayer/diffserv/DiffservUtil.o: networklayer/diffserv/DiffservUtil.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/diffserv/DSCP_m.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/diffserv/DiffservUtil.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  util/opp_utils.h \
  base/INETDefs.h \
  networklayer/ipv4/IPv4Datagram.h
$O/networklayer/diffserv/MultiFieldClassifier.o: networklayer/diffserv/MultiFieldClassifier.cc \
  transport/udp/UDPPacket.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/diffserv/MultiFieldClassifier.h \
  transport/udp/UDPPacket_m.h \
  networklayer/diffserv/DiffservUtil.h \
  base/ByteArray.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h
$O/networklayer/diffserv/SingleRateThreeColorMeter.o: networklayer/diffserv/SingleRateThreeColorMeter.cc \
  networklayer/diffserv/DiffservUtil.h \
  base/INETDefs.h \
  networklayer/diffserv/SingleRateThreeColorMeter.h
$O/networklayer/diffserv/TokenBucketMeter.o: networklayer/diffserv/TokenBucketMeter.cc \
  networklayer/diffserv/TokenBucketMeter.h \
  networklayer/diffserv/DiffservUtil.h \
  base/INETDefs.h
$O/networklayer/diffserv/TwoRateThreeColorMeter.o: networklayer/diffserv/TwoRateThreeColorMeter.cc \
  networklayer/diffserv/DiffservUtil.h \
  networklayer/diffserv/TwoRateThreeColorMeter.h \
  base/INETDefs.h
$O/networklayer/extras/Dummy.o: networklayer/extras/Dummy.cc \
  base/INETDefs.h
$O/networklayer/extras/FailureManager.o: networklayer/extras/FailureManager.cc \
  base/IScriptable.h \
  base/INETDefs.h \
  networklayer/extras/FailureManager.h
$O/networklayer/icmpv6/ICMPv6.o: networklayer/icmpv6/ICMPv6.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  base/ModuleAccess.h \
  applications/pingapp/PingPayload_m.h \
  base/NotifierConsts.h \
  networklayer/icmpv6/ICMPv6Message_m.h \
  base/INETDefs.h \
  networklayer/icmpv6/ICMPv6.h \
  networklayer/contract/IPv6ControlInfo.h
$O/networklayer/icmpv6/IPv6NeighbourCache.o: networklayer/icmpv6/IPv6NeighbourCache.cc \
  networklayer/contract/IPv6Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/icmpv6/IPv6NeighbourCache.h \
  base/INETDefs.h
$O/networklayer/icmpv6/IPv6NeighbourDiscovery.o: networklayer/icmpv6/IPv6NeighbourDiscovery.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/xmipv6/MobilityHeader_m.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/xmipv6/xMIPv6.h \
  networklayer/xmipv6/BindingUpdateList.h \
  networklayer/contract/IPv6Address.h \
  networklayer/xmipv6/MobilityHeader.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv6/RoutingTable6Access.h \
  networklayer/ipv6/IPv6Datagram.h \
  base/INotifiable.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/xmipv6/xMIPv6Access.h \
  networklayer/ipv6/IPv6ExtensionHeaders_m.h \
  networklayer/icmpv6/ICMPv6Message_m.h \
  networklayer/ipv6/RoutingTable6.h \
  networklayer/icmpv6/ICMPv6Access.h \
  networklayer/icmpv6/IPv6NeighbourCache.h \
  networklayer/ipv6tunneling/IPv6Tunneling.h \
  base/INETDefs.h \
  networklayer/ipv6/IPv6ExtensionHeaders.h \
  networklayer/icmpv6/ICMPv6.h \
  networklayer/icmpv6/IPv6NDMessage_m.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/icmpv6/IPv6NeighbourDiscovery.h
$O/networklayer/internetcloud/CloudDelayerBase.o: networklayer/internetcloud/CloudDelayerBase.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/internetcloud/CloudDelayerBase.h
$O/networklayer/internetcloud/InternetCloudTaggerChannel.o: networklayer/internetcloud/InternetCloudTaggerChannel.cc \
  networklayer/internetcloud/InternetCloudTaggerChannel.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  networklayer/common/InterfaceTable.h
$O/networklayer/internetcloud/MatrixCloudDelayer.o: networklayer/internetcloud/MatrixCloudDelayer.cc \
  util/XMLUtils.h \
  networklayer/internetcloud/MatrixCloudDelayer.h \
  util/PatternMatcher.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/INETDefs.h \
  networklayer/internetcloud/CloudDelayerBase.h
$O/networklayer/ipv4/ErrorHandling.o: networklayer/ipv4/ErrorHandling.cc \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPMessage_m.h \
  base/INETDefs.h \
  networklayer/ipv4/ErrorHandling.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/ipv4/ICMP.o: networklayer/ipv4/ICMP.cc \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  applications/pingapp/PingPayload_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/ipv4/IGMPv2.o: networklayer/ipv4/IGMPv2.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/ipv4/IGMPv2.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ipv4/IGMPMessage_m.h
$O/networklayer/ipv4/IPv4.o: networklayer/ipv4/IPv4.cc \
  networklayer/ipv4/ICMP.h \
  base/ReassemblyBuffer.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  base/AbstractQueue.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/arp/ARPPacket_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/ipv4/IPv4.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/ipv4/IPv4FragBuf.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/QueueBase.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/ipv4/IPv4FragBuf.o: networklayer/ipv4/IPv4FragBuf.cc \
  base/ReassemblyBuffer.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4FragBuf.h \
  base/ModuleAccess.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/ipv4/IPv4InterfaceData.o: networklayer/ipv4/IPv4InterfaceData.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h
$O/networklayer/ipv4/IPv4Route.o: networklayer/ipv4/IPv4Route.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h
$O/networklayer/ipv4/NetworkInfo.o: networklayer/ipv4/NetworkInfo.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv4/IRoutingTable.h \
  base/NotifierConsts.h \
  base/IScriptable.h \
  networklayer/ipv4/NetworkInfo.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/networklayer/ipv4/RoutingTable.o: networklayer/ipv4/RoutingTable.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv4/RoutingTableParser.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h
$O/networklayer/ipv4/RoutingTableParser.o: networklayer/ipv4/RoutingTableParser.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv4/RoutingTableParser.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h
$O/networklayer/ipv4/RoutingTableRecorder.o: networklayer/ipv4/RoutingTableRecorder.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/ipv4/RoutingTableRecorder.h
$O/networklayer/ipv6/IPv6.o: networklayer/ipv6/IPv6.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/ipv6tunneling/IPv6TunnelingAccess.h \
  networklayer/xmipv6/MobilityHeader_m.h \
  base/ReassemblyBuffer.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/xmipv6/MobilityHeader.h \
  networklayer/icmpv6/IPv6NeighbourDiscoveryAccess.h \
  networklayer/common/IInterfaceTable.h \
  base/AbstractQueue.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/RoutingTable6Access.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/ipv6/IPv6.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv6/IPv6ExtensionHeaders_m.h \
  base/QueueBase.h \
  networklayer/icmpv6/ICMPv6Message_m.h \
  networklayer/ipv6/RoutingTable6.h \
  networklayer/icmpv6/ICMPv6Access.h \
  networklayer/ipv6/IPv6FragBuf.h \
  networklayer/icmpv6/IPv6NeighbourCache.h \
  networklayer/ipv6tunneling/IPv6Tunneling.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h \
  base/ProtocolMap.h \
  networklayer/ipv6/IPv6ExtensionHeaders.h \
  networklayer/icmpv6/ICMPv6.h \
  networklayer/icmpv6/IPv6NDMessage_m.h \
  networklayer/icmpv6/IPv6NeighbourDiscovery.h \
  networklayer/contract/IPv6ControlInfo.h
$O/networklayer/ipv6/IPv6Datagram.o: networklayer/ipv6/IPv6Datagram.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv6/IPv6ExtensionHeaders_m.h \
  base/INETDefs.h \
  networklayer/ipv6/IPv6ExtensionHeaders.h
$O/networklayer/ipv6/IPv6ErrorHandling.o: networklayer/ipv6/IPv6ErrorHandling.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/ipv6/IPv6ErrorHandling.h \
  networklayer/contract/IPv6Address.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/icmpv6/ICMPv6Message_m.h \
  base/INETDefs.h \
  networklayer/contract/IPv6ControlInfo.h
$O/networklayer/ipv6/IPv6ExtensionHeaders.o: networklayer/ipv6/IPv6ExtensionHeaders.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv6/IPv6ExtensionHeaders_m.h \
  base/INETDefs.h \
  networklayer/ipv6/IPv6ExtensionHeaders.h
$O/networklayer/ipv6/IPv6FragBuf.o: networklayer/ipv6/IPv6FragBuf.cc \
  base/ReassemblyBuffer.h \
  networklayer/contract/IPv6Address.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv6/IPv6ExtensionHeaders_m.h \
  networklayer/icmpv6/ICMPv6Message_m.h \
  networklayer/ipv6/IPv6FragBuf.h \
  base/INETDefs.h \
  networklayer/ipv6/IPv6ExtensionHeaders.h \
  networklayer/icmpv6/ICMPv6.h
$O/networklayer/ipv6/IPv6InterfaceData.o: networklayer/ipv6/IPv6InterfaceData.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv6/RoutingTable6Access.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv6/RoutingTable6.h \
  base/INETDefs.h
$O/networklayer/ipv6/RoutingTable6.o: networklayer/ipv6/RoutingTable6.cc \
  networklayer/ipv6tunneling/IPv6TunnelingAccess.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  util/opp_utils.h \
  base/NotificationBoard.h \
  networklayer/ipv6/RoutingTable6.h \
  networklayer/ipv6tunneling/IPv6Tunneling.h \
  base/INETDefs.h
$O/networklayer/ipv6tunneling/IPv6Tunneling.o: networklayer/ipv6tunneling/IPv6Tunneling.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/xmipv6/MobilityHeader_m.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/xmipv6/xMIPv6.h \
  networklayer/xmipv6/BindingUpdateList.h \
  networklayer/contract/IPv6Address.h \
  networklayer/xmipv6/MobilityHeader.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv6/RoutingTable6Access.h \
  networklayer/ipv6/IPv6Datagram.h \
  base/INotifiable.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/xmipv6/xMIPv6Access.h \
  networklayer/ipv6/IPv6ExtensionHeaders_m.h \
  networklayer/ipv6/RoutingTable6.h \
  base/INETDefs.h \
  networklayer/ipv6tunneling/IPv6Tunneling.h \
  networklayer/ipv6/IPv6ExtensionHeaders.h \
  networklayer/contract/IPv6ControlInfo.h
$O/networklayer/ldp/LDP.o: networklayer/ldp/LDP.cc \
  transport/udp/UDPPacket.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/rsvp_te/IntServ.h \
  networklayer/ted/TED_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  transport/udp/UDPPacket_m.h \
  networklayer/mpls/ConstType.h \
  networklayer/ted/TEDAccess.h \
  base/ModuleAccess.h \
  transport/contract/UDPControlInfo_m.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/mpls/LIBTable.h \
  networklayer/ldp/LDPPacket_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/mpls/LIBTableAccess.h \
  networklayer/ldp/LDP.h \
  networklayer/ted/TED.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/rsvp_te/IntServ_m.h \
  networklayer/mpls/IClassifier.h \
  transport/contract/TCPSocketMap.h \
  transport/contract/UDPSocket.h
$O/networklayer/manetrouting/aodv/aodv_msg_struct.o: networklayer/manetrouting/aodv/aodv_msg_struct.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  transport/udp/UDPPacket.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  transport/udp/UDPPacket_m.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv_msg_struct_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/common/InterfaceTable.h \
  networklayer/manetrouting/aodv/aodv_msg_struct.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/aodv/aodv_uu_omnet.o: networklayer/manetrouting/aodv/aodv_uu_omnet.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  util/FWMath.h \
  transport/udp/UDPPacket.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv_uu_omnet.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/udp/UDPPacket_m.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.h \
  networklayer/manetrouting/aodv/aodv-uu/locality.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  networklayer/manetrouting/aodv/aodv_msg_struct_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/seek_list.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv_msg_struct.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_hello.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/packet_queue_omnet.h
$O/networklayer/manetrouting/aodv/packet_queue_omnet.o: networklayer/manetrouting/aodv/packet_queue_omnet.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv_uu_omnet.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.h \
  networklayer/manetrouting/aodv/aodv-uu/locality.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv_msg_struct_m.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/seek_list.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv_msg_struct.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_hello.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/packet_queue_omnet.h
$O/networklayer/manetrouting/aodv/aodv-uu/aodv_hello.o: networklayer/manetrouting/aodv/aodv-uu/aodv_hello.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/seek_list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.o: networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.o: networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.o: networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.o: networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/locality.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/seek_list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/aodv_socket.o: networklayer/manetrouting/aodv/aodv-uu/aodv_socket.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/seek_list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.o: networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/nl.h \
  networklayer/manetrouting/aodv/aodv-uu/seek_list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/debug_aodv.o: networklayer/manetrouting/aodv/aodv-uu/debug_aodv.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rreq.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/seek_list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/list.o: networklayer/manetrouting/aodv/aodv-uu/list.cc \
  networklayer/manetrouting/aodv/aodv-uu/list.h
$O/networklayer/manetrouting/aodv/aodv-uu/locality.o: networklayer/manetrouting/aodv/aodv-uu/locality.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/locality.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/routing_table.o: networklayer/manetrouting/aodv/aodv-uu/routing_table.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_socket.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/routing_table.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/nl.h \
  networklayer/manetrouting/aodv/aodv-uu/seek_list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rrep.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_rerr.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/seek_list.o: networklayer/manetrouting/aodv/aodv-uu/seek_list.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/aodv/aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/seek_list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.o: networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rrep.h \
  networklayer/manetrouting/aodv/aodv-uu/list.h \
  networklayer/manetrouting/aodv/aodv-uu/../packet_queue_omnet.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_uu_omnet.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/aodv/aodv-uu/timer_queue_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/params.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/seek_list.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/debug_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rerr.h \
  networklayer/common/InterfaceToken.h \
  networklayer/manetrouting/aodv/aodv-uu/debug_aodv.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/locality.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/defs_aodv.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_hello.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_rreq.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/timer_queue_aodv.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_neighbor.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_timeout.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv_msg_struct.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/aodv_socket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/aodv/aodv-uu/defs_aodv.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/aodv/aodv-uu/../aodv-uu/routing_table.h
$O/networklayer/manetrouting/base/ManetAddress.o: networklayer/manetrouting/base/ManetAddress.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/manetrouting/base/ManetAddress.h
$O/networklayer/manetrouting/base/ManetRoutingBase.o: networklayer/manetrouting/base/ManetRoutingBase.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  util/FWMath.h \
  transport/udp/UDPPacket.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/IPassiveQueue.h \
  networklayer/common/InterfaceEntry.h \
  base/Coord.h \
  networklayer/ipv4/RoutingTableAccess.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAPBase.h \
  networklayer/common/InterfaceToken.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  base/PassiveQueueBase.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/udp/UDPPacket_m.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtAP.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtBase.h \
  networklayer/ipv4/ICMPMessage_m.h \
  linklayer/ieee80211/mgmt/Ieee80211MgmtFrames_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ControlInfoBreakLink_m.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/batman/BatmanMain.o: networklayer/manetrouting/batman/BatmanMain.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/manetrouting/batman/BatmanMsg_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/batman/BatmanMsg.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/udp/UDPPacket_m.h \
  networklayer/manetrouting/batman/batmand/batman.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/batman/BatmanMain.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/batman/batmand/batman.o: networklayer/manetrouting/batman/batmand/batman.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/manetrouting/batman/BatmanMsg_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/batman/BatmanMsg.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/manetrouting/batman/batmand/batman.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/batman/BatmanMain.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/batman/batmand/bitarray.o: networklayer/manetrouting/batman/batmand/bitarray.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/batman/BatmanMsg_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/batman/BatmanMsg.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/manetrouting/batman/batmand/batman.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/batman/BatmanMain.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/batman/batmand/hna.o: networklayer/manetrouting/batman/batmand/hna.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/batman/BatmanMsg_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/batman/BatmanMsg.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/manetrouting/batman/batmand/batman.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/batman/BatmanMain.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/batman/batmand/originator.o: networklayer/manetrouting/batman/batmand/originator.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/manetrouting/batman/BatmanMsg_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/batman/BatmanMsg.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/manetrouting/batman/batmand/batman.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/batman/BatmanMain.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/batman/batmand/os.o: networklayer/manetrouting/batman/batmand/os.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/manetrouting/batman/BatmanMsg_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/batman/BatmanMsg.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/manetrouting/batman/batmand/batman.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/batman/BatmanMain.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/batman/batmand/ring_buffer.o: networklayer/manetrouting/batman/batmand/ring_buffer.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/batman/BatmanMsg_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/manetrouting/batman/BatmanMsg.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/manetrouting/batman/batmand/batman.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/batman/BatmanMain.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/batman/batmand/schedule.o: networklayer/manetrouting/batman/batmand/schedule.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/manetrouting/batman/BatmanMsg_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/batman/BatmanMsg.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/manetrouting/batman/batmand/batman.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/batman/BatmanMain.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/dsdv/DSDV_2.o: networklayer/manetrouting/dsdv/DSDV_2.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/manetrouting/dsdv/DSDV_2.h \
  networklayer/manetrouting/dsdv/DSDVhello_m.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ipv4/IPv4Datagram.h
$O/networklayer/manetrouting/dsr/dsr-pkt_omnet.o: networklayer/manetrouting/dsr/dsr-pkt_omnet.cc \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/ipv4/IPv4Datagram.h
$O/networklayer/manetrouting/dsr/dsr-uu-omnetpp.o: networklayer/manetrouting/dsr/dsr-uu-omnetpp.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/dsr/dsr-uu/dsr-ack.o: networklayer/manetrouting/dsr/dsr-uu/dsr-ack.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-dev.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/dsr-io.o: networklayer/manetrouting/dsr/dsr-uu/dsr-io.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rtc.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-dev.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/dsr/dsr-uu/dsr-opt.o: networklayer/manetrouting/dsr/dsr-uu/dsr-opt.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.o: networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.o: networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-dev.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.o: networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-dev.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.o: networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-dev.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/dsr-srt.o: networklayer/manetrouting/dsr/dsr-uu/dsr-srt.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/link-cache.o: networklayer/manetrouting/dsr/dsr-uu/link-cache.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rtc.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/maint-buf.o: networklayer/manetrouting/dsr/dsr-uu/maint-buf.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-dev.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/neigh.o: networklayer/manetrouting/dsr/dsr-uu/neigh.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/path-cache.o: networklayer/manetrouting/dsr/dsr-uu/path-cache.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rtc.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dsr/dsr-uu/send-buf.o: networklayer/manetrouting/dsr/dsr-uu/send-buf.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-opt.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-srt.h \
  networklayer/manetrouting/dsr/dsr-uu-omnetpp.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dsr/dsr-uu/neigh.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dsr/dsr-uu/tbl.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dsr/dsr-uu/link-cache.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-ack.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  networklayer/manetrouting/dsr/dsr-uu/send-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/debug_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-io.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-pkt.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr_list.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dsr/dsr-uu/maint-buf.h \
  networklayer/manetrouting/dsr/dsr-uu/timer.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rrep.h \
  networklayer/manetrouting/dsr/dsr-uu/path-cache.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/base/compatibility_dsr.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rreq.h \
  networklayer/manetrouting/dsr/dsr-uu/ns-agent.h \
  networklayer/manetrouting/dsr/dsr-pkt_omnet.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dsr/dsr-uu/dsr-rerr.h
$O/networklayer/manetrouting/dymo/dymo_msg_struct.o: networklayer/manetrouting/dymo/dymo_msg_struct.cc \
  networklayer/manetrouting/dymo/dymo_msg_struct.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/manetrouting/base/ManetAddress.h
$O/networklayer/manetrouting/dymo/dymo_packet_queue_omnet.o: networklayer/manetrouting/dymo/dymo_packet_queue_omnet.cc \
  util/FWMath.h \
  networklayer/manetrouting/dymo/dymo_msg_struct.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_re.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymo_um_omnet.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_socket.h \
  networklayer/manetrouting/dymo/dymo_packet_queue_omnet.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/blacklist.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  networklayer/manetrouting/dymo/dymoum/dymo_uerr.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/pending_rreq.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/dymo_timeout.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  networklayer/manetrouting/dymo/dymoum/dymo_generic.h \
  networklayer/manetrouting/dymo/dymoum/dymo_hello.h \
  networklayer/manetrouting/dymo/dymoum/dymo_nb.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/icmp_socket.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymo_um_omnet.o: networklayer/manetrouting/dymo/dymo_um_omnet.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  util/FWMath.h \
  transport/udp/UDPPacket.h \
  networklayer/manetrouting/dymo/dymo_msg_struct.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_re.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymo_um_omnet.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_socket.h \
  networklayer/manetrouting/dymo/dymo_packet_queue_omnet.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  transport/udp/UDPPacket_m.h \
  networklayer/manetrouting/dymo/dymoum/blacklist.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  networklayer/manetrouting/dymo/dymoum/dymo_uerr.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/pending_rreq.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/dymo_timeout.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/dymo/dymoum/dymo_generic.h \
  networklayer/manetrouting/dymo/dymoum/dymo_hello.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/manetrouting/dymo/dymoum/dymo_nb.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/icmp_socket.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/blacklist.o: networklayer/manetrouting/dymo/dymoum/blacklist.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/manetrouting/dymo/dymoum/blacklist.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/debug_dymo.o: networklayer/manetrouting/dymo/dymoum/debug_dymo.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/dymo_generic.o: networklayer/manetrouting/dymo/dymoum/dymo_generic.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/manetrouting/dymo/dymoum/dymo_re.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  networklayer/manetrouting/dymo/dymoum/dymo_uerr.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/dymo_generic.h \
  networklayer/manetrouting/dymo/dymoum/dymo_hello.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/dymo_hello.o: networklayer/manetrouting/dymo/dymoum/dymo_hello.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_socket.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/dymo_generic.h \
  networklayer/manetrouting/dymo/dymoum/dymo_hello.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/manetrouting/dymo/dymoum/dymo_nb.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h
$O/networklayer/manetrouting/dymo/dymoum/dymo_nb.o: networklayer/manetrouting/dymo/dymoum/dymo_nb.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/manetrouting/dymo/dymoum/dymo_nb.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/dymo_re.o: networklayer/manetrouting/dymo/dymoum/dymo_re.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/manetrouting/dymo/dymoum/dymo_re.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_socket.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/manetrouting/dymo/dymoum/blacklist.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/manetrouting/dymo/dymoum/pending_rreq.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/dymo_generic.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/base/MeshControlInfo_m.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/icmp_socket.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h
$O/networklayer/manetrouting/dymo/dymoum/dymo_rerr.o: networklayer/manetrouting/dymo/dymoum/dymo_rerr.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_socket.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/dymo_generic.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h
$O/networklayer/manetrouting/dymo/dymoum/dymo_socket.o: networklayer/manetrouting/dymo/dymoum/dymo_socket.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_socket.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/dymo_generic.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/dymo_timeout.o: networklayer/manetrouting/dymo/dymoum/dymo_timeout.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/manetrouting/dymo/dymoum/dymo_re.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/manetrouting/dymo/dymoum/blacklist.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/manetrouting/dymo/dymoum/pending_rreq.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/dymo_netlink.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/manetrouting/dymo/dymoum/dymo_nb.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/dymo_uerr.o: networklayer/manetrouting/dymo/dymoum/dymo_uerr.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  networklayer/manetrouting/dymo/dymoum/dymo_socket.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  networklayer/manetrouting/dymo/dymoum/dymo_uerr.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/dymo_generic.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h
$O/networklayer/manetrouting/dymo/dymoum/icmp_socket.o: networklayer/manetrouting/dymo/dymoum/icmp_socket.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/manetrouting/dymo/dymoum/blacklist.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/icmp_socket.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/pending_rreq.o: networklayer/manetrouting/dymo/dymoum/pending_rreq.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/manetrouting/dymo/dymoum/pending_rreq.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/rtable.o: networklayer/manetrouting/dymo/dymoum/rtable.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  networklayer/manetrouting/dymo/dymoum/rtable.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  networklayer/manetrouting/dymo/dymoum/k_route.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/manetrouting/dymo/dymoum/pending_rreq.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/dymo_netlink.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h \
  networklayer/manetrouting/dymo/dymoum/debug_dymo.h
$O/networklayer/manetrouting/dymo/dymoum/timer_queue.o: networklayer/manetrouting/dymo/dymoum/timer_queue.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/pending_rreq.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/rtable.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/icmp_socket.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/manetrouting/dymo/dymoum/dlist.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  linklayer/ieee80211/mac/Ieee80211Consts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_packet_queue_omnet.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/blacklist.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_uerr.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_rerr.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_msg_struct.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_socket.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymo_um_omnet.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_hello.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_re.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/timer_queue.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/defs_dymo.h \
  linklayer/ieee80211/mac/Ieee80211Frame_m.h \
  networklayer/manetrouting/dymo/dymoum/timer_queue.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_nb.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/debug_dymo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_generic.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/manetrouting/dymo/dymoum/defs_dymo.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dymo_timeout.h \
  networklayer/manetrouting/dymo/dymoum/../dymoum/dlist.h
$O/networklayer/manetrouting/dymo_fau/DYMO.o: networklayer/manetrouting/dymo_fau/DYMO.cc \
  util/FWMath.h \
  transport/udp/UDPPacket.h \
  base/ReassemblyBuffer.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo_fau/DYMO_TokenBucket.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo_fau/DYMO_RoutingEntry.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo_fau/DYMO_OutstandingRREQList.h \
  base/AbstractQueue.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dymo_fau/DYMO_RREP_m.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/ipv4/IPv4.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo_fau/DYMO.h \
  networklayer/manetrouting/dymo_fau/DYMO_RERR_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/manetrouting/dymo_fau/DYMO_RM_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  transport/udp/UDPPacket_m.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/ipv4/RoutingTable.h \
  networklayer/ipv4/IPv4FragBuf.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_DataQueue.h \
  transport/contract/UDPControlInfo_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/QueueBase.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_Packet_m.h \
  networklayer/manetrouting/dymo_fau/InspectorHelpers.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timeout_m.h \
  base/ProtocolMap.h \
  networklayer/common/InterfaceTable.h \
  networklayer/manetrouting/dymo_fau/DYMO_PacketBBMessage_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timer.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo_fau/DYMO_RREQ_m.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo_fau/DYMO_AddressBlock.h \
  networklayer/manetrouting/dymo_fau/DYMO_UERR_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_RoutingTable.h \
  transport/contract/UDPSocket.h
$O/networklayer/manetrouting/dymo_fau/DYMO_DataQueue.o: networklayer/manetrouting/dymo_fau/DYMO_DataQueue.cc \
  base/ReassemblyBuffer.h \
  networklayer/ipv4/ICMP.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  base/AbstractQueue.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/ipv4/IPv4.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/ipv4/IPv4FragBuf.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_DataQueue.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/QueueBase.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h
$O/networklayer/manetrouting/dymo_fau/DYMO_OutstandingRREQList.o: networklayer/manetrouting/dymo_fau/DYMO_OutstandingRREQList.cc \
  networklayer/manetrouting/dymo_fau/DYMO_OutstandingRREQList.h \
  networklayer/contract/IPv4Address.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timeout_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timer.h
$O/networklayer/manetrouting/dymo_fau/DYMO_RoutingEntry.o: networklayer/manetrouting/dymo_fau/DYMO_RoutingEntry.cc \
  util/FWMath.h \
  base/ReassemblyBuffer.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo_fau/DYMO_TokenBucket.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo_fau/DYMO_RoutingEntry.h \
  networklayer/manetrouting/dymo_fau/DYMO_OutstandingRREQList.h \
  base/AbstractQueue.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dymo_fau/DYMO_RREP_m.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/ipv4/IPv4.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo_fau/DYMO.h \
  networklayer/manetrouting/dymo_fau/DYMO_RERR_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_RM_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/ipv4/RoutingTable.h \
  networklayer/ipv4/IPv4FragBuf.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_DataQueue.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/QueueBase.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_Packet_m.h \
  networklayer/manetrouting/dymo_fau/InspectorHelpers.h \
  networklayer/ipv4/IPv4Route.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timeout_m.h \
  networklayer/common/InterfaceTable.h \
  networklayer/manetrouting/dymo_fau/DYMO_PacketBBMessage_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timer.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo_fau/DYMO_RREQ_m.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo_fau/DYMO_AddressBlock.h \
  networklayer/manetrouting/dymo_fau/DYMO_UERR_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_RoutingTable.h
$O/networklayer/manetrouting/dymo_fau/DYMO_RoutingTable.o: networklayer/manetrouting/dymo_fau/DYMO_RoutingTable.cc \
  util/FWMath.h \
  base/ReassemblyBuffer.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/manetrouting/dymo_fau/DYMO_TokenBucket.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo_fau/DYMO_RoutingEntry.h \
  networklayer/manetrouting/dymo_fau/DYMO_OutstandingRREQList.h \
  base/AbstractQueue.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dymo_fau/DYMO_RREP_m.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/ipv4/IPv4.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/manetrouting/dymo_fau/DYMO.h \
  networklayer/manetrouting/dymo_fau/DYMO_RERR_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_RM_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/ipv4/RoutingTable.h \
  networklayer/ipv4/IPv4FragBuf.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_DataQueue.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/QueueBase.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_Packet_m.h \
  networklayer/manetrouting/dymo_fau/InspectorHelpers.h \
  networklayer/ipv4/IPv4Route.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  base/ProtocolMap.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timeout_m.h \
  networklayer/common/InterfaceTable.h \
  networklayer/manetrouting/dymo_fau/DYMO_PacketBBMessage_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timer.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo_fau/DYMO_RREQ_m.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo_fau/DYMO_AddressBlock.h \
  networklayer/manetrouting/dymo_fau/DYMO_UERR_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_RoutingTable.h
$O/networklayer/manetrouting/dymo_fau/DYMO_Timer.o: networklayer/manetrouting/dymo_fau/DYMO_Timer.cc \
  base/INETDefs.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timeout_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timer.h
$O/networklayer/manetrouting/dymo_fau/DYMO_TokenBucket.o: networklayer/manetrouting/dymo_fau/DYMO_TokenBucket.cc \
  networklayer/ipv4/ICMP.h \
  base/ReassemblyBuffer.h \
  networklayer/manetrouting/dymo_fau/DYMO_TokenBucket.h \
  networklayer/contract/IPv6Address.h \
  networklayer/manetrouting/dymo_fau/DYMO_RoutingEntry.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/dymo_fau/DYMO_OutstandingRREQList.h \
  base/AbstractQueue.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/manetrouting/dymo_fau/DYMO_RREP_m.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/ipv4/IPv4.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_RERR_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/manetrouting/dymo_fau/DYMO_RM_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/RoutingTable.h \
  networklayer/ipv4/ICMPAccess.h \
  networklayer/ipv4/IPv4FragBuf.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/base/ControlManetRouting_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_DataQueue.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/QueueBase.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_Packet_m.h \
  networklayer/manetrouting/dymo_fau/InspectorHelpers.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timeout_m.h \
  base/ProtocolMap.h \
  networklayer/common/InterfaceTable.h \
  networklayer/manetrouting/dymo_fau/DYMO_PacketBBMessage_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_Timer.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/manetrouting/dymo_fau/DYMO_RREQ_m.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/dymo_fau/DYMO_AddressBlock.h \
  networklayer/manetrouting/dymo_fau/DYMO_UERR_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_RoutingTable.h
$O/networklayer/manetrouting/dymo_fau/InspectorHelpers.o: networklayer/manetrouting/dymo_fau/InspectorHelpers.cc \
  networklayer/manetrouting/dymo_fau/DYMO_RERR_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_RM_m.h \
  networklayer/manetrouting/dymo_fau/InspectorHelpers.h \
  base/INETDefs.h \
  networklayer/manetrouting/dymo_fau/DYMO_PacketBBMessage_m.h \
  networklayer/manetrouting/dymo_fau/DYMO_AddressBlock.h
$O/networklayer/manetrouting/olsr/OLSR.o: networklayer/manetrouting/olsr/OLSR.cc \
  util/FWMath.h \
  networklayer/contract/IPv6ControlInfo_m.h \
  transport/udp/UDPPacket.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  base/Coord.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  transport/udp/UDPPacket_m.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_parameter.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/olsr/OLSR_state.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/olsr/OLSR.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/olsr/OLSR_repositories.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/olsr/OLSR_rtable.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/olsr/OLSRpkt_m.h
$O/networklayer/manetrouting/olsr/OLSROPT.o: networklayer/manetrouting/olsr/OLSROPT.cc \
  util/FWMath.h \
  networklayer/contract/IPv6ControlInfo_m.h \
  transport/udp/UDPPacket.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/manetrouting/olsr/OLSROPT.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  base/Coord.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/udp/UDPPacket_m.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_parameter.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/olsr/OLSR_state.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/olsr/OLSR.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/olsr/OLSR_repositories.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  linklayer/contract/Ieee802Ctrl_m.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/olsr/OLSR_rtable.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/olsr/OLSRpkt_m.h
$O/networklayer/manetrouting/olsr/OLSR_ETX.o: networklayer/manetrouting/olsr/OLSR_ETX.cc \
  util/FWMath.h \
  networklayer/contract/IPv6ControlInfo_m.h \
  transport/udp/UDPPacket.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/manetrouting/olsr/OLSR_ETX_state.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  base/Coord.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_repositories.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  transport/udp/UDPPacket_m.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_parameter.h \
  networklayer/manetrouting/olsr/OLSR_ETX.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/manetrouting/olsr/OLSR_state.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/olsr/OLSR_ETX_dijkstra.h \
  networklayer/manetrouting/olsr/OLSR.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/olsr/OLSR_repositories.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/manetrouting/olsr/OLSR_rtable.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/olsr/OLSRpkt_m.h
$O/networklayer/manetrouting/olsr/OLSR_ETX_dijkstra.o: networklayer/manetrouting/olsr/OLSR_ETX_dijkstra.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/olsr/OLSR_ETX_state.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  base/Coord.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_repositories.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_parameter.h \
  networklayer/manetrouting/olsr/OLSR_ETX.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/olsr/OLSR_state.h \
  networklayer/manetrouting/olsr/OLSR_ETX_dijkstra.h \
  networklayer/manetrouting/olsr/OLSR.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/olsr/OLSR_repositories.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/olsr/OLSR_rtable.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/olsr/OLSRpkt_m.h
$O/networklayer/manetrouting/olsr/OLSR_ETX_state.o: networklayer/manetrouting/olsr/OLSR_ETX_state.cc \
  util/FWMath.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/olsr/OLSR_ETX_state.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  base/Coord.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_repositories.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_parameter.h \
  networklayer/manetrouting/olsr/OLSR_ETX.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/olsr/OLSR_state.h \
  networklayer/manetrouting/olsr/OLSR.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/olsr/OLSR_repositories.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/olsr/OLSR_rtable.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/olsr/OLSRpkt_m.h
$O/networklayer/manetrouting/olsr/OLSR_rtable.o: networklayer/manetrouting/olsr/OLSR_rtable.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_parameter.h \
  networklayer/manetrouting/olsr/OLSR_state.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/olsr/OLSR.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/olsr/OLSR_repositories.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/olsr/OLSR_rtable.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/olsr/OLSRpkt_m.h
$O/networklayer/manetrouting/olsr/OLSR_state.o: networklayer/manetrouting/olsr/OLSR_state.cc \
  util/FWMath.h \
  networklayer/ipv4/ICMP.h \
  networklayer/manetrouting/base/compatibility.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/Coord.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/manetrouting/base/ManetRoutingBase.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/manetrouting/olsr/OLSR_ETX_parameter.h \
  base/NotifierConsts.h \
  networklayer/manetrouting/olsr/OLSR_state.h \
  base/NotificationBoard.h \
  networklayer/manetrouting/olsr/OLSR.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/manetrouting/olsr/OLSR_repositories.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/manetrouting/olsr/OLSR_rtable.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/arp/ARP.h \
  networklayer/manetrouting/base/ManetAddress.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/manetrouting/olsr/OLSRpkt_m.h
$O/networklayer/mpls/LIBTable.o: networklayer/mpls/LIBTable.cc \
  util/XMLUtils.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/mpls/ConstType.h \
  base/ModuleAccess.h \
  networklayer/mpls/LIBTable.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/ipv4/IPv4Datagram.h
$O/networklayer/mpls/MPLS.o: networklayer/mpls/MPLS.cc \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  networklayer/rsvp_te/IntServ.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/mpls/MPLSPacket.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/mpls/MPLS.h \
  networklayer/mpls/ConstType.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/mpls/LIBTable.h \
  networklayer/ldp/LDPPacket_m.h \
  networklayer/rsvp_te/Utils.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/ldp/LDP.h \
  networklayer/mpls/LIBTableAccess.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/rsvp_te/IntServ_m.h \
  networklayer/mpls/IClassifier.h \
  transport/contract/TCPSocketMap.h \
  transport/contract/UDPSocket.h
$O/networklayer/mpls/MPLSPacket.o: networklayer/mpls/MPLSPacket.cc \
  networklayer/mpls/MPLSPacket.h \
  base/INETDefs.h
$O/networklayer/ospfv2/OSPFRouting.o: networklayer/ospfv2/OSPFRouting.cc \
  util/XMLUtils.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  util/PatternMatcher.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotificationBoard.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  base/INETDefs.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/ospfv2/OSPFRouting.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/interface/OSPFInterface.o: networklayer/ospfv2/interface/OSPFInterface.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/interface/OSPFInterfaceState.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDown.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/interface/OSPFInterfaceState.o: networklayer/ospfv2/interface/OSPFInterfaceState.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDesignatedRouter.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateBackup.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateNotDesignatedRouter.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/interface/OSPFInterfaceState.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/interface/OSPFInterfaceStateBackup.o: networklayer/ospfv2/interface/OSPFInterfaceStateBackup.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateBackup.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceState.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDown.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/interface/OSPFInterfaceStateDesignatedRouter.o: networklayer/ospfv2/interface/OSPFInterfaceStateDesignatedRouter.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDesignatedRouter.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceState.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDown.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/interface/OSPFInterfaceStateDown.o: networklayer/ospfv2/interface/OSPFInterfaceStateDown.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateWaiting.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateNotDesignatedRouter.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ospfv2/interface/OSPFInterfaceStatePointToPoint.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceState.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDown.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.o: networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/ospfv2/router/LSA.h \
  base/INETDefs.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/interface/OSPFInterfaceState.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDown.h
$O/networklayer/ospfv2/interface/OSPFInterfaceStateNotDesignatedRouter.o: networklayer/ospfv2/interface/OSPFInterfaceStateNotDesignatedRouter.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateNotDesignatedRouter.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceState.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDown.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/interface/OSPFInterfaceStatePointToPoint.o: networklayer/ospfv2/interface/OSPFInterfaceStatePointToPoint.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ospfv2/interface/OSPFInterfaceStatePointToPoint.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceState.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDown.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/interface/OSPFInterfaceStateWaiting.o: networklayer/ospfv2/interface/OSPFInterfaceStateWaiting.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateWaiting.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateLoopback.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceState.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/interface/OSPFInterfaceStateDown.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.o: networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/messagehandler/HelloHandler.o: networklayer/ospfv2/messagehandler/HelloHandler.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.o: networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/messagehandler/LinkStateRequestHandler.o: networklayer/ospfv2/messagehandler/LinkStateRequestHandler.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.o: networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/messagehandler/MessageHandler.o: networklayer/ospfv2/messagehandler/MessageHandler.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ipv4/ICMPMessage.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/neighbor/OSPFNeighbor.o: networklayer/ospfv2/neighbor/OSPFNeighbor.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateDown.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/neighbor/OSPFNeighborState.o: networklayer/ospfv2/neighbor/OSPFNeighborState.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/neighbor/OSPFNeighborStateAttempt.o: networklayer/ospfv2/neighbor/OSPFNeighborStateAttempt.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateInit.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateDown.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateAttempt.h
$O/networklayer/ospfv2/neighbor/OSPFNeighborStateDown.o: networklayer/ospfv2/neighbor/OSPFNeighborStateDown.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateInit.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateDown.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateAttempt.h
$O/networklayer/ospfv2/neighbor/OSPFNeighborStateExchange.o: networklayer/ospfv2/neighbor/OSPFNeighborStateExchange.cc \
  networklayer/ospfv2/neighbor/OSPFNeighborStateExchangeStart.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateTwoWay.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateInit.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateFull.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateDown.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateExchange.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateLoading.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/neighbor/OSPFNeighborStateExchangeStart.o: networklayer/ospfv2/neighbor/OSPFNeighborStateExchangeStart.cc \
  networklayer/ospfv2/neighbor/OSPFNeighborStateExchangeStart.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateTwoWay.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateInit.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateDown.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateExchange.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/neighbor/OSPFNeighborStateFull.o: networklayer/ospfv2/neighbor/OSPFNeighborStateFull.cc \
  networklayer/ospfv2/neighbor/OSPFNeighborStateExchangeStart.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateTwoWay.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateInit.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateFull.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateDown.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/neighbor/OSPFNeighborStateInit.o: networklayer/ospfv2/neighbor/OSPFNeighborStateInit.cc \
  networklayer/ospfv2/neighbor/OSPFNeighborStateExchangeStart.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateTwoWay.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateInit.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateDown.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/neighbor/OSPFNeighborStateLoading.o: networklayer/ospfv2/neighbor/OSPFNeighborStateLoading.cc \
  networklayer/ospfv2/neighbor/OSPFNeighborStateExchangeStart.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateTwoWay.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateInit.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateFull.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateDown.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateLoading.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/neighbor/OSPFNeighborStateTwoWay.o: networklayer/ospfv2/neighbor/OSPFNeighborStateTwoWay.cc \
  networklayer/ospfv2/neighbor/OSPFNeighborStateExchangeStart.h \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateTwoWay.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateInit.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/neighbor/OSPFNeighborStateDown.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ospfv2/neighbor/OSPFNeighborState.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/router/ASExternalLSA.o: networklayer/ospfv2/router/ASExternalLSA.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/router/LSA.h \
  base/INETDefs.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h
$O/networklayer/ospfv2/router/LSA.o: networklayer/ospfv2/router/LSA.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/router/LSA.h \
  base/INETDefs.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h
$O/networklayer/ospfv2/router/NetworkLSA.o: networklayer/ospfv2/router/NetworkLSA.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/router/LSA.h \
  base/INETDefs.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h
$O/networklayer/ospfv2/router/OSPFArea.o: networklayer/ospfv2/router/OSPFArea.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/router/OSPFRouter.o: networklayer/ospfv2/router/OSPFRouter.cc \
  networklayer/ospfv2/neighbor/OSPFNeighbor.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/ospfv2/messagehandler/HelloHandler.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ospfv2/router/OSPFRouter.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/messagehandler/LinkStateUpdateHandler.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/ospfv2/OSPFTimer_m.h \
  networklayer/common/InterfaceToken.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ospfv2/messagehandler/MessageHandler.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  networklayer/ospfv2/messagehandler/LinkStateRequestHandler.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/ospfv2/messagehandler/DatabaseDescriptionHandler.h \
  networklayer/ospfv2/interface/OSPFInterface.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h \
  networklayer/ospfv2/messagehandler/IMessageHandler.h \
  networklayer/ospfv2/messagehandler/LinkStateAcknowledgementHandler.h \
  networklayer/ospfv2/router/OSPFArea.h
$O/networklayer/ospfv2/router/OSPFRoutingTableEntry.o: networklayer/ospfv2/router/OSPFRoutingTableEntry.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  networklayer/ospfv2/router/OSPFRoutingTableEntry.h \
  networklayer/ospfv2/router/LSA.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h
$O/networklayer/ospfv2/router/RouterLSA.o: networklayer/ospfv2/router/RouterLSA.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/router/LSA.h \
  base/INETDefs.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h
$O/networklayer/ospfv2/router/SummaryLSA.o: networklayer/ospfv2/router/SummaryLSA.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/ospfv2/router/LSA.h \
  base/INETDefs.h \
  networklayer/ospfv2/OSPFPacket_m.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ospfv2/router/OSPFcommon.h
$O/networklayer/rsvp_te/RSVP.o: networklayer/rsvp_te/RSVP.cc \
  networklayer/rsvp_te/RSVPPathMsg.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  util/XMLUtils.h \
  networklayer/ted/TED_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/rsvp_te/IntServ.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/rsvp_te/RSVPPacket.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/rsvp_te/RSVPPacket_m.h \
  networklayer/rsvp_te/RSVPHello_m.h \
  networklayer/rsvp_te/RSVP.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/mpls/ConstType.h \
  networklayer/ted/TEDAccess.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/IScriptable.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/mpls/LIBTable.h \
  networklayer/rsvp_te/Utils.h \
  networklayer/ipv4/IPv4Route.h \
  networklayer/rsvp_te/RSVPResvMsg.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/rsvp_te/SignallingMsg_m.h \
  networklayer/mpls/LIBTableAccess.h \
  networklayer/ted/TED.h \
  networklayer/rsvp_te/RSVPHelloMsg.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/rsvp_te/RSVPPathMsg_m.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/rsvp_te/IntServ_m.h \
  networklayer/mpls/IClassifier.h \
  networklayer/rsvp_te/IRSVPClassifier.h \
  networklayer/rsvp_te/RSVPResvMsg_m.h
$O/networklayer/rsvp_te/SimpleClassifier.o: networklayer/rsvp_te/SimpleClassifier.cc \
  networklayer/rsvp_te/RSVPPathMsg.h \
  util/XMLUtils.h \
  networklayer/rsvp_te/IntServ.h \
  networklayer/contract/IPv4Address.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/INotifiable.h \
  networklayer/rsvp_te/RSVPPacket.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/rsvp_te/RSVP.h \
  networklayer/rsvp_te/RSVPHello_m.h \
  networklayer/rsvp_te/RSVPPacket_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/mpls/ConstType.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/IScriptable.h \
  base/NotificationBoard.h \
  networklayer/rsvp_te/SimpleClassifier.h \
  networklayer/rsvp_te/RSVPAccess.h \
  networklayer/mpls/LIBTable.h \
  networklayer/rsvp_te/RSVPResvMsg.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/rsvp_te/SignallingMsg_m.h \
  networklayer/mpls/LIBTableAccess.h \
  networklayer/rsvp_te/RSVPHelloMsg.h \
  networklayer/rsvp_te/RSVPPathMsg_m.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/rsvp_te/IntServ_m.h \
  networklayer/mpls/IClassifier.h \
  networklayer/rsvp_te/IRSVPClassifier.h \
  networklayer/rsvp_te/RSVPResvMsg_m.h
$O/networklayer/rsvp_te/Utils.o: networklayer/rsvp_te/Utils.cc \
  networklayer/rsvp_te/IntServ.h \
  networklayer/contract/IPv4Address.h \
  networklayer/rsvp_te/Utils.h \
  base/INETDefs.h \
  networklayer/rsvp_te/IntServ_m.h
$O/networklayer/ted/LinkStateRouting.o: networklayer/ted/LinkStateRouting.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ted/LinkStatePacket_m.h \
  networklayer/rsvp_te/IntServ.h \
  networklayer/ted/TED_m.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ted/TEDAccess.h \
  base/ModuleAccess.h \
  networklayer/ted/LinkStateRouting.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ted/TED.h \
  networklayer/rsvp_te/IntServ_m.h
$O/networklayer/ted/TED.o: networklayer/ted/TED.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ted/TED_m.h \
  networklayer/rsvp_te/IntServ.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/ted/TED.h \
  networklayer/rsvp_te/IntServ_m.h
$O/networklayer/xmipv6/BindingCache.o: networklayer/xmipv6/BindingCache.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/xmipv6/BindingCache.h \
  base/INETDefs.h
$O/networklayer/xmipv6/BindingUpdateList.o: networklayer/xmipv6/BindingUpdateList.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/xmipv6/BindingUpdateList.h \
  networklayer/contract/IPv6Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/common/InterfaceToken.h \
  base/NotifierConsts.h \
  base/INETDefs.h
$O/networklayer/xmipv6/MobilityHeader.o: networklayer/xmipv6/MobilityHeader.cc \
  networklayer/xmipv6/MobilityHeader_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/xmipv6/MobilityHeader.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv6/IPv6ExtensionHeaders_m.h \
  base/INETDefs.h \
  networklayer/ipv6/IPv6ExtensionHeaders.h
$O/networklayer/xmipv6/xMIPv6.o: networklayer/xmipv6/xMIPv6.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/ipv6tunneling/IPv6TunnelingAccess.h \
  networklayer/xmipv6/MobilityHeader_m.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/xmipv6/BindingUpdateList.h \
  networklayer/xmipv6/xMIPv6.h \
  networklayer/contract/IPv6Address.h \
  networklayer/xmipv6/MobilityHeader.h \
  networklayer/icmpv6/IPv6NeighbourDiscoveryAccess.h \
  networklayer/common/IInterfaceTable.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/xmipv6/BindingCache.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv6/IPv6Datagram.h \
  networklayer/ipv6/RoutingTable6Access.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/icmpv6/ICMPv6Message_m.h \
  networklayer/ipv6/IPv6ExtensionHeaders_m.h \
  networklayer/ipv6/RoutingTable6.h \
  networklayer/icmpv6/IPv6NeighbourCache.h \
  base/INETDefs.h \
  networklayer/ipv6tunneling/IPv6Tunneling.h \
  networklayer/ipv6/IPv6ExtensionHeaders.h \
  networklayer/xmipv6/BindingCacheAccess.h \
  networklayer/icmpv6/IPv6NDMessage_m.h \
  networklayer/icmpv6/IPv6NeighbourDiscovery.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/xmipv6/BindingUpdateListAccess.h
$O/transport/contract/SCTPSocket.o: transport/contract/SCTPSocket.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPSocket.h \
  transport/contract/SCTPCommand_m.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  transport/sctp/SCTPMessage_m.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/contract/TCPSocket.o: transport/contract/TCPSocket.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h
$O/transport/contract/TCPSocketMap.o: transport/contract/TCPSocketMap.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/TCPCommand_m.h \
  base/INETDefs.h \
  transport/contract/TCPSocket.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/TCPSocketMap.h
$O/transport/contract/UDPSocket.o: transport/contract/UDPSocket.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  transport/contract/UDPControlInfo.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  transport/contract/UDPControlInfo_m.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/rtp/RTCP.o: transport/rtp/RTCP.cc \
  transport/rtp/RTCPPacket3.h \
  transport/rtp/RTCPPacket1_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  transport/rtp/RTCPPacket2.h \
  transport/rtp/RTPParticipantInfo_m.h \
  transport/rtp/sdes.h \
  transport/rtp/RTPSenderInfo.h \
  transport/rtp/RTPInnerPacket.h \
  transport/rtp/RTCPPacket.h \
  transport/rtp/RTPSenderControlMessage_m.h \
  transport/rtp/RTCPPacket3_m.h \
  transport/rtp/RTPReceiverInfo.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPParticipantInfo.h \
  transport/rtp/RTPPacket_m.h \
  transport/contract/UDPControlInfo_m.h \
  transport/rtp/reports_m.h \
  transport/rtp/RTCPPacket1.h \
  transport/rtp/RTCPPacket2_m.h \
  transport/rtp/RTCP.h \
  base/INETDefs.h \
  transport/rtp/RTPSenderStatusMessage_m.h \
  networklayer/contract/IPvXAddress.h \
  transport/rtp/reports.h \
  transport/rtp/RTPInnerPacket_m.h \
  transport/contract/UDPSocket.h
$O/transport/rtp/RTCPPacket.o: transport/rtp/RTCPPacket.cc \
  transport/rtp/RTCPPacket3.h \
  transport/rtp/RTCPPacket1_m.h \
  transport/rtp/RTCPPacket2.h \
  transport/rtp/sdes.h \
  transport/rtp/RTCPPacket.h \
  transport/rtp/RTCPPacket3_m.h \
  transport/rtp/reports_m.h \
  transport/rtp/RTCPPacket1.h \
  transport/rtp/RTCPPacket2_m.h \
  base/INETDefs.h \
  transport/rtp/reports.h
$O/transport/rtp/RTP.o: transport/rtp/RTP.cc \
  networklayer/contract/IPv6Address.h \
  transport/rtp/RTPProfile.h \
  transport/rtp/RTPInterfacePacket_m.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/rtp/RTPInnerPacket.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/rtp/RTPSenderControlMessage_m.h \
  base/ModuleAccess.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  transport/contract/UDPControlInfo_m.h \
  base/NotifierConsts.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/rtp/RTPSenderStatusMessage_m.h \
  networklayer/contract/IPvXAddress.h \
  transport/rtp/RTP.h \
  transport/rtp/RTPInnerPacket_m.h \
  transport/contract/UDPSocket.h
$O/transport/rtp/RTPInnerPacket.o: transport/rtp/RTPInnerPacket.cc \
  networklayer/contract/IPv4Address.h \
  transport/rtp/RTPInnerPacket.h \
  transport/rtp/RTPSenderControlMessage_m.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  base/INETDefs.h \
  transport/rtp/RTPSenderStatusMessage_m.h \
  transport/rtp/RTPInnerPacket_m.h
$O/transport/rtp/RTPPacket.o: transport/rtp/RTPPacket.cc \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  base/INETDefs.h
$O/transport/rtp/RTPParticipantInfo.o: transport/rtp/RTPParticipantInfo.cc \
  networklayer/contract/IPv4Address.h \
  transport/rtp/RTPParticipantInfo_m.h \
  transport/rtp/sdes.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPParticipantInfo.h \
  transport/rtp/RTPPacket_m.h \
  transport/rtp/reports_m.h \
  base/INETDefs.h \
  transport/rtp/reports.h
$O/transport/rtp/RTPPayloadReceiver.o: transport/rtp/RTPPayloadReceiver.cc \
  networklayer/contract/IPv4Address.h \
  transport/rtp/RTPInnerPacket.h \
  transport/rtp/RTPSenderControlMessage_m.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  base/INETDefs.h \
  transport/rtp/RTPSenderStatusMessage_m.h \
  transport/rtp/RTPPayloadReceiver.h \
  transport/rtp/RTPInnerPacket_m.h
$O/transport/rtp/RTPPayloadSender.o: transport/rtp/RTPPayloadSender.cc \
  transport/rtp/RTPInterfacePacket_m.h \
  networklayer/contract/IPv4Address.h \
  transport/rtp/RTPInnerPacket.h \
  transport/rtp/RTPSenderControlMessage_m.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  base/INETDefs.h \
  transport/rtp/RTPSenderStatusMessage_m.h \
  transport/rtp/RTPPayloadSender.h \
  transport/rtp/RTPInnerPacket_m.h
$O/transport/rtp/RTPProfile.o: transport/rtp/RTPProfile.cc \
  transport/rtp/RTPProfile.h \
  networklayer/contract/IPv4Address.h \
  transport/rtp/RTPInnerPacket.h \
  transport/rtp/RTPSenderControlMessage_m.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  base/INETDefs.h \
  transport/rtp/RTPSenderStatusMessage_m.h \
  transport/rtp/RTPPayloadReceiver.h \
  transport/rtp/RTPPayloadSender.h \
  transport/rtp/RTPInnerPacket_m.h
$O/transport/rtp/RTPReceiverInfo.o: transport/rtp/RTPReceiverInfo.cc \
  networklayer/contract/IPv4Address.h \
  transport/rtp/sdes.h \
  transport/rtp/RTPParticipantInfo_m.h \
  transport/rtp/RTPReceiverInfo.h \
  transport/rtp/RTPParticipantInfo.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  transport/rtp/reports_m.h \
  base/INETDefs.h \
  transport/rtp/reports.h
$O/transport/rtp/RTPSenderInfo.o: transport/rtp/RTPSenderInfo.cc \
  networklayer/contract/IPv4Address.h \
  transport/rtp/sdes.h \
  transport/rtp/RTPParticipantInfo_m.h \
  transport/rtp/RTPSenderInfo.h \
  transport/rtp/RTPParticipantInfo.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  transport/rtp/reports_m.h \
  base/INETDefs.h \
  transport/rtp/reports.h
$O/transport/rtp/reports.o: transport/rtp/reports.cc \
  transport/rtp/reports_m.h \
  transport/rtp/reports.h
$O/transport/rtp/sdes.o: transport/rtp/sdes.cc \
  transport/rtp/sdes.h \
  base/INETDefs.h
$O/transport/rtp/profiles/avprofile/RTPAVProfile.o: transport/rtp/profiles/avprofile/RTPAVProfile.cc \
  transport/rtp/RTPProfile.h \
  base/INETDefs.h \
  transport/rtp/profiles/avprofile/RTPAVProfile.h
$O/transport/rtp/profiles/avprofile/RTPAVProfilePayload32Receiver.o: transport/rtp/profiles/avprofile/RTPAVProfilePayload32Receiver.cc \
  transport/rtp/profiles/avprofile/RTPMpegPacket_m.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  transport/rtp/profiles/avprofile/RTPAVProfilePayload32Receiver.h \
  base/INETDefs.h \
  transport/rtp/RTPPayloadReceiver.h
$O/transport/rtp/profiles/avprofile/RTPAVProfilePayload32Sender.o: transport/rtp/profiles/avprofile/RTPAVProfilePayload32Sender.cc \
  networklayer/contract/IPv4Address.h \
  transport/rtp/profiles/avprofile/RTPMpegPacket_m.h \
  transport/rtp/RTPInnerPacket.h \
  transport/rtp/profiles/avprofile/RTPAVProfilePayload32Sender.h \
  transport/rtp/RTPSenderControlMessage_m.h \
  transport/rtp/RTPPacket.h \
  transport/rtp/RTPPacket_m.h \
  base/INETDefs.h \
  transport/rtp/RTPSenderStatusMessage_m.h \
  transport/rtp/RTPPayloadSender.h \
  transport/rtp/RTPInnerPacket_m.h
$O/transport/sctp/ChunkMap.o: transport/sctp/ChunkMap.cc \
  transport/sctp/ChunkMap.h
$O/transport/sctp/GapList.o: transport/sctp/GapList.cc \
  transport/sctp/GapList.h \
  transport/sctp/SCTPSeqNumbers.h
$O/transport/sctp/QoSStatsCollector.o: transport/sctp/QoSStatsCollector.cc \
  transport/sctp/QoSStatsCollector.h
$O/transport/sctp/SCTP.o: transport/sctp/SCTP.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPCommand_m.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  transport/contract/UDPControlInfo_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPv6ControlInfo.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPAlg.o: transport/sctp/SCTPAlg.cc \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTPAlg.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/sctp/SCTPAlgorithm.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPAssociationAddIP.o: transport/sctp/SCTPAssociationAddIP.cc \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTP.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/contract/IPvXAddressResolver.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPAssociationBase.o: transport/sctp/SCTPAssociationBase.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPCommand_m.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/sctp/SCTPAlgorithm.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPAssociationEventProc.o: transport/sctp/SCTPAssociationEventProc.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPCommand_m.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/sctp/SCTPAlgorithm.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPAssociationRcvMessage.o: transport/sctp/SCTPAssociationRcvMessage.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPCommand_m.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/sctp/SCTPAlgorithm.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPAssociationSendAll.o: transport/sctp/SCTPAssociationSendAll.cc \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTP.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPCommand_m.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/sctp/SCTPAlgorithm.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPAssociationStreamReset.o: transport/sctp/SCTPAssociationStreamReset.cc \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTP.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPCommand_m.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPAssociationUtil.o: transport/sctp/SCTPAssociationUtil.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/contract/SCTPCommand_m.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  transport/contract/UDPControlInfo_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/contract/SCTPCommand.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPv6ControlInfo.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/sctp/SCTPAlgorithm.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPCCFunctions.o: transport/sctp/SCTPCCFunctions.cc \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTP.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPMessage.o: transport/sctp/SCTPMessage.cc \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTP.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPReceiveStream.h \
  transport/sctp/SCTPMessage.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPNatTable.o: transport/sctp/SCTPNatTable.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/QoSStatsCollector.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  util/common.h \
  transport/sctp/ChunkMap.h \
  transport/sctp/SCTPMessage_m.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPReceiveStream.h \
  transport/sctp/SCTPMessage.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/sctp/SCTPNatTable.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPQueue.o: transport/sctp/SCTPQueue.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPReceiveStream.o: transport/sctp/SCTPReceiveStream.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPSSFunctions.o: transport/sctp/SCTPSSFunctions.cc \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTP.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPMessage.h \
  transport/sctp/SCTPReceiveStream.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/SCTPSendStream.o: transport/sctp/SCTPSendStream.cc \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTP.h \
  networklayer/contract/IPv4Address.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPSendStream.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h \
  transport/contract/UDPSocket.h
$O/transport/sctp/TimeStatsCollector.o: transport/sctp/TimeStatsCollector.cc \
  transport/sctp/TimeStatsCollector.h
$O/transport/tcp/TCP.o: transport/tcp/TCP.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  transport/tcp/queues/TCPByteStreamRcvQueue.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/ByteArrayBuffer.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  transport/tcp/queues/TCPMsgBasedSendQueue.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/TCPReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  transport/tcp/queues/TCPByteStreamSendQueue.h \
  base/NotificationBoard.h \
  networklayer/icmpv6/ICMPv6Message_m.h \
  networklayer/ipv4/ICMPMessage_m.h \
  transport/contract/TCPCommand_m.h \
  transport/tcp/queues/TCPVirtualDataSendQueue.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  transport/tcp/queues/TCPVirtualDataRcvQueue.h \
  networklayer/common/InterfaceTable.h \
  transport/tcp/queues/TCPMsgBasedRcvQueue.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/TCPConnectionBase.o: transport/tcp/TCPConnectionBase.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  transport/tcp/TCPSACKRexmitQueue.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  transport/tcp/TCPReceiveQueue.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/TCPConnectionEventProc.o: transport/tcp/TCPConnectionEventProc.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  transport/tcp/TCPReceiveQueue.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/TCPConnectionRcvSegment.o: transport/tcp/TCPConnectionRcvSegment.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  transport/tcp/TCPSACKRexmitQueue.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  transport/tcp/TCPReceiveQueue.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/TCPConnectionSackUtil.o: transport/tcp/TCPConnectionSackUtil.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  transport/tcp/TCPSACKRexmitQueue.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  transport/tcp/TCPReceiveQueue.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/TCPConnectionUtil.o: transport/tcp/TCPConnectionUtil.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  transport/tcp/mptcp_extension/TCPMultipathSchedulerI.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  transport/tcp/TCPSACKRexmitQueue.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  transport/tcp/mptcp_extension/mptcp_scheduler/TCPSchedulerManager.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  transport/tcp/TCPReceiveQueue.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/TCPSACKRexmitQueue.o: transport/tcp/TCPSACKRexmitQueue.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  transport/tcp/TCPSACKRexmitQueue.h \
  networklayer/common/InterfaceEntry.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/ByteArray.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/flavours/DumbTCP.o: transport/tcp/flavours/DumbTCP.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  transport/tcp/flavours/DumbTCP.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/flavours/TCPBaseAlg.o: transport/tcp/flavours/TCPBaseAlg.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  transport/tcp/TCPSACKRexmitQueue.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  transport/tcp/flavours/TCPBaseAlg.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/flavours/TCPNewReno.o: transport/tcp/flavours/TCPNewReno.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  transport/tcp/flavours/TCPNewReno.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  transport/tcp/flavours/TCPBaseAlg.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  transport/tcp/flavours/TCPTahoeRenoFamily.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/flavours/TCPNoCongestionControl.o: transport/tcp/flavours/TCPNoCongestionControl.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/flavours/TCPBaseAlg.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  transport/tcp/flavours/TCPNoCongestionControl.h \
  base/NotifierConsts.h \
  base/ByteArray.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/flavours/TCPReno.o: transport/tcp/flavours/TCPReno.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  transport/tcp/flavours/TCPReno.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  transport/tcp/flavours/TCPBaseAlg.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  transport/tcp/flavours/TCPTahoeRenoFamily.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/flavours/TCPTahoe.o: transport/tcp/flavours/TCPTahoe.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  transport/tcp/flavours/TCPBaseAlg.h \
  transport/tcp/flavours/TCPTahoe.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  transport/tcp/flavours/TCPTahoeRenoFamily.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/flavours/TCPTahoeRenoFamily.o: transport/tcp/flavours/TCPTahoeRenoFamily.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/flavours/TCPBaseAlg.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/ByteArray.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  transport/tcp/flavours/TCPTahoeRenoFamily.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/mptcp_extension/TCPMultipathFlow.o: transport/tcp/mptcp_extension/TCPMultipathFlow.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  transport/tcp/mptcp_extension/TCPMultipathSchedulerI.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  transport/tcp/TCPSACKRexmitQueue.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  transport/tcp/mptcp_extension/mptcp_scheduler/TCPSchedulerManager.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/mptcp_extension/TCPMultipathPCB.o: transport/tcp/mptcp_extension/TCPMultipathPCB.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/mptcp_extension/flavours/MPTCP_RFC6356.o: transport/tcp/mptcp_extension/flavours/MPTCP_RFC6356.cc \
  transport/tcp/mptcp_extension/flavours/MPTCP_RFC6356.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/TCPAlgorithm.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  transport/tcp/flavours/TCPNewReno.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/flavours/TCPBaseAlg.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/ByteArray.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  transport/tcp/flavours/TCPTahoeRenoFamily.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathMsgBasedRcvQueue.o: transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathMsgBasedRcvQueue.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathVirtualDataRcvQueue.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathMsgBasedRcvQueue.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/ByteArray.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathVirtualDataRcvQueue.o: transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathVirtualDataRcvQueue.cc \
  transport/tcp_common/TCPSegment.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathVirtualDataRcvQueue.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  base/ByteArray.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/INETDefs.h
$O/transport/tcp/mptcp_extension/mptcp_scheduler/TCPMultipathRoundRobinScheduler.o: transport/tcp/mptcp_extension/mptcp_scheduler/TCPMultipathRoundRobinScheduler.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  transport/tcp/mptcp_extension/TCPMultipathSchedulerI.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_scheduler/TCPMultipathRoundRobinScheduler.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/mptcp_extension/mptcp_scheduler/TCPSchedulerManager.o: transport/tcp/mptcp_extension/mptcp_scheduler/TCPSchedulerManager.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  transport/tcp/mptcp_extension/TCPMultipathSchedulerI.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/mptcp_scheduler/TCPMultipathRoundRobinScheduler.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  transport/tcp/mptcp_extension/mptcp_scheduler/TCPSchedulerManager.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/queues/TCPByteStreamRcvQueue.o: transport/tcp/queues/TCPByteStreamRcvQueue.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  transport/tcp/queues/TCPByteStreamRcvQueue.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  base/ByteArrayMessage.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  networklayer/common/InterfaceToken.h \
  base/ByteArrayMessage_m.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  transport/tcp/TCPReceiveQueue.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  transport/tcp/TCPConnection.h \
  base/INETDefs.h \
  transport/tcp/queues/TCPVirtualDataRcvQueue.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/queues/TCPByteStreamSendQueue.o: transport/tcp/queues/TCPByteStreamSendQueue.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  base/ByteArrayMessage.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  base/ByteArrayBuffer.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  base/ByteArrayMessage_m.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  transport/tcp/queues/TCPByteStreamSendQueue.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/queues/TCPMsgBasedRcvQueue.o: transport/tcp/queues/TCPMsgBasedRcvQueue.cc \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  transport/tcp/TCPReceiveQueue.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  transport/tcp/queues/TCPVirtualDataRcvQueue.h \
  networklayer/common/InterfaceTable.h \
  transport/tcp/queues/TCPMsgBasedRcvQueue.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/queues/TCPMsgBasedSendQueue.o: transport/tcp/queues/TCPMsgBasedSendQueue.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  transport/tcp/queues/TCPMsgBasedSendQueue.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  transport/tcp/TCPConnection.h \
  base/INETDefs.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/queues/TCPVirtualDataRcvQueue.o: transport/tcp/queues/TCPVirtualDataRcvQueue.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/TCPReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  transport/tcp/TCPConnection.h \
  transport/tcp/queues/TCPVirtualDataRcvQueue.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp/queues/TCPVirtualDataSendQueue.o: transport/tcp/queues/TCPVirtualDataSendQueue.cc \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/tcp/mptcp_extension/TCPMultipathPCB.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  networklayer/common/InterfaceToken.h \
  transport/tcp/mptcp_extension/mptcp_queues/TCPMultipathReceiveQueue.h \
  transport/tcp/mptcp_extension/TCPMultipath.h \
  base/INotifiable.h \
  transport/tcp/TCPSendQueue.h \
  networklayer/ipv4/IRoutingTable.h \
  networklayer/ipv4/RoutingTable.h \
  base/ModuleAccess.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  transport/tcp/mptcp_extension/TCPMultipathFlow.h \
  base/NotificationBoard.h \
  transport/contract/TCPCommand_m.h \
  transport/tcp/queues/TCPVirtualDataSendQueue.h \
  networklayer/ipv4/IPv4Route.h \
  transport/tcp/TCPConnection.h \
  base/INETDefs.h \
  networklayer/common/InterfaceTable.h \
  networklayer/contract/IPvXAddress.h \
  transport/tcp/TCP.h
$O/transport/tcp_common/TCPSegment.o: transport/tcp_common/TCPSegment.cc \
  transport/tcp_common/TCPSegment.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  base/ByteArray.h \
  base/INETDefs.h
$O/transport/tcp_common/TCPSpoof.o: transport/tcp_common/TCPSpoof.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/contract/IPvXAddressResolver.h \
  transport/tcp_common/TCPSpoof.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/ByteArray.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h
$O/transport/udp/UDP.o: transport/udp/UDP.cc \
  networklayer/contract/IPv6ControlInfo_m.h \
  transport/udp/UDPPacket.h \
  networklayer/ipv4/ICMP.h \
  networklayer/ipv6/IPv6InterfaceData.h \
  networklayer/ipv4/IPv4InterfaceData.h \
  networklayer/contract/IPv6Address.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceTableAccess.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/contract/UDPControlInfo.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv6/IPv6Datagram.h \
  base/INotifiable.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/udp/UDPPacket_m.h \
  networklayer/ipv4/ICMPAccess.h \
  base/ModuleAccess.h \
  transport/udp/UDP.h \
  transport/contract/UDPControlInfo_m.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/icmpv6/ICMPv6Message_m.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/icmpv6/ICMPv6Access.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/icmpv6/ICMPv6.h \
  networklayer/contract/IPv6ControlInfo.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/ipv4/ICMPMessage.h
$O/util/Delayer.o: util/Delayer.cc \
  util/Delayer.h \
  base/INETDefs.h
$O/util/Macho.o: util/Macho.cc \
  util/Macho.h
$O/util/MessageChecker.o: util/MessageChecker.cc \
  util/MessageChecker.h \
  base/INETDefs.h
$O/util/NetAnimTrace.o: util/NetAnimTrace.cc \
  util/FWMath.h \
  base/Coord.h \
  util/NetAnimTrace.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/INETDefs.h
$O/util/OrdinalBasedDropper.o: util/OrdinalBasedDropper.cc \
  util/OrdinalBasedDropper.h \
  base/INETDefs.h
$O/util/OrdinalBasedDuplicator.o: util/OrdinalBasedDuplicator.cc \
  util/OrdinalBasedDuplicator.h \
  base/INETDefs.h
$O/util/PacketDump.o: util/PacketDump.cc \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  transport/sctp/SCTP.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  base/ByteArray_m.h \
  networklayer/common/InterfaceEntry.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  networklayer/ipv6/IPv6Datagram.h \
  base/INotifiable.h \
  networklayer/ipv6/IPv6Datagram_m.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPReceiveStream.h \
  transport/sctp/SCTPMessage.h \
  transport/udp/UDPPacket_m.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/ByteArray.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  networklayer/ipv4/ICMPMessage_m.h \
  networklayer/ipv4/IPv4Route.h \
  util/PacketDump.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  networklayer/ipv4/ICMPMessage.h \
  transport/contract/UDPSocket.h
$O/util/PatternMatcher.o: util/PatternMatcher.cc \
  util/PatternMatcher.h \
  base/INETDefs.h
$O/util/PcapDump.o: util/PcapDump.cc \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  transport/udp/UDPPacket_m.h \
  util/PcapDump.h \
  util/headerserializers/ipv4/IPv4Serializer.h \
  base/INETDefs.h \
  networklayer/ipv4/IPv4Datagram.h
$O/util/PcapRecorder.o: util/PcapRecorder.cc \
  networklayer/contract/IPv4Address.h \
  util/PcapRecorder.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  util/PcapDump.h \
  util/PacketDump.h \
  base/INETDefs.h \
  networklayer/ipv4/IPv4Datagram.h
$O/util/TCPDump.o: util/TCPDump.cc \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  util/PcapDump.h \
  util/PacketDump.h \
  base/INETDefs.h \
  networklayer/ipv4/IPv4Datagram.h \
  util/TCPDump.h
$O/util/ThruputMeter.o: util/ThruputMeter.cc \
  util/ThruputMeter.h \
  base/INETDefs.h
$O/util/ThruputMeteringChannel.o: util/ThruputMeteringChannel.cc \
  util/ThruputMeteringChannel.h \
  base/INETDefs.h
$O/util/XMLUtils.o: util/XMLUtils.cc \
  util/XMLUtils.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPvXAddressResolver.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/util/common.o: util/common.cc \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  util/common.h \
  base/INETDefs.h \
  networklayer/contract/IPvXAddress.h
$O/util/int128.o: util/int128.cc \
  util/int128.h \
  base/INETDefs.h
$O/util/opp_utils.o: util/opp_utils.cc \
  util/opp_utils.h \
  base/INETDefs.h
$O/util/headerserializers/TCPIPchecksum.o: util/headerserializers/TCPIPchecksum.cc \
  base/INETDefs.h \
  util/headerserializers/TCPIPchecksum.h
$O/util/headerserializers/ipv4/ICMPSerializer.o: util/headerserializers/ipv4/ICMPSerializer.cc \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPProtocolId_m.h \
  util/headerserializers/ipv4/ICMPSerializer.h \
  util/headerserializers/ipv4/headers/ip_icmp.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  util/headerserializers/ipv4/headers/ip.h \
  applications/pingapp/PingPayload_m.h \
  networklayer/ipv4/ICMPMessage_m.h \
  util/headerserializers/ipv4/IPv4Serializer.h \
  base/INETDefs.h \
  util/headerserializers/headers/bsdint.h \
  util/headerserializers/headers/in_systm.h \
  networklayer/ipv4/IPv4Datagram.h \
  util/headerserializers/headers/defs.h \
  util/headerserializers/headers/in.h \
  util/headerserializers/TCPIPchecksum.h
$O/util/headerserializers/ipv4/IGMPSerializer.o: util/headerserializers/ipv4/IGMPSerializer.cc \
  networklayer/contract/IPv4Address.h \
  networklayer/contract/IPProtocolId_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  util/headerserializers/ipv4/headers/igmp.h \
  util/headerserializers/ipv4/headers/ip.h \
  util/headerserializers/ipv4/IPv4Serializer.h \
  base/INETDefs.h \
  util/headerserializers/headers/bsdint.h \
  networklayer/ipv4/IGMPMessage_m.h \
  util/headerserializers/headers/in_systm.h \
  networklayer/ipv4/IPv4Datagram.h \
  util/headerserializers/headers/defs.h \
  util/headerserializers/headers/in.h \
  util/headerserializers/TCPIPchecksum.h \
  util/headerserializers/ipv4/IGMPSerializer.h
$O/util/headerserializers/ipv4/IPv4Serializer.o: util/headerserializers/ipv4/IPv4Serializer.cc \
  transport/udp/UDPPacket.h \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  util/headerserializers/sctp/SCTPSerializer.h \
  networklayer/contract/IPv4Address.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/contract/IPProtocolId_m.h \
  util/headerserializers/ipv4/ICMPSerializer.h \
  util/headerserializers/tcp/TCPSerializer.h \
  transport/sctp/SCTPMessage_m.h \
  networklayer/ipv4/IPv4Datagram_m.h \
  util/headerserializers/udp/UDPSerializer.h \
  transport/sctp/SCTPMessage.h \
  transport/udp/UDPPacket_m.h \
  util/headerserializers/tcp/headers/tcp.h \
  util/headerserializers/ipv4/headers/ip.h \
  base/ByteArray.h \
  networklayer/ipv4/ICMPMessage_m.h \
  util/headerserializers/ipv4/IPv4Serializer.h \
  base/INETDefs.h \
  util/headerserializers/headers/bsdint.h \
  networklayer/ipv4/IGMPMessage_m.h \
  util/headerserializers/headers/in_systm.h \
  networklayer/contract/IPvXAddress.h \
  networklayer/ipv4/IPv4Datagram.h \
  util/headerserializers/headers/defs.h \
  util/headerserializers/headers/in.h \
  util/headerserializers/TCPIPchecksum.h \
  util/headerserializers/ipv4/IGMPSerializer.h
$O/util/headerserializers/sctp/SCTPSerializer.o: util/headerserializers/sctp/SCTPSerializer.cc \
  networklayer/contract/IPv6Address.h \
  util/headerserializers/sctp/SCTPSerializer.h \
  transport/sctp/SCTP.h \
  networklayer/common/IInterfaceTable.h \
  networklayer/contract/IPv4Address.h \
  networklayer/common/InterfaceTableAccess.h \
  linklayer/contract/MACAddress.h \
  networklayer/common/InterfaceEntry.h \
  networklayer/ipv4/RoutingTableAccess.h \
  transport/sctp/TimeStatsCollector.h \
  networklayer/common/InterfaceToken.h \
  base/INotifiable.h \
  transport/sctp/SCTPQueue.h \
  transport/sctp/QoSStatsCollector.h \
  networklayer/contract/IPProtocolId_m.h \
  transport/sctp/SCTPAssociation.h \
  transport/sctp/ChunkMap.h \
  util/common.h \
  networklayer/ipv4/IRoutingTable.h \
  transport/sctp/SCTPMessage_m.h \
  transport/sctp/SCTPReceiveStream.h \
  transport/sctp/SCTPMessage.h \
  networklayer/ipv4/RoutingTable.h \
  transport/sctp/GapList.h \
  base/ModuleAccess.h \
  util/headerserializers/ipv4/headers/ip.h \
  transport/sctp/SCTPSendStream.h \
  networklayer/contract/IPv4ControlInfo.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  util/headerserializers/sctp/headers/sctp.h \
  networklayer/ipv4/IPv4Route.h \
  base/INETDefs.h \
  networklayer/contract/IPv4ControlInfo_m.h \
  util/headerserializers/headers/bsdint.h \
  util/headerserializers/headers/in_systm.h \
  networklayer/common/InterfaceTable.h \
  transport/sctp/SCTPSeqNumbers.h \
  networklayer/contract/IPvXAddress.h \
  util/headerserializers/headers/defs.h \
  util/headerserializers/headers/in.h \
  transport/contract/UDPSocket.h
$O/util/headerserializers/tcp/TCPSerializer.o: util/headerserializers/tcp/TCPSerializer.cc \
  transport/tcp_common/TCPSegment.h \
  networklayer/contract/IPv6Address.h \
  networklayer/contract/IPv4Address.h \
  base/ByteArray_m.h \
  transport/tcp_common/TCPSegment_m.h \
  networklayer/contract/IPProtocolId_m.h \
  util/headerserializers/tcp/TCPSerializer.h \
  util/headerserializers/tcp/headers/tcp.h \
  base/ByteArray.h \
  base/INETDefs.h \
  util/headerserializers/headers/bsdint.h \
  util/headerserializers/headers/in_systm.h \
  networklayer/contract/IPvXAddress.h \
  util/headerserializers/headers/defs.h \
  util/headerserializers/headers/in.h \
  util/headerserializers/TCPIPchecksum.h
$O/util/headerserializers/udp/UDPSerializer.o: util/headerserializers/udp/UDPSerializer.cc \
  transport/udp/UDPPacket.h \
  util/headerserializers/udp/UDPSerializer.h \
  transport/udp/UDPPacket_m.h \
  base/INETDefs.h \
  util/headerserializers/headers/bsdint.h \
  util/headerserializers/headers/in_systm.h \
  util/headerserializers/headers/defs.h \
  util/headerserializers/headers/in.h \
  util/headerserializers/udp/headers/udp.h \
  util/headerserializers/TCPIPchecksum.h
$O/world/annotations/AnnotationDummy.o: world/annotations/AnnotationDummy.cc \
  ./world/annotations/AnnotationDummy.h \
  base/INETDefs.h
$O/world/annotations/AnnotationManager.o: world/annotations/AnnotationManager.cc \
  util/FWMath.h \
  base/Coord.h \
  ./world/annotations/AnnotationManager.h \
  base/ModuleAccess.h \
  base/INETDefs.h
$O/world/httptools/HttpController.o: world/httptools/HttpController.cc \
  applications/httptools/HttpRandom.h \
  applications/httptools/HttpMessages_m.h \
  applications/httptools/HttpEventMessages_m.h \
  applications/httptools/HttpLogdefs.h \
  base/INETDefs.h \
  world/httptools/HttpController.h \
  applications/httptools/HttpUtils.h
$O/world/obstacles/Obstacle.o: world/obstacles/Obstacle.cc \
  util/FWMath.h \
  ./world/obstacles/Obstacle.h \
  base/Coord.h \
  ./world/annotations/AnnotationManager.h \
  base/ModuleAccess.h \
  base/INETDefs.h
$O/world/obstacles/ObstacleControl.o: world/obstacles/ObstacleControl.cc \
  util/FWMath.h \
  ./world/obstacles/Obstacle.h \
  base/Coord.h \
  ./world/obstacles/ObstacleControl.h \
  ./world/annotations/AnnotationManager.h \
  base/ModuleAccess.h \
  base/INETDefs.h
$O/world/powercontrol/PowerControlManager.o: world/powercontrol/PowerControlManager.cc \
  base/INETDefs.h \
  world/powercontrol/IPowerControl.h \
  world/powercontrol/PowerControlMessages_m.h \
  world/powercontrol/PowerControlManager.h
$O/world/radio/ChannelAccess.o: world/radio/ChannelAccess.cc \
  base/BasicModule.h \
  util/FWMath.h \
  base/Coord.h \
  base/INotifiable.h \
  world/radio/ChannelAccess.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  world/radio/IChannelControl.h
$O/world/radio/ChannelControl.o: world/radio/ChannelControl.cc \
  util/FWMath.h \
  world/radio/ChannelControl.h \
  base/Coord.h \
  linklayer/radio/AirFrame_m.h \
  base/INETDefs.h \
  linklayer/radio/ModulationType.h \
  world/radio/IChannelControl.h
$O/world/radio/IdealChannelModel.o: world/radio/IdealChannelModel.cc \
  base/BasicModule.h \
  util/FWMath.h \
  world/radio/IdealChannelModel.h \
  linklayer/radio/IdealRadio.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  linklayer/radio/IdealAirFrame_m.h \
  linklayer/contract/RadioState.h \
  world/radio/IdealChannelModelAccess.h \
  base/INETDefs.h \
  world/powercontrol/IPowerControl.h
$O/world/radio/IdealChannelModelAccess.o: world/radio/IdealChannelModelAccess.cc \
  base/BasicModule.h \
  util/FWMath.h \
  world/radio/IdealChannelModel.h \
  base/Coord.h \
  base/INotifiable.h \
  base/ModuleAccess.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  world/radio/IdealChannelModelAccess.h
$O/world/scenario/ScenarioManager.o: world/scenario/ScenarioManager.cc \
  base/IScriptable.h \
  base/INETDefs.h \
  world/scenario/ScenarioManager.h
$O/world/traci/TraCIScenarioManager.o: world/traci/TraCIScenarioManager.cc \
  base/BasicModule.h \
  util/FWMath.h \
  ./mobility/models/MobilityBase.h \
  base/Coord.h \
  base/INotifiable.h \
  ./world/traci/TraCIScenarioManager.h \
  base/ModuleAccess.h \
  ./world/traci/TraCIConstants.h \
  mobility/IMobility.h \
  base/NotifierConsts.h \
  base/NotificationBoard.h \
  base/INETDefs.h \
  ./mobility/models/TraCIMobility.h
$O/world/traci/TraCIScenarioManagerLaunchd.o: world/traci/TraCIScenarioManagerLaunchd.cc \
  util/FWMath.h \
  ./world/traci/TraCIScenarioManagerLaunchd.h \
  base/Coord.h \
  ./world/traci/TraCIScenarioManager.h \
  base/ModuleAccess.h \
  ./world/traci/TraCIConstants.h \
  base/INETDefs.h
