#
# Migrates neddoc comments in NED and MSG files from "auto-hyperlinking" mode to "tilde mode"
#
$listfname = $ARGV[0];
open(LISTFILE, $listfname) || die "cannot open $listfname";
while (<LISTFILE>)
{
    chomp;
    s/\r$//; # cygwin/mingw perl does not do CR/LF translation

    $fname = $_;
    print "processing $fname...\n";

    open(INFILE, $fname) || die "cannot open $fname";
    read(INFILE, $txt, 1000000) || die "cannot read $fname";
    close INFILE;

    # module and message names to process
    my $names = "ANSimMobility|ARP|ARPTest|ARPTest|BGPNet|BGPRouter|BGPRouter|BGPRouterSimple|BGPRouting|BGPTest|BGPTest|BGPTest|BGPTest|BGPTest|Backbone|BasicDecider|BasicSnrEval|Blackboard|BonnMotionMobility|BulkTransfer|BulkTransfer6|BurstHost|BurstTests|BusLAN|CSMAMacLayer|ChannelControl|ChannelInstaller|CircleMobility|ClientServer|CompareMACs|ConstSpeedMobility|Decider80211|DemoNetworkEth|DropTailQoSQueue|DropTailQueue|DropsGenerator|Dummy|DuplicatesGenerator|ErrAndCollDecider|ErrorHandling|EtherAppCli|EtherAppSrv|EtherBus|EtherEncap|EtherHost|EtherHostFullDuplex|EtherHostFullDuplexQ|EtherHostQ|EtherHub|EtherLLC|EtherMAC|EtherMACFullDuplex|EtherSwitch|EtherSwitchFullDuplex|EthernetInterface|EthernetInterfaceNoQueue|ExtClient|ExtInterface|ExtRouter|FailedRouter|FailureManager|FlatNet|FlatNetworkConfigurator|FlatNetworkConfigurator6|GenericRadio|GilbertElliotSnr|HandoverNetwork|HubLAN|ICMP|ICMPv6|IGMP|IP|IPTrafGen|IPTrafSink|IPv6|IPv6ErrorHandling|IPv6NeighbourDiscovery|Ieee80211AgentSTA|Ieee80211Mac|Ieee80211MgmtAP|Ieee80211MgmtAPSimplified|Ieee80211MgmtAdhoc|Ieee80211MgmtSTA|Ieee80211MgmtSTASimplified|Ieee80211Nic|Ieee80211NicAP|Ieee80211NicAPSimplified|Ieee80211NicAdhoc|Ieee80211NicSTA|Ieee80211NicSTASimplified|Ieee80211Radio|InterfaceTable|Join|KIDSNw1|LDP|LDPTEST|LDP_FAILED|LDP_LSR|LIBTable|Lan80211|LargeLAN|LargeNet|LinearMobility|LinkStateRouting|MACRelayUnitNP|MACRelayUnitPP|MFMobileHost|MPLS|Mac80211|MassMobility|MediumLAN|MessageChecker|MixedLAN|MobileHost|MobileNet|MulticastNetwork|NAMTrace|NAMTraceWriter|NClients|NClients|NClients2|NClientsEth|NClientsEth|NClientsPPP|NClientsPPP|Net|Net80211|Net80211|NetAnimTrace|NetworkConfigurator|NetworkInfo|NetworkLayer|NetworkLayer6|Nic80211|NicCsma|Nop|NotificationBoard|NullMobility|OSPFRouter|OSPFRouting|OSPF_Area1|OSPF_Area2|OSPF_Area3|OSPF_AreaTest|OSPF_TestNetwork|OneNetArea|PPP|PPPInterface|PPPInterfaceNoQueue|PPPInterfaceWithDLDuplicatesGenerator|PPPInterfaceWithDLThruputMeter|PPPInterfaceWithULDropsGenerator|PPPInterfaceWithULThruputMeter|PingApp|PlainMobilityHost|R37|R37orig|REDQueue|REDTest|REDTestDebug|REDTestTh|RSVP|RSVPTE4|RSVPTE4|RSVPTE4|RSVPTE4|RSVPTE4|RSVP_FAILED|RSVP_LSR|RTCP|RTP|RTPAVProfile|RTPAVProfilePayload10Receiver|RTPAVProfilePayload10Sender|RTPAVProfilePayload32Receiver|RTPAVProfilePayload32Sender|RTPAVProfileSampleBasedAudioReceiver|RTPAVProfileSampleBasedAudioSender|RTPApplication|RTPHost|RTPMulticast1|RTPMulticast11|RTPNetwork|RTPPayloadReceiver|RTPPayloadSender|RTPProfile|RTPUnicast2|RandomWPMobility|RectangleMobility|Router|Router6|RouterPerfNetwork|RoutingTable|RoutingTable6|SCTP|SCTPClient|SCTPPeer|SCTPServer|ScenarioManager|SimpleClassifier|SimpleTest|Sink|SmallLAN|SnrDecider|SnrEval|SnrEval80211|SnrNic|SpeedTest|SpeedTest|SpeedTest|StandardHost|StandardHost6|StandardHostWithDLDuplicatesGenerator|StandardHostWithDLThruputMeter|StandardHostWithULDropsGenerator|StandardHostWithULThruputMeter|SwitchedDuplexLAN|SwitchedLAN|TCP|TCPBasicClientApp|TCPDump|TCPEchoApp|TCPGenericSrvApp|TCPSessionApp|TCPSinkApp|TCPSpoof|TCPSpoofingHost|TCPSrvHostApp|TCP_NSC|TCP_lwip|TCP_old|TED|TelnetApp|Test|Throughput|Throughput|ThroughputClient|ThroughputClient|ThroughputServer|ThruputMeter|Traceroute|TurtleMobility|TwoHosts|TwoNetsArea|UDP|UDPBasicApp|UDPEchoApp|UDPSink|UDPVideoStreamCli|UDPVideoStreamSvr|WirelessAP|WirelessAPSimplified|WirelessAPWithEth|WirelessAPWithEthSimplified|WirelessAPWithSink|WirelessHost|WirelessHostSimplified|WirelessMac";
    $names .= "|ARPOpcode|ARPPacket|AirFrame|BGPASPathSegment|BGPHeader|BGPKeepAliveMessage|BGPOpenMessage|BGPOptionalParameters|BGPParameterValues|BGPPathSegmentType|BGPType|BGPUpdateAtomicAggregateValues|BGPUpdateAttributeFlags|BGPUpdateAttributeType|BGPUpdateAttributeTypeCode|BGPUpdateMessage|BGPUpdateNLRI|BGPUpdateOriginValues|BGPUpdatePathAttributeList|BGPUpdatePathAttributes|BGPUpdatePathAttributesASPath|BGPUpdatePathAttributesAtomicAggregate|BGPUpdatePathAttributesLocalPref|BGPUpdatePathAttributesNextHop|BGPUpdatePathAttributesOrigin|BGPUpdateWithdrawnRoutes|ByteArray|ByteArrayMessage|ControlManetRouting|EroObj_t|EtherAppReq|EtherAppResp|EtherFrame|EtherFrameWithLLC|EtherFrameWithSNAP|EtherJam|EtherPadding|EtherPauseFrame|EtherTraffic|EtherType|EthernetIIFrame|ExternalTOSInfo|FEC_TLV|FilterSpecObj_t|FlowDescriptor_t|FlowSpecObj_t|GenericAppMsg|HelloTimeoutMsg|HelloTimerMsg|ICMPMessage|ICMPType|ICMPv6DEST_UN|ICMPv6DestUnreachableMsg|ICMPv6EchoReplyMsg|ICMPv6EchoRequestMsg|ICMPv6Message|ICMPv6PacketTooBigMsg|ICMPv6ParamProblemMsg|ICMPv6TimeExceededMsg|ICMPv6Type|ICMPv6_PARAMETER_PROB|ICMPv6_TIME_EX|IPControlInfo|IPDatagram|IPOption|IPOptionClass|IPProtocolId|IPRecordRouteOption|IPRoutingDecision|IPSourceRoutingOption|IPTimestampOption|IPv6AuthenticationHeader|IPv6ControlInfo|IPv6Datagram|IPv6DestinationOptionsHeader|IPv6EncapsulatingSecurityPayloadHeader|IPv6ExtensionHeader|IPv6FragmentHeader|IPv6HopByHopOptionsHeader|IPv6NDMessage|IPv6NDPrefixInformation|IPv6NeighbourAdvertisement|IPv6NeighbourSolicitation|IPv6Redirect|IPv6RouterAdvertisement|IPv6RouterSolicitation|IPv6RoutingHeader|Ieee80211ACKFrame|Ieee80211AssociationRequestFrame|Ieee80211AssociationRequestFrameBody|Ieee80211AssociationResponseFrame|Ieee80211AssociationResponseFrameBody|Ieee80211AuthenticationFrame|Ieee80211AuthenticationFrameBody|Ieee80211BSSType|Ieee80211BeaconFrame|Ieee80211BeaconFrameBody|Ieee80211CTSFrame|Ieee80211CapabilityInformation|Ieee80211DataFrame|Ieee80211DataFrameWithSNAP|Ieee80211DataOrMgmtFrame|Ieee80211DeauthenticationFrame|Ieee80211DeauthenticationFrameBody|Ieee80211DisassociationFrame|Ieee80211DisassociationFrameBody|Ieee80211Frame|Ieee80211FrameBody|Ieee80211FrameType|Ieee80211HandoverParameters|Ieee80211ManagementFrame|Ieee80211OneAddressFrame|Ieee80211PrimConfirm|Ieee80211PrimConfirmCode|Ieee80211PrimRequest|Ieee80211PrimRequestCode|Ieee80211PrimResultCode|Ieee80211Prim_AssociateConfirm|Ieee80211Prim_AssociateRequest|Ieee80211Prim_AuthenticateConfirm|Ieee80211Prim_AuthenticateRequest|Ieee80211Prim_BSSDescription|Ieee80211Prim_DeauthenticateRequest|Ieee80211Prim_DisassociateRequest|Ieee80211Prim_ReassociateConfirm|Ieee80211Prim_ReassociateRequest|Ieee80211Prim_ScanConfirm|Ieee80211Prim_ScanRequest|Ieee80211ProbeRequestFrame|Ieee80211ProbeRequestFrameBody|Ieee80211ProbeResponseFrame|Ieee80211ProbeResponseFrameBody|Ieee80211RTSFrame|Ieee80211ReasonCode|Ieee80211ReassociationRequestFrame|Ieee80211ReassociationRequestFrameBody|Ieee80211ReassociationResponseFrame|Ieee80211ReassociationResponseFrameBody|Ieee80211StatusCode|Ieee80211SupportedRatesElement|Ieee80211TwoAddressFrame|Ieee802Ctrl|Ieee802MessageKind|LDPAddress|LDPHello|LDPIni|LDPLabelMapping|LDPLabelRequest|LDPNotify|LDPPacket|LDP_MESSAGE_TYPES|LDP_STATUS_TYPES|LSARequest|LSAType|LabelRequestObj_t|Link|LinkStateMsg|LinkType|MIPv6HAInformation|MIPv6NDAdvertisementInterval|Mac80211Pkt|MacPkt|ManetControlType|OSPFASExternalLSA|OSPFASExternalLSAContents|OSPFDDOptions|OSPFDatabaseDescriptionPacket|OSPFHelloPacket|OSPFLSA|OSPFLSAHeader|OSPFLinkStateAcknowledgementPacket|OSPFLinkStateRequestPacket|OSPFLinkStateUpdatePacket|OSPFNetworkLSA|OSPFOptions|OSPFPacket|OSPFPacketType|OSPFRouterLSA|OSPFSummaryLSA|OSPFTimer|OSPFTimerType|PPPFrame|PathNotifyMsg|PhyCommandCode|PhyControlInfo|PingPayload|PsbTimeoutMsg|PsbTimerMsg|RSVPHelloMsg|RSVPMessage|RSVPPacket|RSVPPathError|RSVPPathMsg|RSVPPathTear|RSVPResvError|RSVPResvMsg|RSVPResvTear|RTCPByePacket|RTCPCompoundPacket|RTCPPacket|RTCPPacketType|RTCPReceiverReportPacket|RTCPSDESPacket|RTCPSenderReportPacket|RTPCICreateSenderModule|RTPCIDeleteSenderModule|RTPCIEnterSession|RTPCILeaveSession|RTPCISenderControl|RTPCISenderModuleCreated|RTPCISenderModuleDeleted|RTPCISenderStatus|RTPCISessionEntered|RTPCISessionLeft|RTPControlInfo|RTPControlMsg|RTPInnerPacket|RTPMpegPacket|RTPPacket|RTPPacketEnums|RTPParticipantInfo|RTPSenderControlMessage|RTPSenderControlMessageCommands|RTPSenderStatus|RTPSenderStatusMessage|RTPSessionControlInfo|RTP_IFP_TYPE|RTP_INP_TYPE|ReceptionReport|RsbCommitTimerMsg|RsbRefreshTimerMsg|RsbTimeoutMsg|RsvpHopObj_t|SAPCode|SCTPAbortChunk|SCTPChunk|SCTPCommand|SCTPConnectInfo|SCTPCookie|SCTPCookieAckChunk|SCTPCookieEchoChunk|SCTPDataChunk|SCTPDataMsg|SCTPErrorChunk|SCTPErrorCode|SCTPErrorInfo|SCTPForwardTsnChunk|SCTPHeartbeatAckChunk|SCTPHeartbeatChunk|SCTPInfo|SCTPInitAckChunk|SCTPInitChunk|SCTPMessage|SCTPOpenCommand|SCTPParameter|SCTPPathInfo|SCTPRcvCommand|SCTPResetInfo|SCTPSackChunk|SCTPSendCommand|SCTPShutdownAckChunk|SCTPShutdownChunk|SCTPShutdownCompleteChunk|SCTPSimpleMessage|SCTPStatusInfo|Sack|SenderDescriptor_t|SenderReport|SenderTemplateObj_t|SenderTspecObj_t|SessionObj_t|SignallingMsg|SnrControlInfo|TCPCommand|TCPConnectInfo|TCPDataTransferMode|TCPErrorCode|TCPErrorInfo|TCPOpenCommand|TCPOption|TCPOptionNumbers|TCPPayloadMessage|TCPSegment|TCPSendCommand|TCPStatusInfo|TEDChangeInfo|TELinkStateInfo|TOSData|TcpCommandCode|TcpStatusInd|TimestampFlag|TransmComplete|UDPCommandCode|UDPControlInfo|UDPEchoAppMsg|UDPPacket|UDPStatusInd|ExtFrame";

    #module interfaces:
    $names .= "|BasicMobility|IBidirectionalChannel|Ieee80211Mgmt|IEtherMAC|INetworkInterface|IPTrafficGenerator|IRTPPayloadReceiver|IRTPPayloadSender|ITCP|IUnidirectionalChannel|MACRelayUnit|OutputQueue|Radio|SCTPApp|TCPApp|UDPApp|Traci|TraCIDemo";


    # add tilde to non-backslashed recognized names
    for ($i=1; $i < 20; $i++)
    {
        $txt =~ s!(//.*?)([^\\\~])\b($names)\b!$1$2~$3!mg;
    }

    # remove backslashes from recognized names
    for ($i=1; $i < 20; $i++)
    {
        $txt =~ s!(//.*?)\\($names)\b!$1$2!mg;
    }

    # or: remove backslashes from all names
    for ($i=1; $i < 20; $i++)
    {
        $txt =~ s!(//.*?)\\([A-Za-z0-9_])!$1$2!mg;
    }

    open(OUTFILE, ">$fname") || die "cannot open $fname for write";
    print OUTFILE $txt || die "cannot write $fname";
    close OUTFILE;
}
