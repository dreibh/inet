//
// Copyright (C) 2008 Irene Ruengeler
// Copyright (C) 2009-2012 Thomas Dreibholz
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

package inet.transport.sctp;

//
// Implements the SCTP protocol.
//
simple SCTP
{
    parameters:
        //#====== SCTP Association Parameters =================================
        int    numGapReports                = default(3);
        double rtoInitial @unit(s)          = default(3s);
        double rtoMin @unit(s)              = default(1s);
        double rtoMax @unit(s)              = default(60s);
        double rtoAlpha                     = default(0.125);
        double rtoBeta                      = default(0.250);
        int    maxBurst                     = default(4);
        string maxBurstVariant              = default("useItOrLoseIt");   // T.D. 22.02.2010   // PRIVATE
        int    initialWindow                = default(0);                 // T.D. 09.09.2010   // PRIVATE
        int    assocMaxRetrans              = default(10);
        int    pathMaxRetrans               = default(5);
        int    maxInitRetrans               = default(8);
        double sackPeriod @unit(s)          = default(200ms);
        int    sackFrequency                = default(2);
        bool   reactivatePrimaryPath        = default(false);
        int    sendQueueLimit               = default(0);
        double validCookieLifetime @unit(s) = default(10s);

        //#====== Testing =====================================================
        bool   checkQueues                  = default(true);     // T.D. 20.11.2009

        //#====== Heartbeats ==================================================
        bool   enableHeartbeats             = default(true);
        double hbInterval @unit(s)          = default(30s);
        bool   sendHeartbeatsOnActivePaths  = default(false);

        //#====== Nagle Algorithm =============================================
        bool   nagleEnabled                 = default(true);
        int    naglePoint                   = default(1468);

        //#====== Congestion Control ==========================================
        int    RTXMethod                    = default(0);        // 0=Once after 3 Sacks; 1=once per RTT; 2=Switch off Fast Retransmit; 3=Always after 3 Sacks
        bool   fastRecoverySupported        = default(true);
        string sctpAlgorithmClass           = default("SCTPAlg");
        int    ccModule                     = default(0);        // RFC4960=0
        bool   osbWithHeader                = default(false);

        //#====== Other Parameters ============================================
        bool   natFriendly                  = default(false);
        int    bytesToAddPerRcvdChunk       = default(0);        // for flowcontrol
        int    bytesToAddPerPeerChunk       = default(0);        // for flowcontrol
        bool   tellArwnd                    = default(false);    // for flowcontrol
        int    messageAcceptLimit           = default(0);        // for flowcontrol
        double fairStart @unit(s)           = default(0s);
        double fairStop @unit(s)            = default(0s);
        int    ssModule                     = default(0);        // ROUND_ROBIN=0
        string streamsToPaths               = default("");
        int    arwnd                        = default(65535);
        int    swsLimit                     = default(3000);     // Limit for SWS
        int    startEndToEndDelay           = default(0);
        int    stopEndToEndDelay            = default(10);
        bool   udpEncapsEnabled             = default(false);
        double throughputInterval           = default(1);

        //#====== Chunk Authentication ========================================
        bool   auth                         = default(false);
        string chunks                       = default("");
        bool   padding                      = default(false);

        //#====== Add-IP ======================================================
        bool   addIP                        = default(false);
        double addTime @unit(s)             = default(0s);
        string addAddress                   = default("");
        string addIpType                    = default("0");      // SET_PRIMARY_ADDRESS=49156,ADD_IP_ADDRESS=49153,DELETE_IP_ADDRESS=49154

        //#====== Packet Drop =================================================
        bool   packetDrop                   = default(false);

        //#====== SACK Now ====================================================
        bool   sackNow                      = default(false);

        //#====== High-Speed CC ===============================================       // PRIVATE
        bool   highSpeedCC                  = default(false);    // T.D. 22.02.2010   // PRIVATE

        //#====== SACK Sequence Numbers =======================================
        bool   checkSackSeqNumber           = default(false);    // T.D. 23.02.2010

        //#====== NR-SACK =====================================================
        bool   nrSack                       = default(false);    // T.D. 03.03.2010
        bool   disableReneging              = default(false);    // T.D. 29.10.2010
        int    gapReportLimit               = default(100000000);// T.D. 29.10.2010   // PRIVATE
        string gapListOptimizationVariant   = default("none");   // T.D. 18.10.2010   // PRIVATE
        bool   smartOverfullSACKHandling    = default(false);    // T.D. 25.10.2010   // PRIVATE

        //#====== QoS-SCTP ====================================================       // PRIVATE
        bool   allowQoSTracking             = default(false);    // T.D. 11.08.2009   // PRIVATE
        double qosTrackingInterval @unit(s) = default(1.0s);     // T.D. 12.08.2009   // PRIVATE

        //#====== CMT-SCTP ====================================================       // PRIVATE
        string cmtSendAllVariant            = default("normal"); // T.D. 20.03.2009   // PRIVATE
        string cmtRetransmissionVariant     = default("normal"); // T.D. 20.03.2009   // PRIVATE
        string cmtCUCVariant                = default("normal"); // T.D. 23.03.2009   // PRIVATE
        string cmtBufferSplitVariant        = default("none");   // T.D. 03.03.2010   // PRIVATE
        bool   cmtBufferSplittingUsesOSB    = default(false);    // T.D. 19.11.2010   // PRIVATE
        bool   cmtUseSFR                    = default(true);     // T.D. 24.03.2009   // PRIVATE
        bool   cmtUseDAC                    = default(true);     // T.D. 25.03.2009   // PRIVATE
        bool   cmtUseFRC                    = default(true);     // T.D. 02.12.2009   // PRIVATE
        bool   cmtSmartT3Reset              = default(true);     // T.D. 02.03.2010   // PRIVATE
        bool   cmtSmartFastRTX              = default(true);     // T.D. 11.03.2010   // PRIVATE
        bool   cmtSmartReneging             = default(false);    // T.D. 24.02.2010   // PRIVATE
        bool   cmtSlowPathRTTUpdate         = default(false);    // T.D. 25.02.2010   // PRIVATE
        string cmtChunkReschedulingVariant  = default("none");   // T.D. 10.02.2010   // PRIVATE
        double cmtChunkReschedulingThreshold= default(0.5);      // T.D. 10.02.2010   // PRIVATE
        bool   cmtMovedChunksReduceCwnd     = default(true);     // T.D. 28.02.2010   // PRIVATE
        double movedChunkFastRTXFactor      = default(2.0);      // T.D. 18.02.2010   // PRIVATE
        string cmtSackPath                  = default("standard"); // T.D. 15.07.2011 // PRIVATE
        //#====== CMT/RP-SCTP =================================================       // PRIVATE
        bool   strictCwndBooking            = default(false);    // T.D. 06.01.2010   // PRIVATE
        string cmtCCVariant                 = default("off");    // T.D. 19.01.2011   // PRIVATE
        string cmtCCPathGroups              = default("");       // T.D. 28.01.2011   // PRIVATE
        bool   rpPathBlocking               = default(false);    // T.D. 15.08.2011   // PRIVATE
        bool   rpScaleBlockingTimeout       = default(false);    // T.D. 15.08.2011   // PRIVATE
        int    rpMinCwnd                    = default(1);        // T.D. 15.08.2011   // PRIVATE

        //#====== Test ========================================================       // PRIVATE
        double testValue0                   = default(0);   // PRIVATE
        double testValue1                   = default(0);   // PRIVATE
        double testValue2                   = default(0);   // PRIVATE
        double testValue3                   = default(0);   // PRIVATE
        double testValue4                   = default(0);   // PRIVATE
        string testString0                  = default("");  // PRIVATE
        string testString1                  = default("");  // PRIVATE
        string testString2                  = default("");  // PRIVATE
        string testString3                  = default("");  // PRIVATE
        string testString4                  = default("");  // PRIVATE

    gates:
        input  from_appl[] @labels(SCTPCommand/down);
        input  from_ip     @labels(SCTPPacket,IPControlInfo/up);
        input  from_ipv6   @labels(SCTPPacket);
        output to_appl[]   @labels(SCTPCommand/up);
        output to_ip       @labels(SCTPPacket,IPControlInfo/down);
        output to_ipv6     @labels(SCTPPacket);
}
