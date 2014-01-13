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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "SCTPAssociation.h"

#ifdef _MSC_VER
inline double rint(double x) {return floor(x+.5);}
#endif

// #define sctpEV3 std::cout


static inline double GET_SRTT(const double srtt)
{
    return (floor(1000.0 * srtt * 8.0));
}


#ifdef PRIVATE
// ====== High-Speed CC cwnd adjustment table from RFC 3649 appendix B ======
struct HighSpeedCwndAdjustmentEntry {
   int32_t cwndThreshold;
   double  increaseFactor;
   double  decreaseFactor;
};
static const HighSpeedCwndAdjustmentEntry HighSpeedCwndAdjustmentTable[] = {
   {    38,  1,  0.50 },
   {   118,  2,  0.44 },
   {   221,  3,  0.41 },
   {   347,  4,  0.38 },
   {   495,  5,  0.37 },
   {   663,  6,  0.35 },
   {   851,  7,  0.34 },
   {  1058,  8,  0.33 },
   {  1284,  9,  0.32 },
   {  1529, 10,  0.31 },
   {  1793, 11,  0.30 },
   {  2076, 12,  0.29 },
   {  2378, 13,  0.28 },
   {  2699, 14,  0.28 },
   {  3039, 15,  0.27 },
   {  3399, 16,  0.27 },
   {  3778, 17,  0.26 },
   {  4177, 18,  0.26 },
   {  4596, 19,  0.25 },
   {  5036, 20,  0.25 },
   {  5497, 21,  0.24 },
   {  5979, 22,  0.24 },
   {  6483, 23,  0.23 },
   {  7009, 24,  0.23 },
   {  7558, 25,  0.22 },
   {  8130, 26,  0.22 },
   {  8726, 27,  0.22 },
   {  9346, 28,  0.21 },
   {  9991, 29,  0.21 },
   { 10661, 30,  0.21 },
   { 11358, 31,  0.20 },
   { 12082, 32,  0.20 },
   { 12834, 33,  0.20 },
   { 13614, 34,  0.19 },
   { 14424, 35,  0.19 },
   { 15265, 36,  0.19 },
   { 16137, 37,  0.19 },
   { 17042, 38,  0.18 },
   { 17981, 39,  0.18 },
   { 18955, 40,  0.18 },
   { 19965, 41,  0.17 },
   { 21013, 42,  0.17 },
   { 22101, 43,  0.17 },
   { 23230, 44,  0.17 },
   { 24402, 45,  0.16 },
   { 25618, 46,  0.16 },
   { 26881, 47,  0.16 },
   { 28193, 48,  0.16 },
   { 29557, 49,  0.15 },
   { 30975, 50,  0.15 },
   { 32450, 51,  0.15 },
   { 33986, 52,  0.15 },
   { 35586, 53,  0.14 },
   { 37253, 54,  0.14 },
   { 38992, 55,  0.14 },
   { 40808, 56,  0.14 },
   { 42707, 57,  0.13 },
   { 44694, 58,  0.13 },
   { 46776, 59,  0.13 },
   { 48961, 60,  0.13 },
   { 51258, 61,  0.13 },
   { 53677, 62,  0.12 },
   { 56230, 63,  0.12 },
   { 58932, 64,  0.12 },
   { 61799, 65,  0.12 },
   { 64851, 66,  0.11 },
   { 68113, 67,  0.11 },
   { 71617, 68,  0.11 },
   { 75401, 69,  0.10 },
   { 79517, 70,  0.10 },
   { 84035, 71,  0.10 },
   { 89053, 72,  0.10 },
   { 94717, 73,  0.09 }
};


void SCTPAssociation::updateHighSpeedCCThresholdIdx(SCTPPathVariables* path)
{
   if(path->cwnd > HighSpeedCwndAdjustmentTable[path->highSpeedCCThresholdIdx].cwndThreshold * path->pmtu) {
      while( (path->cwnd > HighSpeedCwndAdjustmentTable[path->highSpeedCCThresholdIdx].cwndThreshold * path->pmtu) &&
             (path->highSpeedCCThresholdIdx < (sizeof(HighSpeedCwndAdjustmentTable) / sizeof(HighSpeedCwndAdjustmentEntry))) ) {
         path->highSpeedCCThresholdIdx++;
      }
   }
   else {
      while( (path->cwnd <= HighSpeedCwndAdjustmentTable[path->highSpeedCCThresholdIdx].cwndThreshold * path->pmtu) &&
             (path->highSpeedCCThresholdIdx > 0) ) {
         path->highSpeedCCThresholdIdx--;
      }
   }
}
#endif


void SCTPAssociation::cwndUpdateBeforeSack()
{
#ifdef PRIVATE
   // First, calculate per-path values.
   for (SCTPPathMap::iterator otherPathIterator = sctpPathMap.begin();
      otherPathIterator != sctpPathMap.end(); otherPathIterator++) {
      SCTPPathVariables* otherPath = otherPathIterator->second;
      otherPath->utilizedCwnd      = otherPath->outstandingBytesBeforeUpdate;
   }

   // Calculate per-path-group values.
   for (SCTPPathMap::iterator currentPathIterator = sctpPathMap.begin();
        currentPathIterator != sctpPathMap.end(); currentPathIterator++) {
      SCTPPathVariables* currentPath = currentPathIterator->second;

      currentPath->cmtGroupPaths                      = 0;
      currentPath->cmtGroupTotalCwnd                  = 0;
      currentPath->cmtGroupTotalSsthresh              = 0;
      currentPath->cmtGroupTotalUtilizedCwnd          = 0;
      currentPath->cmtGroupTotalCwndBandwidth         = 0.0;
      currentPath->cmtGroupTotalUtilizedCwndBandwidth = 0.0;

      double qNumerator   = 0.0;
      double qDenominator = 0.0;
      for (SCTPPathMap::const_iterator otherPathIterator = sctpPathMap.begin();
         otherPathIterator != sctpPathMap.end(); otherPathIterator++) {
         const SCTPPathVariables* otherPath = otherPathIterator->second;
         if(otherPath->cmtCCGroup == currentPath->cmtCCGroup) {
            currentPath->cmtGroupPaths++;

            currentPath->cmtGroupTotalCwnd                  += otherPath->cwnd;
            currentPath->cmtGroupTotalSsthresh              += otherPath->ssthresh;
            currentPath->cmtGroupTotalCwndBandwidth         += otherPath->cwnd / GET_SRTT(otherPath->srtt.dbl());

            if( (otherPath->blockingTimeout < 0.0) || (otherPath->blockingTimeout < simTime()) ) {
               currentPath->cmtGroupTotalUtilizedCwnd          += otherPath->utilizedCwnd;
               currentPath->cmtGroupTotalUtilizedCwndBandwidth += otherPath->utilizedCwnd / GET_SRTT(otherPath->srtt.dbl());
            }

            qNumerator   = max(qNumerator, otherPath->cwnd / (pow(GET_SRTT(otherPath->srtt.dbl()), 2.0)));
            qDenominator = qDenominator + (otherPath->cwnd / GET_SRTT(otherPath->srtt.dbl()));
         }
      }
      currentPath->cmtGroupAlpha = currentPath->cmtGroupTotalCwnd * (qNumerator / pow(qDenominator, 2.0));

/*
      printf("alpha(%s)=%1.6f\ttotalCwnd=%u\tcwnd=%u\tpaths=%u\n",
             currentPath->remoteAddress.str().c_str(),
             currentPath->cmtGroupAlpha,
             currentPath->cmtGroupTotalCwnd,
             currentPath->cwnd,
             currentPath->cmtGroupPaths);
*/
   }
#endif
}


#ifdef PRIVATE
static uint32 updateMPTCP(const uint32 w,
                          const uint32 totalW,
                          double       a,
                          const uint32 mtu,
                          const uint32 ackedBytes)
{
   const uint32 increase =
      max(1,
          min( (uint32)ceil((double)w * a * (double)min(ackedBytes, mtu)  / (double)totalW),
               (uint32)min(ackedBytes, mtu) ));
/*
   printf("\n%1.6f:\tMPTCP-Like CC: a=%1.6f\tc=%u -> %u\tincrease=%u\n",
          simTime().dbl(), a, w, w + increase, increase);
*/
   return(w + increase);
}
#endif


#ifdef PRIVATE

void SCTPAssociation::recalculateOLIABasis(){
    // it is necessary to calculate all flow information
    double assoc_best_paths_l_rXl_r__rtt_r = 0.0;
    uint32 max_w = 0;
    uint32 max_w_paths_cnt = 0;
    uint32 best_paths_cnt =0;

    // Create the sets
    int cnt = 0;
    assoc_collected_paths.clear();
    assoc_best_paths.clear();
    assoc_max_w_paths.clear();
    for (SCTPPathMap::iterator iter = sctpPathMap.begin(); iter != sctpPathMap.end(); iter++, cnt++) {
        SCTPPathVariables* path = iter->second;

           double r_sRTT = GET_SRTT(path->srtt.dbl());
           double r_l_rXl_r__rtt_r = ((path->olia_sent_bytes * path->olia_sent_bytes) / r_sRTT);
           if(assoc_best_paths.empty()){
               assoc_best_paths_l_rXl_r__rtt_r = r_l_rXl_r__rtt_r;
               assoc_best_paths.insert(std::make_pair(cnt,path));
           }
           if(assoc_max_w_paths.empty()){
               max_w = path->cwnd;
               assoc_max_w_paths.insert(std::make_pair(cnt,path));
           }
           if(cnt == 0) continue;
           // set up the sets
           if(r_l_rXl_r__rtt_r > assoc_best_paths_l_rXl_r__rtt_r){
               assoc_best_paths_l_rXl_r__rtt_r = r_l_rXl_r__rtt_r;
               assoc_best_paths.insert(std::make_pair(cnt,path));
               assoc_best_paths.erase(best_paths_cnt);
               best_paths_cnt = cnt;
           }
           if(path->cwnd > max_w){
               max_w = path->cwnd;
               assoc_max_w_paths.insert(std::make_pair(cnt,path));
               assoc_max_w_paths.erase(best_paths_cnt);
               max_w_paths_cnt = cnt;
           }

           if((assoc_max_w_paths.find(cnt) == assoc_max_w_paths.end()) && (assoc_max_w_paths.find(cnt) == assoc_max_w_paths.end()) )
                assoc_collected_paths.insert(std::make_pair(cnt,path));
    }
}

uint32 SCTPAssociation::updateOLIA(uint32 w, const uint32 s,
        const uint32 totalW,
        double       a,
        const uint32 mtu,
        const uint32 ackedBytes, SCTPPathVariables* path)
{

    bool is_in_collected_path = false;
    bool is_max_w_paths = false;

    if ((!(w < s)) && (!path->fastRecoveryActive)){
        // in CA
        recalculateOLIABasis();

        int cnt = 0;
        for (SCTP_Path_Collection::iterator it =assoc_collected_paths.begin(); it != assoc_collected_paths.end(); it++, cnt++) {
          if(it->second == path){
              is_in_collected_path = true;
              break;
          }
        }
        cnt = 0;
        for (SCTP_Path_Collection::iterator it = assoc_max_w_paths.begin(); it != assoc_max_w_paths.end(); it++, cnt++) {
          if(it->second == path){
              is_max_w_paths = true;
              break;
          }
        }

        double r_sRTT = GET_SRTT(path->srtt.dbl());

        double numerator_1 = path->cwnd/(r_sRTT * r_sRTT);
        double denominator_1 = 0;

        for (SCTPPathMap::iterator iter = sctpPathMap.begin(); iter != sctpPathMap.end(); iter++) {
                SCTPPathVariables* p_path = iter->second;
               double p_sRTT = GET_SRTT(p_path->srtt.dbl());
               denominator_1 += (p_path->cwnd/p_sRTT);
        }
        denominator_1 =  denominator_1 *  denominator_1;
        double term1 = numerator_1/ denominator_1;

       if(is_in_collected_path){
          /*
          For each ACK on the path r:
           - If r is in collected_paths, increase w_r by

                w_r/rtt_r^2                          1
            -------------------    +     -----------------------       (2)
           (SUM (w_p/rtt_p))^2    w_r * number_of_paths * |collected_paths|

           multiplied by MSS_r * bytes_acked.
           */

          double numerator_2 = 1;
          double denominator_2 = path->cwnd * sctpPathMap.size() * assoc_collected_paths.size();
          double term2 = 0.0;
          if(denominator_2 > 0.0){
              term2 = numerator_2 / denominator_2;
          }
          w += (term1 + term2) * (path->pmtu *  std::min(ackedBytes,path->pmtu) ); // TODO std::min(acked,
        }
        else if((is_max_w_paths) && (!assoc_collected_paths.empty())){
            /*
            - If r is in max_w_paths and if collected_paths is not empty,
             increase w_r by

                   w_r/rtt_r^2                         1
              --------------------    -     ------------------------     (3)
              (SUM (w_r/rtt_r))^2     w_r * number_of_paths * |max_w_paths|

             multiplied by MSS_r * bytes_acked.
             */
            double numerator_2 = 1;
            double denominator_2 = path->cwnd * sctpPathMap.size() * assoc_max_w_paths.size();
            double term2 = 0.0;
            if(denominator_2 > 0.0){
                term2 = numerator_2 / denominator_2;
            }
            w += (term1 + term2) * (path->pmtu * std::min(ackedBytes,path->pmtu) );// TODO
        }
        else{
            /*
            - Otherwise, increase w_r by

                                     (w_r/rtt_r^2)
                             ----------------------------------           (4)
                                    (SUM (w_r/rtt_r))^2

              multiplied by MSS_r * bytes_acked.
              */
            w += term1 * (path->pmtu * std::min(ackedBytes,path->pmtu) ); // TODO std::min(acked,

        }
    }
    else
        w += path->pmtu; //ackedBytes;

    return w;
}
#endif

void SCTPAssociation::recordCwndUpdate(SCTPPathVariables* path)
{
    if (path == NULL) {
        uint32 totalSsthresh = 0.0;
        uint32 totalCwnd = 0.0;
        double totalBandwidth = 0.0;
        for (SCTPPathMap::iterator pathIterator = sctpPathMap.begin();
                pathIterator != sctpPathMap.end(); pathIterator++) {
            SCTPPathVariables* path = pathIterator->second;
            totalSsthresh += path->ssthresh;
            totalCwnd += path->cwnd;
            totalBandwidth += path->cwnd / GET_SRTT(path->srtt.dbl());
        }
        statisticsTotalSSthresh->recordWithLimit(totalSsthresh, 1000000000);
        statisticsTotalCwnd->recordWithLimit(totalCwnd, 1000000000);
        statisticsTotalBandwidth->record(totalBandwidth);
    }
    else {
        path->statisticsPathSSthresh->recordWithLimit(path->ssthresh, 1000000000);
        path->statisticsPathCwnd->recordWithLimit(path->cwnd, 1000000000);
        path->statisticsPathBandwidth->record(path->cwnd / GET_SRTT(path->srtt.dbl()));
    }
}


uint32 SCTPAssociation::getInitialCwnd(const SCTPPathVariables* path) const
{
    uint32 newCwnd;
#ifdef PRIVATE
    const uint32 upperLimit = (state->initialWindow > 0) ? (state->initialWindow * path->pmtu) : max(2 * path->pmtu, 4380);
    if( (state->allowCMT == false) || (state->cmtCCVariant == SCTPStateVariables::CCCV_CMT) ) {
        newCwnd = (int32)min((state->initialWindow > 0) ? (state->initialWindow * path->pmtu) : (4 * path->pmtu),
                             upperLimit);
    }
    else {
        newCwnd = (int32)min( (int32)ceil(((state->initialWindow > 0) ?
                                          (state->initialWindow * path->pmtu) :
                                          (4 * path->pmtu)) / (double)sctpPathMap.size()),
                              upperLimit);
        if(newCwnd < path->pmtu) {   // T.D. 09.09.2010: cwnd < MTU makes no sense ...
            newCwnd = path->pmtu;
        }
    }
#else
    newCwnd = max(2 * path->pmtu, 4380);
#endif
    return (newCwnd);
}


void SCTPAssociation::initCCParameters(SCTPPathVariables* path)
{
    path->cwnd = getInitialCwnd(path);
    path->ssthresh = state->peerRwnd;
    recordCwndUpdate(path);

    sctpEV3 << assocId << ": " << simTime() << ":\tCC [initCCParameters]\t" << path->remoteAddress
#ifdef PRIVATE
            << " (cmtCCGroup=" << path->cmtCCGroup << ")"
#endif
            << "\tsst=" << path->ssthresh
            << "\tcwnd=" << path->cwnd << endl;
#ifdef PRIVATE
    // init OLIA
#warning  ¨TO FIX¨
    // assoc_new_olia_counting_start = state->snd_una;
    assoc_best_paths.clear();
    assoc_max_w_paths.clear();
#endif
}


int32 SCTPAssociation::rpPathBlockingControl(SCTPPathVariables* path, const double reduction)
{
    // ====== Compute new cwnd ===============================================
    const int32 newCwnd = (int32)ceil(path->cwnd - reduction);
    // NOTE: newCwnd may be negative!
#ifdef PRIVATE
    // ====== Block path if newCwnd < 1 MTU ==================================
    if( (state->rpPathBlocking == true) && (newCwnd < (int32)path->pmtu) ) {
        if( (path->blockingTimeout < 0.0) || (path->blockingTimeout < simTime()) ) {
            // printf("a=%1.9f b=%1.9f   a=%d b=%d\n", path->blockingTimeout.dbl(), simTime().dbl(), (path->blockingTimeout < 0.0), (path->blockingTimeout < simTime()) );

            const simtime_t timeout = (state->rpScaleBlockingTimeout == true) ?
                                      path->cmtGroupPaths * path->pathRto :
                                      path->pathRto;
            sctpEV3 << "Blocking " << path->remoteAddress << " for " << timeout << endl;

            path->blockingTimeout = simTime() + timeout;
            assert(!path->BlockingTimer->isScheduled());
            startTimer(path->BlockingTimer, timeout);
        }
    }
#endif
    return (newCwnd);
}


void SCTPAssociation::cwndUpdateAfterSack()
{
    recordCwndUpdate(NULL);

    for (SCTPPathMap::iterator iter = sctpPathMap.begin(); iter != sctpPathMap.end(); iter++) {
        SCTPPathVariables* path = iter->second;
        if (path->fastRecoveryActive == false) {

            // ====== Retransmission required -> reduce congestion window ======
            if (path->requiresRtx) {
                double decreaseFactor = 0.5;
#ifdef PRIVATE
                sctpEV3 << assocId << ": "<< simTime() << ":\tCC [cwndUpdateAfterSack]\t" << path->remoteAddress
                        << " (cmtCCGroup=" << path->cmtCCGroup << ")"
                        << "\tsst="     << path->ssthresh
                        << "\tcwnd="    << path->cwnd
                        << "\tSST="     << path->cmtGroupTotalSsthresh
                        << "\tCWND="    << path->cmtGroupTotalCwnd
                        << "\tBW.CWND=" << path->cmtGroupTotalCwndBandwidth;
                if(state->highSpeedCC == true) {
                   decreaseFactor = HighSpeedCwndAdjustmentTable[path->highSpeedCCThresholdIdx].decreaseFactor;
                   sctpEV3 << "\tHighSpeedDecreaseFactor=" << decreaseFactor;
                }

                // ====== SCTP or CMT-SCTP (independent congestion control) =====
                if( (state->allowCMT == false) ||
                    (state->cmtCCVariant == SCTPStateVariables::CCCV_CMT) ) {
#endif
                    path->ssthresh = max((int32)path->cwnd - (int32)rint(decreaseFactor * (double)path->cwnd),
                                         4 * (int32)path->pmtu);
                    path->cwnd = path->ssthresh;
#ifdef PRIVATE
                }
                // ====== Resource Pooling ======================================
                else {
                    // ====== CMT/RP-SCTPv1 Fast Retransmit ======================
                    if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRPv1) {
                        const double sstRatio    = (double)path->ssthresh / (double)path->cmtGroupTotalSsthresh;
                        const int32  reducedCwnd = rpPathBlockingControl(path, rint(path->cmtGroupTotalCwnd * decreaseFactor));
                        path->ssthresh = max(reducedCwnd,
                                             max((int32)path->pmtu,
                                                 (int32)ceil((double)state->rpMinCwnd * (double)path->pmtu * sstRatio)));
                        path->cwnd     = path->ssthresh;
                    }
                    // ====== CMT/RPv2-SCTP Fast Retransmit ======================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRPv2) {
                        // Bandwidth is based on cwnd, *not* ssthresh!
                        const double pathBandwidth   = path->cwnd / GET_SRTT(path->srtt.dbl());
                        const double bandwidthToGive = path->cmtGroupTotalCwndBandwidth / 2.0;
                        const double reductionFactor = max(0.5, bandwidthToGive / pathBandwidth);
                        const int32  reducedCwnd     = rpPathBlockingControl(path, reductionFactor * path->cwnd);
                        path->ssthresh = (int32)max(reducedCwnd, (int32)state->rpMinCwnd * (int32)path->pmtu);
                        path->cwnd     = path->ssthresh;
                    }
                    // ====== Like MPTCP Fast Retransmit =========================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_Like_MPTCP) {
                        // Just like plain CMT-SCTP ...
                        const int32 reducedCwnd = rpPathBlockingControl(path, rint(decreaseFactor * (double)path->cwnd));
                        path->ssthresh = max(reducedCwnd, (int32)state->rpMinCwnd * (int32)path->pmtu);
                        path->cwnd     = path->ssthresh;
                    }
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMT_OLIA) {
                           // like draft
                           path->ssthresh = max((int32)path->cwnd - (int32)rint(decreaseFactor * (double)path->cwnd),
                                                                   4 * (int32)path->pmtu);
                           path->cwnd     = path->ssthresh;
                    }
                    // ====== TEST Fast Retransmit ===============================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRP_Test1) {
                        // Bandwidth is based on cwnd, *not* ssthresh!
                        const double pathBandwidth   = path->cwnd / GET_SRTT(path->srtt.dbl());
                        const double bandwidthToGive = path->cmtGroupTotalCwndBandwidth / 2.0;
                        const double reductionFactor = max(0.5, bandwidthToGive / pathBandwidth);
                        const int32  reducedCwnd     = rpPathBlockingControl(path, reductionFactor * path->cwnd);
                        path->ssthresh = (int32)max(reducedCwnd, (int32)state->rpMinCwnd * (int32)path->pmtu);
                        path->cwnd     = path->ssthresh;
                    }
                    // ====== TEST Fast Retransmit ===============================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRP_Test2) {
                        // Just like CMT-SCTP ...
                        const int32 reducedCwnd = rpPathBlockingControl(path, rint(decreaseFactor * (double)path->cwnd));
                        path->ssthresh = max(reducedCwnd, (int32)state->rpMinCwnd * (int32)path->pmtu);
                        path->cwnd     = path->ssthresh;
                    }
                    // ====== Other -> error =====================================
                    else {
                        throw cRuntimeError("Implementation for this cmtCCVariant is missing!");
                    }
                }
#endif

                recordCwndUpdate(path);
                path->partialBytesAcked = 0;

                path->vectorPathPbAcked->record(path->partialBytesAcked);
 #ifdef PRIVATE
                if(state->highSpeedCC == true) {
                    updateHighSpeedCCThresholdIdx(path);
                }
#endif
               sctpEV3 << "\t=>\tsst=" << path->ssthresh
                       << "\tcwnd=" << path->cwnd << endl;

                // ====== Fast Recovery =========================================
                if (state->fastRecoverySupported) {
                    uint32 highestAckOnPath = state->lastTsnAck;
                    uint32 highestOutstanding = state->lastTsnAck;
                    for (SCTPQueue::PayloadQueue::const_iterator chunkIterator = retransmissionQ->payloadQueue.begin();
                            chunkIterator != retransmissionQ->payloadQueue.end(); chunkIterator++) {
                        const SCTPDataVariables* chunk = chunkIterator->second;
                        if (chunk->getLastDestinationPath() == path) {
                            if (chunkHasBeenAcked(chunk)) {
                                if (tsnGt(chunk->tsn, highestAckOnPath)) {
                                    highestAckOnPath = chunk->tsn;
                                }
                            }
                            else {
                                if (tsnGt(chunk->tsn, highestOutstanding)) {
                                    highestOutstanding = chunk->tsn;
                                }
                            }
                        }
                    }
#ifdef PRIVATE
                    path->olia_sent_bytes = 0;
#endif
                    // This can ONLY become TRUE, when Fast Recovery IS supported.
                    path->fastRecoveryActive = true;
                    path->fastRecoveryExitPoint = highestOutstanding;
                    path->fastRecoveryEnteringTime = simTime();
                    path->vectorPathFastRecoveryState->record(path->cwnd);

                    sctpEV3 << assocId << ": " << simTime() << ":\tCC [cwndUpdateAfterSack] Entering Fast Recovery on path "
                            << path->remoteAddress
                            << ", exit point is " << path->fastRecoveryExitPoint
#ifdef PRIVATE
                            << ", pseudoCumAck=" << path->pseudoCumAck
                            << ", rtxPseudoCumAck=" << path->rtxPseudoCumAck
#endif
                            << endl;
                }
            }
        }
        else {
            for (SCTPPathMap::iterator iter = sctpPathMap.begin(); iter != sctpPathMap.end(); iter++) {
                SCTPPathVariables* path = iter->second;
                if (path->fastRecoveryActive) {
                    sctpEV3 << assocId << ": " << simTime() << ":\tCC [cwndUpdateAfterSack] Still in Fast Recovery on path "
                            << path->remoteAddress
                            << ", exit point is " << path->fastRecoveryExitPoint << endl;
                }
            }
        }
    }
}


void SCTPAssociation::cwndUpdateAfterRtxTimeout(SCTPPathVariables* path)
{
    cwndUpdateBeforeSack();

    double decreaseFactor = 0.5;
#ifdef PRIVATE
    path->olia_sent_bytes = 0;
#endif
#ifdef PRIVATE

    sctpEV3 << assocId << ": " << simTime() << ":\tCC [cwndUpdateAfterRtxTimeout]\t" << path->remoteAddress
            << " (cmtCCGroup=" << path->cmtCCGroup << ")"
            << "\tsst="     << path->ssthresh
            << "\tcwnd="    << path->cwnd
            << "\tSST="     << path->cmtGroupTotalSsthresh
            << "\tCWND="    << path->cmtGroupTotalCwnd
            << "\tBW.CWND=" << path->cmtGroupTotalCwndBandwidth;
    if(state->highSpeedCC == true) {
        decreaseFactor = HighSpeedCwndAdjustmentTable[path->highSpeedCCThresholdIdx].decreaseFactor;
        sctpEV3 << "\tHighSpeedDecreaseFactor=" << decreaseFactor;
    }

    // ====== SCTP or CMT-SCTP (independent congestion control) ==============
    if( (state->allowCMT == false) || (state->cmtCCVariant == SCTPStateVariables::CCCV_CMT) ) {
#endif
        path->ssthresh = max((int32)path->cwnd - (int32)rint(decreaseFactor * (double)path->cwnd),
                             4 * (int32)path->pmtu);
        path->cwnd = path->pmtu;
#ifdef PRIVATE
    }
    // ====== Resource Pooling RTX Timeout ===================================
    else {
        // ====== CMT/RPv1-SCTP RTX Timeout ===================================
        if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRPv1) {
            const double sstRatio        = (double)path->ssthresh / (double)path->cmtGroupTotalSsthresh;
            const int32  decreasedWindow = (int32)path->cwnd - (int32)rint(path->cmtGroupTotalCwnd * decreaseFactor);
            path->ssthresh = max(decreasedWindow,
                                 max((int32)path->pmtu,
                                     (int32)ceil((double)state->rpMinCwnd * (double)path->pmtu * sstRatio)));
            path->cwnd = max((int32)path->pmtu,
                             (int32)ceil((double)path->pmtu * sstRatio));
        }
        // ====== CMT/RPv2-SCTP RTX Timeout ===================================
        else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRPv2) {
            const double pathBandwidth   = path->cwnd / GET_SRTT(path->srtt.dbl());
            const double bandwidthToGive = path->cmtGroupTotalCwndBandwidth / 2.0;
            const double reductionFactor = max(0.5, bandwidthToGive / pathBandwidth);

            path->ssthresh = (int32)max((int32)state->rpMinCwnd * (int32)path->pmtu,
                                        (int32)ceil(path->cwnd - reductionFactor * path->cwnd));
            path->cwnd = path->pmtu;
        }
        // ====== Like MPTCP RTX Timeout ======================================
        else if(state->cmtCCVariant == SCTPStateVariables::CCCV_Like_MPTCP) {
            path->ssthresh = max((int32)path->cwnd - (int32)rint(decreaseFactor * (double)path->cwnd),
                                 (int32)state->rpMinCwnd * (int32)path->pmtu);
            path->cwnd     = path->pmtu;
        }
        else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMT_OLIA) {
            // like draft
            path->ssthresh = max((int32)path->cwnd - (int32)rint(decreaseFactor * (double)path->cwnd),
                                 4 * (int32)path->pmtu);
            path->cwnd     = path->pmtu;
        }

        // ====== TEST RTX Timeout ============================================
        else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRP_Test1) {
            const double pathBandwidth   = path->cwnd / GET_SRTT(path->srtt.dbl());
            const double bandwidthToGive = path->cmtGroupTotalCwndBandwidth / 2.0;
            const double reductionFactor = max(0.5, bandwidthToGive / pathBandwidth);

            path->ssthresh = (int32)max((int32)state->rpMinCwnd * (int32)path->pmtu,
                                        (int32)ceil(path->cwnd - reductionFactor * path->cwnd));
            path->cwnd = path->pmtu;
        }
        // ====== Like MPTCP RTX Timeout ======================================
        else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRP_Test2) {
            path->ssthresh = max((int32)path->cwnd - (int32)rint(decreaseFactor * (double)path->cwnd),
                                 (int32)state->rpMinCwnd * (int32)path->pmtu);
            path->cwnd     = path->pmtu;
        }
        // ====== Other -> error ==============================================
        else {
            throw cRuntimeError("Implementation for this cmtCCVariant is missing!");
        }
    }
    path->highSpeedCCThresholdIdx = 0;
#endif
    path->partialBytesAcked = 0;
    path->vectorPathPbAcked->record(path->partialBytesAcked);
    sctpEV3 << "\t=>\tsst=" << path->ssthresh
            << "\tcwnd=" << path->cwnd << endl;
    recordCwndUpdate(path);

    // Leave Fast Recovery mode
    if (path->fastRecoveryActive == true) {
        path->fastRecoveryActive = false;
        path->fastRecoveryExitPoint = 0;
        path->vectorPathFastRecoveryState->record(0);
    }
}


void SCTPAssociation::cwndUpdateBytesAcked(SCTPPathVariables* path,
        const uint32       ackedBytes,
        const bool         ctsnaAdvanced)
{
    if (path->fastRecoveryActive == false) {
        // T.D. 21.11.09: Increasing cwnd is only allowed when not being in
        //                Fast Recovery mode!

        // ====== Slow Start ==================================================
        if (path->cwnd <= path->ssthresh)  {
            // ------ Clear PartialBytesAcked counter --------------------------
            // uint32 oldPartialBytesAcked = path->partialBytesAcked;
            path->partialBytesAcked = 0;

            // ------ Increase Congestion Window -------------------------------
#ifndef PRIVATE
            if ((ctsnaAdvanced == true) &&
                (path->outstandingBytesBeforeUpdate >= path->cwnd)) {
#else
            if ((ctsnaAdvanced == true) &&
                ((path->outstandingBytesBeforeUpdate >= path->cwnd) ||
                 ((state->strictCwndBooking) && (path->outstandingBytesBeforeUpdate + path->pmtu > path->cwnd)))) {
               sctpEV3 << assocId << ": "<< simTime() << ":\tCC [cwndUpdateBytesAcked-SlowStart]\t" << path->remoteAddress
                       << " (cmtCCGroup=" << path->cmtCCGroup << ")"
                       << "\tacked="   << ackedBytes
                       << "\tsst="     << path->ssthresh
                       << "\tcwnd="    << path->cwnd
                       << "\tSST="     << path->cmtGroupTotalSsthresh
                       << "\tCWND="    << path->cmtGroupTotalCwnd
                       << "\tBW.CWND=" << path->cmtGroupTotalCwndBandwidth;

                // ====== SCTP or CMT-SCTP (independent congestion control) =====
                if( (state->allowCMT == false) || (state->cmtCCVariant == SCTPStateVariables::CCCV_CMT) ) {
#endif
                    path->cwnd += (int32)min(path->pmtu, ackedBytes);
#ifdef PRIVATE
                }
                // ====== Resource Pooling Slow Start ===========================
                else {
                    // ====== CMT/RPv1-SCTP Slow Start ===========================
                    if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRPv1) {
                        const double sstRatio = (double)path->ssthresh / (double)path->cmtGroupTotalSsthresh;
                        path->cwnd += (int32)ceil(min(path->pmtu, ackedBytes) * sstRatio);
                    }
                    // ====== CMT/RPv2-SCTP Slow Start ===========================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRPv2) {
                        // Increase ratio based on cwnd bandwidth share!
                        const double increaseRatio = ((double)path->cwnd / GET_SRTT(path->srtt.dbl())) /
                                                         (double)path->cmtGroupTotalCwndBandwidth;
                        path->cwnd += (int32)ceil(min(path->pmtu, ackedBytes) * increaseRatio);
                    }
                    // ====== Like MPTCP Slow Start ==============================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_Like_MPTCP) {
                        // T.D. 14.08.2011: Rewrote MPTCP-Like CC code
                        path->cwnd = updateMPTCP(path->cwnd, path->cmtGroupTotalCwnd,
                                                 path->cmtGroupAlpha, path->pmtu, ackedBytes);
                    }
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMT_OLIA) {
                        // OLIA see draft
                        path->cwnd = updateOLIA(path->cwnd, path->ssthresh, path->cmtGroupTotalCwnd,
                                                                         path->cmtGroupAlpha, path->pmtu, ackedBytes,path);
                    }
                    // ====== TEST Slow Start ====================================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRP_Test1) {
                        // Increase ratio based on cwnd bandwidth share!
                        const double increaseRatio = ((double)path->utilizedCwnd / GET_SRTT(path->srtt.dbl())) /
                                                         (double)path->cmtGroupTotalUtilizedCwndBandwidth;
                        path->cwnd += (int32)ceil(min(path->pmtu, ackedBytes) * increaseRatio);
                    }
                    // ====== Like MPTCP Slow Start ==============================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRP_Test2) {
                        path->cwnd = updateMPTCP(path->cwnd, path->cmtGroupTotalCwnd,
                                                 path->cmtGroupAlpha, path->pmtu, ackedBytes);
                    }
                    // ====== Other -> error =====================================
                    else {
                        throw cRuntimeError("Implementation for this cmtCCVariant is missing!");
                    }
                }
                path->vectorPathPbAcked->record(path->partialBytesAcked);
                sctpEV3 << "\t=>\tsst=" << path->ssthresh
                        << "\tcwnd=" << path->cwnd << endl;
#endif

                recordCwndUpdate(path);
            }
            // ------ No need to increase Congestion Window --------------------
            else {
                sctpEV3 << assocId << ": " << simTime() << ":\tCC "
                        << "Not increasing cwnd of path " << path->remoteAddress << " in slow start:\t"
                        << "ctsnaAdvanced=" << ((ctsnaAdvanced == true) ? "yes" : "no") << "\t"
                        << "cwnd=" << path->cwnd << "\t"
                        << "sst=" << path->ssthresh << "\t"
                        << "ackedBytes=" << ackedBytes << "\t"
                        << "pathOsbBeforeUpdate=" << path->outstandingBytesBeforeUpdate << "\t"
                        << "pathOsb=" << path->outstandingBytes << "\t"
                        << "(pathOsbBeforeUpdate >= path->cwnd)="
                        << (path->outstandingBytesBeforeUpdate >= path->cwnd) << endl;
            }
        }

        // ====== Congestion Avoidance ========================================
        else
        {
            // ------ Increase PartialBytesAcked counter -----------------------
            path->partialBytesAcked += ackedBytes;

            // ------ Increase Congestion Window -------------------------------
            double increaseFactor = 1.0;
#ifndef PRIVATE
            if ( (path->partialBytesAcked >= path->cwnd) &&
                 (ctsnaAdvanced == true) &&
                 (path->outstandingBytesBeforeUpdate >= path->cwnd) ) {
#else
            if(state->highSpeedCC == true) {
               updateHighSpeedCCThresholdIdx(path);
               increaseFactor = HighSpeedCwndAdjustmentTable[path->highSpeedCCThresholdIdx].increaseFactor;
               sctpEV3 << "HighSpeedCC Increase: factor=" << increaseFactor << endl;
            }

            const bool avancedAndEnoughOutstanding =
                 (ctsnaAdvanced == true) &&
                 ( (path->outstandingBytesBeforeUpdate >= path->cwnd) ||
                   ( (state->strictCwndBooking) &&
                     (path->outstandingBytesBeforeUpdate + path->pmtu > path->cwnd) ) );
            const bool enoughPartiallyAcked =
                  (path->partialBytesAcked >= path->cwnd) ||
                  ( (state->strictCwndBooking) &&
                    (path->partialBytesAcked >= path->pmtu) &&
                    (path->partialBytesAcked + path->pmtu > path->cwnd) );

            if ( avancedAndEnoughOutstanding && enoughPartiallyAcked) {
               sctpEV3 << assocId << ": " << simTime() << ":\tCC [cwndUpdateBytesAcked-CgAvoidance]\t" << path->remoteAddress
                       << " (cmtCCGroup=" << path->cmtCCGroup << ")"
                       << "\tacked="   << ackedBytes
                       << "\tsst="     << path->ssthresh
                       << "\tcwnd="    << path->cwnd
                       << "\tSST="     << path->cmtGroupTotalSsthresh
                       << "\tCWND="    << path->cmtGroupTotalCwnd
                       << "\tBW.CWND=" << path->cmtGroupTotalCwndBandwidth;

               // ====== SCTP or CMT-SCTP (independent congestion control) =====
               if( (state->allowCMT == false) || (state->cmtCCVariant == SCTPStateVariables::CCCV_CMT) ) {
#endif
                   path->cwnd += (int32)rint(increaseFactor * path->pmtu);
#ifdef PRIVATE
                }
                // ====== Resource Pooling Congestion Avoidance =================
                else {
                    // ====== CMT/RP-SCTP Congestion Avoidance ===================
                    if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRPv1) {
                        const double sstRatio = (double)path->ssthresh / (double)path->cmtGroupTotalSsthresh;
                        path->cwnd += (int32)ceil(increaseFactor * path->pmtu * sstRatio);
                    }
                    // ====== CMT/RPv2-SCTP Congestion Avoidance =================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRPv2) {
                        // Increase ratio based on cwnd bandwidth share!
                        const double increaseRatio = ((double)path->cwnd / GET_SRTT(path->srtt.dbl())) /
                                                         (double)path->cmtGroupTotalCwndBandwidth;
                        path->cwnd += (int32)ceil(increaseFactor * path->pmtu * increaseRatio);
                    }
                    // ====== Like MPTCP Congestion Avoidance ====================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_Like_MPTCP) {
                        // T.D. 14.08.2011: Rewrote MPTCP-Like CC code
                        path->cwnd = updateMPTCP(path->cwnd, path->cmtGroupTotalCwnd,
                                                 path->cmtGroupAlpha, path->pmtu, path->pmtu);
                    }
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMT_OLIA) {
                        // like draft
                        path->cwnd = updateOLIA(path->cwnd, path->ssthresh, path->cmtGroupTotalCwnd,
                                                 path->cmtGroupAlpha, path->pmtu, path->pmtu, path);
                    }
                    // ====== TEST Congestion Avoidance ==========================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRP_Test1) {
                        // Increase ratio based on cwnd bandwidth share!
                        const double increaseRatio = ((double)path->utilizedCwnd / GET_SRTT(path->srtt.dbl())) /
                                                         (double)path->cmtGroupTotalUtilizedCwndBandwidth;
                        path->cwnd += (int32)ceil(increaseFactor * path->pmtu * increaseRatio);
                    }
                    // ====== TEST Congestion Avoidance ==========================
                    else if(state->cmtCCVariant == SCTPStateVariables::CCCV_CMTRP_Test2) {
                        path->cwnd = updateMPTCP(path->cwnd, path->cmtGroupTotalCwnd,
                                                 path->cmtGroupAlpha, path->pmtu, path->pmtu);
                    }
                    // ====== Other -> error =====================================
                    else {
                        throw cRuntimeError("Implementation for this cmtCCVariant is missing!");
                    }
                }
                sctpEV3 << "\t=>\tsst=" << path->ssthresh
                        << "\tcwnd=" << path->cwnd << endl;
#endif
                recordCwndUpdate(path);
                path->partialBytesAcked =
                        ((path->cwnd < path->partialBytesAcked) ?
                                (path->partialBytesAcked - path->cwnd) : 0);
            }
            // ------ No need to increase Congestion Window -------------------
            else {
                sctpEV3 << assocId << ": " << simTime() << ":\tCC "
                        << "Not increasing cwnd of path " << path->remoteAddress << " in congestion avoidance: "
                        << "ctsnaAdvanced=" << ((ctsnaAdvanced == true) ? "yes" : "no") << "\t"
                        << "cwnd=" << path->cwnd << "\t"
                        << "sst=" << path->ssthresh << "\t"
                        << "ackedBytes=" << ackedBytes << "\t"
                        << "pathOsbBeforeUpdate=" << path->outstandingBytesBeforeUpdate << "\t"
                        << "pathOsb=" << path->outstandingBytes << "\t"
                        << "(pathOsbBeforeUpdate >= path->cwnd)="
                        << (path->outstandingBytesBeforeUpdate >= path->cwnd) << "\t"
                        << "partialBytesAcked=" << path->partialBytesAcked << "\t"
                        << "(path->partialBytesAcked >= path->cwnd)="
                        << (path->partialBytesAcked >= path->cwnd) << endl;
            }
        }

        // ====== Reset PartialBytesAcked counter if no more outstanding bytes
        if (path->outstandingBytes == 0) {
            path->partialBytesAcked = 0;
        }
        path->vectorPathPbAcked->record(path->partialBytesAcked);
    }
    else {
        sctpEV3 << assocId << ": " << simTime() << ":\tCC "
                << "Not increasing cwnd of path " << path->remoteAddress
                << " during Fast Recovery" << endl;
    }
}


void SCTPAssociation::updateFastRecoveryStatus(const uint32 lastTsnAck)
{
    for (SCTPPathMap::iterator iter = sctpPathMap.begin(); iter != sctpPathMap.end(); iter++) {
        SCTPPathVariables* path = iter->second;

        if (path->fastRecoveryActive) {
            if ( (tsnGt(lastTsnAck, path->fastRecoveryExitPoint)) ||
                 (lastTsnAck == path->fastRecoveryExitPoint)
#ifdef PRIVATE
                 || ((state->allowCMT) && (state->cmtUseFRC) &&
                     ((path->newPseudoCumAck && tsnGt(path->pseudoCumAck, path->fastRecoveryExitPoint)) ||
                      (path->newRTXPseudoCumAck && tsnGt(path->rtxPseudoCumAck, path->fastRecoveryExitPoint)))
                    )
#endif
            ) {
                path->fastRecoveryActive = false;
                path->fastRecoveryExitPoint = 0;
                path->vectorPathFastRecoveryState->record(0);

                sctpEV3 << assocId << ": " << simTime() << ":\tCC [cwndUpdateAfterSack] Leaving Fast Recovery on path "
                        << path->remoteAddress
                        << ", lastTsnAck=" << lastTsnAck
#ifdef PRIVATE
                        << ", pseudoCumAck=" << path->pseudoCumAck
                        << ", rtxPseudoCumAck=" << path->rtxPseudoCumAck
                        << ", newPseudoCumAck=" << path->newPseudoCumAck
                        << ", newRTXPseudoCumAck=" << path->newRTXPseudoCumAck
#endif
                        << endl;
            }
        }
    }
}


void SCTPAssociation::cwndUpdateMaxBurst(SCTPPathVariables* path)
{
#ifdef PRIVATE
   if( (state->maxBurstVariant == SCTPStateVariables::MBV_UseItOrLoseIt) ||
       (state->maxBurstVariant == SCTPStateVariables::MBV_CongestionWindowLimiting) ||
       (state->maxBurstVariant == SCTPStateVariables::MBV_UseItOrLoseItTempCwnd) ||
       (state->maxBurstVariant == SCTPStateVariables::MBV_CongestionWindowLimitingTempCwnd) ) {
#endif

        // ====== cwnd allows to send more than the maximum burst size ========
        if (path->cwnd > ((path->outstandingBytes + state->maxBurst * path->pmtu))) {
            sctpEV3 << assocId << ": " << simTime() << ":\tCC [cwndUpdateMaxBurst]\t"
                    << path->remoteAddress
                    << "\tsst=" << path->ssthresh
                    << "\tcwnd=" << path->cwnd
#ifdef PRIVATE
                    << "\ttempCwnd=" << path->tempCwnd
#endif
                    << "\tosb=" << path->outstandingBytes
                    << "\tmaxBurst=" << state->maxBurst * path->pmtu;

#ifdef PRIVATE
             // ====== Update cwnd or tempCwnd, according to MaxBurst variant ===
             if( (state->maxBurstVariant == SCTPStateVariables::MBV_UseItOrLoseIt) ||
                 (state->maxBurstVariant == SCTPStateVariables::MBV_CongestionWindowLimiting) ) {
                path->cwnd = path->outstandingBytes + (state->maxBurst * path->pmtu);
             }
             else if( (state->maxBurstVariant == SCTPStateVariables::MBV_UseItOrLoseItTempCwnd) ||
                      (state->maxBurstVariant == SCTPStateVariables::MBV_CongestionWindowLimitingTempCwnd) ) {
                path->tempCwnd = path->outstandingBytes + (state->maxBurst * path->pmtu);
             }
             else {
                assert(false);
             }

             if(state->maxBurstVariant == SCTPStateVariables::MBV_CongestionWindowLimiting) {
                if(path->ssthresh < path->cwnd) {
                   path->ssthresh = path->cwnd;
                }
             }
             if(state->maxBurstVariant == SCTPStateVariables::MBV_CongestionWindowLimitingTempCwnd) {
                if(path->ssthresh < path->tempCwnd) {
                   path->ssthresh = path->tempCwnd;
                }
             }
#else
            // ====== Update cwnd ==============================================
            path->cwnd = path->outstandingBytes + (state->maxBurst * path->pmtu);
#endif
            recordCwndUpdate(path);

            sctpEV3 << "\t=>\tsst=" << path->ssthresh
                    << "\tcwnd=" << path->cwnd
#ifdef PRIVATE
                    << "\ttempCwnd=" << path->tempCwnd
#endif
                    << endl;
        }
#ifdef PRIVATE
        // ====== Possible transmission will not exceed burst size ============
        else {
            // Just store current cwnd to tempCwnd
            path->tempCwnd = path->cwnd;
        }
    }
#endif
}


void SCTPAssociation::cwndUpdateAfterCwndTimeout(SCTPPathVariables* path)
{
    // When the association does not transmit data on a given transport address
    // within an RTO, the cwnd of the transport address SHOULD be adjusted to 2*MTU.
    sctpEV3 << assocId << ": " << simTime() << ":\tCC [cwndUpdateAfterCwndTimeout]\t" << path->remoteAddress
#ifdef PRIVATE
            << " (cmtCCGroup=" << path->cmtCCGroup << ")"
#endif
            << "\tsst=" << path->ssthresh
            << "\tcwnd=" << path->cwnd;
    path->cwnd = getInitialCwnd(path);
    sctpEV3 << "\t=>\tsst=" << path->ssthresh
            << "\tcwnd=" << path->cwnd << endl;
    recordCwndUpdate(path);
    recordCwndUpdate(NULL);
}
