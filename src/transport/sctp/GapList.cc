//
// Copyright (C) 2010-2012 Thomas Dreibholz
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
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//

#include "GapList.h"


// #define DEBUG_GAPLIST

#ifdef DEBUG_GAPLIST
#define sctpEV3 std::cout
#warning DEBUG_GAPLIST is ON!
#endif


// ###### Constructor #######################################################
SimpleGapList::SimpleGapList()
{
    NumGaps = 0;
    for (unsigned int i = 0; i < MAX_GAP_COUNT; i++) {
        GapStartList[i] = 0xffff00ff;
        GapStopList[i] = 0xffff0000;
    }
}


// ###### Destructor ########################################################
SimpleGapList::~SimpleGapList()
{
}


// ###### Check gap list ####################################################
void SimpleGapList::check(const uint32 cTsnAck) const
{
    for (uint32 i = 0; i < NumGaps; i++) {
        if (i == 0) {
            assert(tsnGt(GapStartList[i], cTsnAck + 1));
        }
        else {
            assert(tsnGt(GapStartList[i], GapStopList[i - 1] + 1));
        }
        assert(tsnLe(GapStartList[i], GapStopList[i]));
    }
}


// ###### Print gap list ####################################################
void SimpleGapList::print(std::ostream& os) const
{
    os << "{";
    for (uint32 i = 0; i < NumGaps; i++) {
        if (i > 0) {
            os << ",";
        }
        os << " " << GapStartList[i] << "-" << GapStopList[i];
    }
    os << " }";
}


// ###### Is TSN in gap list? ###############################################
bool SimpleGapList::tsnInGapList(const uint32 tsn) const
{
    for (uint32 i = 0; i < NumGaps; i++) {
        if (tsnBetween(GapStartList[i], tsn, GapStopList[i])) {
            return true;
        }
    }
    return false;
}


// ###### Forward CumAckTSN #################################################
void SimpleGapList::forwardCumAckTSN(const uint32 cTsnAck)
{
    if (NumGaps > 0) {
        // It is only possible to advance CumAckTSN when there are gaps.
        uint32 counter = 0;
        uint32 advance = 0;
        while (counter < NumGaps) {
            // Check whether CumAckTSN can be advanced.
            if (tsnGe(cTsnAck, GapStartList[counter])) {   // Yes!
                advance++;
            }
            else {   // No -> end of search.
                break;
            }
            counter++;
        }

        if (advance > 0) {
            // We can remove "advance" block now.
            for (uint32 i = advance; i < NumGaps; i++) {
                GapStartList[i - advance] = GapStartList[i];
                GapStopList[i - advance] = GapStopList[i];
            }
            NumGaps -= advance;
        }
    }
}


// ###### Try to advance CumAckTSN ##########################################
bool SimpleGapList::tryToAdvanceCumAckTSN(uint32& cTsnAck)
{
    bool progress = false;
    if (NumGaps > 0) {
        // It is only possible to advance CumAckTSN when there are gaps.
        uint32 counter = 0;
        while (counter < NumGaps) {
            // Check whether CumAckTSN can be advanced.
            if (cTsnAck + 1 == GapStartList[0]) {   // Yes!
                cTsnAck = GapStopList[0];
                // We can take out all fragments of this block
                for (uint32 i = 1; i < NumGaps; i++) {
                    GapStartList[i-1] = GapStartList[i];
                    GapStopList[i-1] = GapStopList[i];
                }
                progress = true;
            }
            counter++;
        }
    }
    return (progress);
}


// ###### Remove TSN from gap list ##########################################
void SimpleGapList::removeFromGapList(const uint32 removedTSN)
{
    const int32 initialNumGaps = NumGaps;

    for (int32 i = initialNumGaps - 1; i >= 0; i--) {
        if (tsnBetween(GapStartList[i], removedTSN, GapStopList[i])) {
            // ====== Gap block contains more than one TSN =====================
            const int32 gapsize = (int32)(GapStopList[i] - GapStartList[i] + 1);
            if (gapsize > 1) {
                if (GapStopList[i] == removedTSN) {   // Remove stop TSN
                    GapStopList[i]--;
                }
                else if (GapStartList[i] == removedTSN) {   // Remove start TSN
                    GapStartList[i]++;
                }
                else {   // Block has to be splitted up
                    NumGaps = std::min(NumGaps + 1, (uint32)MAX_GAP_COUNT);   // T.D. 18.12.09: Enforce upper limit!
                    for (int32 j = NumGaps - 1;  j > i; j--) {
                        GapStopList[j] = GapStopList[j - 1];
                        GapStartList[j] = GapStartList[j - 1];
                    }
                    GapStopList[i] = removedTSN - 1;
                    if ((uint32)i + 1 < NumGaps) {
                        GapStartList[i + 1] = removedTSN + 1;
                    }
                }
            }

            // ====== Just a single TSN in the gap block (start==stop) =========
            else {
                for (int32 j = i; j <= initialNumGaps - 1; j++) {
                    GapStopList[j] = GapStopList[j + 1];
                    GapStartList[j] = GapStartList[j + 1];
                }
                GapStartList[initialNumGaps - 1] = 0;
                GapStopList[initialNumGaps - 1] = 0;
                NumGaps--;
            }

            break;  // TSN removed -> done!
        }
    }
}


// ###### Add TSN to gap list ###############################################
bool SimpleGapList::updateGapList(const uint32 receivedTSN,
        uint32&      cTsnAck,
        bool&        newChunkReceived)
{
    if (tsnLe(receivedTSN, cTsnAck)) {
        // Received TSN covered by CumAckTSN -> nothing to do.
        return (false);
    }

    uint32 lo = cTsnAck + 1;
    for (uint32 i = 0; i < NumGaps; i++) {
        if (GapStartList[i] > 0) {
            const uint32 hi = GapStartList[i] - 1;
            if (tsnBetween(lo, receivedTSN, hi)) {
                const uint32 gapsize = hi - lo + 1;
                if (gapsize > 1) {
                    /**
                     * TSN either sits at the end of one gap, and thus changes gap
                     * boundaries, or it is in between two gaps, and becomes a new gap
                     */
                    if (receivedTSN == hi) {
                        GapStartList[i] = receivedTSN;
                        newChunkReceived = true;
                        return true;
                    }
                    else if (receivedTSN == lo) {
                        if (receivedTSN == (cTsnAck + 1)) {
                            cTsnAck++;
                            newChunkReceived = true;
                            return true;
                        }
                        /* some gap must increase its upper bound */
                        GapStopList[i-1] = receivedTSN;
                        newChunkReceived = true;
                        return true;
                    }
                    else {   /* a gap in between */
                        NumGaps = std::min(NumGaps + 1, (uint32)MAX_GAP_COUNT);   // T.D. 18.12.09: Enforce upper limit!

                        for (uint32 j = NumGaps - 1; j > i; j--) {   // T.D. 18.12.09: Fixed invalid start value.
                            GapStartList[j] = GapStartList[j-1];
                            GapStopList[j] = GapStopList[j-1];
                        }
                        GapStartList[i] = receivedTSN;
                        GapStopList[i] = receivedTSN;
                        newChunkReceived = true;
                        return true;
                    }
                }
                else {   /* alright: gapsize is 1: our received tsn may close gap between fragments */
                    if (lo == cTsnAck + 1) {
                        cTsnAck = GapStopList[i];
                        if (i == NumGaps-1) {
                            GapStartList[i] = 0;
                            GapStopList[i] = 0;
                        }
                        else {
                            for (uint32 j = i; j < NumGaps - 1; j++) {      // T.D. 18.12.09: Fixed invalid end value.
                                GapStartList[j] = GapStartList[j + 1];
                                GapStopList[j] = GapStopList[j + 1];
                            }
                        }
                        NumGaps--;
                        newChunkReceived = true;
                        return true;
                    }
                    else {
                        GapStopList[i-1] = GapStopList[i];
                        if (i == NumGaps-1) {
                            GapStartList[i] = 0;
                            GapStopList[i] = 0;
                        }
                        else {
                            for (uint32 j = i; j < NumGaps - 1; j++) {      // T.D. 18.12.09: Fixed invalid end value.
                                GapStartList[j] = GapStartList[j + 1];
                                GapStopList[j] = GapStopList[j + 1];
                            }
                        }
                        NumGaps--;
                        newChunkReceived = true;
                        return true;
                    }
                }
            }
            else {  /* receivedTSN is not in the gap between these fragments... */
                lo = GapStopList[i] + 1;
            }
        } /* end: for */
    } /* end: for */

    // ====== We have reached the end of the list ============================
    if (receivedTSN == lo) {   // just increase CumAckTSN, handle further update of CumAckTSN later
        if (receivedTSN == cTsnAck + 1) {
            cTsnAck = receivedTSN;
            newChunkReceived = true;
            return true;
        }
        // Update last fragment, stop TSN by one.
        GapStopList[NumGaps-1]++;

        newChunkReceived = true;
        return true;

    }
    else {
        // T.D. 24.09.2010:
        // If the received TSN is new, the list is either empty or the received
        // TSN is larger than the last gap end + 1. Otherwise, the TSN has already
        // been acknowledged.
        if ( (NumGaps == 0) ||
                (tsnGt(receivedTSN, GapStopList[NumGaps - 1] + 1)) ) {
            // A new fragment altogether, past the end of the list
            if (NumGaps < MAX_GAP_COUNT) {   // T.D. 18.12.09: Enforce upper limit!
                GapStartList[NumGaps] = receivedTSN;
                GapStopList[NumGaps] = receivedTSN;
                NumGaps++;
                newChunkReceived = true;
            }
        }
        return true;
    }

    return false;
}



// ###### Constructor #######################################################
GapList::GapList()
{
    CumAckTSN = 0;
}


// ###### Destructor ########################################################
GapList::~GapList()
{
}


// ###### Check gap list ####################################################
void GapList::check() const
{
    CombinedGapList.check(CumAckTSN);
    RevokableGapList.check(CumAckTSN);
    NonRevokableGapList.check(CumAckTSN);
}


// ###### Print gap list ####################################################
void GapList::print(std::ostream& os) const
{
    os << "CumAck=" << CumAckTSN;
    os << "   Combined-Gaps=";
    CombinedGapList.print(os);
    os << "   R-Gaps=";
    RevokableGapList.print(os);
    os << "   NR-Gaps=";
    NonRevokableGapList.print(os);
}


// ###### Forward CumAckTSN #################################################
void GapList::forwardCumAckTSN(const uint32 cumAckTSN)
{
    CumAckTSN = cumAckTSN;
    CombinedGapList.forwardCumAckTSN(CumAckTSN);
    RevokableGapList.forwardCumAckTSN(CumAckTSN);
    NonRevokableGapList.forwardCumAckTSN(CumAckTSN);
#ifdef DEBUG_GAPLIST
    check();
#endif
}


// ###### Advance CumAckTSN #################################################
bool GapList::tryToAdvanceCumAckTSN()
{
    if (CombinedGapList.tryToAdvanceCumAckTSN(CumAckTSN)) {
        RevokableGapList.forwardCumAckTSN(CumAckTSN);
        NonRevokableGapList.forwardCumAckTSN(CumAckTSN);
#ifdef DEBUG_GAPLIST
        check();
#endif
        return (true);
    }
    return (false);
}


// ###### Remove TSN from gap list ##########################################
void GapList::removeFromGapList(const uint32 removedTSN)
{
    RevokableGapList.removeFromGapList(removedTSN);
    NonRevokableGapList.removeFromGapList(removedTSN);
    CombinedGapList.removeFromGapList(removedTSN);
#ifdef DEBUG_GAPLIST
    check();
#endif
}


// ###### Add TSN to gap list ###############################################
bool GapList::updateGapList(const uint32 receivedTSN,
        bool&        newChunkReceived,
        bool         tsnIsRevokable)
{
    uint32 oldCumAckTSN = CumAckTSN;
    if (tsnIsRevokable) {
        // Once a TSN become non-revokable, it cannot become revokable again!
        // However, if the list became too long, updateGapList() may be called
        // again when the chunk is received again.
        RevokableGapList.updateGapList(receivedTSN, oldCumAckTSN, newChunkReceived);
    }
    else {
        if (NonRevokableGapList.updateGapList(receivedTSN, oldCumAckTSN, newChunkReceived) == true) {
            // TSN has moved from revokable to non-revokable!
            RevokableGapList.removeFromGapList(receivedTSN);
        }
    }

    // Finally, add TSN to combined list and set CumAckTSN.
    oldCumAckTSN = CumAckTSN;
    const bool newChunk = CombinedGapList.updateGapList(receivedTSN, CumAckTSN, newChunkReceived);
    if (oldCumAckTSN != CumAckTSN) {
        RevokableGapList.forwardCumAckTSN(CumAckTSN);
        NonRevokableGapList.forwardCumAckTSN(CumAckTSN);
    }

#ifdef DEBUG_GAPLIST
    check();
#endif
    return (newChunk);
}



#if 0
int main(int argc, char** argv)
{
    bool    newChunk = false;
    GapList gl;

    gl.setInitialCumAckTSN(1000);
    gl.updateGapList(1004, newChunk); gl.check();
    gl.updateGapList(1005, newChunk); gl.check();
    std::cout << "A1:\t"; gl.print(std::cout); std::cout << endl;

    gl.updateGapList(1009, newChunk); gl.check();
    gl.updateGapList(1010, newChunk); gl.check();
    std::cout << "A2:\t"; gl.print(std::cout); std::cout << endl;

    gl.updateGapList(1006, newChunk, false); gl.check();
    gl.updateGapList(1008, newChunk, false); gl.check();

    std::cout << "A3:\t"; gl.print(std::cout); std::cout << endl;
    gl.updateGapList(1007, newChunk); gl.check();

    std::cout << "A3:\t"; gl.print(std::cout); std::cout << endl;
    gl.updateGapList(1002, newChunk); gl.check();
    std::cout << "A4:\t"; gl.print(std::cout); std::cout << endl;
    gl.updateGapList(1001, newChunk); gl.check();
    std::cout << "A5:\t"; gl.print(std::cout); std::cout << endl;
    gl.updateGapList(1003, newChunk); gl.check();

    std::cout << "A6:\t"; gl.print(std::cout); std::cout << endl;
    gl.updateGapList(1004, newChunk, false); gl.check();   // Already-acked
    gl.updateGapList(1005, newChunk, false); gl.check();   // Already-acked

    std::cout << "A7:\t"; gl.print(std::cout); std::cout << endl;
    gl.updateGapList(1012, newChunk, true);  gl.check();
    std::cout << "A8:\t"; gl.print(std::cout); std::cout << endl;
    gl.updateGapList(1012, newChunk, false); gl.check();   // Already-acked

    std::cout << "Ende:\t"; gl.print(std::cout); std::cout << endl;
}
#endif
