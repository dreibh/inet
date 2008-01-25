/***************************************************************************
                          RTPAVProfileSampleBasedAudioReceiver.cc  -  description
                             -------------------
    begin                : Fri Sep 13 2002
    copyright            : (C) 2002 by Matthias Oppitz
    email                : matthias.oppitz@gmx.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/


#include <audiofile.h>
#include "RTPAVProfileSampleBasedAudioReceiver.h"
#include "RTPInnerPacket.h"


Define_Module_Like(RTPAVProfileSampleBasedAudioReceiver, RTPPayloadReceiver);

RTPAVProfileSampleBasedAudioReceiver::~RTPAVProfileSampleBasedAudioReceiver() {
    closeOutputFile();
};


/*
void RTPAVProfileSampleBasedAudioReceiver::activity() {
    simtime_t expectedPacketArrivalTime = 0.0;
    simtime_t timeBuffer = 0.0;

    int timeStamp = 0;

    while (true) {
        cMessage *msg = receive();
        RTPPacket *packet = (RTPPacket *)(msg);

        // this checks for packets in wrong order
        if (packet->timeStamp() < timeStamp) {
            cout << "packet too late" << endl;
        }
        else {
            timeStamp = packet->timeStamp();
        }


        // this part is possibly useful for making jitter hearable
        simtime_t playTime = ((float)numberOfFrames) / ((float)_samplingRate);
        if (expectedPacketArrivalTime != 0.0) {
            simtime_t timeDifference = simTime() - expectedPacketArrivalTime;
            // is packet too late
            if (timeDifference > 0.0) {
                // do we have a time buffer?
                if (timeBuffer >= timeDifference) {
                    // reduce time buffer
                    timeBuffer = timeBuffer - timeDifference;
                    expectedPacketArrivalTime = simTime() + playTime;
                }
                else {
                    // insert silence into output file
//                    insertSilence(timeDifference - timeBuffer);
                    timeBuffer = 0.0;
*/


void RTPAVProfileSampleBasedAudioReceiver::processPacket(RTPPacket *packet) {
    //RTPPayloadReceiver::processPacket(packet);
    void *data = packet->par("data");
    int dataSize = packet->payloadLength();
    int numberOfFrames = dataSize  / ((_sampleWidth / 8) * _numberOfChannels);
    afWriteFrames(_audioFile, AF_DEFAULT_TRACK, data, numberOfFrames);
};


void RTPAVProfileSampleBasedAudioReceiver::openOutputFile(const char *fileName) {
    _fileSetup = afNewFileSetup();
    afInitByteOrder(_fileSetup, AF_DEFAULT_TRACK, AF_BYTEORDER_LITTLEENDIAN);
    afInitChannels(_fileSetup, AF_DEFAULT_TRACK, _numberOfChannels);
    afInitSampleFormat(_fileSetup, AF_DEFAULT_TRACK, AF_SAMPFMT_TWOSCOMP, _sampleWidth);
    afInitRate(_fileSetup, AF_DEFAULT_TRACK, (double)_samplingRate);
    _audioFile = afOpenFile(fileName, "w", _fileSetup);
    if (_audioFile == AF_NULL_FILEHANDLE) {
        opp_error("payload receiver: error creating output file");
    };
};


void RTPAVProfileSampleBasedAudioReceiver::closeOutputFile() {
    if (afCloseFile(_audioFile)) {
        opp_error("payload receiver: error closing output file");
    };
};


void RTPAVProfileSampleBasedAudioReceiver::insertSilence(simtime_t duration) {
    // depends at least on sampling rate and sample width
};