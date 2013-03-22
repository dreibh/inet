#!/bin/bash
# script testing several simple scenarios TCP-SCTP-CMT-MPTCP
# ((c) 2013
# v0.1

####################### Config  Runs ##################### 

RUNS="SCTP_Netperfmeter TCP_Netperfmeter CMT_Netperfmeter_Single CMT_Netperfmeter_Multi MPTCP_Netperfmeter_Single MPTCP_Netperfmeter_Multi Experiment_Bottleneck_TCP Experiment_Bottleneck_SCTP Experiment_Bottleneck_SCTP_TCP Experiment_Bottleneck_MPTCP_TCP Experiment_Bottleneck_CMT_SCTP"
DURATION_CLIENT="300 s"
DURATION_SERVER="360 s"
BIGFILES="NO" # YES
####################### Prepare Runs ######################
echo "Get Parameter"
if [ $1 != "" ];
then
	tmp=$RUNS
	if [ $1 == "ALL" ];
	then
		echo "Do ALL"
	fi
	if [ $1 == "help" ];
	then
		echo $RUNS
		exit 0
	else
		let j=0
		for i in $* 
		do
			let j=j+1
			if [ $j == 1 ];
			then
				RUNS="$i"
			else
			echo "Set parameter" $i
				RUNS="$RUNS $i"
			fi
		done
	fi
fi
	
echo "Work on " $RUNS
DELETE_FIRST="test_vectors.vec test_scalars.sca results.log abort.log"
for FILE in $DELETE_FIRST
do
	if [ -e $FILE ];
	then
		echo "Move old file to archive " $FILE
		mv  $FILE Archive/old.$FILE
	fi
done

# Delete job files
for JOB in $RUNS
do
	[ -f Archive/$JOB_vectors.vec ] && mv Archive/$JOB_vectors.vec Archive/old.$JOB_vectors.vec
	[ -f Archive/$JOB_scalars.sca ] && mv Archive/$JOB_scalars.sca Archive/old.$JOB_scalars.sca
done


echo "Write build.ini" 
###################### Write ini    ######################
echo "## Test build ##" 										> build.ini
echo "[Config Bottleneck_NetPerfMeter]" 								>> build.ini
echo "#############################################################################################" 	>> build.ini
echo "extends = _Bottleneck_NetPerfMeter							  #" 	>> build.ini 
echo "description = "Setup with Bottleneck"						          #" 	>> build.ini 
echo "#############################################################################################" 	>> build.ini
echo "**.mptcp1.netPerfMeterApp[*].startTime       				= 1.0 s"		>> build.ini
echo "**.mptcp1.netPerfMeterApp[*].resetTime       				=  60 s"		>> build.ini 
echo "**.mptcp1.netPerfMeterApp[*].stopTime        				= $DURATION_CLIENT"	>> build.ini
echo ""
echo "**.server*.netPerfMeterApp[*].connectTime      				= 0.001 s"		>> build.ini
echo "**.server*.netPerfMeterApp[*].startTime  		       			= uniform(0.9s,1.1s)"	>> build.ini 
echo "**.server*.netPerfMeterApp[*].resetTime         				=  60 s"		>> build.ini
echo "**.server*.netPerfMeterApp[*].stopTime          				= $DURATION_SERVER"	>> build.ini
echo ""
echo "**.default1*.netPerfMeterApp[*].startTime       				= uniform(0.9s,1.1s)"	>> build.ini
echo "**.default1*.netPerfMeterApp[*].resetTime      				= 60 s"			>> build.ini
echo "**.default1*.netPerfMeterApp[*].stopTime       				= $DURATION_CLIENT" 	>> build.ini
cat _build.ini >> build.ini
###################### Do the runs #######################
rm -f dat.log
rm -f err.log
for JOB in $RUNS
do
	echo "run Szenario " $JOB
	time ../../../src/inet -r 0 -u Cmdenv -c $JOB -n ../..:../../../simulations:../../../src  build.ini >> dat.log 2>> err.log 
	sleep 5
	if [ $BIGFILES == "yes" ];
	then
	cat vectors.vec >> Archive/test_vectors.vec
	cat scalars.sca >> Archive/test_scalars.sca
	fi
	cp vectors.vec Archive/vector_$JOB.vec
	cp scalars.sca Archive/scalars_$JOB.sca
	
   echo $JOB
done
###################### Do the Rest #######################
echo ""
echo "Errors"
cat dat.log | grep "ASSERT:" >> abort.log
cat abort.log
echo "Results"
cat dat.log | grep "No more events -- simulation ended at event" >> results.log
for JOB in $RUNS
do  
	echo $JOB  >> results.log
	cat Archive/scalars_$JOB.sca | grep "Total Received Bytes" 	     >> results.log
	cat Archive/scalars_$JOB.sca | grep "Total Reception Bit Rate"       >> results.log
done
cat results.log
