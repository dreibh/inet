#!/bin/bash
# script testing several simple scenarios TCP-SCTP-CMT-MPTCP
# ((c) 2013
# v0.1

####################### Config  Runs ##################### 

RUNS="experiments/Basic_CC/CMT_SCTP experiments/Basic_CC/MPTCP experiments/Basic_CC/Basic_SCTP experiments/Basic_CC/Basic_TCP"

####################### Prepare Runs ######################
echo "Get Parameter"
if [ ! -z $1 ];
then
	tmp=$RUNS
	if [ $1 == "ALL" ];
	then
		echo "todo"
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
else
echo "please use parameter .... see help"
exit 0
fi
	
for JOB in $RUNS
do
	echo "run Szenario " $JOB
	time ../../../0/gcc-debug/src/inet -r 0 -u Cmdenv -n ../..:../../../simulations:./:../../../src  $JOB/run.ini
    $JOB/plot $JOB/vectors/vectors.vec $JOB/pdf/result.pdf
    echo $JOB
done

