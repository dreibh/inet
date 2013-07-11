#!/bin/bash 

FILTER=$1
echo "Convert all *.svg to pdf"
echo "be sure librsvg2-bin packet is installed"
dateien=`find ../$FOLDER -name "*"$FILTER"*" -a -name "_*.svg" -type f`
rm -f *.pdf 
for i in $dateien ; do 
        echo "process.."
        /usr/bin/rsvg-convert -f pdf  -o $i.pdf $i 
done
echo "created:"
ls -l *.pdf
echo "done"
