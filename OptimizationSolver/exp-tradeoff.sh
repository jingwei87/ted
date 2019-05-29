#!/bin/bash
for i in $(seq 0.05 0.05 1)
do
    ./main $i origin.pfreq > report_$i
done      

