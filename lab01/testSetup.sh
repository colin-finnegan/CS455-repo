#!/bin/bash
echo "Script to test Network Topology"
echo "By: Colin Finnegan"
echo
date
echo
echo -n "Hostname: "
hostname
echo
echo "Network Devices"
ifconfig -a
echo

IPlist=(192.168.2.1 192.168.3.1  192.168.4.1    \
        192.168.2.2 192.168.2.22 192.168.3.3 )
# echo ${IPlist[*]}
fail=0
for i in "${IPlist[@]}"
do
    echo -n "Pinging $i  ... "
    ping -c 1 $i  2>&1 > /dev/null
    ok=$?
    if [  $ok = 0 ];
    then
        echo "ok"
    else
        echo "FAILED"
        fail=`expr $fail + 1`
    fi
done

echo
if [ $fail -gt 0 ]; then
    echo "Failures Occured: $fail"
else 
    echo "ALL is GOOD"
fi
echo
