#!/bin/bash

SWID="$1"
PORT="$2"

for i in `ls -1 /sys/class/net/*/address`; do
    nic=`echo $i | cut -d/ -f 5`
    address=`cat $i | tr -d :`
    sw_id=`cat /sys/class/net/$nic/phys_switch_id 2>/dev/null`
    if [ "$address" = "$SWID" ] && [ "$sw_id" = "$SWID" ]; then
        echo "NAME=${nic}_$PORT"
        break
    fi
done
