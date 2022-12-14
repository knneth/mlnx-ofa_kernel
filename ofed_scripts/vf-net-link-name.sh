#!/bin/bash

SWID="$1"
PORT="$2"

for i in `ls -1 /sys/class/net/*/address`; do
    nic=`echo $i | cut -d/ -f 5`
    address=`cat $i | tr -d :`
    sw_id=`cat /sys/class/net/$nic/phys_switch_id 2>/dev/null`
    if [ "$sw_id" = "$SWID" ]; then
        if [ "$address" = "$SWID" ] || \
           [ -d "/sys/class/net/${nic}/device/virtfn0" ]; then
            dev_name=${nic}_$PORT
            if [ ! -d "/sys/class/net/${dev_name}" ]; then
                echo "NAME=$dev_name"
                break
            fi
        fi
    fi
done
