#! /bin/bash
if [ -z $1 ]; then
        echo "usage: $0 <interface or IB device> "
        exit 1
fi

source common_irq_affinity.sh

IRQS=$( get_irq_list $1 )
if [ -z "$IRQS" ] ; then
        echo No IRQs found for $1.
        exit 1
fi

for irq in $IRQS
do
	show_irq_affinity $irq
done

