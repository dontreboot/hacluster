#!/bin/bash

INTERFACE=$1
IP=$2
ALIAS=$3

if [[ $IP =~ '/' ]]
then
    CIDR=$IP
else
    CIDR="$IP/32"
fi

/sbin/ifcfg ${INTERFACE}:${ALIAS} add ${CIDR}
