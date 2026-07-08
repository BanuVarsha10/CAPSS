#!/bin/bash

echo "Starting UE..."

sudo pkill -f nr-ue 2>/dev/null

sleep 1

exec sudo ~/5g-project/UERANSIM/build/nr-ue \
    -c ~/5g-project/UERANSIM/config/open5gs-ue.yaml