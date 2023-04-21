#!/bin/bash
############################
# File Name: setup.sh
# Author: yuemx
# mail: xxr_2011@outlook.com
# Created Time: 2023年04月21日 星期五 16时16分11秒
############################


ip link add dev wg0 type wireguard
ip addr add 10.0.0.1/24 dev wg0

wg set wg0 listen-port 10000
wg set wg0 private-key ./private
wg set wg0 peer *** endpoint *** allowed-ips ***

ip link set wg0 up
