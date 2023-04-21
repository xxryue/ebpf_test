#!/usr/bin/env bash

tc filter del dev enp89s0 egress
tc qdisc del dev enp89s0 clsact

tc qdisc add dev enp89s0 clsact

tc filter add dev enp89s0 egress bpf da obj cmake-build-debug/tc_egress.bpf.o sec wg_egress