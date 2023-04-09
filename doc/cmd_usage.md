## generate eBPF bytecode by clang



```
clang -target bpf -I/usr/include/$(shell uname -m)-linux-gnu -g -O2 -c test.c -o test.o
```

## 使用llvm-objdump来查看ebpf目标字节码文件

```
llvm-objdump -S test.o
```

## Loading the Program into the kernel

```
sudo bpftool prog load test.o /sys/fs/bpf/test
```
## list all ebpf program
```
bpftool prog list
```

## list specific program info in json

```
bpftool prog show id *** --pretty

bpttool prog show name test --pretty
```
## attaching to an event

```
bpftool net attach xdp id *** dev eth0
```

## view all the network-attached eBPF programs 
```
bpftool net list
or 
ip link

## we can view the output of a bpf program
```
cat /sys/kernel/debug/tracing/trace_pipe
or
bpftool prog tracelog
```

## detaching the program
```
bpftool net detach xdp dev eth0
```

## unloading the program

```
rm /sys/fs/bpf/test
```
```
