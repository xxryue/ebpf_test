# ebpf program by libbpf

# testing

```
git clone git@github.com:xxryue/ebpf_test.git
git submodule update --init
cd src
mkdir build
cmake .. && make
sudo ./ebpf_test
```


# Enable LSM for Ubuntu or Centos 8

add "lsm=lockdown,capability,bpf" to "RUB_CMDLINE_LINUX" in "/etc/default/grub"
