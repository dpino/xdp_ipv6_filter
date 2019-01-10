XDP Example: IPv6 packet filter
===============================

Source code for the example explained at: 

You need a kernel with XDP enabled in order to run this example. Very likely, you'll also need the kernel sources in order to build it.

Compile
-------

$ make
clang -I. -I/lib/modules/4.19.0/source/arch/x86/include -I/lib/modules/4.19.0/source/arch/x86/include/generated -I/lib/modules/4.19.0/source/include -I/lib/modules/4.19.0/source/arch/x86/include/uapi -I/lib/modules/4.19.0/source/arch/x86/include/generated/uapi -I/lib/modules/4.19.0/source/include/uapi -I/lib/modules/4.19.0/source/include/generated/uapi -include /lib/modules/4.19.0/source/include/linux/kconfig.h -I/lib/modules/4.19.0/source/tools/testing/selftests/bpf/ -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign -D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -O2 -emit-llvm -c xdp_ipv6_filter.c -o - | \
llc -march=bpf -mcpu= -filetype=obj -o xdp_ipv6_filter.o

Settings
--------

The example pushes packets to a veth end (veth0) which runs a XDP program. The program filters only IPv6 traffic, which reaches the other end (veth1). Thus, it's necessary to create a veth pair and load the compiled XDP program (`xdp_ipv6_filter.o`) into veth1.

```
$ sudo ip link add dev veth0 type veth peer name veth1
$ sudo ip link set up dev veth0
$ sudo ip link set up dev veth1
```

```
$ sudo ip link set dev veth1 xdp object xdp_ipv6_filter.o
```

Run
---

Expect 10 IPv6 packets on veth1:

```
$ sudo tcpdump "ip6" -i veth1 -w captured.pcap -c 10
tcpdump: listening on veth1, link-type EN10MB (Ethernet), capture size 262144 bytes
```

Push packets into veth0:

```
$ sudo tcpreplay -i veth0 ipv4-and-ipv6-data.pcap
```

The program running tcpdump terminates succesfully

```
10 packets captured
10 packets received by filter
0 packets dropped by kernel
```
