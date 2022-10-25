# Introduction
**IMPORTANT: THIS IS JUST A STUDY - DO NOT USE IN PRODUCTION**

A extended Berkeley Packet Filter (eBPF) Linux kernel program to filter http requests to local network address e.g. cloud metadata services, such as AWS IMDSv2 or Azure Metadata Service. Note: You will need to have software engineering, security, some Linux and especially Linux kernel knowledge.

We discuss here different ways for eBPF modules to filter requests so that only the allowed users can make calls to those addresses. This enables a more limited permissions on those metadata services and thus can potentially increase security.

Generally, the approach works also with all other possible IP addresses without changing it. Instead of IP addresses one may also do filtering based on DNS names, which can be implemented as an extension to our approach (e.g. filter packets to a DNS server or in case of DNS/HTTPS via filtering a library call). For our demonstration case this was not needed.


## Blog
Find additional considerations in this blog post (WIP).
## Code
The code is available under:
* Codeberg (a non-commercial European hosted Git for Open Source): https://codeberg.org/ZuInnoTe/rust-ebpf-localnet-kernel-filter-study
* Github (an US hosted commercial Git platform): https://github.com/ZuInnoTe/rust-ebpf-localnet-kernel-filter-study

## License
You can choose to either use [EUPL-1.2](./LICENSE-EUPL-1.2) ([Web](https://spdx.org/licenses/EUPL-1.2.html)) or [Apache-2.0](./LICENSE-Apache-2.0) ([Web](https://spdx.org/licenses/Apache-2.0.html)) license.



# What we want to achieve
This study investigates the usage of [Rust](https://www.rust-lang.org/) and eBPF for an advanced security and observability use case. The case is about filtering traffic to compute cloud metadata services, such as [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) or [Azure Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service). Usually, in the cloud a set of permissions is assigned to a compute resource (e.g. VM, container or serverless) to access further cloud services from within this compute instance. For instance, writing to an object store. Obviously those permissions should be minimal and not allow data leackage, modifiying infrastructure etc. Nevertheless, within the compute instance all processes, including potential malware, can use those permissions to do malicious activities. We study here a possibility to limit this to a certain subset of processes run by a given user in a efficient way. 

The software written as part of this study is generic, you can use this to allow/block any IPv4, IPv6 address (other protocols are simply allowed).

# Examples
* Use case implemented as a eBPF TC (traffic control) program: [net-tc-filter](net-tc-filter)
* Use case implemented as a eBPF uprobe syscall filter (e.g. for the sharedd OpenSSL Library): WIP


# eBPF
The extended [Berkeley Packet Filter](https://ebpf.io/) (eBPF) is a capability in the Linux kernel that gained in recent year a lot of traction, because it enables novel ways for massive scaling cloud applications, their security and observability. You can find [here](https://ebpf.io/applications) some application examples.

We cannot cover here them in their completeness (you can start [here](https://ebpf.io/what-is-ebpf/)), because they are extremely powerful and they are continuously extended. They usually works best with recent Linux kernels, but also older versions support them.

Essentially you can imagine that eBPF programs are written using specific platform-independent instructions that are interpreted by the kernel and run in a sandbox. They can be hooked into any part of the kernel, e.g. network layer, system calls, thread scheduler, application/library calls etc.

The kernel has some in-built eBPF programs and one can load additional ones. eBPF programs can call each other and be combined in different ways to deliver extremely powerful applications.

eBPF programs have access to certain data structures of the kernel. Obviously they can be different in different kernel versions. The [BPF Type Format](https://www.kernel.org/doc/html/latest/bpf/btf.html) (BPT)  addresses this issue to a large extent and is available since Linux 5.4. Additionally, there is a mechanism called [CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html). Nevertheless, the best way is to use built-in Linux kernel eBPF functions to get the needed information from the data structures without the need to take into account different kernel versions. Note that usually recent kernel versions provide the most eBPF in-built kernel functions and that depending on the type of eBPF program you can only access a subset of those.

eBPF development can be complex and [requires sophisticated understanding of distributed systems](https://lwn.net/Articles/779120/).

You do not have to program to start with eBPF. You can use for instance [bpftrace](https://bpftrace.org/) for tracing kernel/application events. Find [here](https://github.com/iovisor/bpftrace) a lot of examples. The [BPF Compiler Collection](https://github.com/iovisor/bcc) (BCC) provides a lot of tools related to eBPF. They also provide [a lot of example code](https://github.com/iovisor/bcc#contents) on a wide range of use cases.


## Type of eBPF programs
Essentially depending on the type of eBPF program (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h#n948))you have access to different data structures and kernel internal eBPF functions.

Find here some type of eBPF programs:
* Networking
  * eXpress Data Path (XDP): allows filtering of network packet before they are processed by the kernel (before sk_buff is created). This is for high-performance package filtering. In the past, it used to be limited to ingress filtering. In recent kernel versions egress is supported (cf. [here](https://lwn.net/Articles/813406/)). The eBPF program can decide to allow/drop a package. It has access to the package content (* which may be encrypted) and can modify it.  Furthermore you have access to the data structure xdp_md (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h?h=v6.0#n5944). You can also do make routing decisions, e.g. to forward it to a different network interface. One can also implement traffing shaping mechanisms. The concepts are also explained [here](https://docs.kernel.org/networking/af_xdp.html). It has support for certain Linux internal eBPF functions (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c?h=v6.0#n8003))
  * traffic control (TC): allows classification (filter) and actions (actions on classification) of network packet after they have been processed by the kernel (after sk_buff is created). This is less performant than XDP (except on certain systems where it can nearly be equal), but has all the information contained in [sk_buff](https://docs.kernel.org/networking/kapi.html#c.sk_buff) available, which is more than XDP. It has access to the package content (* which may be encrypted) and can modify it. It provides more actions that can be done on a packet compared to XDP (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/pkt_cls.h?v=6.0#n11)). It supports more kernel internal eBPF functions compared to XDP (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c?h=v6.0#n7869))
  * socket: network packet filter. It has access to the data structure bfp_sock_addr (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h?v=6.0#n6291)) Can rewrite the packet and the socket options. It has acceess to certain kernel internal eBPF functions (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c?h=v6.0#n7668))
    * Filter: Filtering of packets received from sockets. This was also available in classic BPF. Note: You can NOT block/allow a packet. You can only decide which packets are sent to the user space pogram for analysis. Essentially it is similar to what [tcpdump](https://www.tcpdump.org/) does. You can analyze all supported protocols of the Linux kernel.
    * Stram Parser: operates on a group of sockets that are added to a special BPF map. Processes messages send or received on those sockets.
      * SK_SKB parses packets into individual messages and instructs the kernel to drop them or send them to another socket
      * SK_MSG filters egress messages and either approves or rejects them
  * LWT: [lightweight tunnels](https://lwn.net/Articles/650778/) (LWT).  Certain eBPF functions are allowed. (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c?h=v6.0#n8210)
  * Note: eBPF programs are very small and have limited capabilities for analysis. You can though use this do transfer suspicious packets to a user space program that can do further analysis or classify it with artificial intelligence. While you can block the packet usually the analysis of a packet would take too long and would drop performance too much. You may though combine it with other types of eBPF programs to preselect more efficiently a relevant packet.
* [CGroups](https://en.wikipedia.org/wiki/Cgroups): 
  * skb: CGroup skb eBPF program can be triggered based on network traffic associated with a given process in a cgroup (socket eBPFs are attached to a network interface). It has access to the [sk_buff](https://docs.kernel.org/networking/kapi.html#c.sk_buff) structure. It has access to certain kernel internal eBPF functions (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c?h=v6.0#n7824)). It is a bit like a tc for cgroups.
  * sock: CGroup sock eBPF program can react on socket options in a cgroup. It has access to certain kernel internal eBPF functions (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c?h=v6.0#n6291)). It has access to the data structure bfp_sock_addr (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h?v=6.0#n6291)). It is a bit like a socket for cgroups.

  * device: CGroup device program is triggered when accessing a device within a cgroup. See [kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html) and an [example](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf/progs/dev_cgroup.c). You have access the data structure bpf_cgroup_dev_ctx (see [here for Linux Kernel 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h?v=6.0#n6662)). You can decide to allow/deny access to the device.
* System/Application calls (probes/tracing):
  * [kprobes](https://www.kernel.org/doc/html/latest/trace/kprobes.html): can be used to trace kernel instructions or kernel return functions. You can also change the behaviour when a kernel instruction is hit (e.g. do not continue execution). You have access to certain kernel information that are available to the instruction (pt_regs, e.g. see  [here for x86 in Linux 6.0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/uapi/asm/ptrace.h?v=6.0#n18)). It has a less stable API as the kernel changes in each version. However, kernel functions once they are defined and tested over some iterations of kernel versions usually do not change much. Tracepoints are the static variant.
  * [uprobes](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html) (User-level dynamic tracing): These can be used to trace instructions in user spaces (e.g. applciations). This offers a huge range of applications. It enables also to tap into encrypted network traffic by attaching itself to corresponding library calls (e.g. OpenSSL). However, virtually any type of call can be monitored, e.g. you can intercept [MySQL SQL queries](https://github.com/iovisor/bcc/blob/master/examples/tracing/mysqld_query.py), determine all commands that [are executed using bash](https://brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html), trace DNS lookups or determine suspicious behaviour. You can also block those calls if they do not match certain criteria. Userland Statically Defined Tracepoints (USDT) are the static variant.
* LSM ([Linux Security Modules](https://en.wikipedia.org/wiki/Linux_Security_Modules), see also [kernel documentation](https://www.kernel.org/doc/html/latest/security/lsm.html))
* Performance/Monitoring: 
  * PerfEvents: allow access to [Linux Perf events](https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html). This can be used to filter suspicious/anomalous activity or predict future poor system health. You 



There are more types and the possible types evolves in each Linux kernel version. See also a list provided [here](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#program-types).

You can already see from the list that the same thing can be implemented differently, so having a good design and testing is mandatory. It depends heavily on your use case.

Events can be sent from eBPF programs to a user space application. Different eBPF programs or user space applications can exchange configuration via maps. 

Depending on your use case, you have to choose the right type of eBPF program and you may need to combine different type of eBPF programs.

Note on encrypted network connections: Obviously if the network connection is encrypted then you can only work with the metadata as you do not have access to the encrypted packet content. There are ways around it. For example, Wireshark requests to have the private key for decryption. This may be infeasible in some cases. Alternatively, you can intercept the call to the library that encrypts the content, e.g. to the OpenSSL or LibreSSL calls. 


# Concept
The concept of an application using eBPF is simple. Essentially you have two modules:
* The user space program (can be written in any language) that loads the
* eBPF program (needs to be compiled into the [eBPF instruction set](https://www.kernel.org/doc/html/latest/bpf/instruction-set.html))

Both can communicate with each other using maps. 

# Executing eBPF programs
You can decide to execute eBPF programs as root (sudo) or provide to the binary the right [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) (e.g. via setcap). You should avoid executing them as root for security reasons and you should avoid to provide a lot of capabilities or very powerful capabilities (you must NOT use  CAP_SYS_ADMIN - this provides in the end unprivileged users root access!). Always work under the mantra of minimal permissions. We give in the different subfolders for each eBPF application that we developed an example of minimal capabilities.


# Technology choices
We use in this study the programming language [Rust](https://www.rust-lang.org/). Rust has the advantage that it is system language with similar performance characteristics as C, but it is safe by default. This is especially important for eBPF as those programs run closely with the kernel and they should be safe by default. Although Rust in the Linux kernel comes only in 6.1, you can even use on much older kernels Rust for eBPF, because they are compiled into the eBPF instruction set which is programming language independent. Hence, they are a perfect match.

Rust is the chosen language and we have also to choose a eBPF framework that faciltiates writing eBPF programs and loading them. You have the following choices in Rust:
* [Aya](https://aya-rs.dev/) - fully written in Rust. It is a rather novel library, but is already used in several production applications. It can be compiled once and run on different kernel versions.
* [libbpf](https://github.com/libbpf/libbpf) - is a C library which has a [Rust wrapper](https://github.com/libbpf/libbpf-rs). Libbpf is mature, but the wrapper is still in development
* [bcc](https://github.com/iovisor/bcc) - is a C library which has a [Rust wrapper](https://github.com/rust-bpf/rust-bcc). Bcc is mature, but most of its use cases are related to C and  Python.


We choose Aya as it is fully implemented in Rust and is a promising alternative for eBPF programs written in Rust.

