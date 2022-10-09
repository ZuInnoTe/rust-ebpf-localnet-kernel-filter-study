# Introduction
**IMPORTANT: THIS IS JUST A STUDY - DO NOT USE IN PRODUCTION**
A extended Berkeley Packet Filter (eBPF) Linux kernel program to filter http requests to local network address e.g. cloud metadata services, such as AWS IMDSv2 or Azure Metadata Service. Note: You will need to have software engineering, security, some Linux and especially Linux kernel knowledge.

We discuss here different ways for eBPF modules to filter requests so that only the allowed users can make calls to those addresses. This enables a more limited permissions on those metadata services and thus can potentially increase security.

Generally, the approach works also with all other possible IP addresses without changing it. Instead of IP addresses one may also do filtering based on DNS names, which can be implemented as an extension to our approach (e.g. filter packets to a DNS server or in case of DNS/HTTPS via filtering a library call). For our demonstration case this was not needed.


## Blog
Find additional considerations in this blog post.
## Code
The code is available under:
* Codeberg (a non-commercial European hosted Git for Open Source): https://codeberg.org/ZuInnoTe/rust-ebpf-localnet-kernel-filter-study
* Github (an US hosted commercial Git platform): https://github.com/ZuInnoTe/rust-ebpf-localnet-kernel-filter-study

## License
You can choose to either use [EUPL-1.2](./LICENSE-EUPL-1.2) ([Web](https://spdx.org/licenses/EUPL-1.2.html)) or [Apache-2.0](./LICENSE-Apache-2.0) ([Web](https://spdx.org/licenses/Apache-2.0.html)) license.



# What we want to achieve
This study investigates the usage of [Rust](https://www.rust-lang.org/) and eBPF for an advanced security and observability use case. The case is about filtering traffic to compute cloud metadata services, such as [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) or [Azure Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service). Usually, in the cloud a set of permissions is assigned to a compute resource (e.g. VM, container or serverless) to access further cloud services from within this compute instance. For instance, writing to an object store. Obviously those permissions should be minimal and not allow data leackage, modifiying infrastructure etc. Nevertheless, within the compute instance all processes, including potential malware, can use those permissions to do malicious activities. We study here a possibility to limit this to a certain subset of processes run by a given user in a efficient way. 

The software written as part of this study is generic, you can use this to allow/block any IPv4, IPv6 address (other protocols are simply allowed).


# eBPF
The extended [Berkeley Packet Filter](https://ebpf.io/) (eBPF) is a capability in the Linux kernel that gained in recent year a lot of traction, because it enables novel ways for massive scaling cloud applications, their security and observability. You can find [here](https://ebpf.io/applications) some application examples.

We cannot cover here them in their completeness (you can start [here](https://ebpf.io/what-is-ebpf/)), because they are extremely powerful and they are continuously extended. They usually works best with recent Linux kernels, but also older versions support them.

Essentially you can imagine that eBPF programs are written using specific platform-independent instructions that are interpreted by the kernel and run in a sandbox. They can be hooked into any part of the kernel, e.g. network layer, system calls, thread scheduler, application/library calls etc.

The kernel has some in-built eBPF programs and one can load additional ones. eBPF programs can call each other and be combined in different ways to deliver extremely powerful applications.

eBPF programs have access to certain data structures of the kernel. Obviously they can be different in different kernel versions. The [BPF Type Format](https://www.kernel.org/doc/html/latest/bpf/btf.html) (BPT)  addresses this issue to a large extent and is available since Linux 5.4. Nevertheless, the best way is to use built-in Linux kernel eBPF functions to get the needed information from the data structures without the need to take into account different kernel versions. Note that usually recent kernel versions provide the most eBPF in-built kernel functions and that depending on the type of eBPF program you can only access a subset of those.

You do not have to program to start with eBPF. 

## Type of eBPF programs
Find here some type of eBPF programs:
* eXpress Data Path (XDP): allows filtering of network packet before they are processed by the kernel (before sk_buff is created). This is for high-performance package filtering. In the past, it used to be limited to ingress filtering. In recent kernel versions egress is supported (cf. [here](https://lwn.net/Articles/813406/)). The eBPF program can decide to allow 
* traffic control (TC): allows classification of network packet after they have been processed by the kernel (after sk_buff is created). This is less performant than XDP, but has all the information contained in sk_buff available.
* Socket: allows inspecting the content of a packet. This is less performant than TC. Note: eBPF programs are very small and have limited capabilities for analysis. You can though use this do transfer suspicious packets to a user space program that can do further analysis or classify it with artificial intelligence. While you can block the packet usually the analysis of a packet would take too long and would drop performance too much. You may though combine it with other types of eBPF programs to preselect more efficiently a relevant packet.
* PerfEvents: allow access to [Linux Perf events](https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html). This can be used to filter suspicious/anomalous activity or predict future poor system health.


There are more types and the possible types evolves in each Linux kernel version.

Events can be sent from eBPF programs to a user space application. Different eBPF programs or user space applications can exchange configuration via maps. 

Depending on your use case, you have to choose the right type of eBPF program and you may need to combine different type of eBPF programs.

Note on encrypted network connections: Obviously if the network connection is encrypted then you can only work with the metadata as you do not have access to the encrypted packet content. There are ways around it. For example, Wireshark requests to have the private key for decryption. This may be infeasible in some cases. Alternatively, you can intercept the call to the library that encrypts the content, e.g. to the OpenSSL or LibreSSL calls. 


# Concept
user space program
ebpf program

# Technology choices
=> rust, aya etc.


# Executing eBPF programs
You can decide to execute eBPF programs as root or provide to the binary the right [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) (e.g. via setcap). You should avoid executing them as root for security reasons and you should avoid to provide a lot of capabilities or very powerful capabilities (you must NOT use  CAP_SYS_ADMIN - this provides in the end unprivileged users root access!). Always work under the mantra of minimal permissions. We give in the different subfolders for each eBPF application that we developed an example of minimal capabilities.

# Alternatives to hook into the Linux Kernel for the use case

tbd, tc vs xdp, which event => performance
network issue: TLS encryption => we cannot hook into this, but most endpoints are not TLS encrypted (only local, the effort to encrypt vs the risks is low)
=> alternative more complex (https://blog.px.dev/ebpf-openssl-tracing/), some software may use a static library etc.
xdp only ingress historically, but now also egress (https://lwn.net/Articles/813406/, https://elixir.bootlin.com/linux/v5.19.1/source/include/uapi/linux/bpf.h#L5861) 
xpd => data: https://elixir.bootlin.com/linux/v5.0/source/include/uapi/linux/bpf.h#L2637
xdp ebpf functions => https://elixir.bootlin.com/linux/v5.19.1/source/net/core/filter.c#L7838
xdp => does not know which user id a package belongs to => we could not filter by uid
xdp => does not allow to get package content?
tc => data: skbuff
tc ebpf functions=> https://elixir.bootlin.com/linux/v5.19.1/source/net/core/filter.c#L7713
tc ingress+egress,  only uid BPF_FUNC_get_socket_uid, can get full socket: BPF_FUNC_sk_fullsock => we give user space program uid, pid (from full sock)

socks: https://www.kernel.org/doc/html/latest/networking/filter.html
socks functions: https://elixir.bootlin.com/linux/v5.19.1/source/net/core/filter.c#L7889
=> we can get package content (encrypted if tls is used) => we can attach a raw socket (requires to set capabilities: sudo setcap cap_net_admin,cap_net_raw=eip a.out) to a network interface and then monitor it

needs to be inspected by user space program, decision to drop package possible, can we find pid of socket? 
=> uprobe...
ktrace => we can only monitor syscall or interrupt and deny? sendmsg https://lwn.net/Articles/740146/
seccomp => we can interrupt syscall: https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt

additionally we can also hook into the localnet daemon => block connections from there (e.g. if they do not come from localhost)

=> how to find out which path they can 


# Observations
* We do by default for a given user a deny all packets with specific allow lists for trusted programs. The other approach (allowing all, deny specific packages) is more problematic as it is then easier for malicious programs to trick the filter by trying to obfuscate the inputs (fragmentation, adding spaces etc.) of a request
* One could also filter by answer done by the endpoint. For example, an authentication token in the answer might be dropped and not forwarded to the process
* HTTP3/Quic is UDP based and we do not look at this. One may need to do special considerations on filtering get requests and/or dealing with out of order packages
* HTTP2 is TCP based and works slightly different to HTTP 1.x, which may require additional considerations
* Unit testing is mostly possible for the userspace program. The eBPF program itself is more challenging to unit test
* Integration testing is really mandatory, because only when integrating all pieces one can truely assess the program as eBPF program and userspace program are tightly coupled.