# rust-ebpf-localnet-kernel-filter-study
A eBPF Linux kernel module to filter http requests to local network address e.g. cloud metadata services.

**IMPORTANT: THIS IS JUST A STUDY - DO NOT USE IN PRODUCTION**


# What we want to achieve

=> filter local cloud metadata services
=> probably the most benefit will be if we can filter by pid

# eBPF
tbd - ebpf, important hook points, further literature

combine different ebpf programs

# Concept
user space program
ebpf program

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

# Technology choices
=> rust, aya etc.

# Observations
* We do by default for a given user a deny all packages with specific allow lists for trusted programs. The other approach (allowing all, deny specific packages) is more problematic as it is then easier for malicious programs to trick the filter by trying to obfuscate the inputs (fragmentation, adding spaces etc.) of a request
* One could also filter by answer done by the endpoint. For example, an authentication token in the answer might be dropped and not forwarded to the process
* HTTP3/Quic is UDP based and we do not look at this. One may need to do special considerations on filtering get requests and/or dealing with out of order packages
* HTTP2 is TCP based and works slightly different to HTTP 1.x, which may require additional considerations
* Unit testing is mostly possible for the userspace program. The eBPF program itself is more challenging to unit test
* Integration testing is really mandatory, because only when integrating all pieces one can truely assess the program as eBPF program and userspace program are tightly coupled.