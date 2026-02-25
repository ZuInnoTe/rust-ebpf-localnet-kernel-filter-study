# Introduction
**DISCLAIMER: THIS IS JUST FOR DEMONSTRATION PURPOSES AND NOT FOR PRODUCTION APPLICATIONS**

More background information are provided in the [README.md](../README.md) of the root of the project.

This application demonstrates how to use a extended Berkeley Packet Filter (ePBF) Traffic Classifier (tc) to allow egress for specific Linux users to specific IPs. It supports IPv4 and IPv6. It can be used, for example, to limit access on a compute instance to a local metadata service providing critical information, such as secrets to access other services. Examples for such services are [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) or [Azure Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service). If only a specific user can access it, then it increases the security as malware running potentially under a different user account cannot access it. In any case, you must always additionally limit the permissions assigned to your compute instance to minimal permissions.

Note: root users can easily remove the eBPF tc or kill the application, so they can circumwent blocking of their network traffic.

A potential extension could also include filtering by process name, because the eBPF tc has access to [sk_buff](https://docs.kernel.org/networking/kapi.html#c.sk_buff), which contains the process id of the process sending the package. Nevertheless, this is less practical for several reasons:
* The eBPF would have to send the process id to the user space program to determine the corresponding process name and get from the user space program the information if this should be allowed or not. This involves a huge performance penalty for the back and forth communication and may slow down network throughput. Nevertheless, one has to test this to determine how small/big this problem is.
* We would have to parse the skBuff, which may change in different kernel versions and thus we may run into problems. This is not a problem with respect to the user id, because to determine the user id we call a kernel-defined bpf function that is stable cross kernel versions. 
* If the process creates new processes of different programs then it becomes complex to check the full process hierarchy if this should be allowed or blocked.

## Further References
### Available kernel eBPF functions for TC
You can look up the available eBPF functions that you can use in a eBPF for TC in net/core/filter.c, e.g. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c?h=v6.0#n7869

Note: aya-rs may not have implemented all of them yet, but it is rather straight forward to link others. 

### TCContext
Find here the eBPF functions that are currently available in TCContext:
https://github.com/aya-rs/aya/blob/main/ebpf/aya-ebpf/src/programs/tc.rs#L46

There the program skbuff calls the ebPF: https://github.com/aya-rs/aya/blob/main/ebpf/aya-ebpf/src/programs/sk_buff.rs#L56

As you can see in the bindings, e.g. for x86_64, there are already a lot of other bpf functions so you can just easily add them yourself and possibly contribute this to the aya-rs project. Nevertheless, keep in mind that not all functions are allowed by the Linux kernel for a given eBPF program type, e.g. tc.

# Running
You can run the the app provided in net-tc-filter-app. During its compilation it includes the eBPF tc of net-tc-filter-ebpf. Thus during runtime it loads it into the kernel, configures the eBPF tc according to the configuration and the eBPF tc based on the allow-rules in the configuration drops traffic (TC_ACT_SHOT) or forwards it to other tcs (TC_ACT_PIPE). The decision the eBPF module makes is communicated to the net-tc-filter-app for logging purposes.

You need to provide the binary the right capabilities. Generally it is NOT recommended to run as root as this is less secure.

You can use setcap to provide it the right [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html):
```
sudo setcap cap_bpf,cap_perfmon,cap_net_admin=+ep net-tc-filter/net-tc-filter-app/target/release/net-tc-filter-app
```

Note: This types of capabilities require a recent kernel.

The following capabilities are needed:
* cap_bpf - to be able to load a eBPF program
* cap_perfmon - to be able to communicate back decisions by the eBPF tc to the user space app
* cap_net_admin - eBPF program can make decision on the network, ie shot or pipe a package

You can run it as follows
```
RUST_LOG=info net-tc-filter/net-tc-filter-app/target/release/net-tc-filter-app
```

You will see an output similar to the following:
```
8:48:09 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:106] [FEAT PROBE] BPF program name support: true
18:48:09 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:109] [FEAT PROBE] BTF support: true
18:48:09 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:113] [FEAT PROBE] BTF func support: true
18:48:09 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:116] [FEAT PROBE] BTF global func support: true
18:48:09 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:122] [FEAT PROBE] BTF var and datasec support: true
18:48:09 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:128] [FEAT PROBE] BTF float support: true
18:48:09 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:131] [FEAT PROBE] BTF decl_tag support: true
18:48:09 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:134] [FEAT PROBE] BTF type_tag support: true
18:48:09 [DEBUG] (1) aya::obj::relocation: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/obj/relocation.rs:270] relocating program tc_egress function tc_egress
18:48:09 [DEBUG] (1) aya::obj::relocation: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/obj/relocation.rs:363] finished relocating program tc_egress function tc_egress
18:48:09 [INFO] net-tc_filter: [src/main.rs:72] Configuring endpoint: imdsv2
18:48:09 [INFO] net-tc_filter: [src/main.rs:75] Attaching to interface eth0 ...
18:48:09 [INFO] net-tc_filter: [src/main.rs:98] Adding rules for user testuser with id 1000
18:48:09 [INFO] net-tc_filter: [src/main.rs:115] Adding prefix 169.254.169.254 range 32
18:48:09 [INFO] net-tc_filter: [src/main.rs:182] Waiting for Ctrl-C...
18:48:13 [INFO] net-tc_filter: [src/main.rs:168] LOG: SRC 93.184.216.34, ACTION 2, UID 1000
18:48:13 [INFO] net-tc_filter: [src/main.rs:168] LOG: SRC 2606:2800:220:1:248:1893:25c8:1946, ACTION 2, UID 1000
18:48:14 [INFO] net-tc_filter:

```

# Configuration

The application can be configured to allow access to specific users to specific IP address ranges (Cidr). An example configuration can be found in [../conf/net-tc-filter.yml](../conf/net-tc-filter.yml). Note: Once running the application blocks all traffic for all users on a specific network interface that is not explicitly allowed! Attention: If you forgot to configure an interface then traffic on this interface is not blocked!

Essentially one can configure a list of endpoints in which one describes on which interface for which range(s) one wants to allow traffic for which users. You can specify a list of ranges and a list of users.
In the following example we configure an endpoint with the name "imdsv2". All traffic on the interface "eth0" to the range "169.254.169.254/32" is allowed for the user "testuser".

```
endpoints:
    - imdsv2:
        iface: [eth0] 
        range: [169.254.169.254/32]
        allow:
          - testuser

```

You can specify also IPv6 ranges, e.g. "::1/128". 

One could also think about further restrictions, e.g. only allow calls at specific times

# Build

The application consists of the following components:
* net-tc-filter-app - the user space application that loads the eBPF module, configures it and receives network traffic decision made by the app. Note: The eBPF module is compiled into the application, ie we do not load it from the file system when executing the application. You can change this behaviour easily.
* net-tc-filter-common - common functionality for the eBPF module and the userspace application
* net-tc-filter-ebpf - the eBPF module that makes network traffic decisions as configured

You need to install rust nightly to compile "net-tc-filter-ebpf". You need to configure aya-rs as specified in [their instructions](https://aya-rs.dev/book/start/development/).

You can compile the net-tc-filter-ebpf by changing into its directory and executing:
```
cargo build --target bpfel-unknown-none -Z build-std=core --release
```

You can afterwards compile the net-tc-filter-app by changing into its directory and executing:
```
cargo build --release
```

See the above sections for running the compiled program.