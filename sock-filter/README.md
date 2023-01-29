# Introduction
**DISCLAIMER: THIS IS JUST FOR DEMONSTRATION PURPOSES AND NOT FOR PRODUCTION APPLICATIONS**

More background information are provided in the [README.md](../README.md) of the root of the project.

This application demonstrates how to use a extended Berkeley Packet Filter (ePBF) socket filter to filter certain traffic on a specific socket (in our example case a raw socket that receives all packets send/received through a specific network interface). It supports IPv4 and IPv6. It can be used, for example, to filter traffic to a local metadata service providing critical information, such as secrets to access other services - to find out unusual/suspicious patterns. Examples for such services are [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) or [Azure Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service). vNote: Contrary to the other example, it does not drop packets from the network - it just allows for a socket that is created by the user space application that loads the eBPF program to decide which packets should allowed to be provided to the socket and thus the user space program. 

In any case, you must always additionally limit the permissions assigned to your compute instance in the cloud to minimal permissions.

A socket filter is attached to a socket and you can make at kernel level decisions if a packet should be made available to the socket it attaches to or not. You cannot use it to manipulate packets or to make decisions if the packet should be dropped in general for all applications at the network level. The main purpose is analytics, e.g. similar to what [tcpdump](https://www.tcpdump.org/) does (it uses socket filters in the background). Nevertheless, you can combine your application with multiple other eBPF programs to also make decisions on the network traffic, e.g. dropping a packet. For instance, you can have a deep packet analysis using a sock filter with a machine learning program. If this machine learning program determines that packets to/from a certain address are suspicious it could inform a eBPF XDP or TC program to block this traffic or reroute it to an appliance for further more in-depth analysis.

***Important***: A socket filter does NOT drop the packet at the network level. It is simply made available or not to the socket. Another limitation is that you cannot attach it to sockets of other processes (except voluntary through a [unix domain socket](https://en.wikipedia.org/wiki/Unix_domain_socket)), so you cannot define that a packet should not be available to a socket of another process - except if is is a child process of the process that originally created the socket. This makes it less useful for a EBPF Sock Filter to make decisions if a socket should read/send a given packet (use eBPF TC or eBPF XDP for this).

Most of the time sockets are used to create clients connecting to a specific address on a specific - say a web service - or they are used to create a server that listens to incoming connections and messages on a a specific port. There are though also special sockets: raw sockets. They work at a lower level and can receive/send on any port. They can be also attached to network interfaces to process any packet received through this network interface and send any packet through this interface.

Given the use case mentioned above we develop in this application a socket filter that analyses requests made to a cloud instance metadata service. For this the user space application creates two raw sockets - one for IPv4 and one for IPv6 - binds them to a specific interface. Instead of analysing all possible packets on that interface, we use a eBPF socket filter to only provide to our raw sockets the packets reaching the cloud instance metadata service.


***IMPORTANT: IF YOU USE RAW SOCKETS THEN YOU CANNOT FILTER BY USER ID - IT IS ALWAYS 65534 (USER: NOBODY). THE RAW SOCKET DOES NOT KNOW TO WHICH USER A PACKET BELONGS. YOU EITHER HAVE TO CREATE A SPECIFIC SOCKET OR USE A EBPF TC PROGRAM***



If you do NOT use sockets of AF_PACKET type, but IP (e.g. AF_INET, AF_INET6) then there is one challenge for the user program that the API for raw sockets is different for IPv4 and IPv6 (see e.g. [here](https://schoenitzer.de/blog/2018/Linux%20Raw%20Sockets.html)): The IPv4 raw socket API provides essentially the full IP packet on the socket and the IPv6 raw socket API provides only the TCP or UDP packet. In the latter case you would not know, for example, to which IP address or from which IP address the packet is coming from. The APIv6 raw socket API though allows to fetch further information, such as the IP address, about the IP packet through the [ancilliary data](https://datatracker.ietf.org/doc/rfc2292/) API. Although for our use case this does not matter as we anyway filter the packet in the eBPF socket filter, we still include in our user space program how you can use both APIs, so the application can easily be used and extended towards more complex use cases.


## Further References
### Available kernel eBPF functions for socket filter filter
You can look up the available eBPF functions that you can use in a eBPF for socket filter in net/core/filter.c, e.g. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/core/filter.c?h=v6.0#n7802

Note: aya-rs may not have implemented all of them yet in the context, but they are all included in aya, so you can call them yourself directly. 

### SkBuffContext
Find here the eBPF functions that are currently available in SkBuffContext:
https://github.com/aya-rs/aya/blob/main/bpf/aya-bpf/src/programs/sk_buff.rs#L222

There the program skbuff calls the ebPF: https://github.com/aya-rs/aya/blob/main/bpf/aya-bpf/src/programs/sk_buff.rs#L56

As you can see in the bindings, e.g. for x86_64, there are already a lot of other bpf functions so you can just easily add them yourself and possibly contribute this to the aya-rs project. Nevertheless, keep in mind that not all functions are allowed by the Linux kernel for a given eBPF program type, e.g. sock filter.

# Running
You can run the the app provided sock-filter-app. During its compilation it includes the eBPF tc of sock-filter-ebpf. Thus during runtime it loads it into the kernel, configures the eBPF tc according to the configuration and the eBPF sock filter based on the allow-rules in the configuration provides the packet to the attached socket (-1) or not (0). The decision the eBPF module makes is communicated to the sock-filter-app for logging purposes.

You need to provide the binary the right capabilities. Generally it is NOT recommended to run as root as this is less secure.

You can use setcap to provide it the right [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html):
```
sudo setcap cap_bpf,cap_perfmon,cap_net_raw,cap_net_admin=+ep sock-filter/sock-filter-app/target/release/sock-filter-app
```

Note: This types of capabilities require a recent kernel.

The following capabilities are needed:
* cap_bpf - to be able to load a eBPF program
* cap_perfmon - to be able to communicate back decisions by the eBPF socket filter to the user space app
* cap_net_admin - eBPF program can make decision on the network, ie to filter a certain packet for a socket
* cap_net_raw - user space application can create raw sockets

You will see an output similar to the following:
```
18:02:47 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:106] [FEAT PROBE] BPF program name support: true
18:02:47 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:109] [FEAT PROBE] BTF support: true
18:02:47 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:113] [FEAT PROBE] BTF func support: true
18:02:47 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:116] [FEAT PROBE] BTF global func support: true
18:02:47 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:122] [FEAT PROBE] BTF var and datasec support: true
18:02:47 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:128] [FEAT PROBE] BTF float support: true
18:02:47 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:131] [FEAT PROBE] BTF decl_tag support: true
18:02:47 [DEBUG] (1) aya::bpf: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/bpf.rs:134] [FEAT PROBE] BTF type_tag support: true
18:02:47 [DEBUG] (1) aya::obj::relocation: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/obj/relocation.rs:270] relocating program sock_egress function sock_egress
18:02:47 [DEBUG] (1) aya::obj::relocation: [/home/testuser/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.11.0/src/obj/relocation.rs:363] finished relocating program sock_egress function sock_egress
18:02:47 [INFO] sock_filter_app: [src/main.rs:84] Allowing filtering of socket traffic of all users
18:02:47 [INFO] sock_filter_app: [src/main.rs:125] Adding prefix 93.184.216.34 range 32
18:02:47 [INFO] sock_filter_app: [src/main.rs:142] Configuring endpoint: imdsv2
18:02:47 [INFO] sock_filter_app: [src/main.rs:145] Attaching to interface wlp4s0 ...
18:02:47 [INFO] sock_filter_app: [src/main.rs:156] Attaching complete ...
18:02:47 [INFO] sock_filter_app: [src/main.rs:157] Socket  reading process start.
18:02:47 [INFO] sock_filter_app: [src/main.rs:216] Waiting for Ctrl-C...
18:02:53 [INFO] sock_filter_app: [src/main.rs:201] EBPF EVENT: LOG: DST 2606:2800:220:1:248:1893:25c8:1946, IP Version 6, SUID 0, DECISION 0
18:02:55 [INFO] sock_filter_app: [src/main.rs:265] User space: raw socket received packet 
IP Version:  IP_V4
Transport:  TCP
Source IP:  192.168.178.1
Destination IP:  93.184.216.34
18:02:55 [INFO] sock_filter_app: [src/main.rs:201] EBPF EVENT: LOG: DST 93.184.216.34, IP Version 4, SUID 0, DECISION -1
18:02:55 [INFO] sock_filter_app: [src/main.rs:201] EBPF EVENT: LOG: DST 93.184.216.34, IP Version 4, SUID 0, DECISION -1
18:02:55 [INFO] sock_filter_app: [src/main.rs:265] User space: raw socket received packet 
IP Version:  IP_V4
Transport:  TCP
Source IP:  192.168.178.1
Destination IP:  93.184.216.34
18:02:55 [INFO] sock_filter_app: [src/main.rs:201] EBPF EVENT: LOG: DST 93.184.216.34, IP Version 4, SUID 0, DECISION -1
18:02:55 [INFO] sock_filter_app: [src/main.rs:265] User space: raw socket received packet 
IP Version:  IP_V4
Transport:  TCP
Source IP:  192.168.178.1
Destination IP:  93.184.216.34
```

Essentially you see two types of events:
* eBPF EVENT: this is an event from the eBPF program and essentially describes the destination address for a packet, the IP Version, the SUID and the decision made (-1 pass to user space application), 0 do not pass to user space application)
* User space: this event is created when a message is read from the raw socket and it describes some information it parses out of the packet, such as IP Version, Transport protocol, source IP, destination, IP etc.

We parse only some basic packet data, but the code is rather easy to enhance to filter also at higher protocol levels, e.g. HTTP requests. This is possible either in the eBPF program or in the user space program. Be aware that the possibilities in a eBPF program are rather limited and also string parsing there is more cumbersome. For performance reasons you need to decide where to parse what. If you parse everything in the eBPF program then network performance may suffer from a complex logic there. This you can only assess by doing real performance tests.

Important:
* The events are coming from different threads, ie you may not see immediately after an eBPF event the corresponding user space event. In fact, they can come in any order and there can be also events in-between
* You see in the example SUID 0. This is shown when the packet is for root OR if you configure to allow packets of all users to a specific IP
* Normally raw sockets have always the user id of nobody (often: 65534). You cannot determine for raw sockets from which user they came from. This is only possible for normal sockets. You can use a combination of a eBPF traffic classifier and a eBPF socket filter to deal with this

# Configuration

The application can be configured to allow filtering of specific IP address ranges (Cidr) of specific. An example configuration can be found in [../conf/sock-filter.yml](../conf/sock-filter.yml). 

Essentially one can configure a list of endpoints in which one describes on which interface for which range(s) one wants to filter traffic for which users. You can specify a list of ranges and a list of users.
In the following example we configure an endpoint with the name "imdsv2". All traffic on the interface "eth0" to the range "169.254.169.254/32" is filtered of the user "*" (ie all users), you can also specify a username, e.g. testuser.

```
endpoints:
    - imdsv2: 
        range: [169.254.169.254/32]
        iface: [eth0]
        filter:
          - "*"

```

You can specify also IPv6 ranges, e.g. "::1/128". 

One could also think about further restrictions, e.g. filtering only calls at specific times

# Build

The application consists of the following components:
* sock-filter-app - the user space application that loads the eBPF module, configures it and inspect the packets that are provided by the eBPF sock filter. Note: The eBPF module is compiled into the application, ie we do not load it from the file system when executing the application. You can change this behaviour easily.
* sock-filter-common - common functionality for the eBPF module and the userspace application
* sock-filter-ebpf - the eBPF module that decides what should be filtered and what not

You need to install rust nightly to compile sock-filter-ebpf". You need to configure aya-rs as specified in [their instructions](https://aya-rs.dev/book/start/development/).

You can compile the sock-filter-ebpf by changing into its directory and executing:
```
cargo build --target bpfel-unknown-none -Z build-std=core --release
```

You can afterwards compile the sock-filter-app by changing into its directory and executing:
```
cargo build --release
```

See the above sections for running the compiled program.