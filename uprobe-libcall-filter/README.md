 # Introduction
**DISCLAIMER: THIS IS JUST FOR DEMONSTRATION PURPOSES AND NOT FOR PRODUCTION APPLICATIONS**
 
More background information are provided in the [README.md](../README.md) of the root of the project.

This application demonstrates how to use a extended Berkeley Packet Filter (ePBF) uprobe to filter calls to the functions [SSL_read](https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html) and [SSL_write](https://www.openssl.org/docs/man1.1.1/man3/SSL_write.html) of the OpenSSL library. This can be used to get access to unencrypted data as this is, for instance, not possible using network eBPF programs as they see only encrypted data. Note: This uprobe assumes that OpenSSL is used for encryption of network traffic, but it can be adapted to any other encryption library. If [kernel TLS](https://www.kernel.org/doc/html/latest/networking/tls.html) is used then you can work with kprobes or possibly use the standard eBPF networking filter (to be checked).

This application has been inspired by [this](https://blog.px.dev/ebpf-openssl-tracing/) blog post, but has been written using Rust and aya-rs. Furthermore, we stream the data directly to the user space program and thus are not limited by the size of the data. The application can also be easily extended to filter calls by PID/TGID or provide the PID/TGID to the user space program (e.g. to combine data related to one process).

While metadata services related to a compute instance use usually unencrypted HTTP connection, this could change in the future. Examples for such services are [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) or [Azure Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service). 

It might also be used to debug encrypted connections made by software to troubleshoot problems and for performance assessments.

You can also override the return code of the function [bpf_override_return](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html), e.g. you can overwrite the data read/written to 0 to make the application believe nothing has happened - thus seeing no data.


In order to be able to fetch the unencrypted data we attach two u(ret)probes to SSL_read of the OpenSSL library two u(ret)probes to SSL_write of the OpenSSL library. The following table explains what they are doing:
|           | SSL_read (SSL *ssl, void *buf, int num)                                                                                                                                                                             | SSL_write (SSL *ssl, void *buf, int num)                                                                                                                                                                            |
|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| uprobe    | Record the address of unencrypted data (buf) under the pid/tgid of the calling process                                                                                                                              | Record the address of unencrypted data (buf) under the pid/tgid of the calling process                                                                                                                              |
| uretprobe | * Retrieved recorded address of unencrypted data of the pid/tgid of the calling process * Get the length of unencrypted data (return value of the function) * Stream the unencrypted data to user space application | * Retrieved recorded address of unencrypted data of the pid/tgid of the calling process * Get the length of unencrypted data (return value of the function) * Stream the unencrypted data to user space application |

Note: We need both, because the unecrypted data only exists when the OpenSSL functions return and only then we know how much data is actually available.
## Further References
### Probes and Return probes
Probes can be attached to a function when it is called. You have access to the parameters that were used to call the function.

Return probes are attached to a function when it returns. You have access to the return values.
### Static vs Dynamic Uprobes
We demonstrate here only dynamic uprobes for a dynamically loaded shared OpenSSL library. Similarly you can also attach it to other applications/libraries. See also the [Linux kernel documentation on uprobes](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html). 

You can also to define User Statically-Defined Tracing (USDT) probes, which you can explicitly put into your own application to make it debug-able, e.g. in production.
### Kprobes
[Kprobes](https://www.kernel.org/doc/html/latest/trace/kprobes.html) are similar to uprobes, but they can be attached to kernel functions.
### Available kernel eBPF functions for uprobes
You can look up the available eBPF functions that you can use in a eBPF for a probe here: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md

Note: aya-rs may not have implemented all of them yet, but it is rather straight forward to link others, e.g. we do it in the application for determining the tgid/pid of the process calling the library functions.

### Probe Context
Find here the eBPF functions that are currently available in ProbeContext:
https://github.com/aya-rs/aya/blob/main/bpf/aya-bpf/src/programs/probe.rs


As you can see in the bindings, e.g. for x86_64, there are already a lot of other bpf functions so you can just easily add them yourself and possibly contribute this to the aya-rs project. Nevertheless, keep in mind that not all functions are allowed by the Linux kernel for a given eBPF program type, e.g. tc.

# Running
You can run the the app provided in uprobe-libcall-filter. During its compilation it includes the eBPF tc ofuprobe-libcall-filter. Thus during runtime it loads it into the kernel and submits any unecrypted data before it is encrypted by OpenSSL to the user space applciations.

Note: See configuration in the next section - you need to specify the path to the OpenSSL library and you need to make sure that the application you want to fetch the unencrypted data from uses this library.

You need to provide the binary the right capabilities. Generally it is NOT recommended to run as root as this is less secure.

You can use setcap to provide it the right [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html):
```
sudo setcap cap_bpf,cap_perfmon=+ep uprobe-libcall-filter/uprobe-libcall-filter-app/target/release/uprobe-libcall-filter-app
```

Note: This types of capabilities require a recent kernel.

The following capabilities are needed:
* cap_bpf - to be able to load a eBPF program
* cap_perfmon - to be able to communicate back unecrypted data by the eBPF uprobes to the user space app

You can then start the application as follows:
```
RUST_LOG=info uprobe-libcall-filter/uprobe-libcall-filter-app/target/release/uprobe-libcall-filter-app
```


Note: Depending on your currently running applications you may see a lot of unencrypted data. You can though easily implement a filter to search only for a specific process id to reduce what is captured.


After you have started the application you can run a command that uses the OpenSSL library. We use here curl. See also below how to determine the shared library location. First we make sure that curl uses the version of OpenSSL that we configured (see next section) and then we run curl:
```
curl --version
curl 7.87.0 (x86_64-suse-linux-gnu) libcurl/7.87.0 OpenSSL/1.1.1s-fips zlib/1.2.13 brotli/1.0.9 zstd/1.5.2 libidn2/2.3.4 libpsl/0.21.2 (+libidn2/2.3.4) libssh/0.10.4/openssl/zlib nghttp2/1.51.0
Release-Date: 2022-12-21
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp
Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM NTLM_WB PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd

curl  --http1.1  https://example.org
```

You will see an output of our urprobes similar to the following:
```
[2023-01-29T18:43:24Z INFO  uprobe_libcall_filter_app] Configuring operation filter
[2023-01-29T18:43:24Z INFO  uprobe_libcall_filter_app] Configuring application: openssl1.1
[2023-01-29T18:43:24Z INFO  uprobe_libcall_filter_app] Configuring openssl_lib: /usr/lib64/libssl.so.1.1
[2023-01-29T18:43:24Z INFO  uprobe_libcall_filter_app] Waiting for Ctrl-C...
[2023-01-29T18:43:28Z INFO  uprobe_libcall_filter_app] Unencrypted SSL_write data: GET / HTTP/1.1
    Host: example.org
    User-Agent: curl/7.87.0
    Accept: */*
    
    
[2023-01-29T18:43:28Z INFO  uprobe_libcall_filter_app] Unencrypted SSL_read data: HTTP/1.1 200 OK
    Age: 522120
    Cache-Control: max-age=604800
    Content-Type: text/html; charset=UTF-8
    Date: Sun, 29 Jan 2023 18:43:28 GMT
    Etag: "3147526947+ident"
    Expires: Sun, 05 Feb 2023 18:43:28 GMT
    Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
    Server: ECS (dcb/7F83)
    Vary: Accept-Encoding
    X-Cache: HIT
    Content-Length: 1256
    
    
[2023-01-29T18:43:28Z INFO  uprobe_libcall_filter_app] Unencrypted SSL_read data: <!doctype html>
    <html>
    <head>
        <title>Example Domain</title>
    
        <meta charset="utf-8" />
        <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style type="text/css">
        body {
            background-color: #f0f0f2;
            margin: 0;
            padding: 0;
            font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
            
        }
        div {
            width: 600px;
            margin: 5em auto;
            padding: 2em;
            background-color: #fdfdff;
            border-radius: 0.5em;
            box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
        }
        a:link, a:visited {
            color: #38488f;
            text-decoration: none;
        }
        @media (max-width: 700px) {
            div {
                margin: 0 auto;
                width: auto;
            }
        }
        </style>    
    </head>
    
    <body>
    <div>
        <h1>Example Domain</h1>
        <p>This domain is for use in illustrative examples in documents. You may use this
        domain in literature without prior coordination or asking for permission.</p>
        <p><a href="https://www.iana.org/domains/example">More information...</a></p>
    </div>
    </body>
    </html>

```

# Configuration
You can configure all the OpenSSL libraries that exist in your system. If a configured SSL library does not exist in your system then you will receive an error message. Also often systems have many different OpenSSL libraries installed and if you do not configure all of them or miss the one used by the application you want to get unencrypted data from, you will not see an output. 
Additionally, if the application does not used a dynamically linked OpenSSL library, but a statically loaded library then you may need to configure the path of the application directly. 

In the following we configure one OpenSSL library located in '/usr/lib64/libssl.so.1.1'


```
applications: 
        filter:
             openssl1.1:
                openssl_lib: "/usr/lib64/libssl.so.1.1"
                 
```

# Build

The application consists of the following components:
* uprobe-libcall-filter-app - the user space application that loads the eBPF module and receives the unecrypted data from the uprobes Note: The eBPF module is compiled into the application, ie we do not load it from the file system when executing the application. You can change this behaviour easily.
* uprobe-libcall-filter-common - common functionality for the eBPF module and the userspace application
* uprobe-libcall-filter-ebpf - the eBPF module that intercepts the calls to the OpenSSL library and provides the unecrypted data tot he user space program

You need to install rust nightly to compile "uprobe-libcall-filter-ebpf". You need to configure aya-rs as specified in [their instructions](https://aya-rs.dev/book/start/development/).

You can compile the uprobe-libcall-filter-ebpf by changing into its directory and executing:
```
cargo  build --target bpfel-unknown-none -Z build-std=core --release
```

You can afterwards compile the uprobe-libcall-filter-app by changing into its directory and executing:
```
cargo build --release
```

See the above sections for running the compiled program.

# Determine shared library location
Sometimes it can be tricky to find out which shared library version is loaded from where. Modern Linux distributions often have the same library in different versions in different places for different applications. 

First, you can use [ldd](https://www.man7.org/linux/man-pages/man1/ldd.1.html) to look what shared libraries curl reference:
```
ldd /usr/bin/curl
```

We can see in the output also the used SSL library by curl
```
[..]
/lib64/glibc-hwcaps/x86-64-v3/libssl.so.3.1.2
[..]
```