#![no_std]

// how much data can be exchanged in a buffer between eBPF and user space application in one go
pub const DATA_BUF_CAPACITY: usize = 16384;
// note: per SSL_read/SSL_write call OpenSSL supports up to 16 KB (cf. https://docs.openssl.org/3.0/man3/SSL_read/), ie it does not make sense to configure here much more
// this is also according to the TLS specification: https://www.rfc-editor.org/rfc/rfc8446
