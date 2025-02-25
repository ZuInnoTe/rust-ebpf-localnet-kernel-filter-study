//! Demonstration on how how to use a Linux eBPF module (uprobe/uretporbe) for fetching unecrypted data from OpenSSL library calls
//! This part is the main program that loads the configuration, the eBPF module
//! Adaption from: https://github.com/aya-rs/book/tree/main/examples/kprobetcp
//!
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::__u32,
    macros::map,
    macros::uprobe,
    macros::uretprobe,
    maps::{HashMap, PerCpuArray, PerfEventByteArray},
    programs::ProbeContext,
    programs::RetProbeContext,
};
use aya_ebpf_bindings::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user};
use aya_log_ebpf::warn;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[repr(C)]
pub struct DataBuf {
    pub buf: [u8; uprobe_libcall_filter_common::DATA_BUF_CAPACITY],
}

struct c_ptr(*const core::ffi::c_void);
unsafe impl Send for c_ptr {}
unsafe impl Sync for c_ptr {}


// Data structures for exchanging SSL_read data with user space
#[map]
static SSLREADDATABUF: PerCpuArray<DataBuf> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SSLREADDATA: PerfEventByteArray = PerfEventByteArray::new(0);

#[map] // contains the pointer to the read buffer containing the decrypted data provided by OpenSSL
       // key is the tgid_pid of the process
       // value is the pointer to the read buffer
static SSLREADARGSMAP: HashMap<u64, c_ptr> =
    HashMap::<u64, c_ptr>::with_max_entries(1024, 0);

// Data structures for exchanging SSL_write data with user space
#[map]
static SSLWRITEDATABUF: PerCpuArray<DataBuf> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SSLWRITEDATA: PerfEventByteArray = PerfEventByteArray::new(0);

#[map] // contains the pointer to the read buffer containing the decrypted data provided by OpenSSL
       // key is the tgid_pid of the process
       // value is the pointer to the read buffer
static SSLWRITEARGSMAP: HashMap<u64, c_ptr> =
    HashMap::<u64, c_ptr>::with_max_entries(1024, 0);

/// This uprobe is triggered when a process calls the SSL_read function.
/// It stores the address of the buffer containing the unencrypted data under the pid/tgid of the calling process
///
/// # Return
/// returns 0, but the return code is currently ignored in the kernel
#[uprobe]
pub fn osslreadprobe(ctx: ProbeContext) -> u32 {
    // get the current process id
    let current_pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // get the parameter containing the read buffer, cf. https://docs.openssl.org/3.0/man3/SSL_read/, Note: aya starts from 0 (ie Parameter 2 = arg(1))
    let buffer_ptr: c_ptr = match *&ctx.arg(1) {
        Some(ptr) =>  c_ptr(ptr),
        None => return 0,
    };
    unsafe {
        match SSLREADARGSMAP.insert(&current_pid_tgid, &buffer_ptr, 0) {
            _ => (),
        };
    }
    return 0;
}

/// This uretprobe is triggered the SSL_read function returns
/// It fetches the address of the buffer containing the unencrypted data that was previously stored by the uprobe.
/// It checks how much data was processed by SSL_read and then streams the unencrypted data to the user space application
///
/// # Return
/// returns 0, but the return code is currently ignored in the kernel
#[uretprobe]
pub fn osslreadretprobe(ctx: RetProbeContext) -> u32 {
    // get the current process id
    let current_pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // get return value (is the length of data read)
    // get return value (is the length of data read)
    let ret_value_len: i32 = match ctx.ret() {
        Some(ret) => ret,
        None => return 0,
    };
    if ret_value_len > 0 {
        // only if there was actually sth. to read.
        if ret_value_len as usize > uprobe_libcall_filter_common::DATA_BUF_CAPACITY {
            warn!(
                &ctx,
                "Read Buffer {} is larger than Buffer Capacity {} - data is not processed",
                ret_value_len,
                uprobe_libcall_filter_common::DATA_BUF_CAPACITY
            );
        } else {
            // get pointer stored when the read function was called
            unsafe {
                match SSLREADARGSMAP.get(&current_pid_tgid) {
                    Some(src_buffer_ptr) => {
                        if let Some(output_buf_ptr) = SSLREADDATABUF.get_ptr_mut(0) {
                            let output_buf = &mut *output_buf_ptr;
                            bpf_probe_read_user(
                                output_buf.buf.as_mut_ptr() as *mut core::ffi::c_void,
                                ret_value_len as u32
                                    & (uprobe_libcall_filter_common::DATA_BUF_CAPACITY - 1) as u32, // needed by eBPF verifier to be able to ensure that not more than necessary is read
                              src_buffer_ptr.0,
                            );

                            SSLREADDATA.output(&ctx, &output_buf.buf[..ret_value_len as usize], 0);
                        }
                    }
                    None => (),
                }
            }
        };
    }

    // clean up map
    unsafe {
        match SSLREADARGSMAP.remove(&current_pid_tgid) {
            _ => (),
        }
    }
    return 0;
}

/// This uprobe is triggered when a process calls the SSL_write function.
/// It stores the address of the buffer containing the unencrypted data under the pid/tgid of the calling process
///
/// # Return
/// returns 0, but the return code is currently ignored in the kernel
#[uprobe]
pub fn osslwriteprobe(ctx: ProbeContext) -> u32 {
    // get the current process id
    let current_pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // get the parameter containing the write buffer, cf. https://docs.openssl.org/3.0/man3/SSL_write/, Note: aya starts from 0 (ie Parameter 2 = arg(1))
    let buffer_ptr: c_ptr = match *&ctx.arg(1) {
        Some(ptr) => c_ptr(ptr),
        None => return 0,
    };
    unsafe {
        match SSLWRITEARGSMAP.insert(&current_pid_tgid, &buffer_ptr, 0) {
            _ => (),
        };
    }
    return 0;
}

/// This uretprobe is triggered the SSL_write function returns
/// It fetches the address of the buffer containing the unencrypted data that was previously stored by the uprobe.
/// It checks how much data was processed by SSL_write and then streams the unencrypted data to the user space application
///
/// # Return
/// returns 0, but the return code is currently ignored in the kernel
#[uretprobe]
pub fn osslwriteretprobe(ctx: RetProbeContext) -> u32 {
    // get the current process id
    let current_pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // get return value (is the length of data read)
    let ret_value_len: i32 = match ctx.ret() {
        Some(ret) => ret,
        None => return 0,
    };
    if ret_value_len > 0 {
        // only if there was actually sth. to read.

        if ret_value_len as usize > uprobe_libcall_filter_common::DATA_BUF_CAPACITY {
            warn!(
                &ctx,
                "Write Buffer is larger than Buffer Capacity - data is not processed"
            );
        } else {
            // get pointer stored when the read function was called

            unsafe {
                match SSLWRITEARGSMAP.get(&current_pid_tgid) {
                    Some(src_buffer_ptr) => {
                        if let Some(output_buf_ptr) = SSLWRITEDATABUF.get_ptr_mut(0) {
                            let output_buf = &mut *output_buf_ptr;
                            bpf_probe_read_user(
                                output_buf.buf.as_mut_ptr() as *mut core::ffi::c_void,
                                ret_value_len as u32
                                    & (uprobe_libcall_filter_common::DATA_BUF_CAPACITY - 1) as u32, // needed by eBPF verifier to be able to ensure that not more than necessary is read
                                src_buffer_ptr.0,
                            );

                            SSLWRITEDATA.output(&ctx, &output_buf.buf[..ret_value_len as usize], 0);
                        }
                    }
                    None => (),
                }
            }
        };
    }

    // clean up map
    unsafe {
        match SSLWRITEARGSMAP.remove(&current_pid_tgid) {
            _ => (),
        }
    }
    return 0;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
