//! Demonstration on how how to use a Linux eBPF module (uprobe/uretporbe) for fetching unecrypted data from OpenSSL library calls
//! This part is the main program that loads the configuration, the eBPF module 
//! Adaption from: https://github.com/aya-rs/book/tree/main/examples/kprobetcp
//! 
#![no_std]
#![no_main]

use aya_bpf::{
    macros::map,
    macros::uprobe,
    macros::uretprobe,
    maps::{HashMap, PerCpuArray, PerfEventByteArray},
    programs::ProbeContext,
};
use aya_bpf_bindings::helpers::{bpf_get_current_pid_tgid, bpf_probe_read};
use aya_log_ebpf::{ warn};
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

#[repr(C)]
pub struct DataBuf {
    pub buf: [u8; uprobe_libcall_filter_common::DATA_BUF_CAPACITY],
}

// Data structures for exchanging SSL_read data with user space
#[map]
pub static mut SSL_READ_DATA_BUF: PerCpuArray<DataBuf> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "SSLREADDATA")]
pub static mut SSLREADDATA: PerfEventByteArray = PerfEventByteArray::new(0);

#[map(name = "SSLREADARGSMAP")] // contains the pointer to the read buffer containing the decrypted data provided by OpenSSL
                                // key is the tgid_pid of the process
                                // value is the pointer to the read buffer
static mut SSLREADARGSMAP: HashMap<u64, *const core::ffi::c_void> =
    HashMap::<u64, *const core::ffi::c_void>::with_max_entries(1024, 0);

// Data structures for exchanging SSL_write data with user space
#[map]
pub static mut SSL_WRITE_DATA_BUF: PerCpuArray<DataBuf> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "SSLWRITEDATA")]
pub static mut SSLWRITEDATA: PerfEventByteArray = PerfEventByteArray::new(0);

#[map(name = "SSLWRITEARGSMAP")] // contains the pointer to the read buffer containing the decrypted data provided by OpenSSL
                                 // key is the tgid_pid of the process
                                 // value is the pointer to the read buffer
static mut SSLWRITEARGSMAP: HashMap<u64, *const core::ffi::c_void> =
    HashMap::<u64, *const core::ffi::c_void>::with_max_entries(1024, 0);

/// This uprobe is triggered when a process calls the SSL_read function.
/// It stores the address of the buffer containing the unencrypted data under the pid/tgid of the calling process
/// 
/// # Return
/// returns 0, but the return code is currently ignored in the kernel
#[uprobe(name = "osslreadprobe")]
pub fn openssl_read_probe(ctx: ProbeContext) -> u32 {
    // get the current process id
    let current_pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // get the parameter containing the read buffer, cf. https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html, Note: aya starts from 0 (ie Parameter 2 = arg(1))
    let buffer_ptr: *const core::ffi::c_void = *&ctx.arg(1).unwrap();

    unsafe {
        SSLREADARGSMAP.insert(&current_pid_tgid, &buffer_ptr, 0).unwrap();
    }
    return 0;
}

/// This uretprobe is triggered the SSL_read function returns
/// It fetches the address of the buffer containing the unencrypted data that was previously stored by the uprobe. 
/// It checks how much data was processed by SSL_read and then streams the unencrypted data to the user space application
/// 
/// # Return
/// returns 0, but the return code is currently ignored in the kernel
#[uretprobe(name = "osslreadretprobe")]
pub fn openssl_read_ret_probe(ctx: ProbeContext) -> u32 {
    // get the current process id
    let current_pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // get return value (is the length of data read)
    let ret_value_len: i32 = ctx.ret().unwrap();
    if ret_value_len > 0 {
        // only if there was actually sth. to read.

        if ret_value_len
            > uprobe_libcall_filter_common::DATA_BUF_CAPACITY
                .try_into()
                .unwrap()
        {
            warn!(
                &ctx,
                "Read Buffer is larger than Buffer Capacity - data is not processed"
            );
        } else {
            // get pointer stored when the read function was called

            unsafe {
                match SSLREADARGSMAP.get(&current_pid_tgid) {
                    Some(src_buffer_ptr) => {
                        if let Some(output_buf_ptr) = SSL_READ_DATA_BUF.get_ptr_mut(0) {
                            let output_buf =  &mut *output_buf_ptr ;

                            bpf_probe_read(
                                output_buf.buf.as_mut_ptr() as *mut core::ffi::c_void,
                                (&ret_value_len).clone().try_into().unwrap(),
                                *src_buffer_ptr,
                            );

                                SSLREADDATA.output(
                                    &ctx,
                                    &output_buf.buf[..ret_value_len as usize],
                                    0,
                                );
                        }
                    }
                    None => (),
                }
            }
        };
    }

    // clean up map
    unsafe {
        SSLREADARGSMAP.remove(&current_pid_tgid).unwrap();
    }
    return 0;
}

/// This uprobe is triggered when a process calls the SSL_write function.
/// It stores the address of the buffer containing the unencrypted data under the pid/tgid of the calling process
/// 
/// # Return
/// returns 0, but the return code is currently ignored in the kernel
#[uprobe(name = "osslwriteprobe")]
pub fn openssl_wrke_probe(ctx: ProbeContext) -> u32 {
    // get the current process id
    let current_pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // get the parameter containing the write buffer, cf. https://www.openssl.org/docs/man1.1.1/man3/SSL_write.html, Note: aya starts from 0 (ie Parameter 2 = arg(1))
    let buffer_ptr: *const core::ffi::c_void = *&ctx.arg(1).unwrap();

    unsafe {
        SSLWRITEARGSMAP.insert(&current_pid_tgid, &buffer_ptr, 0).unwrap();
    }

    return 0;
}

/// This uretprobe is triggered the SSL_write function returns
/// It fetches the address of the buffer containing the unencrypted data that was previously stored by the uprobe. 
/// It checks how much data was processed by SSL_write and then streams the unencrypted data to the user space application
/// 
/// # Return
/// returns 0, but the return code is currently ignored in the kernel
#[uretprobe(name = "osslwriteretprobe")]
pub fn openssl_write_ret_probe(ctx: ProbeContext) -> u32 {
    // get the current process id
    let current_pid_tgid = unsafe { bpf_get_current_pid_tgid() };

    // get return value (is the length of data read)
    let ret_value_len: i32 = ctx.ret().unwrap();
    if ret_value_len > 0 {
        // only if there was actually sth. to read.

        if ret_value_len
            > uprobe_libcall_filter_common::DATA_BUF_CAPACITY
                .try_into()
                .unwrap()
        {
            warn!(
                &ctx,
                "Write Buffer is larger than Buffer Capacity - data is not processed"
            );
        } else {
            // get pointer stored when the read function was called

            unsafe {
                match SSLWRITEARGSMAP.get(&current_pid_tgid) {
                    Some(src_buffer_ptr) => {
                        if let Some(output_buf_ptr) = SSL_WRITE_DATA_BUF.get_ptr_mut(0)  {
                            let output_buf =&mut *output_buf_ptr ;

                            bpf_probe_read(
                                output_buf.buf.as_mut_ptr() as *mut core::ffi::c_void,
                                (&ret_value_len).clone().try_into().unwrap(),
                                *src_buffer_ptr,
                            );

                                SSLWRITEDATA.output(
                                    &ctx,
                                    &output_buf.buf[..ret_value_len as usize],
                                    0,
                                );
                            }
                        
                    }
                    None => (),
                }
            }
        };
    }

    // clean up map
    unsafe {
        SSLWRITEARGSMAP.remove(&current_pid_tgid).unwrap();
    }
    return 0;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
