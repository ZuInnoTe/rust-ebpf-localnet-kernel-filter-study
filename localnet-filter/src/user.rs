//! Module to get user information, such as user id (uid)
//! Supported Operating Systems: Linux

use std::ffi::{CStr, CString, OsStr, OsString};
use std::mem;
use std::ptr;

use libc::passwd;

#[derive(Debug, PartialEq)]
pub enum UserInformationError {
    InvalidUserName,
    BufferOverflow,
    NoUserInformationAvailable,
    InvalidUserInformation,
}

const MAX_USERNAME_LEN: usize = 100; // some safety feature to avoid overloading with a too long username
const MAX_GETPWNAM_RETURN_BUFFER_LEN: usize = 8192; // some safety featrue to avoid reading a too large buffer for reading user information

pub fn get_uid_by_name(username: &str) -> Result<u32, UserInformationError> {
    // convert username to a cstring to be able to use libc
    if username.len() > MAX_USERNAME_LEN {
        // do not accept too long usernames
        return Err(UserInformationError::InvalidUserName);
    }
    let c_username = match CString::new(username.as_bytes()) {
        Ok(u) => u,
        Err(_) => {
            // username contains null character
            return Err(UserInformationError::InvalidUserName);
        }
    };
    // prepare parameters and buffers for calling libc getpwnam_r

    let mut pwd = unsafe { mem::zeroed::<libc::passwd>() };
    let mut buf = vec![0; 1024]; // where we store the result
    let mut result = ptr::null_mut::<libc::passwd>();
    while buf.len() < MAX_GETPWNAM_RETURN_BUFFER_LEN {
        let r = unsafe {
            libc::getpwnam_r(
                c_username.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        // successfull call and everything could fit into the buffer
        if r != libc::ERANGE {
            break;
        }

        // increase result buffer by 4
        let increasedsize = match buf.len().checked_mul(4) {
            Some(newsize) => newsize,
            None => return Err(UserInformationError::BufferOverflow),
        };
        buf.resize(increasedsize, 0);
    }
    // check for errors

    if result.is_null() {
        return Err(UserInformationError::NoUserInformationAvailable);
    }

    if result != &mut pwd {
        return Err(UserInformationError::InvalidUserInformation);
    }
    Ok(pwd.pw_uid)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_get_uid_by_name_valid() {
        assert_eq!(0u32, super::get_uid_by_name("root").unwrap());
    }

    #[test]
    fn test_get_uid_by_name_invalid() {
        use rand::{Rng, SeedableRng};
        let random_username_too_long_vec: Vec<u8> = rand::rngs::SmallRng::from_entropy()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(super::MAX_USERNAME_LEN + 1)
            .collect();
        let random_username_too_long_str = String::from_utf8(random_username_too_long_vec).unwrap();
        assert_eq!(
            super::UserInformationError::InvalidUserName,
            super::get_uid_by_name(&random_username_too_long_str).unwrap_err()
        );
    }

    #[test]
    fn test_get_uid_by_name_notfound() {
        use rand::{Rng, SeedableRng};
        let random_username_vec: Vec<u8> = rand::rngs::SmallRng::from_entropy()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(super::MAX_USERNAME_LEN - 1)
            .collect();
        let random_username_str = String::from_utf8(random_username_vec).unwrap();
        assert_eq!(
            super::UserInformationError::NoUserInformationAvailable,
            super::get_uid_by_name(&random_username_str).unwrap_err()
        );
    }
}
