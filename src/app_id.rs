//! Conversion between file paths and WFP application IDs (`FWP_BYTE_BLOB`)

use crate::errors::{WfpError, WfpResult};
use std::ffi::{c_void, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FWP_BYTE_BLOB,
};

/// Owned blob returned by `FwpmGetAppIdFromFileName0`, freed on drop
pub(crate) struct AppId(pub(crate) *mut FWP_BYTE_BLOB);

impl AppId {
    /// Resolve a DOS path to the NT kernel path WFP matches against
    pub(crate) fn from_path(path: &Path) -> WfpResult<Self> {
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
        let result = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path_wide.as_ptr()), &mut blob) };

        if result != ERROR_SUCCESS.0 || blob.is_null() {
            return Err(WfpError::AppPathNotFound(path.display().to_string()));
        }
        Ok(Self(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        unsafe { FwpmFreeMemory0(&mut self.0 as *mut *mut FWP_BYTE_BLOB as *mut *mut c_void) };
    }
}

/// Decode an application ID blob (UTF-16 NT path) without reading past `blob.size`
///
/// # Safety
///
/// `blob.data` must be null or point to at least `blob.size` readable bytes.
pub(crate) unsafe fn app_id_to_path(blob: &FWP_BYTE_BLOB) -> Option<PathBuf> {
    if blob.data.is_null() || blob.size < 2 {
        return None;
    }

    let len = blob.size as usize / 2;
    let mut wide = vec![0u16; len];
    // Byte copy: the blob data has no alignment guarantee for u16
    ptr::copy_nonoverlapping(blob.data, wide.as_mut_ptr() as *mut u8, len * 2);

    let end = wide.iter().position(|&c| c == 0).unwrap_or(len);
    if end == 0 {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(&wide[..end])))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob_of(bytes: &mut [u8]) -> FWP_BYTE_BLOB {
        FWP_BYTE_BLOB {
            size: bytes.len() as u32,
            data: bytes.as_mut_ptr(),
        }
    }

    fn utf16_bytes(s: &str, terminate: bool) -> Vec<u8> {
        let mut units: Vec<u16> = s.encode_utf16().collect();
        if terminate {
            units.push(0);
        }
        units.iter().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn test_null_terminated_path() {
        let mut bytes = utf16_bytes(r"\device\harddiskvolume1\app.exe", true);
        let path = unsafe { app_id_to_path(&blob_of(&mut bytes)) };
        assert_eq!(
            path,
            Some(PathBuf::from(r"\device\harddiskvolume1\app.exe"))
        );
    }

    #[test]
    fn test_unterminated_path_is_bounded_by_size() {
        let mut bytes = utf16_bytes(r"\device\x.exe", false);
        let path = unsafe { app_id_to_path(&blob_of(&mut bytes)) };
        assert_eq!(path, Some(PathBuf::from(r"\device\x.exe")));
    }

    #[test]
    fn test_unaligned_data() {
        let mut bytes = vec![0u8];
        bytes.extend(utf16_bytes("abc", true));
        let blob = FWP_BYTE_BLOB {
            size: (bytes.len() - 1) as u32,
            data: unsafe { bytes.as_mut_ptr().add(1) },
        };
        assert_eq!(unsafe { app_id_to_path(&blob) }, Some(PathBuf::from("abc")));
    }

    #[test]
    fn test_empty_or_null_blob() {
        let null = FWP_BYTE_BLOB {
            size: 10,
            data: ptr::null_mut(),
        };
        assert_eq!(unsafe { app_id_to_path(&null) }, None);

        let mut only_nul = vec![0u8, 0u8];
        assert_eq!(unsafe { app_id_to_path(&blob_of(&mut only_nul)) }, None);

        let mut odd = vec![b'a'];
        assert_eq!(unsafe { app_id_to_path(&blob_of(&mut odd)) }, None);
    }
}
