//! Windows data-only allocation. Do not use memmap2::map_anon here: its
//! Windows implementation creates an executable section before protecting it.
use std::{
    ffi::c_void,
    io,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READONLY,
    PAGE_READWRITE,
};

struct Allocation {
    pointer: NonNull<c_void>,
    length: usize,
}
impl Drop for Allocation {
    fn drop(&mut self) {
        // Every state, including failed protection/authentication, owns this
        // original reservation. MEM_RELEASE requires the original base and 0.
        unsafe { VirtualFree(self.pointer.as_ptr(), 0, MEM_RELEASE) };
    }
}

pub(super) struct WritableMapping(Allocation);
impl WritableMapping {
    pub(super) fn new(length: usize) -> io::Result<Self> {
        if length == 0 || length > isize::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid allocation size",
            ));
        }
        let pointer = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                length,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        let pointer = NonNull::new(pointer).ok_or_else(io::Error::last_os_error)?;
        Ok(Self(Allocation { pointer, length }))
    }

    pub(super) fn make_read_only(self) -> io::Result<ReadOnlyMapping> {
        self.protect_with(|pointer, length| {
            let mut old_protection = 0;
            if unsafe { VirtualProtect(pointer, length, PAGE_READONLY, &mut old_protection) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    }

    fn protect_with(
        self,
        protect: impl FnOnce(*mut c_void, usize) -> io::Result<()>,
    ) -> io::Result<ReadOnlyMapping> {
        // On refusal `self` drops and releases the reservation. Moving the
        // allocation on success consumes the sole mutable mapping.
        protect(self.0.pointer.as_ptr(), self.0.length)?;
        Ok(ReadOnlyMapping(self.0))
    }
}
impl Deref for WritableMapping {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.pointer.as_ptr().cast(), self.0.length) }
    }
}
impl DerefMut for WritableMapping {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.0.pointer.as_ptr().cast(), self.0.length) }
    }
}

pub(super) struct ReadOnlyMapping(Allocation);
impl Deref for ReadOnlyMapping {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.pointer.as_ptr().cast(), self.0.length) }
    }
}
// SAFETY: only a successful PAGE_READONLY transition constructs this type,
// consuming the sole writable owner. There is no mutable view/section alias;
// the uniquely owned reservation remains valid until this owner is dropped.
unsafe impl Send for ReadOnlyMapping {}
unsafe impl Sync for ReadOnlyMapping {}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::{
        VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_FREE, MEM_PRIVATE,
    };

    fn query(pointer: *const c_void) -> MEMORY_BASIC_INFORMATION {
        let mut information = std::mem::MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
        assert_eq!(
            unsafe {
                VirtualQuery(
                    pointer,
                    information.as_mut_ptr(),
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            },
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
        );
        unsafe { information.assume_init() }
    }

    #[test]
    #[serial_test::serial]
    fn staging_is_private_rw_and_final_mapping_is_ro_without_execute_permissions() {
        let mut staging = WritableMapping::new(4096).unwrap();
        let pointer = staging.as_ptr();
        let information = query(pointer.cast());
        assert_eq!(information.State, MEM_COMMIT);
        assert_eq!(information.Type, MEM_PRIVATE);
        assert_eq!(information.AllocationProtect, PAGE_READWRITE);
        assert_eq!(information.Protect, PAGE_READWRITE);
        staging[..8].copy_from_slice(b"verified");
        let immutable = staging.make_read_only().unwrap();
        assert_eq!(immutable.as_ptr(), pointer);
        assert_eq!(&immutable[..8], b"verified");
        let information = query(pointer.cast());
        assert_eq!(information.AllocationProtect, PAGE_READWRITE);
        assert_eq!(information.Protect, PAGE_READONLY);
        drop(immutable);
        assert_eq!(query(pointer.cast()).State, MEM_FREE);
    }

    #[test]
    #[serial_test::serial]
    fn protection_failure_releases_the_reservation_and_stays_retryable() {
        let staging = WritableMapping::new(4096).unwrap();
        let pointer = staging.as_ptr();
        let error = staging
            .protect_with(|_, _| Err(io::Error::from_raw_os_error(5)))
            .err()
            .unwrap();
        assert_eq!(query(pointer.cast()).State, MEM_FREE);
        assert!(crate::native_cache::is_resource_error(&error.into()));
    }
}
