//! Complete, bounded IPv4 owner-table reads shared by routing and boot-disk protection.

// These IPv4 owner rows contain only DWORDs, so every bit pattern is valid.
// Seal the supported types: Copy alone would also admit bool/references, which
// must never be constructed from native response bytes.
mod row_types {
    pub trait Sealed {}
    impl Sealed for u32 {}
    impl Sealed for windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID {}
    impl Sealed for windows::Win32::NetworkManagement::IpHelper::MIB_UDPROW_OWNER_PID {}
}
pub(super) trait OwnerRow: Copy + row_types::Sealed {}
impl<T: Copy + row_types::Sealed> OwnerRow for T {}

pub(super) fn bounded_ip_helper_entries(
    buffer_len: usize,
    advertised_entries: u32,
    entry_size: usize,
) -> usize {
    const TABLE_ENTRY_OFFSET: usize = std::mem::size_of::<u32>();
    if buffer_len < TABLE_ENTRY_OFFSET || entry_size == 0 {
        return 0;
    }
    let max_entries = buffer_len.saturating_sub(TABLE_ENTRY_OFFSET) / entry_size;
    (advertised_entries as usize).min(max_entries)
}

/// Read a complete native owner table. A socket can appear between the size
/// probe and the read, so retry resize responses instead of publishing an empty
/// protocol table. Callers keep the previous snapshot on any unresolved error.
pub(super) fn read_owner_rows<T: OwnerRow>(
    mut query: impl FnMut(Option<*mut std::ffi::c_void>, &mut u32) -> u32,
    mut row: impl FnMut(T),
) -> Result<(), u32> {
    use windows::Win32::Foundation::{
        ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_NOT_ENOUGH_MEMORY,
    };
    const MAX_OWNER_TABLE_BYTES: usize = 64 * 1024 * 1024;
    let mut size = 0;
    let status = query(None, &mut size);
    if status != 0 && status != ERROR_INSUFFICIENT_BUFFER.0 {
        return Err(status);
    }
    for _ in 0..3 {
        let capacity = size as usize;
        if capacity < 4 || std::mem::size_of::<T>() == 0 {
            return Err(ERROR_INVALID_DATA.0);
        }
        if capacity > MAX_OWNER_TABLE_BYTES {
            return Err(ERROR_NOT_ENOUGH_MEMORY.0);
        }
        // IP Helper tables have a DWORD count followed by DWORD-aligned rows.
        let mut buffer = Vec::<u32>::new();
        let words = capacity.div_ceil(4);
        buffer
            .try_reserve_exact(words)
            .map_err(|_| ERROR_NOT_ENOUGH_MEMORY.0)?;
        buffer.resize(words, 0);
        let status = query(Some(buffer.as_mut_ptr().cast()), &mut size);
        if status == ERROR_INSUFFICIENT_BUFFER.0 {
            continue;
        }
        if status != 0 {
            return Err(status);
        }
        if size < 4 || size as usize > capacity {
            return Err(ERROR_INVALID_DATA.0);
        }
        let count = buffer[0] as usize;
        if count != bounded_ip_helper_entries(size as usize, buffer[0], std::mem::size_of::<T>()) {
            return Err(ERROR_INVALID_DATA.0);
        }
        let entries = unsafe { buffer.as_ptr().cast::<u8>().add(4) };
        for index in 0..count {
            row(unsafe {
                entries
                    .add(index * std::mem::size_of::<T>())
                    .cast::<T>()
                    .read_unaligned()
            });
        }
        return Ok(());
    }
    Err(ERROR_INSUFFICIENT_BUFFER.0)
}
