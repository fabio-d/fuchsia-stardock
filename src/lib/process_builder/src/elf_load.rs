// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Utilities for loading ELF files into an existing address space.

use {
    crate::elf_parse as elf,
    crate::util,
    fuchsia_zircon::{self as zx, AsHandleRef},
    std::ffi::{CStr, CString},
    thiserror::Error,
};

/// Possible errors that can occur during ELF loading.
#[allow(missing_docs)] // No docs on individual error variants.
#[derive(Error, Debug)]
pub enum ElfLoadError {
    #[error("ELF load segments were empty")]
    NothingToLoad,
    #[error("Failed to allocate VMAR for ELF: {}", _0)]
    VmarAllocate(zx::Status),
    #[error("Failed to map VMAR: {}", _0)]
    VmarMap(zx::Status),
    #[error("Failed to create CoW VMO clone: {}", _0)]
    VmoCowClone(zx::Status),
    #[error("Failed to create VMO: {}", _0)]
    VmoCreate(zx::Status),
    #[error("Failed to read from VMO: {}", _0)]
    VmoRead(zx::Status),
    #[error("Failed to write to VMO: {}", _0)]
    VmoWrite(zx::Status),
    #[error("Failed to get VMO name: {}", _0)]
    GetVmoName(zx::Status),
    #[error("Failed to set VMO name: {}", _0)]
    SetVmoName(zx::Status),
}

impl ElfLoadError {
    /// Returns an appropriate zx::Status code for the given error.
    pub fn as_zx_status(&self) -> zx::Status {
        match self {
            ElfLoadError::NothingToLoad => zx::Status::NOT_FOUND,
            ElfLoadError::VmarAllocate(s)
            | ElfLoadError::VmarMap(s)
            | ElfLoadError::VmoCowClone(s)
            | ElfLoadError::VmoCreate(s)
            | ElfLoadError::VmoRead(s)
            | ElfLoadError::VmoWrite(s)
            | ElfLoadError::GetVmoName(s)
            | ElfLoadError::SetVmoName(s) => *s,
        }
    }
}

/// Information on what an ELF requires of its address space.
#[derive(Debug)]
pub struct LoadedElfInfo {
    /// The lowest address of the loaded ELF.
    pub low: usize,

    /// The highest address of the loaded ELF.
    pub high: usize,

    /// Union of all address space permissions required to load the ELF.
    pub max_perm: elf::SegmentFlags,
}

/// Returns the address space requirements to load this ELF. Attempting to load it into a VMAR with
/// permissions less than max_perm, or at a base such that the range [base+low, base+high] is not
/// entirely valid, will fail.
pub fn loaded_elf_info(headers: &elf::Elf64Headers) -> LoadedElfInfo {
    let (mut first, mut low, mut high) = (true, 0, 0);
    let mut max_perm = elf::SegmentFlags::empty();
    for hdr in headers.program_headers_with_type(elf::SegmentType::Load) {
        // elf_parse already checked that segments are ordered by vaddr and do not overlap.
        if first {
            low = util::page_start(hdr.vaddr);
            first = false;
        }
        high = util::page_end(hdr.vaddr + hdr.memsz as usize);
        max_perm |= hdr.flags();
    }
    LoadedElfInfo { low, high, max_perm }
}

/// Return value of load_elf.
#[derive(Debug)]
pub struct LoadedElf {
    /// The VMAR that the ELF file was loaded into.
    pub vmar: zx::Vmar,

    /// The virtual address of the VMAR.
    pub vmar_base: usize,

    /// The ELF entry point, adjusted for the base address of the VMAR.
    pub entry: usize,
}

/// A trait so that callers of map_elf_segments can hook the map operation.
pub trait Mapper {
    /// Map memory from the given VMO at the specified location.
    ///
    /// See zx::Vmar::map for more details.
    fn map(
        &self,
        vmar_offset: usize,
        vmo: &zx::Vmo,
        vmo_offset: u64,
        length: usize,
        flags: zx::VmarFlags,
    ) -> Result<usize, zx::Status>;
}

impl Mapper for zx::Vmar {
    fn map(
        &self,
        vmar_offset: usize,
        vmo: &zx::Vmo,
        vmo_offset: u64,
        length: usize,
        flags: zx::VmarFlags,
    ) -> Result<usize, zx::Status> {
        Self::map(self, vmar_offset, vmo, vmo_offset, length, flags)
    }
}

/// Load an ELF into a new sub-VMAR of the specified root.
pub fn load_elf(
    vmo: &zx::Vmo,
    headers: &elf::Elf64Headers,
    root_vmar: &zx::Vmar,
) -> Result<LoadedElf, ElfLoadError> {
    let info = loaded_elf_info(headers);
    let size = info.high - info.low;
    if size == 0 {
        return Err(ElfLoadError::NothingToLoad);
    }

    // Individual mappings with be restricted based on segment permissions, but we also limit the
    // overall VMAR to the maximum permissions required across all load segments.
    let flags = zx::VmarFlags::CAN_MAP_SPECIFIC | elf_to_vmar_can_map_flags(&info.max_perm);
    let (vmar, vmar_base) =
        root_vmar.allocate(0, size, flags).map_err(|s| ElfLoadError::VmarAllocate(s))?;

    // Get the relative bias between p_vaddr addresses in the headers and the allocated VMAR,
    // rather than for the root VMAR. Should be equal to the first segment's starting vaddr
    // negated, so that the first mapping starts at 0 within the allocated VMAR.
    let vaddr_bias = vmar_base.wrapping_sub(info.low);

    map_elf_segments(vmo, headers, &vmar, vmar_base, vaddr_bias)?;
    Ok(LoadedElf { vmar, vmar_base, entry: headers.file_header().entry.wrapping_add(vaddr_bias) })
}

/// Map the segments of an ELF into an existing VMAR.
pub fn map_elf_segments(
    vmo: &zx::Vmo,
    headers: &elf::Elf64Headers,
    mapper: &dyn Mapper,
    mapper_base: usize,
    vaddr_bias: usize,
) -> Result<(), ElfLoadError> {
    // We intentionally use wrapping subtraction here, in case the ELF file happens to use vaddr's
    // that are higher than the VMAR base chosen by the kernel. Wrapping addition will be used when
    // adding this bias to vaddr values.
    let mapper_relative_bias = vaddr_bias.wrapping_sub(mapper_base);
    let vmo_name = vmo.get_name().map_err(|s| ElfLoadError::GetVmoName(s))?;
    for hdr in headers.program_headers_with_type(elf::SegmentType::Load) {
        // Map in all whole pages that this segment touches. Calculate the virtual address
        // range that this mapping needs to cover. These addresses are relative to the
        // allocated VMAR, not the root VMAR.
        let vaddr_start = hdr.vaddr.wrapping_add(mapper_relative_bias);
        let map_start = util::page_start(vaddr_start);
        let map_end = util::page_end(vaddr_start + hdr.memsz as usize);
        let map_size = map_end - map_start;
        if map_size == 0 {
            // Empty segment, ignore and map others.
            continue;
        }

        // Calculate the pages from the VMO that need to be mapped.
        let offset_end = hdr.offset + hdr.filesz as usize;
        let mut vmo_start = util::page_start(hdr.offset);
        let mut vmo_full_page_end = util::page_start(offset_end);
        let vmo_partial_page_size = util::page_offset(offset_end);

        // Page aligned size of VMO content to be mapped in, including any partial pages.
        let vmo_size = util::page_end(offset_end) - vmo_start;
        assert!(map_size >= vmo_size);

        // If this segment is writeable (and we're mapping in some VMO content, i.e. it's not
        // all zero initialized), create a writeable clone of the VMO.
        let vmo_to_map: &zx::Vmo;
        let writeable_vmo: zx::Vmo;
        if vmo_size == 0 || !hdr.flags().contains(elf::SegmentFlags::WRITE) {
            vmo_to_map = vmo;
        } else {
            writeable_vmo = vmo
                .create_child(
                    zx::VmoChildOptions::SNAPSHOT_AT_LEAST_ON_WRITE,
                    vmo_start as u64,
                    vmo_size as u64,
                )
                .map_err(ElfLoadError::VmoCowClone)?;
            writeable_vmo
                .set_name(&vmo_name_with_prefix(&vmo_name, VMO_NAME_PREFIX_DATA))
                .map_err(ElfLoadError::SetVmoName)?;
            vmo_to_map = &writeable_vmo;

            // Update addresses into the VMO that will be mapped.
            vmo_full_page_end -= vmo_start;
            vmo_start = 0;
        }

        // If the mapping size is equal in size to the data to be mapped, then nothing else to
        // do. Create the mapping and we're done with this segment.
        let flags = zx::VmarFlags::SPECIFIC | elf_to_vmar_perm_flags(&hdr.flags());
        if hdr.memsz == hdr.filesz {
            mapper
                .map(map_start, vmo_to_map, vmo_start as u64, vmo_size, flags)
                .map_err(ElfLoadError::VmarMap)?;
            continue;
        }

        // Mapping size is larger than the vmo data size (i.e. the segment contains a .bss
        // section). The mapped region beyond the vmo size is zero initialized. We can start
        // out by mapping any full pages from the vmo.
        let vmo_full_page_size = vmo_full_page_end - vmo_start;
        if vmo_full_page_size > 0 {
            mapper
                .map(map_start, vmo_to_map, vmo_start as u64, vmo_full_page_size, flags)
                .map_err(ElfLoadError::VmarMap)?;
        }

        // Remaining pages are backed by an anonymous VMO, which is automatically zero filled
        // by the kernel as needed.
        let anon_map_start = map_start + vmo_full_page_size;
        let anon_size = map_size - vmo_full_page_size;
        let anon_vmo = zx::Vmo::create(anon_size as u64).map_err(|s| ElfLoadError::VmoCreate(s))?;
        anon_vmo
            .set_name(&vmo_name_with_prefix(&vmo_name, VMO_NAME_PREFIX_BSS))
            .map_err(ElfLoadError::SetVmoName)?;

        // If the segment has a partial page of data at the end, it needs to be copied into the
        // anonymous VMO.
        if vmo_partial_page_size > 0 {
            let mut page_buf = [0u8; util::PAGE_SIZE];
            let buf = &mut page_buf[0..vmo_partial_page_size];
            vmo_to_map.read(buf, vmo_full_page_end as u64).map_err(ElfLoadError::VmoRead)?;
            anon_vmo.write(buf, 0).map_err(|s| ElfLoadError::VmoWrite(s))?;
        }

        // Map the anonymous vmo and done with this segment!
        mapper
            .map(anon_map_start, &anon_vmo, 0, anon_size, flags)
            .map_err(ElfLoadError::VmarMap)?;
    }
    Ok(())
}

// These must not be longer than zx::sys::ZX_MAX_NAME_LEN.
const VMO_NAME_UNKNOWN: &[u8] = b"<unknown ELF>";
const VMO_NAME_PREFIX_BSS: &[u8] = b"bss:";
const VMO_NAME_PREFIX_DATA: &[u8] = b"data:";

// prefix length must be less than zx::sys::ZX_MAX_NAME_LEN-1 and not contain any nul bytes.
fn vmo_name_with_prefix(name: &CStr, prefix: &[u8]) -> CString {
    const MAX_LEN: usize = zx::sys::ZX_MAX_NAME_LEN - 1;
    assert!(prefix.len() <= MAX_LEN);

    let mut name_bytes = name.to_bytes();
    if name_bytes.len() == 0 {
        name_bytes = VMO_NAME_UNKNOWN;
    }
    let name_len = std::cmp::min(MAX_LEN, prefix.len() + name_bytes.len());
    let suffix_len = name_len - prefix.len();

    let mut buf = Vec::with_capacity(name_len);
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(&name_bytes[..suffix_len]);
    assert!(buf.len() <= MAX_LEN);

    // The input name is already a CStr, so it doesn't contain nul, so this should only fail if the
    // prefix contains a nul, and since the prefixes are constants, panic if this fails.
    CString::new(buf).expect("Unexpected nul byte in prefix")
}

fn elf_to_vmar_can_map_flags(elf_flags: &elf::SegmentFlags) -> zx::VmarFlags {
    let mut flags = zx::VmarFlags::empty();
    if elf_flags.contains(elf::SegmentFlags::READ) {
        flags |= zx::VmarFlags::CAN_MAP_READ;
    }
    if elf_flags.contains(elf::SegmentFlags::WRITE) {
        flags |= zx::VmarFlags::CAN_MAP_WRITE;
    }
    if elf_flags.contains(elf::SegmentFlags::EXECUTE) {
        flags |= zx::VmarFlags::CAN_MAP_EXECUTE;
    }
    flags
}

fn elf_to_vmar_perm_flags(elf_flags: &elf::SegmentFlags) -> zx::VmarFlags {
    let mut flags = zx::VmarFlags::empty();
    if elf_flags.contains(elf::SegmentFlags::READ) {
        flags |= zx::VmarFlags::PERM_READ;
    }
    if elf_flags.contains(elf::SegmentFlags::WRITE) {
        flags |= zx::VmarFlags::PERM_WRITE;
    }
    if elf_flags.contains(elf::SegmentFlags::EXECUTE) {
        flags |= zx::VmarFlags::PERM_EXECUTE;
    }
    flags
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        anyhow::{bail, Context, Error},
        std::mem,
        zerocopy::AsBytes,
    };

    #[test]
    fn test_vmo_name_with_prefix() -> Result<(), Error> {
        let empty_vmo_name = CStr::from_bytes_with_nul(b"\0")?;
        let short_vmo_name = CStr::from_bytes_with_nul(b"short_vmo_name\0")?;
        let max_vmo_name = CStr::from_bytes_with_nul(b"a_great_maximum_length_vmo_name\0")?;

        assert_eq!(
            vmo_name_with_prefix(&empty_vmo_name, VMO_NAME_PREFIX_BSS).as_bytes(),
            b"bss:<unknown ELF>"
        );
        assert_eq!(
            vmo_name_with_prefix(&short_vmo_name, VMO_NAME_PREFIX_BSS).as_bytes(),
            b"bss:short_vmo_name"
        );
        assert_eq!(
            vmo_name_with_prefix(&max_vmo_name, VMO_NAME_PREFIX_BSS).as_bytes(),
            b"bss:a_great_maximum_length_vmo_"
        );
        assert_eq!(
            vmo_name_with_prefix(&max_vmo_name, VMO_NAME_PREFIX_DATA).as_bytes(),
            b"data:a_great_maximum_length_vmo"
        );

        assert_eq!(
            vmo_name_with_prefix(&empty_vmo_name, b"a_long_vmo_name_prefix:").as_bytes(),
            b"a_long_vmo_name_prefix:<unknown"
        );
        assert_eq!(
            vmo_name_with_prefix(&empty_vmo_name, max_vmo_name.to_bytes()).as_bytes(),
            max_vmo_name.to_bytes()
        );
        assert_eq!(
            vmo_name_with_prefix(&max_vmo_name, max_vmo_name.to_bytes()).as_bytes(),
            max_vmo_name.to_bytes()
        );
        Ok(())
    }

    /// Wrapper that grows the backing VMO as needed and poisons bytes that were not explicitly set.
    struct VmoBuffer {
        inner: zx::Vmo,
    }

    impl VmoBuffer {
        /// Value of bytes that have not yet been written to; different than zero in order to tell
        /// explicitly zeroed bytes (i.e. the bss section) and uninitialized bytes apart.
        const POISON_VALUE: u8 = 0xff;

        fn new() -> Result<VmoBuffer, Error> {
            let vmo = zx::Vmo::create_with_opts(zx::VmoOptions::RESIZABLE, 0)?;
            assert_eq!(vmo.get_size()?, 0); // No need to initialize with POISON_VALUE if empty

            Ok(VmoBuffer { inner: vmo })
        }

        fn inner(&self) -> &zx::Vmo {
            &self.inner
        }

        /// Write data at the given offset, growing the VMO if needed and poisoning padding bytes.
        fn write(&self, offset: usize, data: &[u8]) -> Result<(), Error> {
            let offset_end = (offset + data.len()) as u64;
            let prev_size = self.inner.get_size()?;
            if offset_end > prev_size {
                self.inner.set_size(offset_end)?;
                let new_size =
                    self.inner.get_size().context("Failed to get new rounded up size")?;
                self.inner.write(
                    vec![VmoBuffer::POISON_VALUE; (new_size - prev_size) as usize].as_bytes(),
                    prev_size,
                )?;
            }

            self.inner.write(data, offset as u64)?;
            Ok(())
        }

        fn fill(&self, offset: usize, length: usize, value: u8) -> Result<(), Error> {
            self.write(offset, vec![value; length].as_bytes())
        }

        fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, Error> {
            let offset_end = (offset + length) as u64;
            let vmo_size = self.inner.get_size()?;
            if offset_end <= vmo_size {
                let mut buf = vec![0; length];
                self.inner.read(&mut buf, offset as u64)?;
                Ok(buf)
            } else {
                bail!(
                    "Attempted to read past the end of the VmoBuffer ({:#x} > {:#x})",
                    offset_end,
                    vmo_size,
                );
            }
        }
    }

    impl Mapper for VmoBuffer {
        fn map(
            &self,
            vmar_offset: usize,
            vmo: &zx::Vmo,
            vmo_offset: u64,
            length: usize,
            _flags: zx::VmarFlags,
        ) -> Result<usize, zx::Status> {
            let mut buf = vec![0; length];
            vmo.read(&mut buf, vmo_offset).unwrap();
            self.write(vmar_offset, &buf).unwrap();
            Ok(vmar_offset)
        }
    }

    /// Synthetize an ELF file with the given segments and fill each of them with a different value.
    fn build_elf_with_program_headers(
        phdrs: &[elf::Elf64ProgramHeader],
    ) -> Result<VmoBuffer, Error> {
        let file_header = elf::Elf64FileHeader {
            ident: elf::ElfIdent {
                magic: elf::ELF_MAGIC,
                class: elf::ElfClass::Elf64 as u8,
                data: elf::NATIVE_ENCODING as u8,
                version: elf::ElfVersion::Current as u8,
                osabi: 0,
                abiversion: 0,
                pad: [0; 7],
            },
            elf_type: elf::ElfType::Executable as u16,
            machine: elf::CURRENT_ARCH as u16,
            version: 1,
            entry: 0,
            phoff: mem::size_of::<elf::Elf64FileHeader>(),
            shoff: 0,
            flags: 0,
            ehsize: mem::size_of::<elf::Elf64FileHeader>() as u16,
            phentsize: mem::size_of::<elf::Elf64ProgramHeader>() as u16,
            phnum: phdrs.len() as u16,
            shentsize: 0,
            shnum: 0,
            shstrndx: 0,
        };
        let headers_size = file_header.phoff + file_header.phentsize as usize * phdrs.len();
        let buf = VmoBuffer::new()?;
        buf.write(0, file_header.as_bytes())?;

        // For each segment, write the corresponding header and fill its data with a constant value.
        // Values are assigned starting from one (we skip zero because loaded data would otherwise
        // be indistinguishable from the bss range).
        for (i, phdr) in phdrs.iter().enumerate() {
            let phdr_offset = file_header.phoff + file_header.phentsize as usize * i;
            buf.write(phdr_offset, phdr.as_bytes())?;

            // If the segment overlaps the ELF header, do not fill the overlapping portion.
            let fill_start = std::cmp::max(headers_size, phdr.offset);
            let fill_end = std::cmp::max(fill_start, phdr.offset + phdr.filesz as usize);
            buf.fill(fill_start, fill_end - fill_start, (i + 1) as u8)?;
        }

        Ok(buf)
    }

    #[test]
    fn test_map_elf_segments() -> Result<(), Error> {
        let program_headers = vec![
            // Eight executable pages, unaligned end
            elf::Elf64ProgramHeader {
                segment_type: elf::SegmentType::Load as u32,
                flags: (elf::SegmentFlags::READ | elf::SegmentFlags::EXECUTE).bits(),
                offset: 0,
                vaddr: 0xA0000,
                paddr: 0,
                filesz: 0x7123,
                memsz: 0x7123,
                align: 0,
            },
            // Eight data pages, aligned end
            elf::Elf64ProgramHeader {
                segment_type: elf::SegmentType::Load as u32,
                flags: (elf::SegmentFlags::READ | elf::SegmentFlags::WRITE).bits(),
                offset: 0x8000,
                vaddr: 0xA8000,
                paddr: 0,
                filesz: 0x8000,
                memsz: 0x8000,
                align: 0,
            },
            // One bss page, unaligned end
            elf::Elf64ProgramHeader {
                segment_type: elf::SegmentType::Load as u32,
                flags: (elf::SegmentFlags::READ | elf::SegmentFlags::WRITE).bits(),
                offset: 0,
                vaddr: 0xB0000,
                paddr: 0,
                filesz: 0,
                memsz: 0x789,
                align: 0,
            },
            // Eight data+bss pages with unaligned boundary, unaligned end
            elf::Elf64ProgramHeader {
                segment_type: elf::SegmentType::Load as u32,
                flags: (elf::SegmentFlags::READ | elf::SegmentFlags::WRITE).bits(),
                offset: 0x10000,
                vaddr: 0xB8000,
                paddr: 0,
                filesz: 0x4123,
                memsz: 0x7456,
                align: 0,
            },
            // Bss within the last data page
            elf::Elf64ProgramHeader {
                segment_type: elf::SegmentType::Load as u32,
                flags: (elf::SegmentFlags::READ | elf::SegmentFlags::WRITE).bits(),
                offset: 0x18000,
                vaddr: 0xC0000,
                paddr: 0,
                filesz: 0x4123,
                memsz: 0x4880,
                align: 0,
            },
        ];

        let file_buf = build_elf_with_program_headers(&program_headers)?;
        let elf_headers = elf::Elf64Headers::from_vmo(file_buf.inner())?;

        // Load it into a mock address space.
        let mut addrspace_buf = VmoBuffer::new()?;
        map_elf_segments(file_buf.inner(), &elf_headers, &mut addrspace_buf, 0, 0)?;

        // Compare the contents of the mock address space to the ELF file, verifying that each
        // segment was loaded properly.
        for phdr in elf_headers.program_headers_with_type(elf::SegmentType::Load) {
            let data_size = phdr.filesz as usize;
            let data_expected = file_buf.read(phdr.offset, data_size)?;
            let data_actual = addrspace_buf.read(phdr.vaddr, data_size)?;
            for i in 0..data_size {
                assert!(
                    data_expected[i] == data_actual[i],
                    "{:#x}: {:#x} != {:#x}",
                    phdr.vaddr + i,
                    data_expected[i],
                    data_actual[i],
                );
            }

            let bss_size = (phdr.memsz - phdr.filesz) as usize;
            let bss_actual = addrspace_buf.read(phdr.vaddr + data_size, bss_size)?;
            for i in 0..bss_size {
                assert!(
                    0 == bss_actual[i],
                    "{:#x}: 0 != {:#x}",
                    phdr.vaddr + data_size + i,
                    bss_actual[i],
                );
            }
        }

        Ok(())
    }
}
