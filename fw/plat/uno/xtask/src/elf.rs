// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! A small reader for 32-bit little-endian ELF files: section headers and the
//! symbol table, enough to check what a firmware link produced.

use std::path::Path;

use anyhow::Context;

/// `sh_flags` bit of a section that takes memory at run time.
pub const SHF_ALLOC: u32 = 0x2;

/// `sh_type` of a section with no bytes in the file, such as `.bss`.
pub const SHT_NOBITS: u32 = 8;

/// `sh_type` of the symbol table.
const SHT_SYMTAB: u32 = 2;

/// `st_shndx` of an absolute symbol, such as one a linker script defines.
pub const SHN_ABS: u16 = 0xfff1;

/// One section header.
#[derive(Clone, Debug)]
pub struct Section {
    /// The section's name.
    pub name: String,
    /// `sh_type`.
    pub kind: u32,
    /// `sh_flags`.
    pub flags: u32,
    /// `sh_addr`.
    pub addr: u32,
    /// `sh_offset`.
    pub offset: u32,
    /// `sh_size`.
    pub size: u32,
}

impl Section {
    /// Whether the section takes memory at run time.
    pub fn is_alloc(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }
}

/// One symbol table entry.
#[derive(Clone, Debug)]
pub struct Symbol {
    /// The symbol's name.
    pub name: String,
    /// `st_value`.
    pub value: u32,
    /// `st_shndx`: the index of the symbol's section.
    pub section: u16,
}

/// An ELF file's sections and symbols.
pub struct Elf {
    data: Vec<u8>,
    /// The sections, in header order.
    pub sections: Vec<Section>,
    /// The symbols, in table order.
    pub symbols: Vec<Symbol>,
}

fn bytes_at(data: &[u8], at: usize, len: usize) -> anyhow::Result<&[u8]> {
    at.checked_add(len)
        .and_then(|end| data.get(at..end))
        .with_context(|| format!("{len} bytes at offset {at:#x} are past the end of the file"))
}

fn u16_at(data: &[u8], at: usize) -> anyhow::Result<u16> {
    let b = bytes_at(data, at, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], at: usize) -> anyhow::Result<usize> {
    let b = bytes_at(data, at, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
}

fn name_at(data: &[u8], table: usize, offset: usize) -> anyhow::Result<String> {
    let start = table
        .checked_add(offset)
        .context("a name offset overflows")?;
    let rest = data
        .get(start..)
        .with_context(|| format!("a name at {start:#x} is past the end of the file"))?;
    let len = rest
        .iter()
        .position(|&b| b == 0)
        .with_context(|| format!("the name at {start:#x} has no terminating NUL"))?;
    Ok(String::from_utf8_lossy(&rest[..len]).into_owned())
}

impl Elf {
    /// Reads and parses an ELF file.
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("can't read {}", path.display()))?;
        Self::parse(data).with_context(|| format!("can't parse {}", path.display()))
    }

    /// Parses an ELF file's bytes.
    pub fn parse(data: Vec<u8>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            data.get(..4) == Some(b"\x7fELF".as_slice()),
            "not an ELF file"
        );
        anyhow::ensure!(
            data.get(4) == Some(&1) && data.get(5) == Some(&1),
            "not a 32-bit little-endian ELF file"
        );
        let shoff = u32_at(&data, 0x20)?;
        let shentsize = usize::from(u16_at(&data, 0x2e)?);
        let shnum = usize::from(u16_at(&data, 0x30)?);
        let shstrndx = usize::from(u16_at(&data, 0x32)?);
        anyhow::ensure!(shentsize >= 40, "bad section header size {shentsize}");

        // name, type, flags, addr, offset, size, link
        let mut headers = Vec::with_capacity(shnum);
        for index in 0..shnum {
            let at = shoff
                .checked_add(index * shentsize)
                .context("a section header offset overflows")?;
            let field = |n: usize| u32_at(&data, at + 4 * n);
            headers.push([
                field(0)?,
                field(1)?,
                field(2)?,
                field(3)?,
                field(4)?,
                field(5)?,
                field(6)?,
            ]);
        }
        let names = headers.get(shstrndx).context("no section name table")?[4];
        let mut sections = Vec::with_capacity(shnum);
        for h in &headers {
            sections.push(Section {
                name: name_at(&data, names, h[0])?,
                kind: h[1] as u32,
                flags: h[2] as u32,
                addr: h[3] as u32,
                offset: h[4] as u32,
                size: h[5] as u32,
            });
        }

        let mut symbols = Vec::new();
        if let Some(symtab) = headers.iter().find(|h| h[1] as u32 == SHT_SYMTAB) {
            let strtab = headers.get(symtab[6]).context("no symbol name table")?[4];
            for index in 0..symtab[5] / 16 {
                let at = symtab[4] + 16 * index;
                symbols.push(Symbol {
                    name: name_at(&data, strtab, u32_at(&data, at)?)?,
                    value: u32_at(&data, at + 4)? as u32,
                    section: u16_at(&data, at + 14)?,
                });
            }
        }
        Ok(Self {
            data,
            sections,
            symbols,
        })
    }

    /// The first section with this name.
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// The first symbol with this name.
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// A section's bytes in the file; none for a `SHT_NOBITS` section.
    pub fn contents(&self, section: &Section) -> anyhow::Result<&[u8]> {
        if section.kind == SHT_NOBITS {
            return Ok(&[]);
        }
        bytes_at(&self.data, section.offset as usize, section.size as usize)
            .with_context(|| format!("section {}", section.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol(name: u32, value: u32, size: u32, section: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(name.to_le_bytes());
        out.extend(value.to_le_bytes());
        out.extend(size.to_le_bytes());
        out.extend([0, 0]);
        out.extend(section.to_le_bytes());
        out
    }

    fn header(
        name: u32,
        kind: u32,
        flags: u32,
        addr: u32,
        offset: usize,
        size: usize,
        link: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for value in [
            name,
            kind,
            flags,
            addr,
            offset as u32,
            size as u32,
            link,
            0,
            0,
            0,
        ] {
            out.extend(value.to_le_bytes());
        }
        out
    }

    /// An ELF file with `.data` at 0x100 holding `hello`, a symbol `greeting`
    /// over it, and an absolute symbol `abs` with the value 0xfa02.
    fn sample() -> Vec<u8> {
        let names = b"\0.data\0.symtab\0.strtab\0.shstrtab\0";
        let strings = b"\0greeting\0abs\0";
        let mut symbols = vec![0u8; 16];
        symbols.extend(symbol(1, 0x100, 5, 1));
        symbols.extend(symbol(10, 0xfa02, 0, SHN_ABS));
        let mut file = vec![0u8; 52];
        let data_at = file.len();
        file.extend(b"hello");
        let symbols_at = file.len();
        file.extend(&symbols);
        let strings_at = file.len();
        file.extend(strings);
        let names_at = file.len();
        file.extend(names);
        let shoff = file.len();
        file.extend(header(0, 0, 0, 0, 0, 0, 0));
        file.extend(header(1, 1, SHF_ALLOC, 0x100, data_at, 5, 0));
        file.extend(header(7, SHT_SYMTAB, 0, 0, symbols_at, symbols.len(), 3));
        file.extend(header(15, 3, 0, 0, strings_at, strings.len(), 0));
        file.extend(header(23, 3, 0, 0, names_at, names.len(), 0));
        file[..6].copy_from_slice(b"\x7fELF\x01\x01");
        file[0x20..0x24].copy_from_slice(&(shoff as u32).to_le_bytes());
        file[0x2e..0x30].copy_from_slice(&40u16.to_le_bytes());
        file[0x30..0x32].copy_from_slice(&5u16.to_le_bytes());
        file[0x32..0x34].copy_from_slice(&4u16.to_le_bytes());
        file
    }

    #[test]
    fn reads_sections_and_symbols() {
        let elf = Elf::parse(sample()).expect("a valid file");
        let names: Vec<&str> = elf.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["", ".data", ".symtab", ".strtab", ".shstrtab"]);
        assert!(elf.section(".data").expect(".data").is_alloc());
        let data = elf.section(".data").expect(".data");
        assert_eq!(elf.contents(data).expect("bytes"), b"hello");
        let greeting = elf.symbol("greeting").expect("greeting");
        assert_eq!((greeting.value, greeting.section), (0x100, 1));
        let abs = elf.symbol("abs").expect("abs");
        assert_eq!((abs.value, abs.section), (0xfa02, SHN_ABS));
    }

    #[test]
    fn rejects_a_bad_file() {
        assert!(Elf::parse(b"\x7fELF\x02\x01".to_vec()).is_err());
        assert!(Elf::parse(b"MZ".to_vec()).is_err());
        let file = sample();
        let shoff = u32_at(&file, 0x20).expect("e_shoff");
        // Cut the file after its ELF header, then inside the last section
        // header's size field.
        for len in [0x34, shoff + 4 * 40 + 22] {
            assert!(Elf::parse(file[..len].to_vec()).is_err(), "{len}");
        }
    }
}
