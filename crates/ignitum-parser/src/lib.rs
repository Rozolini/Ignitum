#![no_std]

use core::convert::TryInto;

/// Errors encountered during the non-allocating, zero-copy parsing
/// of the WebAssembly binary format.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    InvalidMagicNumber,
    UnsupportedVersion,
    UnexpectedEof,
    InvalidLeb128,
    InvalidTypeForm,
}

/// Canonical Wasm binary header: `\0asm`.
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];
/// Only MVP (v1) is supported.
const WASM_VERSION: u32 = 1;

/// Decodes an Unsigned LEB128 integer and mutates the data slice to advance the cursor.
/// Validates for 32-bit overflow (max 5 bytes).
pub(crate) fn read_u32_leb128(data: &mut &[u8]) -> Result<u32, ParseError> {
    let mut result = 0;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            *data = &data[i + 1..];
            return Ok(result);
        }
        shift += 7;
        // 35 bits is the theoretical limit for a 5-byte LEB128 encoding a u32.
        if shift >= 35 {
            return Err(ParseError::InvalidLeb128);
        }
    }
    Err(ParseError::UnexpectedEof)
}

/// Extracts a sub-slice prefixed by a LEB128 length.
/// Used for zero-copy extraction of section payloads.
pub(crate) fn read_vec_slice<'a>(data: &mut &'a [u8]) -> Result<&'a [u8], ParseError> {
    let len = read_u32_leb128(data)? as usize;
    if data.len() < len {
        return Err(ParseError::UnexpectedEof);
    }
    let slice = &data[..len];
    *data = &data[len..];
    Ok(slice)
}

/// Reads a single byte and advances the cursor.
pub(crate) fn read_u8(data: &mut &[u8]) -> Result<u8, ParseError> {
    if data.is_empty() {
        return Err(ParseError::UnexpectedEof);
    }
    let byte = data[0];
    *data = &data[1..];
    Ok(byte)
}

/// Helper for iterating over Wasm vectors that begin with an item count.
pub(crate) struct CountedSection<'a> {
    pub data: &'a [u8],
    pub count: u32,
}

impl<'a> CountedSection<'a> {
    pub fn new(mut data: &'a [u8]) -> Result<Self, ParseError> {
        let count = read_u32_leb128(&mut data)?;
        Ok(Self { data, count })
    }

    /// Checks if there are items remaining and decrements the internal count.
    pub fn take_next(&mut self) -> bool {
        if self.count == 0 || self.data.is_empty() {
            false
        } else {
            self.count -= 1;
            true
        }
    }
}

/// High-level entry point for the zero-copy WebAssembly module parser.
pub struct WasmModule<'a> {
    pub version: u32,
    pub raw_data: &'a [u8],
}

impl<'a> WasmModule<'a> {
    /// Validates the Wasm binary header and returns a reference to the remaining payload.
    /// Strictly non-allocating.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::UnexpectedEof);
        }

        let magic: [u8; 4] = data[0..4].try_into().unwrap_or_default();
        if magic != WASM_MAGIC {
            return Err(ParseError::InvalidMagicNumber);
        }

        let version = u32::from_le_bytes(data[4..8].try_into().unwrap_or_default());
        if version != WASM_VERSION {
            return Err(ParseError::UnsupportedVersion);
        }

        Ok(Self {
            version,
            raw_data: &data[8..],
        })
    }

    /// Provides an iterator over module sections (Type, Function, Code, etc.).
    pub fn sections(&self) -> SectionIterator<'a> {
        SectionIterator::new(self.raw_data)
    }
}

/// Standard WebAssembly Section identifiers (IDs 0-11).
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SectionId {
    Custom = 0,
    Type = 1,
    Import = 2,
    Function = 3,
    Table = 4,
    Memory = 5,
    Global = 6,
    Export = 7,
    Start = 8,
    Element = 9,
    Code = 10,
    Data = 11,
    Unknown,
}

impl From<u8> for SectionId {
    fn from(id: u8) -> Self {
        match id {
            0 => SectionId::Custom,
            1 => SectionId::Type,
            2 => SectionId::Import,
            3 => SectionId::Function,
            4 => SectionId::Table,
            5 => SectionId::Memory,
            6 => SectionId::Global,
            7 => SectionId::Export,
            8 => SectionId::Start,
            9 => SectionId::Element,
            10 => SectionId::Code,
            11 => SectionId::Data,
            _ => SectionId::Unknown,
        }
    }
}

#[derive(Debug)]
pub struct Section<'a> {
    /// Canonical ID identifying the section type (e.g., Type, Function, Code).
    pub id: SectionId,
    /// Zero-copy reference to the section's raw payload.
    pub data: &'a [u8],
}

/// A non-allocating iterator over the top-level sections of a WebAssembly module.
pub struct SectionIterator<'a> {
    remaining_data: &'a [u8],
}

impl<'a> SectionIterator<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            remaining_data: data,
        }
    }

    fn parse_next(&mut self) -> Result<Option<Section<'a>>, ParseError> {
        if self.remaining_data.is_empty() {
            return Ok(None);
        }

        // Section format: [id: u8][size: leb128][payload: bytes]
        let id_byte = read_u8(&mut self.remaining_data)?;
        let data = read_vec_slice(&mut self.remaining_data)?;

        Ok(Some(Section {
            id: SectionId::from(id_byte),
            data,
        }))
    }
}

impl<'a> Iterator for SectionIterator<'a> {
    type Item = Result<Section<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.parse_next().transpose()
    }
}

/// WebAssembly core value types.
#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum ValueType {
    I32 = 0x7F,
    I64 = 0x7E,
    F32 = 0x7D,
    F64 = 0x7C,
    Unknown = 0xFF,
}

impl From<u8> for ValueType {
    fn from(val: u8) -> Self {
        match val {
            0x7F => ValueType::I32,
            0x7E => ValueType::I64,
            0x7D => ValueType::F32,
            0x7C => ValueType::F64,
            _ => ValueType::Unknown,
        }
    }
}

/// Represents a WebAssembly function signature.
#[derive(Debug, PartialEq)]
pub struct FuncType<'a> {
    /// Raw slice of parameter types.
    pub params: &'a [u8],
    /// Raw slice of result types.
    pub returns: &'a [u8],
}

/// Specialized iterator for the 'Type' section.
pub struct TypeSectionIterator<'a> {
    inner: CountedSection<'a>,
}

impl<'a> TypeSectionIterator<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, ParseError> {
        Ok(Self {
            inner: CountedSection::new(data)?,
        })
    }

    fn parse_next(&mut self) -> Result<Option<FuncType<'a>>, ParseError> {
        if !self.inner.take_next() {
            return Ok(None);
        }

        // FuncType must start with the 0x60 form byte.
        let form = read_u8(&mut self.inner.data)?;
        if form != 0x60 {
            return Err(ParseError::InvalidTypeForm);
        }

        let params = read_vec_slice(&mut self.inner.data)?;
        let returns = read_vec_slice(&mut self.inner.data)?;

        Ok(Some(FuncType { params, returns }))
    }
}

impl<'a> Iterator for TypeSectionIterator<'a> {
    type Item = Result<FuncType<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.parse_next().transpose()
    }
}

/// Represents the body of a function, including local variable definitions and bytecode.
#[derive(Debug, PartialEq)]
pub struct FunctionBody<'a> {
    /// Raw local variable declarations.
    pub locals_raw: &'a [u8],
    /// WebAssembly instruction stream (bytecode).
    pub instructions: &'a [u8],
}

/// Specialized iterator for the 'Code' section.
pub struct CodeSectionIterator<'a> {
    inner: CountedSection<'a>,
}

impl<'a> CodeSectionIterator<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, ParseError> {
        Ok(Self {
            inner: CountedSection::new(data)?,
        })
    }

    fn parse_next(&mut self) -> Result<Option<FunctionBody<'a>>, ParseError> {
        if !self.inner.take_next() {
            return Ok(None);
        }

        // Each function body is prefixed with its total size in bytes.
        let mut body_data = read_vec_slice(&mut self.inner.data)?;

        // Decode local groups. Format: [count: leb128]([num_locals: leb128][type: u8])
        let locals_start = body_data;
        let local_group_count = read_u32_leb128(&mut body_data)?;

        for _ in 0..local_group_count {
            read_u32_leb128(&mut body_data)?; // num_locals
            if body_data.is_empty() {
                return Err(ParseError::UnexpectedEof);
            }
            body_data = &body_data[1..]; // type byte
        }

        let locals_len = locals_start.len() - body_data.len();
        let locals_raw = &locals_start[..locals_len];
        let instructions = body_data;

        Ok(Some(FunctionBody {
            locals_raw,
            instructions,
        }))
    }
}

impl<'a> Iterator for CodeSectionIterator<'a> {
    type Item = Result<FunctionBody<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.parse_next().transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_wasm_header() {
        // Canonical Wasm v1 header.
        let valid_wasm = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let module = WasmModule::parse(&valid_wasm).unwrap();
        assert_eq!(module.version, 1);
    }

    #[test]
    fn test_read_leb128() {
        // Valid case: 624485 encoded in LEB128.
        let mut data: &[u8] = &[0xE5, 0x8E, 0x26];
        let val = read_u32_leb128(&mut data).unwrap();
        assert_eq!(val, 624485);
        assert!(data.is_empty());

        // Error case: Overflow (more than 35 bits for u32).
        let mut overflow_data: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let err = read_u32_leb128(&mut overflow_data).unwrap_err();
        assert_eq!(err, ParseError::InvalidLeb128);

        // Error case: Unexpected EOF during decoding.
        let mut eof_data: &[u8] = &[0xE5, 0x8E];
        let err = read_u32_leb128(&mut eof_data).unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEof);
    }

    #[test]
    fn test_section_iterator() {
        // Binary: Header + Custom Section (id 0, size 4, payload "test").
        let wasm: &[u8] = &[
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, b't', b'e', b's', b't',
        ];
        let module = WasmModule::parse(wasm).unwrap();
        let mut iter = module.sections();

        let section = iter.next().unwrap().unwrap();
        assert_eq!(section.id, SectionId::Custom);
        assert_eq!(section.data, b"test");

        // Sentinel: Ensure iterator terminates.
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_unexpected_eof_in_section() {
        // Malformed section: claims size 10 (0x0A), but provides only 2 bytes.
        let wasm: &[u8] = &[
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00,
        ];
        let module = WasmModule::parse(wasm).unwrap();
        let mut iter = module.sections();

        let err = iter.next().unwrap().unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEof);
    }

    #[test]
    fn test_type_section_iterator() {
        // Signature: (i32, i64) -> (f32).
        // Encoding: [count: 1][form: 0x60][param_count: 2][types: 0x7F, 0x7E][ret_count: 1][type: 0x7D].
        let type_data: &[u8] = &[0x01, 0x60, 0x02, 0x7F, 0x7E, 0x01, 0x7D];
        let mut iter = TypeSectionIterator::new(type_data).unwrap();

        let func_type = iter.next().unwrap().unwrap();
        assert_eq!(func_type.params, &[0x7F, 0x7E]);
        assert_eq!(func_type.returns, &[0x7D]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_code_section_iterator() {
        // Function Body:
        // [count: 1][body_size: 4][local_group_count: 1][num_locals: 1][type: i32][instr: end].
        let code_data: &[u8] = &[0x01, 0x04, 0x01, 0x01, 0x7F, 0x0B];
        let mut iter = CodeSectionIterator::new(code_data).unwrap();

        let func_body = iter.next().unwrap().unwrap();

        // Validate zero-copy slicing of locals and instruction stream.
        assert_eq!(func_body.locals_raw, &[0x01, 0x01, 0x7F]);
        assert_eq!(func_body.instructions, &[0x0B]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_code_section_unexpected_eof() {
        // Malformed code body: truncated payload.
        let code_data: &[u8] = &[0x01, 0x0A, 0x01, 0x01];
        let mut iter = CodeSectionIterator::new(code_data).unwrap();

        let err = iter.next().unwrap().unwrap_err();
        assert_eq!(err, ParseError::UnexpectedEof);
    }
}
