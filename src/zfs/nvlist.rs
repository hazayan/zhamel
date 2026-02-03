extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{BootError, Result};

const NV_ENCODE_NATIVE: u8 = 0;
const NV_ENCODE_XDR: u8 = 1;

const DATA_TYPE_UINT64: u32 = 8;
const DATA_TYPE_STRING: u32 = 9;
const DATA_TYPE_NVLIST: u32 = 19;
const DATA_TYPE_NVLIST_ARRAY: u32 = 20;

#[derive(Debug)]
pub struct NvList<'a> {
    data: &'a [u8],
    encoding: u8,
    little_endian: bool,
    pairs_offset: usize,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum NvValue<'a> {
    Uint64(u64),
    String(&'a str),
    NvList(NvList<'a>),
    NvListArray(Vec<NvList<'a>>),
}

impl<'a> NvList<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(BootError::InvalidData("nvlist header too short"));
        }
        let encoding = data[0];
        let endian = data[1];
        let little_endian = match encoding {
            NV_ENCODE_XDR => false,
            NV_ENCODE_NATIVE => endian != 0,
            _ => return Err(BootError::InvalidData("nvlist encoding unsupported")),
        };
        let pairs_offset = 4 + 4 + 4;
        if pairs_offset > data.len() {
            return Err(BootError::InvalidData("nvlist header truncated"));
        }
        Ok(Self {
            data,
            encoding,
            little_endian,
            pairs_offset,
        })
    }

    pub fn find_u64(&self, name: &str) -> Result<Option<u64>> {
        match self.find_value(name)? {
            Some(NvValue::Uint64(value)) => Ok(Some(value)),
            _ => Ok(None),
        }
    }

    pub fn find_string(&self, name: &str) -> Result<Option<String>> {
        match self.find_value(name)? {
            Some(NvValue::String(value)) => Ok(Some(value.to_string())),
            _ => Ok(None),
        }
    }

    #[allow(dead_code)]
    pub fn find_nvlist(&self, name: &str) -> Result<Option<NvList<'a>>> {
        match self.find_value(name)? {
            Some(NvValue::NvList(list)) => Ok(Some(list)),
            _ => Ok(None),
        }
    }

    #[allow(dead_code)]
    pub fn find_nvlist_array(&self, name: &str) -> Result<Option<Vec<NvList<'a>>>> {
        match self.find_value(name)? {
            Some(NvValue::NvListArray(values)) => Ok(Some(values)),
            _ => Ok(None),
        }
    }

    fn find_value(&self, name: &str) -> Result<Option<NvValue<'a>>> {
        let mut cursor = self.pairs_offset;
        loop {
            if cursor + 8 > self.data.len() {
                return Err(BootError::InvalidData("nvlist pair header truncated"));
            }
            let encoded_size = self.read_u32(cursor)? as usize;
            let decoded_size = self.read_u32(cursor + 4)? as usize;
            if encoded_size == 0 && decoded_size == 0 {
                return Ok(None);
            }
            if encoded_size < 8 {
                return Err(BootError::InvalidData("nvlist pair size invalid"));
            }
            let pair_start = cursor;
            let pair_end = pair_start
                .checked_add(encoded_size)
                .ok_or(BootError::InvalidData("nvlist pair overflow"))?;
            if pair_end > self.data.len() {
                return Err(BootError::InvalidData("nvlist pair out of range"));
            }
            let name_start = pair_start + 8;
            let (pair_name, data_type, nelem, data_start) =
                self.parse_pair_header(name_start, pair_end)?;

            if pair_name == name {
                let value = self.parse_value(data_type, nelem, data_start, pair_end)?;
                return Ok(value);
            }
            cursor = pair_end;
        }
    }

    fn parse_pair_header(
        &self,
        offset: usize,
        pair_end: usize,
    ) -> Result<(&'a str, u32, u32, usize)> {
        if offset + 4 > pair_end {
            return Err(BootError::InvalidData("nvlist name header truncated"));
        }
        let name_len = self.read_u32(offset)? as usize;
        let name_data = offset + 4;
        let name_end = name_data
            .checked_add(name_len)
            .ok_or(BootError::InvalidData("nvlist name overflow"))?;
        if name_end > pair_end {
            return Err(BootError::InvalidData("nvlist name out of range"));
        }
        let mut name_bytes = &self.data[name_data..name_end];
        if let Some(0) = name_bytes.last().copied() {
            name_bytes = &name_bytes[..name_bytes.len() - 1];
        }
        let name = core::str::from_utf8(name_bytes)
            .map_err(|_| BootError::InvalidData("nvlist name not utf8"))?;
        let data_offset = align4(name_end);
        if data_offset + 8 > pair_end {
            return Err(BootError::InvalidData("nvlist data header truncated"));
        }
        let data_type = self.read_u32(data_offset)?;
        let nelem = self.read_u32(data_offset + 4)?;
        let data_start = data_offset + 8;
        if data_start > pair_end {
            return Err(BootError::InvalidData("nvlist data overflow"));
        }
        Ok((name, data_type, nelem, data_start))
    }

    fn parse_value(
        &self,
        data_type: u32,
        nelem: u32,
        data_start: usize,
        pair_end: usize,
    ) -> Result<Option<NvValue<'a>>> {
        match data_type {
            DATA_TYPE_UINT64 => {
                if nelem != 1 || data_start + 8 > pair_end {
                    return Err(BootError::InvalidData("nvlist uint64 out of range"));
                }
                Ok(Some(NvValue::Uint64(self.read_u64(data_start)?)))
            }
            DATA_TYPE_STRING => {
                let value = self.parse_string(data_start, pair_end)?;
                Ok(Some(NvValue::String(value)))
            }
            DATA_TYPE_NVLIST => {
                let nested = self.parse_nvlist(data_start, pair_end)?;
                Ok(Some(NvValue::NvList(nested)))
            }
            DATA_TYPE_NVLIST_ARRAY => {
                let list = self.parse_nvlist_array(nelem, data_start, pair_end)?;
                Ok(Some(NvValue::NvListArray(list)))
            }
            _ => Ok(None),
        }
    }

    fn parse_string(&self, offset: usize, pair_end: usize) -> Result<&'a str> {
        if offset + 4 > pair_end {
            return Err(BootError::InvalidData("nvlist string header truncated"));
        }
        let len = self.read_u32(offset)? as usize;
        let data_start = offset + 4;
        let data_end = data_start
            .checked_add(len)
            .ok_or(BootError::InvalidData("nvlist string overflow"))?;
        if data_end > pair_end {
            return Err(BootError::InvalidData("nvlist string out of range"));
        }
        let mut bytes = &self.data[data_start..data_end];
        if let Some(0) = bytes.last().copied() {
            bytes = &bytes[..bytes.len() - 1];
        }
        core::str::from_utf8(bytes).map_err(|_| BootError::InvalidData("nvlist string not utf8"))
    }

    fn parse_nvlist(&self, offset: usize, pair_end: usize) -> Result<NvList<'a>> {
        if offset + 12 > pair_end {
            return Err(BootError::InvalidData("nvlist nested header truncated"));
        }
        let nested = NvList::parse(&self.data[offset..pair_end])?;
        Ok(nested)
    }

    fn parse_nvlist_array(
        &self,
        nelem: u32,
        offset: usize,
        pair_end: usize,
    ) -> Result<Vec<NvList<'a>>> {
        let mut cursor = offset;
        let mut lists = Vec::new();
        for _ in 0..nelem {
            if cursor + 12 > pair_end {
                return Err(BootError::InvalidData("nvlist array truncated"));
            }
            let list = NvList::parse(&self.data[cursor..pair_end])?;
            let next = list.end_offset()?;
            if next <= cursor {
                return Err(BootError::InvalidData("nvlist array did not advance"));
            }
            lists.push(list);
            cursor = next;
        }
        Ok(lists)
    }

    fn end_offset(&self) -> Result<usize> {
        let mut cursor = self.pairs_offset;
        loop {
            if cursor + 8 > self.data.len() {
                return Err(BootError::InvalidData("nvlist end truncated"));
            }
            let encoded_size = self.read_u32(cursor)? as usize;
            let decoded_size = self.read_u32(cursor + 4)? as usize;
            if encoded_size == 0 && decoded_size == 0 {
                return Ok(cursor + 8);
            }
            if encoded_size == 0 {
                return Err(BootError::InvalidData("nvlist pair size invalid"));
            }
            cursor = cursor
                .checked_add(encoded_size)
                .ok_or(BootError::InvalidData("nvlist end overflow"))?;
            if cursor > self.data.len() {
                return Err(BootError::InvalidData("nvlist end out of range"));
            }
        }
    }

    fn read_u32(&self, offset: usize) -> Result<u32> {
        if offset + 4 > self.data.len() {
            return Err(BootError::InvalidData("nvlist read overflow"));
        }
        let bytes: [u8; 4] = self.data[offset..offset + 4]
            .try_into()
            .map_err(|_| BootError::InvalidData("nvlist read u32"))?;
        Ok(match self.encoding {
            NV_ENCODE_XDR => u32::from_be_bytes(bytes),
            _ => {
                if self.little_endian {
                    u32::from_le_bytes(bytes)
                } else {
                    u32::from_be_bytes(bytes)
                }
            }
        })
    }

    fn read_u64(&self, offset: usize) -> Result<u64> {
        if offset + 8 > self.data.len() {
            return Err(BootError::InvalidData("nvlist read overflow"));
        }
        let bytes: [u8; 8] = self.data[offset..offset + 8]
            .try_into()
            .map_err(|_| BootError::InvalidData("nvlist read u64"))?;
        Ok(match self.encoding {
            NV_ENCODE_XDR => u64::from_be_bytes(bytes),
            _ => {
                if self.little_endian {
                    u64::from_le_bytes(bytes)
                } else {
                    u64::from_be_bytes(bytes)
                }
            }
        })
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::vec::Vec;

    use super::{NvList, NV_ENCODE_XDR};

    fn write_u32_be(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    fn write_u64_be(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    fn align4(buf: &mut Vec<u8>) {
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
    }

    fn build_nvpair_u64(name: &str, value: u64) -> Vec<u8> {
        let mut body = Vec::new();
        write_u32_be(&mut body, name.len() as u32 + 1);
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        align4(&mut body);
        write_u32_be(&mut body, 8); // DATA_TYPE_UINT64
        write_u32_be(&mut body, 1);
        write_u64_be(&mut body, value);

        let mut pair = Vec::new();
        let size = (8 + body.len()) as u32;
        write_u32_be(&mut pair, size);
        write_u32_be(&mut pair, size);
        pair.extend_from_slice(&body);
        pair
    }

    fn build_nvpair_string(name: &str, value: &str) -> Vec<u8> {
        let mut body = Vec::new();
        write_u32_be(&mut body, name.len() as u32 + 1);
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        align4(&mut body);
        write_u32_be(&mut body, 9); // DATA_TYPE_STRING
        write_u32_be(&mut body, 1);
        write_u32_be(&mut body, value.len() as u32 + 1);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
        align4(&mut body);

        let mut pair = Vec::new();
        let size = (8 + body.len()) as u32;
        write_u32_be(&mut pair, size);
        write_u32_be(&mut pair, size);
        pair.extend_from_slice(&body);
        pair
    }

    fn build_nvlist(pairs: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[NV_ENCODE_XDR, 0, 0, 0]);
        write_u32_be(&mut buf, 0); // version
        write_u32_be(&mut buf, 0); // flags
        for pair in pairs {
            buf.extend_from_slice(pair);
        }
        write_u32_be(&mut buf, 0);
        write_u32_be(&mut buf, 0);
        buf
    }

    #[test]
    fn parse_nvlist_u64() {
        let pair = build_nvpair_u64("pool_guid", 0x1122334455667788);
        let buf = build_nvlist(&[pair]);
        let nv = NvList::parse(&buf).expect("parse");
        let value = nv.find_u64("pool_guid").expect("find");
        assert_eq!(value, Some(0x1122334455667788));
    }

    #[test]
    fn parse_nvlist_string() {
        let pair = build_nvpair_string("bootonce", "zroot/ROOT/default");
        let buf = build_nvlist(&[pair]);
        let nv = NvList::parse(&buf).expect("parse");
        let value = nv.find_string("bootonce").expect("find");
        assert_eq!(value.as_deref(), Some("zroot/ROOT/default"));
    }
}
