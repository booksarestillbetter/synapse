use std::collections::BTreeMap;
use std::error::Error;
use std::io;
use std::{cmp, fmt, str};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BEncode {
    Int(i64),
    String(Vec<u8>),
    List(Vec<BEncode>),
    Dict(BTreeMap<Vec<u8>, BEncode>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BError {
    UTF8Decode,
    InvalidDict,
    InvalidChar(u8),
    ParseInt,
    MaxDepthExceeded,
    StringTooLong,
    TooManyTokens,
    EOF,
    IO,
}

/// This controls the maximum allocation size we'll perform
/// at once. Needed for parsing strings without OOMing
const MAX_ALLOC_LEN: usize = 4 * 1024 * 1024;
pub const MAX_DEPTH: usize = 128;
pub const MAX_STRING_LEN: usize = 64 * 1024 * 1024;
/// Most values (ints, strings, lists, dicts) one document may contain. Each decoded value
/// costs far more memory than its encoded form (`i0e` is 3 bytes), so this bounds the
/// amplification a small hostile payload can cause. Matches libtorrent's `bdecode` limit.
pub const MAX_TOKENS: usize = 3_000_000;
/// Longest accepted integer / string-length literal. `i64::MIN` is 20 characters.
const MAX_INT_LITERAL: usize = 20;

impl fmt::Display for BError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match *self {
            BError::UTF8Decode => write!(f, "UTF8 Decoding Error"),
            BError::InvalidDict => write!(f, "Invalid BEncoded dictionary"),
            BError::InvalidChar(c) => write!(f, "Invalid character: {}", char::from(c)),
            BError::ParseInt => write!(f, "Invalid integer value encountered"),
            BError::MaxDepthExceeded => {
                write!(f, "Maximum BEncode recursion/nesting depth exceeded")
            }
            BError::StringTooLong => write!(f, "BEncode string length exceeds maximum allowed"),
            BError::TooManyTokens => write!(f, "BEncode document contains too many values"),
            BError::EOF => write!(f, "Unexpected EOF in data"),
            BError::IO => write!(f, "IO error"),
        }
    }
}

impl Error for BError {
    fn description(&self) -> &str {
        "BEncode processing error"
    }
}

impl BEncode {
    pub fn from_int(i: i64) -> BEncode {
        BEncode::Int(i)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> BEncode {
        BEncode::String(Vec::from(s))
    }

    pub fn into_int(self) -> Option<i64> {
        match self {
            BEncode::Int(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            BEncode::String(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_string(self) -> Option<String> {
        match self {
            BEncode::String(v) => String::from_utf8(v).ok(),
            _ => None,
        }
    }

    pub fn into_list(self) -> Option<Vec<BEncode>> {
        match self {
            BEncode::List(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_dict(self) -> Option<BTreeMap<Vec<u8>, BEncode>> {
        match self {
            BEncode::Dict(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<&i64> {
        match *self {
            BEncode::Int(ref v) => Some(v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&Vec<u8>> {
        match *self {
            BEncode::String(ref v) => Some(v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match *self {
            BEncode::String(ref v) => str::from_utf8(v).ok(),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<BEncode>> {
        match *self {
            BEncode::List(ref v) => Some(v),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, BEncode>> {
        match *self {
            BEncode::Dict(ref v) => Some(v),
            _ => None,
        }
    }

    pub fn encode_to_buf(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf).unwrap();
        buf
    }

    pub fn encode<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        enum Token<'a> {
            B(&'a BEncode),
            OS(&'a Vec<u8>),
            E,
        }

        let mut toks = vec![Token::B(self)];
        while let Some(tok) = toks.pop() {
            match tok {
                Token::B(BEncode::Int(i)) => {
                    write_bencode_int(w, *i)?;
                }
                Token::B(BEncode::String(s)) => {
                    write_bencode_len_prefix(w, s.len())?;
                    w.write_all(s)?;
                }
                Token::B(BEncode::List(v)) => {
                    w.write_all(b"l")?;
                    toks.push(Token::E);
                    toks.extend(v.iter().rev().map(Token::B));
                }
                Token::B(BEncode::Dict(d)) => {
                    w.write_all(b"d")?;
                    toks.push(Token::E);
                    for (k, v) in d.iter().rev() {
                        toks.push(Token::B(v));
                        toks.push(Token::OS(k));
                    }
                }
                Token::OS(s) => {
                    write_bencode_len_prefix(w, s.len())?;
                    w.write_all(s)?;
                }
                Token::E => {
                    w.write_all(b"e")?;
                }
            }
        }
        Ok(())
    }
}

fn write_u64_digits(buf: &mut [u8], mut n: u64) -> usize {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    i
}

fn write_bencode_int<W: io::Write>(w: &mut W, val: i64) -> io::Result<()> {
    let mut buf = [0u8; 24];
    buf[23] = b'e';
    let mag = val.unsigned_abs();
    let mut start = write_u64_digits(&mut buf[..23], mag);
    if val < 0 {
        start -= 1;
        buf[start] = b'-';
    }
    start -= 1;
    buf[start] = b'i';
    w.write_all(&buf[start..24])
}

fn write_bencode_len_prefix<W: io::Write>(w: &mut W, len: usize) -> io::Result<()> {
    let mut buf = [0u8; 24];
    buf[23] = b':';
    let start = write_u64_digits(&mut buf[..23], len as u64);
    w.write_all(&buf[start..24])
}

pub fn decode_buf(bytes: &[u8]) -> Result<BEncode, BError> {
    do_decode_slice_with_pos(bytes, false, MAX_DEPTH, MAX_TOKENS).map(|(v, _)| v)
}

pub fn decode_buf_first(bytes: &[u8]) -> Result<BEncode, BError> {
    do_decode_slice_with_pos(bytes, true, MAX_DEPTH, MAX_TOKENS).map(|(v, _)| v)
}

/// Decodes the first bencoded value at the start of `bytes`, returning both the
/// decoded value and the exact byte offset where the value ended.
pub fn decode_buf_prefix(bytes: &[u8]) -> Result<(BEncode, usize), BError> {
    do_decode_slice_with_pos(bytes, true, MAX_DEPTH, MAX_TOKENS)
}

pub fn decode_first<R: io::Read>(bytes: &mut R) -> Result<BEncode, BError> {
    do_decode(bytes, true, MAX_DEPTH, MAX_TOKENS)
}

pub fn decode<R: io::Read>(bytes: &mut R) -> Result<BEncode, BError> {
    do_decode(bytes, false, MAX_DEPTH, MAX_TOKENS)
}

/// Decodes a complete document under tighter limits than the defaults, for untrusted
/// small messages (DHT KRPC packets use depth 10 / 500 tokens, as libtorrent does).
pub fn decode_buf_limited(
    bytes: &[u8],
    max_depth: usize,
    max_tokens: usize,
) -> Result<BEncode, BError> {
    do_decode_slice_with_pos(
        bytes,
        false,
        max_depth.min(MAX_DEPTH),
        max_tokens.min(MAX_TOKENS),
    )
    .map(|(v, _)| v)
}

/// Scans a top-level bencoded dictionary without decoding or re-sorting its contents and
/// returns the raw byte slice corresponding to `target_key`'s value (for example `b"info"`).
/// Preserving raw wire order is necessary for hashing/verifying torrents whose `info` keys
/// are not in canonical sorted order.
pub fn extract_raw_dict_value<'a>(
    data: &'a [u8],
    target_key: &[u8],
) -> Result<Option<&'a [u8]>, BError> {
    if data.is_empty() {
        return Err(BError::EOF);
    }
    if data[0] != b'd' {
        return Err(BError::InvalidDict);
    }
    let mut pos = 1usize;
    let mut tokens = 1usize;

    while pos < data.len() {
        if data[pos] == b'e' {
            return Ok(None);
        }
        if !data[pos].is_ascii_digit() {
            return Err(BError::InvalidDict);
        }
        tokens += 1;
        if tokens > MAX_TOKENS {
            return Err(BError::TooManyTokens);
        }
        let len_bytes = read_until_slice(data, &mut pos, b':', MAX_INT_LITERAL.saturating_sub(1))?;
        let len = decode_int_slice(len_bytes)?;
        if len < 0 {
            return Err(BError::ParseInt);
        }
        let len_usize = len as usize;
        if len_usize > MAX_STRING_LEN {
            return Err(BError::StringTooLong);
        }
        if len_usize > data.len() - pos {
            return Err(BError::EOF);
        }
        let key = &data[pos..pos + len_usize];
        pos += len_usize;

        let val_start = pos;
        skip_one_value(data, &mut pos, MAX_DEPTH, &mut tokens)?;
        if key == target_key {
            return Ok(Some(&data[val_start..pos]));
        }
    }
    Err(BError::EOF)
}

fn skip_one_value(
    data: &[u8],
    pos: &mut usize,
    max_depth: usize,
    tokens: &mut usize,
) -> Result<(), BError> {
    enum Frame {
        List,
        Dict { expecting_key: bool },
    }

    let mut stack: Vec<Frame> = Vec::new();
    loop {
        if *pos >= data.len() {
            return Err(BError::EOF);
        }
        let next = data[*pos];
        if next == b'e' {
            *pos += 1;
            match stack.pop() {
                Some(Frame::List) => {}
                Some(Frame::Dict {
                    expecting_key: true,
                }) => {}
                Some(Frame::Dict {
                    expecting_key: false,
                }) => return Err(BError::InvalidDict),
                None => return Err(BError::InvalidChar(b'e')),
            }
            if stack.is_empty() {
                return Ok(());
            }
            if let Some(Frame::Dict { expecting_key }) = stack.last_mut() {
                *expecting_key = !*expecting_key;
            }
            continue;
        }

        *tokens += 1;
        if *tokens > MAX_TOKENS {
            return Err(BError::TooManyTokens);
        }
        let expecting_dict_key = matches!(
            stack.last(),
            Some(Frame::Dict {
                expecting_key: true
            })
        );

        match next {
            b'i' => {
                if expecting_dict_key {
                    return Err(BError::InvalidDict);
                }
                *pos += 1;
                let s = read_until_slice(data, pos, b'e', MAX_INT_LITERAL)?;
                let _ = decode_int_slice(s)?;
                if stack.is_empty() {
                    return Ok(());
                }
                if let Some(Frame::Dict { expecting_key }) = stack.last_mut() {
                    *expecting_key = !*expecting_key;
                }
            }
            b'l' => {
                if expecting_dict_key {
                    return Err(BError::InvalidDict);
                }
                if stack.len() >= max_depth {
                    return Err(BError::MaxDepthExceeded);
                }
                *pos += 1;
                stack.push(Frame::List);
            }
            b'd' => {
                if expecting_dict_key {
                    return Err(BError::InvalidDict);
                }
                if stack.len() >= max_depth {
                    return Err(BError::MaxDepthExceeded);
                }
                *pos += 1;
                stack.push(Frame::Dict {
                    expecting_key: true,
                });
            }
            b'0'..=b'9' => {
                let len_bytes =
                    read_until_slice(data, pos, b':', MAX_INT_LITERAL.saturating_sub(1))?;
                let len = decode_int_slice(len_bytes)?;
                if len < 0 {
                    return Err(BError::ParseInt);
                }
                let len_usize = len as usize;
                if len_usize > MAX_STRING_LEN {
                    return Err(BError::StringTooLong);
                }
                if len_usize > data.len() - *pos {
                    return Err(BError::EOF);
                }
                *pos += len_usize;
                if stack.is_empty() {
                    return Ok(());
                }
                if let Some(Frame::Dict { expecting_key }) = stack.last_mut() {
                    *expecting_key = !*expecting_key;
                }
            }
            c => return Err(BError::InvalidChar(c)),
        }
    }
}

fn do_decode_slice_with_pos(
    data: &[u8],
    first: bool,
    max_depth: usize,
    max_tokens: usize,
) -> Result<(BEncode, usize), BError> {
    enum Kind {
        Dict(usize),
        List(usize),
    }
    let mut cstack = Vec::new();
    let mut vstack = Vec::new();
    let mut pos = 0usize;
    let mut tokens = 0usize;

    while !(first && cstack.is_empty() && vstack.len() == 1) {
        if pos >= data.len() {
            break;
        }
        let next = data[pos];
        pos += 1;

        if next != b'e' {
            tokens += 1;
            if tokens > max_tokens {
                return Err(BError::TooManyTokens);
            }
        }

        match next {
            b'i' => {
                if cstack.is_empty() && !vstack.is_empty() {
                    return Err(BError::EOF);
                }
                let s = read_until_slice(data, &mut pos, b'e', MAX_INT_LITERAL)?;
                vstack.push(BEncode::Int(decode_int_slice(s)?));
            }
            b'l' => {
                if cstack.is_empty() && !vstack.is_empty() {
                    return Err(BError::EOF);
                }
                if cstack.len() >= max_depth {
                    return Err(BError::MaxDepthExceeded);
                }
                cstack.push(Kind::List(vstack.len()));
            }
            b'd' => {
                if cstack.is_empty() && !vstack.is_empty() {
                    return Err(BError::EOF);
                }
                if cstack.len() >= max_depth {
                    return Err(BError::MaxDepthExceeded);
                }
                cstack.push(Kind::Dict(vstack.len()));
            }
            b'e' => match cstack.pop() {
                Some(Kind::List(i)) => {
                    let l: Vec<BEncode> = vstack.drain(i..).collect();
                    vstack.push(BEncode::List(l));
                }
                Some(Kind::Dict(i)) => {
                    let mut d = BTreeMap::new();
                    if (vstack.len() - i) % 2 != 0 {
                        return Err(BError::InvalidDict);
                    }
                    while vstack.len() > i {
                        let val = vstack.pop().unwrap();
                        match vstack.pop().and_then(BEncode::into_bytes) {
                            Some(key) => {
                                if d.insert(key, val).is_some() {
                                    return Err(BError::InvalidDict);
                                }
                            }
                            None => return Err(BError::InvalidDict),
                        }
                    }
                    vstack.push(BEncode::Dict(d));
                }
                None => return Err(BError::InvalidChar(b'e')),
            },
            _d @ b'0'..=b'9' => {
                if cstack.is_empty() && !vstack.is_empty() {
                    return Err(BError::EOF);
                }
                let start = pos - 1;
                let _rest =
                    read_until_slice(data, &mut pos, b':', MAX_INT_LITERAL.saturating_sub(1))?;
                let len_bytes = &data[start..pos - 1];
                let len = decode_int_slice(len_bytes)?;
                if len < 0 {
                    return Err(BError::ParseInt);
                }
                let len_usize = len as usize;
                if len_usize > MAX_STRING_LEN {
                    return Err(BError::StringTooLong);
                }
                // Check remaining slice length BEFORE allocating anything so a hostile prefix
                // like `67108864:` fails in O(1) with zero heap allocation.
                let remaining = data.len() - pos;
                if len_usize > remaining {
                    return Err(BError::EOF);
                }
                let s = data[pos..pos + len_usize].to_vec();
                pos += len_usize;
                vstack.push(BEncode::String(s));
            }
            c => return Err(BError::InvalidChar(c)),
        }
    }

    if cstack.is_empty() && vstack.len() == 1 {
        Ok((vstack.into_iter().next().unwrap(), pos))
    } else {
        Err(BError::EOF)
    }
}

fn read_until_slice<'a>(
    data: &'a [u8],
    pos: &mut usize,
    delim: u8,
    max: usize,
) -> Result<&'a [u8], BError> {
    let start = *pos;
    let search_end = data.len().min(start.saturating_add(max).saturating_add(1));
    if let Some(rel) = data[start..search_end].iter().position(|&b| b == delim) {
        let end = start + rel;
        *pos = end + 1;
        Ok(&data[start..end])
    } else if data.len() - start > max {
        Err(BError::ParseInt)
    } else {
        Err(BError::EOF)
    }
}

fn do_decode<R: io::Read>(
    bytes: &mut R,
    first: bool,
    max_depth: usize,
    max_tokens: usize,
) -> Result<BEncode, BError> {
    enum Kind {
        Dict(usize),
        List(usize),
    }
    let mut cstack = vec![];
    let mut vstack = vec![];
    let mut buf = [0];
    let mut tokens = 0usize;
    while !(first && cstack.is_empty() && vstack.len() == 1) {
        let next = next_byte(bytes, &mut buf);
        if matches!(next, Ok(c) if c != b'e') {
            tokens += 1;
            if tokens > max_tokens {
                return Err(BError::TooManyTokens);
            }
        }
        match next {
            Ok(b'i') => {
                // Multiple non complex values are not allowed
                if cstack.is_empty() && !vstack.is_empty() {
                    return Err(BError::EOF);
                }
                let mut scratch = [0u8; MAX_INT_LITERAL];
                let n = read_until_stack(bytes, b'e', &mut buf, &mut scratch, 0, MAX_INT_LITERAL)?;
                vstack.push(BEncode::Int(decode_int_slice(&scratch[..n])?));
            }
            Ok(b'l') => {
                if cstack.is_empty() && !vstack.is_empty() {
                    return Err(BError::EOF);
                }
                if cstack.len() >= max_depth {
                    return Err(BError::MaxDepthExceeded);
                }
                cstack.push(Kind::List(vstack.len()));
            }
            Ok(b'd') => {
                if cstack.is_empty() && !vstack.is_empty() {
                    return Err(BError::EOF);
                }
                if cstack.len() >= max_depth {
                    return Err(BError::MaxDepthExceeded);
                }
                cstack.push(Kind::Dict(vstack.len()));
            }
            Err(BError::EOF) => break,
            Ok(b'e') => match cstack.pop() {
                Some(Kind::List(i)) => {
                    let l: Vec<BEncode> = vstack.drain(i..).collect();
                    vstack.push(BEncode::List(l));
                }
                Some(Kind::Dict(i)) => {
                    let mut d = BTreeMap::new();
                    if (vstack.len() - i) % 2 != 0 {
                        return Err(BError::InvalidDict);
                    }
                    while vstack.len() > i {
                        let val = vstack.pop().unwrap();
                        match vstack.pop().and_then(BEncode::into_bytes) {
                            Some(key) => {
                                if d.insert(key, val).is_some() {
                                    return Err(BError::InvalidDict);
                                }
                            }
                            None => return Err(BError::InvalidDict),
                        }
                    }
                    vstack.push(BEncode::Dict(d))
                }
                None => return Err(BError::InvalidChar(b'e')),
            },
            Ok(d @ b'0'..=b'9') => {
                if cstack.is_empty() && !vstack.is_empty() {
                    return Err(BError::EOF);
                }
                let mut scratch = [0u8; MAX_INT_LITERAL];
                scratch[0] = d;
                let n = read_until_stack(
                    bytes,
                    b':',
                    &mut buf,
                    &mut scratch,
                    1,
                    MAX_INT_LITERAL.saturating_sub(1),
                )?;
                let len = decode_int_slice(&scratch[..n])?;
                if len < 0 {
                    return Err(BError::ParseInt);
                }
                let len_usize = len as usize;
                if len_usize > MAX_STRING_LEN {
                    return Err(BError::StringTooLong);
                }
                let mut v = Vec::new();
                let mut chunk_limit = 4096usize;
                while v.len() < len_usize {
                    let to_read =
                        cmp::min(cmp::min(chunk_limit, MAX_ALLOC_LEN), len_usize - v.len());
                    let read_start = v.len();
                    v.resize(read_start + to_read, 0u8);
                    let read_end = v.len();
                    if let Err(e) = bytes.read_exact(&mut v[read_start..read_end]) {
                        return Err(if e.kind() == io::ErrorKind::UnexpectedEof {
                            BError::EOF
                        } else {
                            BError::IO
                        });
                    }
                    chunk_limit = cmp::min(chunk_limit.saturating_mul(2), MAX_ALLOC_LEN);
                }
                vstack.push(BEncode::String(v));
            }
            Err(e) => return Err(e),
            Ok(c) => return Err(BError::InvalidChar(c)),
        }
    }

    if cstack.is_empty() && vstack.len() == 1 {
        Ok(vstack.into_iter().next().unwrap())
    } else {
        Err(BError::EOF)
    }
}

fn next_byte<R: io::Read>(r: &mut R, buf: &mut [u8; 1]) -> Result<u8, BError> {
    loop {
        match r.read(buf) {
            Ok(0) => return Err(BError::EOF),
            Ok(_) => return Ok(buf[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(BError::EOF),
            Err(_) => return Err(BError::IO),
        }
    }
}

fn read_until_stack<R: io::Read>(
    r: &mut R,
    b: u8,
    buf: &mut [u8; 1],
    out: &mut [u8; MAX_INT_LITERAL],
    start_offset: usize,
    max: usize,
) -> Result<usize, BError> {
    let mut len = start_offset;
    let max_total = (start_offset + max).min(out.len());
    loop {
        let n = next_byte(r, buf)?;
        if b == n {
            return Ok(len);
        }
        if len >= max_total {
            return Err(BError::ParseInt);
        }
        out[len] = n;
        len += 1;
    }
}

/// Parses a canonical bencode integer: an optional `-`, then `0` or digits with no leading
/// zero, and never `-0`. Non-canonical spellings (`+5`, `007`, `-0`) re-encode to different
/// bytes, which would silently change a re-serialized document's hash.
fn decode_int_slice(digits_with_sign: &[u8]) -> Result<i64, BError> {
    let digits = digits_with_sign
        .strip_prefix(b"-")
        .unwrap_or(digits_with_sign);
    let canonical = match digits {
        [] => false,
        [b'0'] => digits_with_sign.len() == 1,
        [first, rest @ ..] => (b'1'..=b'9').contains(first) && rest.iter().all(u8::is_ascii_digit),
    };
    if !canonical {
        return Err(BError::ParseInt);
    }
    str::from_utf8(digits_with_sign)
        .map_err(|_| BError::UTF8Decode)
        .and_then(|i| i.parse().map_err(|_| BError::ParseInt))
}

#[cfg(test)]
mod tests {
    use super::{decode_buf, decode_buf_first, BEncode, BError};
    use std::collections::BTreeMap;

    #[test]
    fn test_encode_decode() {
        let i = BEncode::Int(-10);
        let mut v = Vec::new();
        i.encode(&mut v).unwrap();
        assert_eq!(v, b"i-10e");

        let s = BEncode::String(Vec::from(&b"asdf"[..]));
        v = Vec::new();
        s.encode(&mut v).unwrap();
        assert_eq!(v, b"4:asdf");

        let s2r = [1u8, 2, 3, 4];
        let s2e = [52u8, 58, 1, 2, 3, 4];
        let s2 = BEncode::String(Vec::from(&s2r[..]));
        v = Vec::new();
        s2.encode(&mut v).unwrap();
        assert_eq!(v, &s2e);

        let l = BEncode::List(vec![i.clone(), s.clone()]);
        v = Vec::new();
        l.encode(&mut v).unwrap();
        assert_eq!(v, b"li-10e4:asdfe");

        let mut map = BTreeMap::new();
        map.insert(b"asdf".to_vec(), i.clone());
        map.insert(b"qwerty".to_vec(), i.clone());
        let d = BEncode::Dict(map);
        v = Vec::new();
        d.encode(&mut v).unwrap();
        println!("{:?}", std::str::from_utf8(&v));
        assert_eq!(v, b"d4:asdfi-10e6:qwertyi-10ee");

        decode_encode(b"d4:asdfi-10e6:qwertyi-10ee");

        decode_encode(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re");

        encode_decode(&i);
        encode_decode(&s);
        encode_decode(&s2);
        encode_decode(&l);
        encode_decode(&d);
    }

    #[test]
    fn test_first_valid() {
        let twoint = b"i123ei123e";
        assert!(decode_buf_first(twoint).is_ok());
    }

    #[test]
    fn test_invalid() {
        let badint = b"i-123.4e";
        let badint_oom = b"7777777777777:";
        let twoint = b"i123ei123e";
        let badstr = b"5:eeeeeeeeeeee";
        let badstr2 = b"5:e";
        let badstr3 = b"-1:e";
        let badstr4 = b"1:a2:ab";
        let badlist = b"l123e";
        let badlist2 = b"li123e";
        let badlist3 = b"lllllllllllllllllllllllllllllllllllllleeeeeeeeeeee";
        let badlist4 = b"lele";
        let baddict = b"d1:ae";
        let baddict2 = b"di123ei123ee";
        assert!(decode_buf(badint).is_err());
        assert!(decode_buf(badint_oom).is_err());
        assert!(decode_buf(twoint).is_err());
        assert!(decode_buf(badstr).is_err());
        assert!(decode_buf(badstr2).is_err());
        assert!(decode_buf(badstr3).is_err());
        assert!(decode_buf(badstr4).is_err());
        assert!(decode_buf(badlist).is_err());
        assert!(decode_buf(badlist2).is_err());
        assert!(decode_buf(badlist3).is_err());
        assert!(decode_buf(badlist4).is_err());
        assert!(decode_buf(baddict).is_err());
        assert!(decode_buf(baddict2).is_err());
    }

    fn encode_decode(b: &BEncode) {
        let mut v = Vec::new();
        b.encode(&mut v).unwrap();
        assert_eq!(b, &decode_buf(&v).unwrap());
    }

    fn decode_encode(d: &[u8]) {
        let mut v = Vec::new();
        let dec = decode_buf(d).unwrap();
        dec.encode(&mut v).unwrap();
        assert_eq!(d, &v[..]);
    }

    #[test]
    fn test_non_utf8_dict_key() {
        let content = b"d2:\x80\x811:ae";
        decode_buf(content).unwrap();
    }

    #[test]
    fn test_max_depth_exceeded() {
        let mut deeply_nested = Vec::new();
        deeply_nested.extend(std::iter::repeat_n(b'l', 150));
        deeply_nested.extend_from_slice(b"i1e");
        deeply_nested.extend(std::iter::repeat_n(b'e', 150));
        assert_eq!(decode_buf(&deeply_nested), Err(BError::MaxDepthExceeded));
    }

    #[test]
    fn rejects_non_canonical_integers() {
        for bad in [
            &b"i+5e"[..],
            b"i007e",
            b"i-0e",
            b"i-e",
            b"ie",
            b"i 5e",
            b"i5 e",
            b"d3:fooi01ee",
            b"03:abc",
        ] {
            assert!(
                decode_buf(bad).is_err(),
                "{:?} must be rejected",
                String::from_utf8_lossy(bad)
            );
        }
        for good in [&b"i0e"[..], b"i-5e", b"i9223372036854775807e", b"0:"] {
            assert!(
                decode_buf(good).is_ok(),
                "{:?} must parse",
                String::from_utf8_lossy(good)
            );
        }
    }

    #[test]
    fn rejects_overlong_integer_literals() {
        let mut doc = b"i".to_vec();
        doc.extend(std::iter::repeat_n(b'9', 4096));
        doc.push(b'e');
        assert!(decode_buf(&doc).is_err());
    }

    #[test]
    fn rejects_duplicate_dict_keys() {
        assert_eq!(decode_buf(b"d1:ai1e1:ai2ee"), Err(BError::InvalidDict));
    }

    #[test]
    fn enforces_the_token_budget() {
        // "i0e" repeated is 3 bytes per value; a hostile ~9 MB payload would otherwise
        // expand into millions of heap values.
        let mut doc = vec![b'l'];
        for _ in 0..super::MAX_TOKENS {
            doc.extend_from_slice(b"i0e");
        }
        doc.push(b'e');
        assert_eq!(decode_buf(&doc), Err(BError::TooManyTokens));

        let mut ok = vec![b'l'];
        for _ in 0..1000 {
            ok.extend_from_slice(b"i0e");
        }
        ok.push(b'e');
        assert!(decode_buf(&ok).is_ok());
    }

    #[test]
    fn limited_decoder_enforces_depth_and_token_budgets() {
        use super::decode_buf_limited;
        let nested = |d: usize| {
            let mut v = vec![b'l'; d];
            v.extend_from_slice(b"i1e");
            v.extend(std::iter::repeat_n(b'e', d));
            v
        };
        assert!(decode_buf_limited(&nested(9), 10, 500).is_ok());
        assert_eq!(
            decode_buf_limited(&nested(11), 10, 500),
            Err(BError::MaxDepthExceeded)
        );
        let mut wide = vec![b'l'];
        for _ in 0..600 {
            wide.extend_from_slice(b"i0e");
        }
        wide.push(b'e');
        assert_eq!(
            decode_buf_limited(&wide, 10, 500),
            Err(BError::TooManyTokens)
        );
        assert!(decode_buf_limited(&wide, 10, 1000).is_ok());
    }

    #[test]
    fn truncated_large_string_prefix_fails_with_eof_without_large_alloc() {
        assert_eq!(decode_buf(b"67108864:"), Err(BError::EOF));
        assert_eq!(decode_buf(b"5:ab"), Err(BError::EOF));
        assert_eq!(decode_buf(b"67108865:abc"), Err(BError::StringTooLong));

        struct FailReader;
        impl std::io::Read for FailReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk broke"))
            }
        }
        assert_eq!(super::decode(&mut FailReader), Err(BError::IO));
    }

    #[test]
    fn extract_raw_dict_value_preserves_unsorted_wire_bytes() {
        let unsorted_info = b"d1:zi9e1:ai1e4:listl3:onei2ee4:dictd1:k1:vee";
        assert!(decode_buf(unsorted_info).is_ok());
        let mut doc = b"d8:announce10:http://a/b4:info".to_vec();
        doc.extend_from_slice(unsorted_info);
        doc.extend_from_slice(b"7:comment2:hie");

        assert_eq!(
            super::extract_raw_dict_value(&doc, b"info").unwrap(),
            Some(&unsorted_info[..])
        );
        assert_eq!(
            super::extract_raw_dict_value(&doc, b"comment").unwrap(),
            Some(&b"2:hi"[..])
        );
        assert_eq!(
            super::extract_raw_dict_value(&doc, b"missing").unwrap(),
            None
        );
    }

    #[test]
    fn decode_buf_prefix_returns_exact_offset_before_trailing_bytes() {
        let header = b"d8:msg_typei1e5:piecei0ee";
        let mut payload = header.to_vec();
        payload.extend_from_slice(b"\x00\xffBINARY_TRAILING");
        let (val, used) = super::decode_buf_prefix(&payload).unwrap();
        let dict = val.as_dict().unwrap();
        assert_eq!(
            dict.get(b"msg_type".as_ref()).and_then(|v| v.as_int()),
            Some(&1)
        );
        assert_eq!(used, header.len());
        assert_eq!(&payload[used..], b"\x00\xffBINARY_TRAILING");

        let (v2, used2) = super::decode_buf_prefix(b"3:abc999").unwrap();
        assert_eq!(v2.as_str(), Some("abc"));
        assert_eq!(used2, 5);
    }

    #[test]
    fn encode_handles_extreme_integers_and_empty_string() {
        for v in [0i64, 1, -1, 42, -987654321, i64::MAX, i64::MIN] {
            let encoded = BEncode::Int(v).encode_to_buf();
            assert_eq!(encoded, format!("i{v}e").into_bytes());
            assert_eq!(decode_buf(&encoded).unwrap(), BEncode::Int(v));
        }
        let empty = BEncode::String(Vec::new()).encode_to_buf();
        assert_eq!(empty, b"0:");
        assert_eq!(decode_buf(&empty).unwrap(), BEncode::String(Vec::new()));
    }
}
