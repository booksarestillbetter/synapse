use std::collections::BTreeMap;
use std::error::Error;
use std::io::{self, Cursor};
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
        let mut buf = Cursor::new(Vec::new());
        self.encode(&mut buf).unwrap();
        buf.into_inner()
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
                    write!(w, "i{}e", i)?;
                }
                Token::B(BEncode::String(s)) => {
                    write!(w, "{}:", s.len())?;
                    w.write_all(s)?;
                }
                Token::B(BEncode::List(v)) => {
                    write!(w, "l")?;
                    toks.push(Token::E);
                    toks.extend(v.iter().rev().map(Token::B));
                }
                Token::B(BEncode::Dict(d)) => {
                    write!(w, "d")?;
                    toks.push(Token::E);
                    for (k, v) in d.iter().rev() {
                        toks.push(Token::B(v));
                        toks.push(Token::OS(k));
                    }
                }
                Token::OS(s) => {
                    write!(w, "{}:", s.len())?;
                    w.write_all(s)?;
                }
                Token::E => {
                    write!(w, "e")?;
                }
            }
        }
        Ok(())
    }
}

pub fn decode_buf(bytes: &[u8]) -> Result<BEncode, BError> {
    decode(&mut Cursor::new(bytes))
}

pub fn decode_buf_first(bytes: &[u8]) -> Result<BEncode, BError> {
    decode_first(&mut Cursor::new(bytes))
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
    do_decode(
        &mut Cursor::new(bytes),
        false,
        max_depth.min(MAX_DEPTH),
        max_tokens.min(MAX_TOKENS),
    )
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
                let s = read_until(bytes, b'e', &mut buf, MAX_INT_LITERAL)?;
                vstack.push(BEncode::Int(decode_int(s)?));
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
                    let mut l = Vec::with_capacity(vstack.len() - i);
                    while vstack.len() > i {
                        l.push(vstack.pop().unwrap());
                    }
                    l.reverse();
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
                let mut slen = read_until(bytes, b':', &mut buf, MAX_INT_LITERAL)?;
                slen.insert(0, d);
                let len = decode_int(slen)?;
                if len < 0 {
                    return Err(BError::ParseInt);
                }
                let len_usize = len as usize;
                if len_usize > MAX_STRING_LEN {
                    return Err(BError::StringTooLong);
                }
                let mut v = vec![];
                while v.len() < len_usize {
                    let to_read = cmp::min(MAX_ALLOC_LEN, len_usize - v.len());
                    v.resize(v.len() + to_read, 0u8);
                    let read_start = v.len() - to_read;
                    let read_end = v.len();
                    bytes
                        .read_exact(&mut v[read_start..read_end])
                        .map_err(|_| BError::EOF)?;
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
    let amnt = r.read(buf).map_err(|_| BError::IO)?;
    if amnt == 0 {
        Err(BError::EOF)
    } else {
        Ok(buf[0])
    }
}

fn read_until<R: io::Read>(
    r: &mut R,
    b: u8,
    buf: &mut [u8; 1],
    max: usize,
) -> Result<Vec<u8>, BError> {
    let mut v = vec![];
    loop {
        let n = next_byte(r, buf)?;
        if b == n {
            return Ok(v);
        }
        if v.len() >= max {
            return Err(BError::ParseInt);
        }
        v.push(n);
    }
}

/// Parses a canonical bencode integer: an optional `-`, then `0` or digits with no leading
/// zero, and never `-0`. Non-canonical spellings (`+5`, `007`, `-0`) re-encode to different
/// bytes, which would silently change a re-serialized document's hash.
fn decode_int(v: Vec<u8>) -> Result<i64, BError> {
    let digits = v.strip_prefix(b"-").unwrap_or(&v);
    let canonical = match digits {
        [] => false,
        [b'0'] => v.len() == 1,
        [first, rest @ ..] => (b'1'..=b'9').contains(first) && rest.iter().all(u8::is_ascii_digit),
    };
    if !canonical {
        return Err(BError::ParseInt);
    }
    String::from_utf8(v)
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
}
