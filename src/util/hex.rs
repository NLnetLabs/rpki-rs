//! Converting from and to hex strings.
#![allow(dead_code)]

use std::str;


/// Encodes a octet sequence as a hex string.
///
/// The function uses `dest` as the buffer for encoding which therefore must
/// be exactly twice the length of `src`. It returns a reference to this
/// buffer as a `&str`.
///
/// # Panics
///
/// The function panics if `dest` is shorter than twice the length of `src`.
pub fn encode<'a>(src: &[u8], dest: &'a mut [u8]) -> &'a str {
    let dest = &mut dest[..src.len() * 2];
    for (s, d) in src.iter().zip(dest.chunks_mut(2)) {
        d[0] = DIGITS[usize::from(s >> 4)];
        d[1] = DIGITS[usize::from(s & 0x0F)];
    }
    unsafe { str::from_utf8_unchecked(dest) }
}

pub fn encode_u8(ch: u8) -> [u8; 2] {
    [DIGITS[usize::from(ch >> 4)], DIGITS[usize::from(ch & 0x0F)]]
}

const DIGITS: &[u8] = b"0123456789ABCDEF";

