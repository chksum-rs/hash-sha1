//! Module contains items related to the [`State`] structure which allows to the direct SHA-1 state manipulation.
//!
//! # Example
//!
//! ```rust
//! use chksum_hash_sha1 as sha1;
//!
//! // Create new state
//! let mut state = sha1::state::default();
//!
//! // By default it returns initialization values
//! assert_eq!(
//!     state.digest(),
//!     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
//! );
//!
//! // Manually create block of data with proper padding
//! let data = [
//!     u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     // ...
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//! ];
//!
//! // Update state and own new value
//! state = state.update(data);
//!
//! // Proper digest of empty input
//! assert_eq!(
//!     state.digest(),
//!     [0xDA39A3EE, 0x5E6B4B0D, 0x3255BFEF, 0x95601890, 0xAFD80709]
//! );
//!
//! // Reset state to initial values
//! state = state.reset();
//! assert_eq!(
//!     state.digest(),
//!     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
//! );
//! ```
//!
//! # Warning
//!
//! The [`State`] structure does not modify internal state, each function returns a new state that must be used.

use crate::block::LENGTH_DWORDS as BLOCK_LENGTH_DWORDS;
use crate::digest::LENGTH_DWORDS as DIGEST_LENGTH_DWORDS;

#[allow(clippy::unreadable_literal)]
const A: u32 = 0x67452301;
#[allow(clippy::unreadable_literal)]
const B: u32 = 0xEFCDAB89;
#[allow(clippy::unreadable_literal)]
const C: u32 = 0x98BADCFE;
#[allow(clippy::unreadable_literal)]
const D: u32 = 0x10325476;
#[allow(clippy::unreadable_literal)]
const E: u32 = 0xC3D2E1F0;

/// Create a new state.
#[must_use]
pub const fn new() -> State {
    State::new()
}

/// Creates a default state.
#[must_use]
pub fn default() -> State {
    State::default()
}

/// A low-level hash state.
///
/// Check [`state`](self) module for usage examples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct State {
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) d: u32,
    pub(crate) e: u32,
}

impl State {
    /// Creates a new state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            a: A,
            b: B,
            c: C,
            d: D,
            e: E,
        }
    }

    /// Returns modified state with the passed data.
    ///
    /// **Warning!** Input block must be in the big-endian byte order.
    #[must_use]
    pub const fn update(&self, block: [u32; BLOCK_LENGTH_DWORDS]) -> Self {
        #[rustfmt::skip]
        let mut block = [
            block[0x0], block[0x1], block[0x2], block[0x3],
            block[0x4], block[0x5], block[0x6], block[0x7],
            block[0x8], block[0x9], block[0xA], block[0xB],
            block[0xC], block[0xD], block[0xE], block[0xF],
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
        ];
        block[0x10] = (block[0x0D] ^ block[0x08] ^ block[0x02] ^ block[0x00]).rotate_left(1);
        block[0x11] = (block[0x0E] ^ block[0x09] ^ block[0x03] ^ block[0x01]).rotate_left(1);
        block[0x12] = (block[0x0F] ^ block[0x0A] ^ block[0x04] ^ block[0x02]).rotate_left(1);
        block[0x13] = (block[0x10] ^ block[0x0B] ^ block[0x05] ^ block[0x03]).rotate_left(1);
        block[0x14] = (block[0x11] ^ block[0x0C] ^ block[0x06] ^ block[0x04]).rotate_left(1);
        block[0x15] = (block[0x12] ^ block[0x0D] ^ block[0x07] ^ block[0x05]).rotate_left(1);
        block[0x16] = (block[0x13] ^ block[0x0E] ^ block[0x08] ^ block[0x06]).rotate_left(1);
        block[0x17] = (block[0x14] ^ block[0x0F] ^ block[0x09] ^ block[0x07]).rotate_left(1);
        block[0x18] = (block[0x15] ^ block[0x10] ^ block[0x0A] ^ block[0x08]).rotate_left(1);
        block[0x19] = (block[0x16] ^ block[0x11] ^ block[0x0B] ^ block[0x09]).rotate_left(1);
        block[0x1A] = (block[0x17] ^ block[0x12] ^ block[0x0C] ^ block[0x0A]).rotate_left(1);
        block[0x1B] = (block[0x18] ^ block[0x13] ^ block[0x0D] ^ block[0x0B]).rotate_left(1);
        block[0x1C] = (block[0x19] ^ block[0x14] ^ block[0x0E] ^ block[0x0C]).rotate_left(1);
        block[0x1D] = (block[0x1A] ^ block[0x15] ^ block[0x0F] ^ block[0x0D]).rotate_left(1);
        block[0x1E] = (block[0x1B] ^ block[0x16] ^ block[0x10] ^ block[0x0E]).rotate_left(1);
        block[0x1F] = (block[0x1C] ^ block[0x17] ^ block[0x11] ^ block[0x0F]).rotate_left(1);
        block[0x20] = (block[0x1D] ^ block[0x18] ^ block[0x12] ^ block[0x10]).rotate_left(1);
        block[0x21] = (block[0x1E] ^ block[0x19] ^ block[0x13] ^ block[0x11]).rotate_left(1);
        block[0x22] = (block[0x1F] ^ block[0x1A] ^ block[0x14] ^ block[0x12]).rotate_left(1);
        block[0x23] = (block[0x20] ^ block[0x1B] ^ block[0x15] ^ block[0x13]).rotate_left(1);
        block[0x24] = (block[0x21] ^ block[0x1C] ^ block[0x16] ^ block[0x14]).rotate_left(1);
        block[0x25] = (block[0x22] ^ block[0x1D] ^ block[0x17] ^ block[0x15]).rotate_left(1);
        block[0x26] = (block[0x23] ^ block[0x1E] ^ block[0x18] ^ block[0x16]).rotate_left(1);
        block[0x27] = (block[0x24] ^ block[0x1F] ^ block[0x19] ^ block[0x17]).rotate_left(1);
        block[0x28] = (block[0x25] ^ block[0x20] ^ block[0x1A] ^ block[0x18]).rotate_left(1);
        block[0x29] = (block[0x26] ^ block[0x21] ^ block[0x1B] ^ block[0x19]).rotate_left(1);
        block[0x2A] = (block[0x27] ^ block[0x22] ^ block[0x1C] ^ block[0x1A]).rotate_left(1);
        block[0x2B] = (block[0x28] ^ block[0x23] ^ block[0x1D] ^ block[0x1B]).rotate_left(1);
        block[0x2C] = (block[0x29] ^ block[0x24] ^ block[0x1E] ^ block[0x1C]).rotate_left(1);
        block[0x2D] = (block[0x2A] ^ block[0x25] ^ block[0x1F] ^ block[0x1D]).rotate_left(1);
        block[0x2E] = (block[0x2B] ^ block[0x26] ^ block[0x20] ^ block[0x1E]).rotate_left(1);
        block[0x2F] = (block[0x2C] ^ block[0x27] ^ block[0x21] ^ block[0x1F]).rotate_left(1);
        block[0x30] = (block[0x2D] ^ block[0x28] ^ block[0x22] ^ block[0x20]).rotate_left(1);
        block[0x31] = (block[0x2E] ^ block[0x29] ^ block[0x23] ^ block[0x21]).rotate_left(1);
        block[0x32] = (block[0x2F] ^ block[0x2A] ^ block[0x24] ^ block[0x22]).rotate_left(1);
        block[0x33] = (block[0x30] ^ block[0x2B] ^ block[0x25] ^ block[0x23]).rotate_left(1);
        block[0x34] = (block[0x31] ^ block[0x2C] ^ block[0x26] ^ block[0x24]).rotate_left(1);
        block[0x35] = (block[0x32] ^ block[0x2D] ^ block[0x27] ^ block[0x25]).rotate_left(1);
        block[0x36] = (block[0x33] ^ block[0x2E] ^ block[0x28] ^ block[0x26]).rotate_left(1);
        block[0x37] = (block[0x34] ^ block[0x2F] ^ block[0x29] ^ block[0x27]).rotate_left(1);
        block[0x38] = (block[0x35] ^ block[0x30] ^ block[0x2A] ^ block[0x28]).rotate_left(1);
        block[0x39] = (block[0x36] ^ block[0x31] ^ block[0x2B] ^ block[0x29]).rotate_left(1);
        block[0x3A] = (block[0x37] ^ block[0x32] ^ block[0x2C] ^ block[0x2A]).rotate_left(1);
        block[0x3B] = (block[0x38] ^ block[0x33] ^ block[0x2D] ^ block[0x2B]).rotate_left(1);
        block[0x3C] = (block[0x39] ^ block[0x34] ^ block[0x2E] ^ block[0x2C]).rotate_left(1);
        block[0x3D] = (block[0x3A] ^ block[0x35] ^ block[0x2F] ^ block[0x2D]).rotate_left(1);
        block[0x3E] = (block[0x3B] ^ block[0x36] ^ block[0x30] ^ block[0x2E]).rotate_left(1);
        block[0x3F] = (block[0x3C] ^ block[0x37] ^ block[0x31] ^ block[0x2F]).rotate_left(1);
        block[0x40] = (block[0x3D] ^ block[0x38] ^ block[0x32] ^ block[0x30]).rotate_left(1);
        block[0x41] = (block[0x3E] ^ block[0x39] ^ block[0x33] ^ block[0x31]).rotate_left(1);
        block[0x42] = (block[0x3F] ^ block[0x3A] ^ block[0x34] ^ block[0x32]).rotate_left(1);
        block[0x43] = (block[0x40] ^ block[0x3B] ^ block[0x35] ^ block[0x33]).rotate_left(1);
        block[0x44] = (block[0x41] ^ block[0x3C] ^ block[0x36] ^ block[0x34]).rotate_left(1);
        block[0x45] = (block[0x42] ^ block[0x3D] ^ block[0x37] ^ block[0x35]).rotate_left(1);
        block[0x46] = (block[0x43] ^ block[0x3E] ^ block[0x38] ^ block[0x36]).rotate_left(1);
        block[0x47] = (block[0x44] ^ block[0x3F] ^ block[0x39] ^ block[0x37]).rotate_left(1);
        block[0x48] = (block[0x45] ^ block[0x40] ^ block[0x3A] ^ block[0x38]).rotate_left(1);
        block[0x49] = (block[0x46] ^ block[0x41] ^ block[0x3B] ^ block[0x39]).rotate_left(1);
        block[0x4A] = (block[0x47] ^ block[0x42] ^ block[0x3C] ^ block[0x3A]).rotate_left(1);
        block[0x4B] = (block[0x48] ^ block[0x43] ^ block[0x3D] ^ block[0x3B]).rotate_left(1);
        block[0x4C] = (block[0x49] ^ block[0x44] ^ block[0x3E] ^ block[0x3C]).rotate_left(1);
        block[0x4D] = (block[0x4A] ^ block[0x45] ^ block[0x3F] ^ block[0x3D]).rotate_left(1);
        block[0x4E] = (block[0x4B] ^ block[0x46] ^ block[0x40] ^ block[0x3E]).rotate_left(1);
        block[0x4F] = (block[0x4C] ^ block[0x47] ^ block[0x41] ^ block[0x3F]).rotate_left(1);

        let Self { a, b, c, d, e } = *self;

        // Step 1

        const fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        #[allow(clippy::unreadable_literal)]
        const fn ff(a: u32, b: u32, c: u32, d: u32, e: u32, data: u32) -> u32 {
            a.rotate_left(5)
                .wrapping_add(f(b, c, d))
                .wrapping_add(e)
                .wrapping_add(data)
                .wrapping_add(0x5A827999)
        }

        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x00]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x01]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x02]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x03]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x04]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x05]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x06]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x07]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x08]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x09]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x0A]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x0B]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x0C]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x0D]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x0E]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x0F]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x10]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x11]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x12]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[0x13]), a, b.rotate_left(30), c, d);

        // Step 2

        const fn g(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        #[allow(clippy::unreadable_literal)]
        const fn gg(a: u32, b: u32, c: u32, d: u32, e: u32, data: u32) -> u32 {
            a.rotate_left(5)
                .wrapping_add(g(b, c, d))
                .wrapping_add(e)
                .wrapping_add(data)
                .wrapping_add(0x6ED9EBA1)
        }

        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x14]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x15]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x16]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x17]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x18]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x19]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x1A]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x1B]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x1C]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x1D]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x1E]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x1F]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x20]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x21]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x22]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x23]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x24]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x25]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x26]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[0x27]), a, b.rotate_left(30), c, d);

        // Step 3

        const fn h(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (x & z) | (y & z)
        }

        #[allow(clippy::unreadable_literal)]
        const fn hh(a: u32, b: u32, c: u32, d: u32, e: u32, data: u32) -> u32 {
            a.rotate_left(5)
                .wrapping_add(h(b, c, d))
                .wrapping_add(e)
                .wrapping_add(data)
                .wrapping_add(0x8F1BBCDC)
        }

        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x28]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x29]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x2A]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x2B]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x2C]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x2D]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x2E]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x2F]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x30]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x31]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x32]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x33]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x34]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x35]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x36]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x37]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x38]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x39]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x3A]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[0x3B]), a, b.rotate_left(30), c, d);

        // Step 4

        const fn i(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        #[allow(clippy::unreadable_literal)]
        const fn ii(a: u32, b: u32, c: u32, d: u32, e: u32, data: u32) -> u32 {
            a.rotate_left(5)
                .wrapping_add(i(b, c, d))
                .wrapping_add(e)
                .wrapping_add(data)
                .wrapping_add(0xCA62C1D6)
        }

        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x3C]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x3D]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x3E]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x3F]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x40]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x41]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x42]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x43]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x44]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x45]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x46]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x47]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x48]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x49]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x4A]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x4B]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x4C]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x4D]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x4E]), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[0x4F]), a, b.rotate_left(30), c, d);

        // Update

        let a = a.wrapping_add(self.a);
        let b = b.wrapping_add(self.b);
        let c = c.wrapping_add(self.c);
        let d = d.wrapping_add(self.d);
        let e = e.wrapping_add(self.e);

        // Return

        Self { a, b, c, d, e }
    }

    /// Returns a new state with initial values.
    #[must_use]
    pub const fn reset(self) -> Self {
        Self::new()
    }

    /// Returns a digest.
    #[must_use]
    pub const fn digest(&self) -> [u32; DIGEST_LENGTH_DWORDS] {
        let Self { a, b, c, d, e } = *self;
        [a, b, c, d, e]
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_empty() {
        let digest = new().digest();
        assert_eq!(digest, [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
    }

    #[test]
    fn default_empty() {
        let digest = default().digest();
        assert_eq!(digest, [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
    }

    #[test]
    fn new_zeros() {
        #[rustfmt::skip]
        let block= [
            u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
        ];
        let digest = new().update(block).digest();
        assert_eq!(digest, [0xDA39A3EE, 0x5E6B4B0D, 0x3255BFEF, 0x95601890, 0xAFD80709]);
    }
}
