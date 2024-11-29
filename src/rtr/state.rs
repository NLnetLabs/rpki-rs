//! Session state.
//!
//! This module defines the types to remember that state of a session with a
//! particular RTR server. The complete state, encapsulated in the type
//! [`State`] consists of a sixteen bit session id and a serial number. Since
//! the serial number follows special rules, it has its own type [`Serial`].

use std::{cmp, fmt, hash, str};
use std::time::SystemTime;


//------------ State ---------------------------------------------------------

/// The RTR session state.
///
/// This state consists of a session ID describing a continuous session with
/// the same evolving data set a server is running and a serial number that
/// describes a particular version of this set.
///
/// Both a session ID and an initial serial number are chosen when a new
/// session is started. Whenever data is being updated, the serial number is
/// increased by one.
///
/// This type contains both these values. You can create the state values for
/// a new session with [`new`] and increase the serial number with [`inc`].
///
/// [`new`]: #method.new
/// [`inc`]: #method.inc
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct State {
    session: u16,
    serial: Serial
}

impl State {
    /// Creates a state value for a new session.
    ///
    /// This will pick a session ID based on the lower 16 bit of the current
    /// Unix time and an initial serial of 0. If you want to choose a
    /// different starting serial, you can use [`new_with_serial`] instead.
    ///
    /// [`new_with_serial`]: #method.new_with_serial
    pub fn new() -> Self {
        Self::new_with_serial(0.into())
    }

    /// Creates a state value with a given initial serial number.
    ///
    /// The function will use a session ID based on the lower 16 bit of the
    /// current time and an initial serial of `serial`.
    pub fn new_with_serial(serial: Serial) -> Self {
        State {
            session: {
                SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH).unwrap()
                .as_secs() as u16
            },
            serial
        }
    }

    /// Creates a new state value from its components.
    pub const fn from_parts(session: u16, serial: Serial) -> Self {
        State { session, serial }
    }

    /// Increases the serial number by one.
    ///
    /// Serial number may wrap but that’s totally fine. See [`Serial`] for
    /// more details.
    pub fn inc(&mut self) {
        self.serial = self.serial.add(1)
    }

    /// Returns the session ID.
    pub fn session(self) -> u16 {
        self.session
    }

    /// Returns the serial number.
    pub fn serial(self) -> Serial {
        self.serial
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}


//------------ Serial --------------------------------------------------------

/// A serial number.
///
/// Serial numbers are regular integers with a special notion for comparison
/// in order to be able to deal with roll-over.
///
/// Specifically, addition and comparison are defined in [RFC 1982].
/// Addition, however, is only defined for values up to `2^31 - 1`, so we
/// decided to not implement the `Add` trait but rather have a dedicated
/// method `add` so as to not cause surprise panics.
/// 
/// Serial numbers only implement a partial ordering. That is, there are
/// pairs of values that are not equal but there still isn’t one value larger
/// than the other. Since this is neatly implemented by the `PartialOrd`
/// trait, the type implements that.
///
/// [RFC 1982]: https://tools.ietf.org/html/rfc1982
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Serial(pub u32);

impl Serial {
    pub const fn from_be(value: u32) -> Self {
        Serial(u32::from_be(value))
    }

    pub const fn to_be(self) -> u32 {
        self.0.to_be()
    }

    /// Add `other` to `self`.
    ///
    /// Serial numbers only allow values of up to `2^31 - 1` to be added to
    /// them. Therefore, this method requires `other` to be a `u32` instead
    /// of a `Serial` to indicate that you cannot simply add two serials
    /// together. This is also why we don’t implement the `Add` trait.
    ///
    /// # Panics
    ///
    /// This method panics if `other` is greater than `2^31 - 1`.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: u32) -> Self {
        assert!(other <= 0x7FFF_FFFF);
        Serial(self.0.wrapping_add(other))
    }
}


//--- Default

impl Default for Serial {
    fn default() -> Self {
        Self::from(0)
    }
}


//--- From and FromStr

impl From<u32> for Serial {
    fn from(value: u32) -> Serial {
        Serial(value)
    }
}

impl From<Serial> for u32 {
    fn from(serial: Serial) -> u32 {
        serial.0
    }
}

impl str::FromStr for Serial {
    type Err = <u32 as str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <u32 as str::FromStr>::from_str(s).map(Into::into)
    }
}


//--- Display

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}


//--- PartialEq and Eq

impl PartialEq for Serial {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<u32> for Serial {
    fn eq(&self, other: &u32) -> bool {
        self.0.eq(other)
    }
}

impl Eq for Serial { }


//--- PartialOrd

impl cmp::PartialOrd for Serial {
    fn partial_cmp(&self, other: &Serial) -> Option<cmp::Ordering> {
        match self.0.cmp(&other.0) {
            cmp::Ordering::Equal => Some(cmp::Ordering::Equal),
            cmp::Ordering::Less => {
                let sub = other.0 - self.0;
                match sub.cmp(&0x8000_0000) {
                    cmp::Ordering::Less => Some(cmp::Ordering::Less),
                    cmp::Ordering::Greater => Some(cmp::Ordering::Greater),
                    _ => None
                }
            },
            cmp::Ordering::Greater => {
                let sub = self.0 - other.0;
                match sub.cmp(&0x8000_0000) {
                    cmp::Ordering::Less => Some(cmp::Ordering::Greater),
                    cmp::Ordering::Greater => Some(cmp::Ordering::Less),
                    _ => None
                }
            }
        }
    }
}


//--- Hash

impl hash::Hash for Serial {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn good_addition() {
        assert_eq!(Serial(0).add(4), Serial(4));
        assert_eq!(Serial(0xFF00_0000).add(0x0F00_0000),
                   Serial(((0xFF00_0000u64 + 0x0F00_0000u64)
                           % 0x1_0000_0000) as u32));
    }

    #[test]
    #[should_panic]
    fn bad_addition() {
        let _ = Serial(0).add(0x8000_0000);
    }

    #[test]
    fn comparison() {
        use std::cmp::Ordering::*;

        assert_eq!(Serial(12), Serial(12));
        assert_ne!(Serial(12), Serial(112));

        assert_eq!(Serial(12).partial_cmp(&Serial(12)), Some(Equal));

        // s1 is said to be less than s2 if [...]
        // (i1 < i2 and i2 - i1 < 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(12).partial_cmp(&Serial(13)), Some(Less));
        assert_ne!(Serial(12).partial_cmp(&Serial(3_000_000_012)), Some(Less));

        // or (i1 > i2 and i1 - i2 > 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(3_000_000_012).partial_cmp(&Serial(12)), Some(Less));
        assert_ne!(Serial(13).partial_cmp(&Serial(12)), Some(Less));

        // s1 is said to be greater than s2 if [...]
        // (i1 < i2 and i2 - i1 > 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(12).partial_cmp(&Serial(3_000_000_012)),
                   Some(Greater));
        assert_ne!(Serial(12).partial_cmp(&Serial(13)), Some(Greater));

        // (i1 > i2 and i1 - i2 < 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(13).partial_cmp(&Serial(12)), Some(Greater));
        assert_ne!(Serial(3_000_000_012).partial_cmp(&Serial(12)),
                   Some(Greater));
        
        // Er, I think that’s what’s left.
        assert_eq!(Serial(1).partial_cmp(&Serial(0x8000_0001)), None);
        assert_eq!(Serial(0x8000_0001).partial_cmp(&Serial(1)), None);
    }
}

