//! Access to the current time.
//!
//! This module provides an extremely thin layer on top of `chrono::Utc::now`
//! that lets you set a time offset for testing. The method `set_offset` is
//! available only in test mode and can be used to set a time off set in
//! seconds for the current thread.
//!
//! When accessing the current time, use `now` from this module instead of
//! `chrono::Utc::now` and you should be able to become a time lord  for the
//! duration of a test.

use chrono::{DateTime, Utc};

#[cfg(not(test))]
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

#[cfg(test)]
thread_local! {
    static OFFSET: ::std::cell::RefCell<i64> = ::std::cell::RefCell::new(0);
}

#[cfg(test)]
pub fn now() -> DateTime<Utc> {
    OFFSET.with(|offset| {
        Utc::now() + ::chrono::Duration::seconds(*offset.borrow())
    })
}

#[cfg(test)]
pub fn set_offset(seconds: i64) {
    OFFSET.with(|offset| offset.replace(seconds));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn offset() {
        set_offset(-10);
        assert_eq!(now().timestamp() + 10, Utc::now().timestamp());
    }
}
