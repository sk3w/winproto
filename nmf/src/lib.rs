//#![cfg_attr(not(feature = "std"), no_std)]
#![no_std]

#[cfg(feature = "std")]
pub mod client;

#[cfg(feature = "std")]
pub mod codec;

#[cfg(feature = "std")]
pub mod frame;

#[cfg(feature = "std")]
pub mod parser;

pub mod records;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
