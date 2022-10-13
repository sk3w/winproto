//! # [MC-NBFX]: .NET Binary Format: XML Data Structure
//!
//! Specifies the XML data structure for the .NET Binary Format for XML. This format can represent
//! many XML documents, as specified in XML1.0. The purpose of the format is to reduce the
//! processing costs associated with XML documents by encoding an XML document in fewer bytes than
//! the same document encoded in UTF-8, as specified in RFC2279.
#![no_std]

extern crate alloc;

pub mod parser;
pub mod records;
pub mod structures;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
