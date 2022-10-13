use alloc::{borrow::ToOwned, string::String, vec::Vec};
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{map, map_res, value},
    multi::{length_data, many0},
    number::complete::{le_u16, u8},
    sequence::{pair, preceded, tuple},
    IResult,
};

use crate::{records::*, structures::*};

/// Top-level parser
///
/// This parser returns zero or more records
pub fn nbfx_data(input: &[u8]) -> IResult<&[u8], NbfxData> {
    // many0(element_record)(input)
    todo!()
}

// Structures

pub fn multi_byte_int_31(input: &[u8]) -> IResult<&[u8], u32> {
    let mut size = 0u32;
    let mut count = 0usize;
    for (i, b) in input.iter().enumerate() {
        size ^= ((b & 0x7f) as u32) << (7 * i);
        if b & 0x80 == 0x00 {
            count = i + 1;
            break;
        }
    }
    Ok((&input[count..], size))
}

pub fn mbi31_string(input: &[u8]) -> IResult<&[u8], String> {
    map_res(length_data(multi_byte_int_31), |b| {
        String::from_utf8(b.to_vec())
    })(input)
}

pub fn u8_string(input: &[u8]) -> IResult<&[u8], String> {
    map_res(length_data(u8), |b: &[u8]| String::from_utf8(b.to_vec()))(input)
}

pub fn u16_string(input: &[u8]) -> IResult<&[u8], String> {
    map_res(length_data(le_u16), |b: &[u8]| {
        String::from_utf8(b.to_vec())
    })(input)
}

pub fn nbfx_string(input: &[u8]) -> IResult<&[u8], NbfxString> {
    map_res(length_data(multi_byte_int_31), |b| {
        core::str::from_utf8(b).map(|s| NbfxString(s.to_owned()))
    })(input)
}

pub fn dictionary_string(input: &[u8]) -> IResult<&[u8], DictionaryString> {
    todo!()
}

// Element Records

pub fn element_record(input: &[u8]) -> IResult<&[u8], ElementRecord> {
    alt((
        short_element,
        //element,
        //short_dictionary_element,
        //dictionary_element,
    ))(input)
}

pub fn short_element(input: &[u8]) -> IResult<&[u8], ElementRecord> {
    preceded(
        tag([RecordType::ShortElement as u8]),
        map(
            pair(nbfx_string, many0(attribute_record)),
            |(name, attributes)| ElementRecord::ShortElement { name, attributes },
        ),
    )(input)
}

pub fn element(input: &[u8]) -> IResult<&[u8], ElementRecord> {
    preceded(tag([RecordType::Element as u8]), map(
        tuple((nbfx_string, nbfx_string, many0(attribute_record))),
        |(prefix, name, attributes)| ElementRecord::Element { prefix, name, attributes }
    ))(input)
}

// Attribute Records

pub fn attribute_record(input: &[u8]) -> IResult<&[u8], AttributeRecord> {
    alt((
        short_attribute,
        // attribute,
        // short_dictionary_attribute,
        // dictionary_attribute,
        // short_xmlns_attribute,
        xmlns_attribute,
        // short_dictionary_xmlns_attribute,
        // dictionary_xmlns_attribute,
        // prefix_dictionary_attribute,
        // prefix_attribute,
        // TODO: all attribute record variants
    ))(input)
}

pub fn short_attribute(input: &[u8]) -> IResult<&[u8], AttributeRecord> {
    map(
        preceded(
            tag([RecordType::ShortAttribute as u8]),
            pair(nbfx_string, text_record),
        ),
        |(name, value)| AttributeRecord::ShortAttribute { name, value },
    )(input)
}

pub fn attribute(input: &[u8]) -> IResult<&[u8], AttributeRecord> {
    todo!()
}

pub fn xmlns_attribute(input: &[u8]) -> IResult<&[u8], AttributeRecord> {
    map(
        preceded(
            tag([RecordType::XmlnsAttribute as u8]),
            pair(nbfx_string, nbfx_string),
        ),
        |(prefix, value)| AttributeRecord::XmlnsAttribute { prefix, value },
    )(input)
}

// Text Records

pub fn text_record(input: &[u8]) -> IResult<&[u8], TextRecord> {
    alt((
        zero_text,
        one_text,
        false_text,
        true_text,
        chars8_text,
        chars16_text,
        // TODO: all text record variants
    ))(input)
}

pub fn zero_text(input: &[u8]) -> IResult<&[u8], TextRecord> {
    value(TextRecord::ZeroText, tag([RecordType::ZeroText as u8]))(input)
}

pub fn one_text(input: &[u8]) -> IResult<&[u8], TextRecord> {
    value(TextRecord::OneText, tag([RecordType::OneText as u8]))(input)
}

pub fn false_text(input: &[u8]) -> IResult<&[u8], TextRecord> {
    value(TextRecord::FalseText, tag([RecordType::FalseText as u8]))(input)
}

pub fn true_text(input: &[u8]) -> IResult<&[u8], TextRecord> {
    value(TextRecord::TrueText, tag([RecordType::TrueText as u8]))(input)
}

pub fn chars8_text(input: &[u8]) -> IResult<&[u8], TextRecord> {
    map(
        preceded(tag([RecordType::Chars8Text as u8]), u8_string),
        |s| TextRecord::Chars8Text(s),
    )(input)
}

pub fn chars16_text(input: &[u8]) -> IResult<&[u8], TextRecord> {
    map(
        preceded(tag([RecordType::Chars16Text as u8]), u16_string),
        |s| TextRecord::Chars16Text(s),
    )(input)
}

// Miscellaneous Records

pub fn end_element(input: &[u8]) -> IResult<&[u8], EndElement> {
    value(EndElement {}, tag([RecordType::EndElement as u8]))(input)
}

pub fn comment(input: &[u8]) -> IResult<&[u8], Comment> {
    map(
        preceded(tag([RecordType::Comment as u8]), nbfx_string),
        |value| Comment { value },
    )(input)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use hex_literal::hex;

    use super::*;

    const EMPTY: &[u8] = &[];

    #[test]
    fn parse_example_01() {
        let input = &hex!("40 03 64 6F 63 01");
        let output = ElementRecord::ShortElement {
            name: NbfxString("doc".to_owned()),
            attributes: Vec::new(),
        };
        let remainder: &[u8] = &hex!("01");
        //assert_eq!(end_element(b"\x01"), Ok((EMPTY, EndElement)))
        assert_eq!(element_record(input), Ok((remainder, output)))
    }

    #[test]
    fn parse_example_41() {
        let input = hex!(
            "41 03 70 72 65 03 64 6F 63 09 03 70"
            "72 65 0A 68 74 74 70 3A 2F 2F 61 62"
            "63 01"
        ).as_ref();
        let output = ElementRecord::Element {
            prefix: NbfxString("pre".to_owned()),
            name: NbfxString("doc".to_owned()),
            attributes: vec![AttributeRecord::XmlnsAttribute { prefix: NbfxString::new("pre"), value: NbfxString::new("http://abc") }],
        };
        let remainder = hex!("01").as_ref();
        assert_eq!(element(input), Ok((remainder, output)))
    }

    #[test]
    fn parse_short_attribute() {
        let input: &[u8] = &hex!("40 03 64 6F 63 04 04 61 74 74 72 84 01");
        let output = ElementRecord::ShortElement {
            name: NbfxString("doc".to_owned()),
            attributes: vec![AttributeRecord::ShortAttribute {
                name: NbfxString("attr".to_owned()),
                value: TextRecord::FalseText,
            }],
        };
        let remainder: &[u8] = &hex!("01");
        assert_eq!(element_record(input), Ok((remainder, output)))
    }
}
