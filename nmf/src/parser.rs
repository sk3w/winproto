use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{into, map, map_res, value},
    multi::{length_data, many_till},
    sequence::preceded,
    IResult,
};

use crate::{frame::NmfFrame, records::*};

pub fn version_record(input: &[u8]) -> IResult<&[u8], VersionRecord> {
    value(
        VersionRecord::default(),
        tag([
            VersionRecord::RECORD_TYPE,
            VersionRecord::MAJOR_VERSION,
            VersionRecord::MINOR_VERSION,
        ]),
    )(input)
}

pub fn mode_record(input: &[u8]) -> IResult<&[u8], ModeRecord> {
    preceded(
        tag([ModeRecord::RECORD_TYPE]),
        alt((
            value(ModeRecord::SingletonUnsized, tag(b"\x01")),
            value(ModeRecord::Duplex, tag(b"\x02")),
            value(ModeRecord::Simplex, tag(b"\x03")),
            value(ModeRecord::SingletonSized, tag(b"\x04")),
        )),
    )(input)
}

pub fn via_record(input: &[u8]) -> IResult<&[u8], ViaRecord> {
    map_res(
        preceded(tag([ViaRecord::RECORD_TYPE]), length_data(record_size)),
        |b: &[u8]| ViaRecord::from_utf8(b),
    )(input)
}

pub fn known_encoding_record(input: &[u8]) -> IResult<&[u8], KnownEncodingRecord> {
    preceded(
        tag([KnownEncodingRecord::RECORD_TYPE]),
        alt((
            value(KnownEncodingRecord::Soap11Utf8, tag(b"\x00")),
            value(KnownEncodingRecord::Soap11Utf16, tag(b"\x01")),
            value(KnownEncodingRecord::Soap11UnicodeLE, tag(b"\x02")),
            value(KnownEncodingRecord::Soap12Utf8, tag(b"\x03")),
            value(KnownEncodingRecord::Soap12Utf16, tag(b"\x04")),
            value(KnownEncodingRecord::Soap12UnicodeLE, tag(b"\x05")),
            value(KnownEncodingRecord::Soap12Mtom, tag(b"\x06")),
            value(KnownEncodingRecord::Soap12Nbfs, tag(b"\x07")),
            value(KnownEncodingRecord::Soap12Nbfse, tag(b"\x08")),
        )),
    )(input)
}

pub fn extensible_encoding_record(input: &[u8]) -> IResult<&[u8], ExtensibleEncodingRecord> {
    map(
        preceded(
            tag([ExtensibleEncodingRecord::RECORD_TYPE]),
            length_data(record_size),
        ),
        |b: &[u8]| ExtensibleEncodingRecord {
            payload: b.to_vec(),
        },
    )(input)
}

pub fn upgrade_request_record(input: &[u8]) -> IResult<&[u8], UpgradeRequestRecord> {
    map_res(
        preceded(
            tag([UpgradeRequestRecord::RECORD_TYPE]),
            length_data(record_size),
        ),
        |b: &[u8]| UpgradeRequestRecord::from_utf8(b),
    )(input)
}

pub fn upgrade_response_record(input: &[u8]) -> IResult<&[u8], UpgradeResponseRecord> {
    value(
        UpgradeResponseRecord::default(),
        tag([UpgradeResponseRecord::RECORD_TYPE]),
    )(input)
}

pub fn preamble_end_record(input: &[u8]) -> IResult<&[u8], PreambleEndRecord> {
    value(PreambleEndRecord, tag([PreambleEndRecord::RECORD_TYPE]))(input)
}

pub fn preamble_ack_record(input: &[u8]) -> IResult<&[u8], PreambleAckRecord> {
    value(PreambleAckRecord, tag([PreambleAckRecord::RECORD_TYPE]))(input)
}

pub fn end_record(input: &[u8]) -> IResult<&[u8], EndRecord> {
    value(EndRecord::default(), tag([EndRecord::RECORD_TYPE]))(input)
}

pub fn sized_envelope_record(input: &[u8]) -> IResult<&[u8], SizedEnvelopeRecord> {
    map(
        preceded(
            tag([SizedEnvelopeRecord::RECORD_TYPE]),
            length_data(record_size),
        ),
        |b: &[u8]| SizedEnvelopeRecord {
            payload: b.to_vec(),
        },
    )(input)
}

pub fn data_chunk(input: &[u8]) -> IResult<&[u8], DataChunk> {
    map(length_data(record_size), |b| DataChunk {
        payload: b.to_vec(),
    })(input)
}

pub fn unsized_envelope_record(input: &[u8]) -> IResult<&[u8], UnsizedEnvelopeRecord> {
    map(
        preceded(
            tag([UnsizedEnvelopeRecord::RECORD_TYPE]),
            many_till(data_chunk, tag([UnsizedEnvelopeRecord::TERMINATOR])),
        ),
        |(chunks, _terminator)| UnsizedEnvelopeRecord { chunks },
    )(input)
}

pub fn fault_record(input: &[u8]) -> IResult<&[u8], FaultRecord> {
    map_res(
        preceded(tag([FaultRecord::RECORD_TYPE]), length_data(record_size)),
        |b: &[u8]| FaultRecord::from_utf8(b),
    )(input)
}

pub fn preamble_message(input: &[u8]) -> IResult<&[u8], PreambleMessage> {
    let (input, version) = version_record(input)?;
    let (input, mode) = mode_record(input)?;
    let (input, via) = via_record(input)?;
    let (input, encoding) = known_encoding_record(input)?;
    Ok((
        input,
        PreambleMessage {
            version,
            mode,
            via,
            encoding,
        },
    ))
}

fn record_size(input: &[u8]) -> IResult<&[u8], u32> {
    // TODO: limit max length to 5 bytes?
    let mut size: u32 = 0;
    let mut count: usize = 0;
    for (i, b) in input.iter().enumerate() {
        size ^= ((b & 0x7f) as u32) << (7 * i);
        if b & 0x80 == 0x00 {
            count = i + 1;
            break;
        }
    }
    Ok((&input[count..], size))
}

pub fn nmf_frame(input: &[u8]) -> IResult<&[u8], NmfFrame> {
    alt((
        into(preamble_message),
        into(preamble_end_record),
        into(preamble_ack_record),
        into(upgrade_request_record),
        into(upgrade_response_record),
        into(end_record),
        into(sized_envelope_record),
        into(unsized_envelope_record),
        into(fault_record),
    ))(input)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    const EMPTY: &[u8] = &[];
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/99b0c4e1-fba1-4e4a-b621-3a73aa4d48ce
    const PREAMBLE_MESSAGE: &[u8] = &hex!(
        "00 01 00 01 02 02 21 6E 65 74 2E 74 63 70 3A 2F"
        "2F 53 61 6D 70 6C 65 53 65 72 76 65 72 2F 53 61"
        "6D 70 6C 65 41 70 70 2F 03 08"
    );
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/952336d9-aa94-4472-a6aa-49252c329c7a
    const SIZED_ENVELOPE_MESSAGE_1: &[u8] = &hex!(
        "06 AA 01 74 2A 68 74 74 70 3A 2F 2F 74 65 6D 70"
        "75 72 69 2E 6F 72 67 2F 49 4F 6E 65 57 61 79 43"
        "6F 6E 74 72 61 63 74 2F 45 78 65 63 75 74 65 21"
        "6E 65 74 2E 74 63 70 3A 2F 2F 53 61 6D 70 6C 65"
        "53 65 72 76 65 72 2F 53 61 6D 70 6C 65 41 70 70"
        "2F 07 45 78 65 63 75 74 65 13 68 74 74 70 3A 2F"
        "2F 74 65 6D 70 75 72 69 2E 6F 72 67 2F 0A 73 65"
        "6E 64 53 74 72 69 6E 67 56 02 0B 01 73 04 0B 01"
        "61 06 56 08 44 0A 1E 00 82 AB 01 44 0C 1E 00 82"
        "AB 03 01 56 0E 42 05 0A 07 42 09 99 0D 54 65 73"
        "74 20 6D 65 73 73 61 67 65 31 01 01 01"
    );
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/7b9e9160-1950-4949-bc3c-22cf6790437b
    const SIZED_ENVELOPE_MESSAGE_2: &[u8] = &hex!(
        "06 36 00 56 02 0B 01 73 04 0B 01 61 06 56 08 44"
        "0A 1E 00 82 AB 01 44 0C 1E 00 82 AB 03 01 56 0E"
        "42 05 0A 07 42 09 99 0D 54 65 73 74 20 6D 65 73"
        "73 61 67 65 32 01 01 01"
    );

    #[test]
    fn parse_preamble_message() {
        assert_eq!(
            preamble_message(PREAMBLE_MESSAGE),
            Ok((
                EMPTY,
                PreambleMessage {
                    version: VersionRecord::default(),
                    mode: ModeRecord::Duplex,
                    via: ViaRecord::new("net.tcp://SampleServer/SampleApp/"),
                    encoding: KnownEncodingRecord::Soap12Nbfse,
                }
            )),
        )
    }

    #[test]
    fn parse_preamble_end_message_record() {
        assert_eq!(
            preamble_end_record(b"\x0c"),
            Ok((EMPTY, PreambleEndRecord::default())),
        )
    }

    #[test]
    fn parse_preamble_ack_message_record() {
        assert_eq!(
            preamble_ack_record(b"\x0b"),
            Ok((EMPTY, PreambleAckRecord::default())),
        )
    }

    #[test]
    fn parse_sized_envelope_message() {
        assert_eq!(
            sized_envelope_record(SIZED_ENVELOPE_MESSAGE_1),
            Ok((
                EMPTY,
                SizedEnvelopeRecord {
                    payload: SIZED_ENVELOPE_MESSAGE_1[3..].to_vec()
                }
            ))
        );
        assert_eq!(
            sized_envelope_record(SIZED_ENVELOPE_MESSAGE_2),
            Ok((
                EMPTY,
                SizedEnvelopeRecord {
                    payload: SIZED_ENVELOPE_MESSAGE_2[2..].to_vec()
                }
            ))
        )
    }

    #[test]
    fn parse_end_message() {
        assert_eq!(end_record(b"\x07"), Ok((EMPTY, EndRecord::default())))
    }
}
