use alloc::{vec::Vec, string::String};

use crate::structures::*;

#[repr(u8)]
pub enum RecordType {
    EndElement = 0x01,
    Comment = 0x02,
    Array = 0x03,
    ShortAttribute = 0x04,
    Attribute = 0x05,
    ShortDictionaryAttribute = 0x06,
    DictionaryAttribute = 0x07,
    ShortXmlnsAttribute = 0x08,
    XmlnsAttribute = 0x09,
    ShortDictionaryXmlnsAttribute = 0x0A,
    DictionaryXmlnsAttribute = 0x0B,
    PrefixDictionaryAttributeA = 0x0C,
    PrefixDictionaryAttributeB = 0x0D,
    PrefixDictionaryAttributeC = 0x0E,
    PrefixDictionaryAttributeD = 0x0F,
    PrefixDictionaryAttributeE = 0x10,
    PrefixDictionaryAttributeF = 0x11,
    PrefixDictionaryAttributeG = 0x12,
    PrefixDictionaryAttributeH = 0x13,
    PrefixDictionaryAttributeI = 0x14,
    PrefixDictionaryAttributeJ = 0x15,
    PrefixDictionaryAttributeK = 0x16,
    PrefixDictionaryAttributeL = 0x17,
    PrefixDictionaryAttributeM = 0x18,
    PrefixDictionaryAttributeN = 0x19,
    PrefixDictionaryAttributeO = 0x1A,
    PrefixDictionaryAttributeP = 0x1B,
    PrefixDictionaryAttributeQ = 0x1C,
    PrefixDictionaryAttributeR = 0x1D,
    PrefixDictionaryAttributeS = 0x1E,
    PrefixDictionaryAttributeT = 0x1F,
    PrefixDictionaryAttributeU = 0x20,
    PrefixDictionaryAttributeV = 0x21,
    PrefixDictionaryAttributeW = 0x22,
    PrefixDictionaryAttributeX = 0x23,
    PrefixDictionaryAttributeY = 0x24,
    PrefixDictionaryAttributeZ = 0x25,
    PrefixAttributeA = 0x26,
    PrefixAttributeB = 0x27,
    PrefixAttributeC = 0x28,
    PrefixAttributeD = 0x29,
    PrefixAttributeE = 0x2A,
    PrefixAttributeF = 0x2B,
    PrefixAttributeG = 0x2C,
    PrefixAttributeH = 0x2D,
    PrefixAttributeI = 0x2E,
    PrefixAttributeJ = 0x2F,
    PrefixAttributeK = 0x30,
    PrefixAttributeL = 0x31,
    PrefixAttributeM = 0x32,
    PrefixAttributeN = 0x33,
    PrefixAttributeO = 0x34,
    PrefixAttributeP = 0x35,
    PrefixAttributeQ = 0x36,
    PrefixAttributeR = 0x37,
    PrefixAttributeS = 0x38,
    PrefixAttributeT = 0x39,
    PrefixAttributeU = 0x3A,
    PrefixAttributeV = 0x3B,
    PrefixAttributeW = 0x3C,
    PrefixAttributeX = 0x3D,
    PrefixAttributeY = 0x3E,
    PrefixAttributeZ = 0x3F,
    ShortElement = 0x40,
    Element = 0x41,
    ShortDictionaryElement = 0x42,
    DictionaryElement = 0x43,
    PrefixDictionaryElementA = 0x44,
    // ...
    PrefixDictionaryElementZ = 0x5D,
    PrefixElementA = 0x5E,
    // ...
    PrefixElementZ = 0x77,
    ZeroText = 0x80,
    ZeroTextWithEndElement = 0x81,
    OneText = 0x82,
    OneTextWithEndElement = 0x83,
    FalseText = 0x84,
    FalseTextWithEndElement = 0x85,
    TrueText = 0x86,
    TrueTextWithEndElement = 0x87,
    Int8Text = 0x88,
    Int8TextWithEndElement = 0x89,
    Int16Text = 0x8A,
    Int16TextWithEndElement = 0x8B,
    Int32Text = 0x8C,
    Int32TextWithEndElement = 0x8D,
    Int64Text = 0x8E,
    Int64TextWithEndElement = 0x8F,
    FloatText = 0x90,
    DoubleText = 0x92,
    DecimalText = 0x94,
    DateTimeText = 0x96,
    Chars8Text = 0x98,
    Chars16Text = 0x9A,
    Chars32Text = 0x9C,
    Bytes8Text = 0x9E,
    Bytes16Text = 0xA0,
    Bytes32Text = 0xA2,
    StartListText = 0xA4,
    EndListText = 0xA6,
    EmptyText = 0xA8,
    DictionaryText = 0xAA,
    UniqueIdText = 0xAC,
    TimeSpanText = 0xAE,
    UuidText = 0xB0,
    UInt64Text = 0xB2,
    BoolText = 0xB4,
    UnicodeChars8Text = 0xB6,
    UnicodeChars16Text = 0xB8,
    UnicodeChars32Text = 0xBA,
    QNameDictionaryText = 0xBC,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ElementRecord {
    /// # 2.2.1.1 ShortElement Record (0x40)
    ///
    /// This structure represents an element without a prefix.
    ShortElement {
        name: NbfxString,
        attributes: Vec<AttributeRecord>,
    },
    /// # 2.2.1.2 Element Record (0x41)
    ///
    /// This structure represents an element with a prefix.
    Element {
        prefix: NbfxString,
        name: NbfxString,
        attributes: Vec<AttributeRecord>,
    },
    /// # 2.2.1.3 ShortDictionaryElement Record (0x42)
    ///
    /// This structure represents an element without a prefix.
    ShortDictionaryElement {
        name: DictionaryString,
        attributes: Vec<AttributeRecord>,
    },
    /// # 2.2.1.4 DictionaryElement Record (0x43)
    ///
    /// This structure represents an element with a prefix.
    DictionaryElement {
        name: DictionaryString,
        attributes: Vec<AttributeRecord>,
    },
    /// # 2.2.1.5 PrefixDictionaryElement[A-Z] Record (0x44-0x5D)
    ///
    /// This structure represents an element with a single lowercase letter prefix.
    PrefixDictionaryElement {
        name: DictionaryString,
        attributes: Vec<AttributeRecord>,
        //prefix: AlphaChar,
    },
    /// # 2.2.1.6 PrefixElement[A-Z] Record (0x5E-0x77)
    ///
    /// This structure represents an element with a single lowercase letter prefix.
    PrefixElement {
        name: NbfxString,
        attributes: Vec<AttributeRecord>,
        //prefix: AlphaChar,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum AttributeRecord {
    ShortAttribute {
        name: NbfxString,
        value: TextRecord,
    },
    Attribute {
        prefix: NbfxString,
        name: NbfxString,
        value: TextRecord,
    },
    XmlnsAttribute {
        prefix: NbfxString,
        value: NbfxString,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TextRecord {
    ZeroText,
    OneText,
    FalseText,
    TrueText,
    // Int8Text(i8),
    // Int16Text(i16),
    // Int32Text(i32),
    // Int64Text(i64),
    // FloatText(f32),
    // DoubleText(f64),
    // DecimalText,
    // DateTimeText,
    Chars8Text(String),
    Chars16Text(String),
    Chars32Text(String),
    // Bytes8Text,
    // Bytes16Text,
    // Bytes32Text,
    // StartListText,
    // EndListText,
    EmptyText,
    // DictionaryText,
    // UniqueIdText,
    // TimeSpanText,
    // UuidText,
    // UInt64Text,
    // BoolText,
    // UnicodeChars8Text,
    // UnicodeChars16Text,
    // UnicodeChars32Text,
    // QNameDictionaryText,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EndElement;

#[derive(Clone, Debug, PartialEq)]
pub struct Comment {
    pub(crate) value: NbfxString,
}