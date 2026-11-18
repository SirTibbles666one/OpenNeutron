//! Ids on the wire, as strings.
//!
//! Message ids are u128 and were serialised as JSON numbers. JavaScript numbers are
//! doubles, so a 20-digit id parses to a float and the low digits are gone — a uid that
//! has been through JSON.parse no longer addresses anything. The client survived by
//! quoting every run of 16+ digits before parsing, which also corrupted any message body
//! containing such a number after a colon (the response then failed to parse and the
//! message rendered as "(encrypted)").
//!
//! Serialising as a decimal string removes both problems. Only responses use these —
//! requests keep accepting either form through `u128_flex`, because clients in the wild
//! send numbers.
use serde::ser::{Serialize, SerializeSeq, Serializer};

pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

pub fn serialize_vec<S: Serializer>(values: &Vec<u128>, serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        seq.serialize_element(&value.to_string())?;
    }
    seq.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct One {
        #[serde(serialize_with = "serialize")]
        uid: u128,
    }

    #[derive(serde::Serialize)]
    struct Many {
        #[serde(serialize_with = "serialize_vec")]
        uids: Vec<u128>,
    }

    #[test]
    fn a_big_id_survives_as_a_string() {
        let big: u128 = 231903818003946380734778029329812390800;
        let json = serde_json::to_string(&One { uid: big }).unwrap();
        assert_eq!(json, format!("{{\"uid\":\"{}\"}}", big));
        // And parsing it back with a JSON parser that keeps strings keeps every digit.
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back["uid"].as_str().unwrap(), big.to_string());
    }

    #[test]
    fn a_list_of_ids_serialises_as_strings() {
        let json = serde_json::to_string(&Many { uids: vec![1, 231903818003946380734778029329812390800] }).unwrap();
        assert_eq!(json, "{\"uids\":[\"1\",\"231903818003946380734778029329812390800\"]}");
    }
}
