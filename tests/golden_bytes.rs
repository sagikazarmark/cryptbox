//! Public-boundary tests for golden-bytes encoding fixtures.

use cryptbox::{Codec, CodecError, Padding, Seal, SealId, Utf8, seal_id, testing::assert_encoding};
use zeroize::Zeroizing;

struct Nickname;

impl Seal for Nickname {
    const ID: SealId = seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = Utf8;
    type Bound = ();
    type Record = ();
    type Indexes = ();
}

#[test]
fn matching_fixture_passes() {
    assert_encoding::<Nickname>(&"ada".to_owned(), "616461");
}

#[test]
#[should_panic(expected = "encoding changed: expected 616461, got 6772616365")]
fn mismatched_fixture_reports_actual_bytes() {
    assert_encoding::<Nickname>(&"grace".to_owned(), "616461");
}

/// Encodes faithfully, but a later release decodes the stored bytes upper-cased.
struct DriftingCodec;

impl Codec<String> for DriftingCodec {
    const ID: &'static str = "drifting/1";

    fn encode(value: &String) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        Ok(Zeroizing::new(value.as_bytes().to_vec()))
    }

    fn decode(bytes: &[u8]) -> Result<String, CodecError> {
        Ok(String::from_utf8_lossy(bytes).to_uppercase())
    }
}

struct DriftingNickname;

impl Seal for DriftingNickname {
    const ID: SealId = seal_id!("5a0f6c1e-2b7d-4e39-8c14-9d3a7e2b6f01");
    const PADDING: Padding = Padding::NONE;
    type Value = String;
    type Codec = DriftingCodec;
    type Bound = ();
    type Record = ();
    type Indexes = ();
}

#[test]
#[should_panic(expected = "decoding changed: expected 616461, got 414441")]
fn fixture_that_decodes_to_another_value_fails() {
    assert_encoding::<DriftingNickname>(&"ada".to_owned(), "616461");
}

#[cfg(feature = "json")]
mod json {
    use cryptbox::{Json, Padding, Seal, SealId, seal_id, testing::assert_encoding};
    use serde::{Deserialize, Serialize};

    // The committed fixture for `{"postal_code":"1010"}`, written before the
    // value type below gained `rename_all`.
    const HOME_ADDRESS: &str = "7b22706f7374616c5f636f6465223a2231303130227d";

    mod before {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        pub struct Address {
            pub postal_code: String,
        }
    }

    /// The same value type after an innocent-looking serde attribute change.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Address {
        postal_code: String,
    }

    struct HomeAddressBefore;

    impl Seal for HomeAddressBefore {
        const ID: SealId = seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
        const PADDING: Padding = Padding::NONE;
        type Value = before::Address;
        type Codec = Json;
        type Bound = ();
        type Record = ();
        type Indexes = ();
    }

    struct HomeAddress;

    impl Seal for HomeAddress {
        const ID: SealId = seal_id!("0b6f3c2a-8e41-4d57-a9c3-5e1f2d7b8a64");
        const PADDING: Padding = Padding::NONE;
        type Value = Address;
        type Codec = Json;
        type Bound = ();
        type Record = ();
        type Indexes = ();
    }

    #[test]
    fn fixture_pins_the_serde_representation() {
        let address = before::Address {
            postal_code: "1010".to_owned(),
        };

        assert_encoding::<HomeAddressBefore>(&address, HOME_ADDRESS);
    }

    #[test]
    #[should_panic(expected = "encoding changed")]
    fn serde_attribute_change_fails_the_fixture() {
        let address = Address {
            postal_code: "1010".to_owned(),
        };

        assert_encoding::<HomeAddress>(&address, HOME_ADDRESS);
    }

    struct Latitude;

    impl Seal for Latitude {
        const ID: SealId = seal_id!("6b1e0d2f-4c3a-4f85-a7d6-1e9c8b0a2f47");
        const PADDING: Padding = Padding::NONE;
        type Value = f64;
        type Codec = Json;
        type Bound = ();
        type Record = ();
        type Indexes = ();
    }

    #[test]
    fn floats_decode_to_exactly_the_encoded_value() {
        // serde_json's default parser reads this back one ulp off.
        assert_encoding::<Latitude>(
            &1.071_566_039_146_582_6e-75,
            "312e30373135363630333931343635383236652d3735",
        );
    }
}
