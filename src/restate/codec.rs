//! Restate journal codecs for stored bytes.
//!
//! The codecs move bytes and never encrypt: replay compares journaled bytes,
//! and a fresh nonce would never compare equal. Values are sealed inside
//! `ctx.run` instead; see [`seal`](super::seal).

use std::convert::Infallible;

use bytes::Bytes;
use restate_sdk::serde::{Deserialize, InputMetadata, OutputMetadata, PayloadMetadata, Serialize};

use crate::{BlindIndex, BlindIndexSpec, Error, Seal, Sealed};

const OCTET_STREAM: &str = "application/octet-stream";

/// Journals the binary envelope unchanged.
impl<F: Seal> Serialize for Sealed<F> {
    type Error = Infallible;

    fn serialize(&self) -> Result<Bytes, Self::Error> {
        Ok(Bytes::copy_from_slice(self.as_bytes()))
    }
}

/// Checks the journaled envelope's structure, as [`Sealed::from_bytes`] does.
/// It uses no keys and does not authenticate.
impl<F: Seal> Deserialize for Sealed<F> {
    type Error = Error;

    fn deserialize(bytes: &mut Bytes) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes.to_vec())
    }
}

/// An `application/octet-stream` payload without a JSON schema.
impl<F: Seal> PayloadMetadata for Sealed<F> {
    fn json_schema() -> Option<serde_json::Value> {
        None
    }

    fn input_metadata() -> InputMetadata {
        octet_stream_input()
    }

    fn output_metadata() -> OutputMetadata {
        octet_stream_output()
    }
}

/// Journals the blind index's bytes unchanged.
impl<Spec> Serialize for BlindIndex<Spec> {
    type Error = Infallible;

    fn serialize(&self) -> Result<Bytes, Self::Error> {
        Ok(Bytes::copy_from_slice(self.as_bytes()))
    }
}

/// Checks the journaled blind index's structure, as [`BlindIndex::from_bytes`]
/// does.
impl<Spec: BlindIndexSpec> Deserialize for BlindIndex<Spec> {
    type Error = Error;

    fn deserialize(bytes: &mut Bytes) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes.to_vec())
    }
}

/// An `application/octet-stream` payload without a JSON schema.
impl<Spec> PayloadMetadata for BlindIndex<Spec> {
    fn json_schema() -> Option<serde_json::Value> {
        None
    }

    fn input_metadata() -> InputMetadata {
        octet_stream_input()
    }

    fn output_metadata() -> OutputMetadata {
        octet_stream_output()
    }
}

const fn octet_stream_input() -> InputMetadata {
    InputMetadata {
        accept_content_type: OCTET_STREAM,
        is_required: true,
    }
}

const fn octet_stream_output() -> OutputMetadata {
    OutputMetadata {
        content_type: OCTET_STREAM,
        set_content_type_if_empty: false,
    }
}
