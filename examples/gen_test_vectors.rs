// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Generate deterministic test vectors for cross-implementation validation.
//!
//! Every fixture uses a fixed `source_id`, `epoch`, key, and payload so
//! the resulting envelope bytes are byte-for-byte reproducible. An
//! implementation in another language (Go, Swift, Python, Zig) can
//! consume these files to verify interop.
//!
//! Run with: `cargo run --example gen_test_vectors --all-features`
//!
//! Outputs into `test-vectors/`:
//!
//! - `NN_description.txt` — human-readable explanation
//! - `NN_description.input.hex` — the plaintext fed into seal
//! - `NN_description.envelope.hex` — the AEAD-sealed envelope
//!
//! The `.input.hex` for framed payloads is the bincode encoding of
//! the `Frame` or `Input` struct, NOT the raw user payload. An
//! independent implementation must match the bincode layout for
//! `{frame_id: u64, timestamp_ms: u64, payload: Vec<u8>}` using
//! bincode v1 default-little-endian fixint encoding.

use std::fs;
use std::path::Path;
use xenia_wire::{Frame, Input, Sealable, Session, PAYLOAD_TYPE_FRAME, PAYLOAD_TYPE_INPUT};

fn main() -> std::io::Result<()> {
    let out_dir = Path::new("test-vectors");
    fs::create_dir_all(out_dir)?;

    emit_01_hello_frame(out_dir)?;
    emit_02_input_pointer(out_dir)?;
    emit_03_empty_payload(out_dir)?;
    emit_04_long_payload(out_dir)?;
    emit_05_nonce_structure(out_dir)?;
    #[cfg(feature = "lz4")]
    emit_06_lz4_frame(out_dir)?;
    #[cfg(feature = "consent")]
    emit_07_consent_request(out_dir)?;

    write_index(out_dir)?;
    println!("Wrote test vectors to {}", out_dir.display());
    Ok(())
}

// Fixtures shared across vectors.
const FIXED_KEY: [u8; 32] = *b"xenia-wire-test-vector-key-2026!";
const FIXED_SOURCE_ID: [u8; 8] = *b"XENIATST";
const FIXED_EPOCH: u8 = 0x42;

fn deterministic_session() -> Session {
    let mut s = Session::with_source_id(FIXED_SOURCE_ID, FIXED_EPOCH);
    s.install_key(FIXED_KEY);
    s
}

fn write_hex(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // Format as lines of 32 hex chars (16 bytes per line) for diff-ability.
    let mut out = String::new();
    for chunk in bytes.chunks(16) {
        for b in chunk {
            out.push_str(&format!("{:02x}", b));
        }
        out.push('\n');
    }
    fs::write(path, out)
}

fn emit_01_hello_frame(out: &Path) -> std::io::Result<()> {
    let mut session = deterministic_session();
    let frame = Frame {
        frame_id: 1,
        timestamp_ms: 1_700_000_000_000,
        payload: b"hello, xenia".to_vec(),
    };
    let plaintext = frame.to_bin().unwrap();
    let envelope = session
        .seal(&plaintext, PAYLOAD_TYPE_FRAME)
        .expect("seal succeeds");

    write_hex(&out.join("01_hello_frame.input.hex"), &plaintext)?;
    write_hex(&out.join("01_hello_frame.envelope.hex"), &envelope)?;
    fs::write(
        out.join("01_hello_frame.txt"),
        "Vector 01: hello_frame\n\
         ----------------------\n\
         A minimal Frame with a 12-byte UTF-8 payload \"hello, xenia\".\n\
         This is the canonical roundtrip fixture.\n\n\
         Scenario:\n\
           source_id = \"XENIATST\"  (8 bytes)\n\
           epoch     = 0x42\n\
           key       = \"xenia-wire-test-vector-key-2026!\"  (32 bytes)\n\
           seq       = 0  (first seal on this session)\n\
           payload_type = 0x10 (FRAME)\n\n\
         Frame struct (bincode-encoded in .input.hex):\n\
           frame_id     = 1          (u64 LE: 0100000000000000)\n\
           timestamp_ms = 1700000000000 (u64 LE: 008b0e0095010000)\n\
           payload      = \"hello, xenia\" (length-prefixed: 0c00000000000000 + utf8)\n\n\
         Envelope layout (.envelope.hex):\n\
           bytes [0..6]   = source_id[0..6]  = 58454e49415453\n\
           byte  [6]      = payload_type     = 10\n\
           byte  [7]      = epoch            = 42\n\
           bytes [8..12]  = sequence LE u32  = 00000000\n\
           bytes [12..]   = ChaCha20-Poly1305 ciphertext || tag (16-byte tag)\n",
    )
}

fn emit_02_input_pointer(out: &Path) -> std::io::Result<()> {
    let mut session = deterministic_session();
    let input = Input {
        sequence: 0,
        timestamp_ms: 1_700_000_000_050,
        payload: b"tap".to_vec(),
    };
    let plaintext = input.to_bin().unwrap();
    let envelope = session.seal(&plaintext, PAYLOAD_TYPE_INPUT).unwrap();

    write_hex(&out.join("02_input_pointer.input.hex"), &plaintext)?;
    write_hex(&out.join("02_input_pointer.envelope.hex"), &envelope)?;
    fs::write(
        out.join("02_input_pointer.txt"),
        "Vector 02: input_pointer\n\
         ------------------------\n\
         A minimal Input with a 3-byte payload \"tap\".\n\
         Demonstrates payload_type=0x11 domain separation on the\n\
         reverse path.\n\n\
         Scenario:\n\
           source_id = \"XENIATST\"\n\
           epoch     = 0x42\n\
           key       = fixture-key\n\
           seq       = 0\n\
           payload_type = 0x11 (INPUT)\n\n\
         Note: because payload_type differs from vector 01, the nonce\n\
         differs even though sequence and source_id are identical.\n\
         This is the domain-separation property — same key, same\n\
         source, same seq, different stream ≠ nonce collision.\n",
    )
}

fn emit_03_empty_payload(out: &Path) -> std::io::Result<()> {
    let mut session = deterministic_session();
    let frame = Frame {
        frame_id: 42,
        timestamp_ms: 1_700_000_000_100,
        payload: vec![],
    };
    let plaintext = frame.to_bin().unwrap();
    let envelope = session.seal(&plaintext, PAYLOAD_TYPE_FRAME).unwrap();

    write_hex(&out.join("03_empty_payload.input.hex"), &plaintext)?;
    write_hex(&out.join("03_empty_payload.envelope.hex"), &envelope)?;
    fs::write(
        out.join("03_empty_payload.txt"),
        "Vector 03: empty_payload\n\
         ------------------------\n\
         Frame with zero-length payload. Verifies empty-plaintext\n\
         sealing works correctly.\n\n\
         Scenario:\n\
           source_id = \"XENIATST\"\n\
           epoch     = 0x42\n\
           key       = fixture-key\n\
           seq       = 0\n\
           frame_id = 42, payload = []\n\n\
         Envelope is 12 (nonce) + 24 (bincode header: frame_id + ts + len=0)\n\
         + 16 (tag) = 52 bytes.\n",
    )
}

fn emit_04_long_payload(out: &Path) -> std::io::Result<()> {
    let mut session = deterministic_session();
    let payload: Vec<u8> = (0..=255).collect();
    let frame = Frame {
        frame_id: 256,
        timestamp_ms: 1_700_000_000_200,
        payload: payload.clone(),
    };
    let plaintext = frame.to_bin().unwrap();
    let envelope = session.seal(&plaintext, PAYLOAD_TYPE_FRAME).unwrap();

    write_hex(&out.join("04_long_payload.input.hex"), &plaintext)?;
    write_hex(&out.join("04_long_payload.envelope.hex"), &envelope)?;
    fs::write(
        out.join("04_long_payload.txt"),
        "Vector 04: long_payload\n\
         -----------------------\n\
         Frame with a 256-byte payload containing every possible byte\n\
         value 0x00..=0xFF. Verifies sealing on non-compressible,\n\
         all-range plaintext.\n\n\
         Scenario:\n\
           source_id = \"XENIATST\"\n\
           epoch     = 0x42\n\
           key       = fixture-key\n\
           seq       = 0\n\
           payload = 0x00, 0x01, 0x02, ..., 0xFF (256 bytes)\n",
    )
}

fn emit_05_nonce_structure(out: &Path) -> std::io::Result<()> {
    // Seal three envelopes in sequence on the same session. Demonstrates
    // the sequence counter in nonce[8..12] incrementing.
    let mut session = deterministic_session();
    let mut envelopes = Vec::new();
    for i in 0..3 {
        let frame = Frame {
            frame_id: i as u64,
            timestamp_ms: 0,
            payload: vec![i as u8],
        };
        let plaintext = frame.to_bin().unwrap();
        let envelope = session.seal(&plaintext, PAYLOAD_TYPE_FRAME).unwrap();
        envelopes.push(envelope);
    }

    // Concatenate with separators so humans can see the sequence
    // progression in the nonce bytes.
    let mut out_bytes = Vec::new();
    for (i, env) in envelopes.iter().enumerate() {
        out_bytes.extend_from_slice(format!("-- seq {} --\n", i).as_bytes());
        for chunk in env.chunks(16) {
            for b in chunk {
                out_bytes.extend_from_slice(format!("{:02x}", b).as_bytes());
            }
            out_bytes.push(b'\n');
        }
    }
    fs::write(out.join("05_nonce_structure.envelopes.hex"), &out_bytes)?;
    fs::write(
        out.join("05_nonce_structure.txt"),
        "Vector 05: nonce_structure\n\
         --------------------------\n\
         Three sealed envelopes on the same session, demonstrating\n\
         the monotonic sequence in nonce bytes [8..12]:\n\n\
           envelope 0: nonce[8..12] = 00000000  (seq = 0)\n\
           envelope 1: nonce[8..12] = 01000000  (seq = 1, little-endian)\n\
           envelope 2: nonce[8..12] = 02000000  (seq = 2)\n\n\
         source_id[0..6], payload_type, and epoch are identical across\n\
         all three envelopes — only the sequence bytes advance.\n\n\
         This vector tests that an independent implementation constructs\n\
         the nonce in the exact byte order specified in SPEC.md §3.\n",
    )
}

#[cfg(feature = "lz4")]
fn emit_06_lz4_frame(out: &Path) -> std::io::Result<()> {
    use xenia_wire::seal_frame_lz4;
    let mut session = deterministic_session();
    // Highly compressible payload so LZ4's effect is visible.
    let payload = vec![0x5A; 2048];
    let frame = Frame {
        frame_id: 9,
        timestamp_ms: 1_700_000_000_500,
        payload: payload.clone(),
    };
    let envelope = seal_frame_lz4(&frame, &mut session).unwrap();

    // Reproduce the plaintext path (bincode then LZ4) for the .input.hex
    // so an independent implementation can cross-check the pre-AEAD bytes.
    let bincoded = frame.to_bin().unwrap();
    let lz4_compressed = lz4_flex::block::compress_prepend_size(&bincoded);

    write_hex(&out.join("06_lz4_frame.bincoded.hex"), &bincoded)?;
    write_hex(
        &out.join("06_lz4_frame.lz4_compressed.hex"),
        &lz4_compressed,
    )?;
    write_hex(&out.join("06_lz4_frame.envelope.hex"), &envelope)?;
    fs::write(
        out.join("06_lz4_frame.txt"),
        format!(
            "Vector 06: lz4_frame\n\
            --------------------\n\
            Frame sealed via LZ4-before-AEAD path (seal_frame_lz4).\n\n\
            Scenario:\n\
              source_id = \"XENIATST\"\n\
              epoch     = 0x42\n\
              key       = fixture-key\n\
              seq       = 0\n\
              payload_type = 0x12 (FRAME_LZ4)\n\
              frame.payload = [0x5A; 2048]  (highly compressible)\n\n\
            Pipeline:\n\
              Frame -> bincode         -> {} bytes (.bincoded.hex)\n\
                     -> lz4 prepend-size -> {} bytes (.lz4_compressed.hex)\n\
                     -> AEAD seal      -> {} bytes (.envelope.hex)\n\n\
            The lz4_compressed bytes are what feeds into the AEAD —\n\
            ChaCha20-Poly1305 encrypts those. An implementation in\n\
            another language must produce byte-identical lz4_compressed\n\
            bytes from the bincoded input, then AEAD-seal them with\n\
            the fixed key/nonce to match the envelope.\n\n\
            LZ4 MUST precede AEAD — ciphertext is pseudorandom and does\n\
            not compress. See SPEC.md §7.\n",
            bincoded.len(),
            lz4_compressed.len(),
            envelope.len()
        ),
    )
}

/// Vector 07: consent_request — deterministic consent ceremony fixture.
///
/// Uses a fixed Ed25519 signing key (derived from a fixture-label seed)
/// so the signature is byte-reproducible. An implementation in another
/// language can regenerate the same key from the seed and produce the
/// same signature.
#[cfg(feature = "consent")]
fn emit_07_consent_request(out: &Path) -> std::io::Result<()> {
    use ed25519_dalek::SigningKey;
    use xenia_wire::consent::{ConsentRequest, ConsentRequestCore, ConsentScope};
    use xenia_wire::PAYLOAD_TYPE_CONSENT_REQUEST;

    // Ed25519 seed: 32 bytes derived from the fixture label.
    let seed: [u8; 32] = *b"xenia-consent-test-vector-seed!!";
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();

    let mut session = deterministic_session();

    let core = ConsentRequestCore {
        request_id: 7,
        requester_pubkey: pk,
        valid_until: 1_700_000_300,
        scope: ConsentScope::ScreenAndInput,
        reason: "xenia test vector".to_string(),
        causal_binding: None,
    };
    let request = ConsentRequest::sign(core, &sk);

    let plaintext = request.to_bin_via_trait();
    let envelope = session
        .seal(&plaintext, PAYLOAD_TYPE_CONSENT_REQUEST)
        .expect("seal consent request");

    write_hex(&out.join("07_consent_request.input.hex"), &plaintext)?;
    write_hex(&out.join("07_consent_request.envelope.hex"), &envelope)?;
    fs::write(
        out.join("07_consent_request.txt"),
        "Vector 07: consent_request (draft-02, feature = consent)\n\
         --------------------------------------------------------\n\
         A ConsentRequest for ScreenAndInput scope, signed with a\n\
         deterministic Ed25519 seed. An alternate-language\n\
         implementation can reproduce every byte from the fixture\n\
         seed + the fixed session parameters.\n\n\
         Fixture parameters:\n\
           source_id  = \"XENIATST\"\n\
           epoch      = 0x42\n\
           key        = fixture-key (shared with vectors 01-05)\n\
           payload_type = 0x20 (CONSENT_REQUEST)\n\n\
         Ed25519 signing seed: \"xenia-consent-test-vector-seed!!\" (32 bytes)\n\n\
         ConsentRequest fields:\n\
           request_id     = 7\n\
           requester_pubkey = derived Ed25519 public key\n\
           valid_until    = 1700000300\n\
           scope          = ScreenAndInput (= 1)\n\
           reason         = \"xenia test vector\"\n\
           causal_binding = None (draft-02 MUST be None)\n\n\
         .input.hex is the bincode-encoded ConsentRequest (including\n\
         the 64-byte signature). .envelope.hex is the AEAD-sealed\n\
         form sealed under the fixture key.\n\n\
         To validate: decrypt envelope with fixture key + extracted\n\
         nonce; bincode-deserialize; verify Ed25519 signature over\n\
         bincode(core).\n",
    )
}

// Trait method used only by the generator example — we can't call
// `ConsentRequest::to_bin()` directly because the `Sealable` trait
// method name collides; this wrapper disambiguates.
#[cfg(feature = "consent")]
trait SealableExt: xenia_wire::Sealable {
    fn to_bin_via_trait(&self) -> Vec<u8> {
        self.to_bin().expect("sealable to_bin succeeds")
    }
}
#[cfg(feature = "consent")]
impl<T: xenia_wire::Sealable> SealableExt for T {}

fn write_index(out: &Path) -> std::io::Result<()> {
    fs::write(
        out.join("README.md"),
        "# Test vectors\n\n\
         Deterministic hex fixtures for cross-implementation validation.\n\n\
         ## Format\n\n\
         Each vector ships as three files:\n\n\
         - `NN_description.txt` — human-readable explanation.\n\
         - `NN_description.input.hex` (or `.bincoded.hex` for LZ4) —\n\
           the plaintext fed into `Session::seal()`.\n\
         - `NN_description.envelope.hex` — the AEAD-sealed envelope\n\
           bytes that a receiver would open.\n\n\
         Hex files are 16 bytes per line, lowercase, no separators within\n\
         a line. Strip newlines and parse as a contiguous byte stream.\n\n\
         ## Fixed parameters\n\n\
         All vectors share:\n\n\
         | Parameter | Value |\n\
         |-----------|-------|\n\
         | `source_id` | `58454e494154535420` (ASCII \"XENIATST\", 8 bytes) |\n\
         | `epoch` | `0x42` |\n\
         | `key` | `78656e69612d776972652d746573742d766563746f722d6b65792d3230323621` (ASCII \"xenia-wire-test-vector-key-2026!\", 32 bytes) |\n\n\
         ## Vectors\n\n\
         | # | Name | What it exercises |\n\
         |---|------|-------------------|\n\
         | 01 | hello_frame | Canonical roundtrip, 12-byte UTF-8 payload. |\n\
         | 02 | input_pointer | `payload_type=0x11` domain separation vs vector 01. |\n\
         | 03 | empty_payload | Zero-length plaintext. |\n\
         | 04 | long_payload | 256-byte payload covering every byte value. |\n\
         | 05 | nonce_structure | Three sequential seals demonstrating seq counter increment. |\n\
         | 06 | lz4_frame | LZ4-before-AEAD (`--features lz4` only). |\n\
         | 07 | consent_request | ConsentRequest signed with a deterministic Ed25519 seed (`--features consent` only, draft-02). |\n\n\
         ## Regenerating\n\n\
         ```console\n\
         $ cargo run --example gen_test_vectors --all-features\n\
         ```\n\n\
         Vectors are version-stamped to `xenia-wire 0.1.0-alpha.1`.\n\
         If a version bump changes the wire format, regenerate and\n\
         bump the spec version (SPEC.md §Version history) in the\n\
         same commit.\n\n\
         ## How to use from another language\n\n\
         For each vector:\n\n\
         1. Parse the `.envelope.hex` file into a byte array.\n\
         2. Construct an AEAD decryption context with the fixed key.\n\
         3. Extract nonce from envelope bytes `[0..12]`.\n\
         4. Decrypt envelope bytes `[12..]` using ChaCha20-Poly1305.\n\
         5. Compare the decrypted plaintext against `.input.hex`.\n\n\
         If steps 1-5 succeed and the plaintext matches, your\n\
         implementation is byte-compatible with `xenia-wire` for that\n\
         scenario.\n",
    )
}
