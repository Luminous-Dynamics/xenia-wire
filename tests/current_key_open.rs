use xenia_wire::{NonceDomain, Sealable, Session, WireError, open_current_key_from_nonce_domain};

#[derive(Debug, PartialEq, Eq)]
struct TestPayload(Vec<u8>);

impl Sealable for TestPayload {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        Ok(self.0.clone())
    }

    fn from_bin(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(Self(bytes.to_vec()))
    }
}

struct RejectPayload;

impl Sealable for RejectPayload {
    fn to_bin(&self) -> Result<Vec<u8>, WireError> {
        Ok(Vec::new())
    }

    fn from_bin(_bytes: &[u8]) -> Result<Self, WireError> {
        Err(WireError::OpenFailed)
    }
}

const SOURCE: [u8; 8] = *b"currkey1";
const OTHER_SOURCE: [u8; 8] = *b"badrole1";
const EPOCH: u8 = 7;
const PAYLOAD: u8 = 0x31;
const KEY_A: [u8; 32] = [0x11; 32];
const KEY_B: [u8; 32] = [0x22; 32];
const KEY_C: [u8; 32] = [0x33; 32];

fn session(source: [u8; 8], key: [u8; 32]) -> Session {
    let mut session = Session::with_source_id(source, EPOCH);
    session.install_key(key);
    session
}

fn expected_domain() -> NonceDomain {
    NonceDomain::from_source_id(SOURCE, PAYLOAD, EPOCH)
}

fn strict_open(bytes: &[u8], receiver: &mut Session) -> Result<TestPayload, WireError> {
    open_current_key_from_nonce_domain(bytes, receiver, expected_domain())
}

#[test]
fn current_key_success_consumes_live_replay_once() {
    let mut sender = session(SOURCE, KEY_B);
    let mut receiver = session(SOURCE, KEY_B);
    let sealed = sender.seal(b"current", PAYLOAD).unwrap();

    assert_eq!(
        strict_open(&sealed, &mut receiver).unwrap(),
        TestPayload(b"current".to_vec())
    );
    assert!(matches!(
        strict_open(&sealed, &mut receiver),
        Err(WireError::OpenFailed)
    ));
}

#[test]
fn previous_key_rejects_before_current_epoch_replay_mutation() {
    let mut old_sender = session(SOURCE, KEY_A);
    let old_seq0 = old_sender.seal(b"old", PAYLOAD).unwrap();

    let mut receiver = session(SOURCE, KEY_A);
    receiver.install_key(KEY_B);
    assert!(matches!(
        strict_open(&old_seq0, &mut receiver),
        Err(WireError::OpenFailed)
    ));

    let mut current_sender = session(SOURCE, KEY_B);
    let current_seq0 = current_sender.seal(b"new", PAYLOAD).unwrap();
    assert_eq!(
        strict_open(&current_seq0, &mut receiver).unwrap(),
        TestPayload(b"new".to_vec())
    );
}

#[test]
fn ordinary_open_still_accepts_previous_key_during_grace() {
    let mut old_sender = session(SOURCE, KEY_A);
    let old = old_sender.seal(b"in-flight", PAYLOAD).unwrap();

    let mut receiver = session(SOURCE, KEY_A);
    receiver.install_key(KEY_B);
    assert_eq!(receiver.open(&old).unwrap(), b"in-flight");
}

#[test]
fn strict_current_key_open_rejects_malformed_and_wrong_key() {
    let mut receiver = session(SOURCE, KEY_B);
    assert!(matches!(
        strict_open(&[0u8; 12], &mut receiver),
        Err(WireError::OpenFailed)
    ));

    let mut wrong_sender = session(SOURCE, KEY_C);
    let wrong = wrong_sender.seal(b"wrong", PAYLOAD).unwrap();
    assert!(matches!(
        strict_open(&wrong, &mut receiver),
        Err(WireError::OpenFailed)
    ));
}

#[test]
fn current_key_success_survives_multiple_rapid_rekeys() {
    let mut receiver = session(SOURCE, KEY_A);
    receiver.install_key(KEY_B);
    receiver.install_key(KEY_C);

    let mut sender = session(SOURCE, KEY_C);
    let sealed = sender.seal(b"epoch-c", PAYLOAD).unwrap();
    assert_eq!(
        strict_open(&sealed, &mut receiver).unwrap(),
        TestPayload(b"epoch-c".to_vec())
    );
}

#[test]
fn strict_current_key_helper_rejects_wrong_role_before_replay() {
    let mut receiver = session(SOURCE, KEY_B);

    let mut wrong_role = session(OTHER_SOURCE, KEY_B);
    let wrong = wrong_role.seal(b"wrong-role", PAYLOAD).unwrap();
    assert!(matches!(
        strict_open(&wrong, &mut receiver),
        Err(WireError::OpenFailed)
    ));

    let mut right_role = session(SOURCE, KEY_B);
    let right = right_role.seal(b"right-role", PAYLOAD).unwrap();
    assert_eq!(
        strict_open(&right, &mut receiver).unwrap(),
        TestPayload(b"right-role".to_vec())
    );
}

#[test]
fn strict_current_key_helper_never_falls_back_to_previous_key() {
    let mut old_sender = session(SOURCE, KEY_A);
    let old = old_sender.seal(b"old", PAYLOAD).unwrap();

    let mut receiver = session(SOURCE, KEY_A);
    receiver.install_key(KEY_B);

    assert!(matches!(
        strict_open(&old, &mut receiver),
        Err(WireError::OpenFailed)
    ));
}

#[test]
fn failed_current_key_aead_does_not_consume_current_replay_slot() {
    let mut receiver = session(SOURCE, KEY_B);

    let mut wrong_sender = session(SOURCE, KEY_C);
    let wrong_seq0 = wrong_sender.seal(b"wrong-key", PAYLOAD).unwrap();
    assert!(matches!(
        strict_open(&wrong_seq0, &mut receiver),
        Err(WireError::OpenFailed)
    ));

    let mut right_sender = session(SOURCE, KEY_B);
    let right_seq0 = right_sender.seal(b"right-key", PAYLOAD).unwrap();
    assert_eq!(
        strict_open(&right_seq0, &mut receiver).unwrap(),
        TestPayload(b"right-key".to_vec())
    );
}

#[test]
fn semantic_decode_rejection_keeps_authenticated_replay_consumed() {
    let mut sender = session(SOURCE, KEY_B);
    let mut receiver = session(SOURCE, KEY_B);
    let sealed = sender.seal(b"authenticated-but-rejected", PAYLOAD).unwrap();

    assert!(matches!(
        open_current_key_from_nonce_domain::<RejectPayload>(
            &sealed,
            &mut receiver,
            expected_domain(),
        ),
        Err(WireError::OpenFailed)
    ));

    // Authentication and replay acceptance happened before the semantic
    // decoder rejected the plaintext, so retrying the exact envelope through
    // a decoder that would otherwise accept it must still fail as a replay.
    assert!(matches!(
        strict_open(&sealed, &mut receiver),
        Err(WireError::OpenFailed)
    ));
}

#[cfg(feature = "consent")]
#[test]
fn consent_rejection_uses_same_live_replay_slot_on_current_key_path() {
    use xenia_wire::PAYLOAD_TYPE_FRAME;

    let mut sender = session(SOURCE, KEY_B);
    let mut receiver = Session::builder()
        .with_source_id(SOURCE, EPOCH)
        .require_consent(true)
        .build();
    receiver.install_key(KEY_B);

    let sealed = sender.seal(b"frame-before-consent", PAYLOAD_TYPE_FRAME).unwrap();
    let frame_domain = NonceDomain::from_source_id(SOURCE, PAYLOAD_TYPE_FRAME, EPOCH);

    // Current-key authentication succeeds, the live replay slot is consumed,
    // and then the shared consent gate rejects the application payload.
    assert!(open_current_key_from_nonce_domain::<TestPayload>(
        &sealed,
        &mut receiver,
        frame_domain,
    )
    .is_err());

    // Consent rejection must not make an already authenticated envelope
    // replayable. The exact packet is rejected by the live replay window on
    // the second attempt, before any later consent-state change could matter.
    assert!(matches!(
        open_current_key_from_nonce_domain::<TestPayload>(
            &sealed,
            &mut receiver,
            frame_domain,
        ),
        Err(WireError::OpenFailed)
    ));
}
