#![cfg(feature = "causal-authority")]

use ed25519_dalek::SigningKey;
use serde_json::Value;
use xenia_wire::Sealable;
use xenia_wire::authority::{
    AuthorityUsePolicy, CausalAuthorityResponse, ExternalActionAuthorityV1, authority_instance_id,
    authority_request_digest, verify_approved_external_action_authority,
};
use xenia_wire::consent::{ConsentRequest, ConsentRequestCore, ConsentScope};

const VECTOR: &str = include_str!("../test-vectors/13_causal_authority_v1.json");

fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must have an even number of digits");
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn fixed<const N: usize>(value: &str) -> [u8; N] {
    hex_bytes(value).try_into().unwrap()
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[test]
fn rust_reproduces_causal_authority_v1_vector() {
    let fixture: Value = serde_json::from_str(VECTOR).unwrap();
    let expected = &fixture["expected"];

    let requester = SigningKey::from_bytes(&fixed::<32>(
        fixture["requester_seed_hex"].as_str().unwrap(),
    ));
    let responder = SigningKey::from_bytes(&fixed::<32>(
        fixture["responder_seed_hex"].as_str().unwrap(),
    ));
    let session_fingerprint = fixed::<32>(fixture["session_fingerprint_hex"].as_str().unwrap());

    assert_eq!(
        hex(&requester.verifying_key().to_bytes()),
        fixture["requester_public_key_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(&responder.verifying_key().to_bytes()),
        fixture["responder_public_key_hex"].as_str().unwrap()
    );

    let authority_fixture = &fixture["authority"];
    let authority = ExternalActionAuthorityV1 {
        subject_id: fixed::<16>(authority_fixture["subject_id_hex"].as_str().unwrap()),
        target: hex_bytes(authority_fixture["target_hex"].as_str().unwrap()),
        capability: hex_bytes(authority_fixture["capability_hex"].as_str().unwrap()),
        action_digest: fixed::<32>(authority_fixture["action_digest_hex"].as_str().unwrap()),
        parameters_digest: fixed::<32>(
            authority_fixture["parameters_digest_hex"].as_str().unwrap(),
        ),
        max_scope: hex_bytes(authority_fixture["max_scope_hex"].as_str().unwrap()),
        expires_at_ms: authority_fixture["expires_at_ms"].as_u64().unwrap(),
        use_policy: AuthorityUsePolicy::SingleUse,
    };
    assert_eq!(authority_fixture["use_policy_variant"].as_u64(), Some(0));

    assert_eq!(
        hex(&bincode::serialize(&authority).unwrap()),
        expected["authority_payload_hex"].as_str().unwrap()
    );

    let predicate = authority.to_causal_predicate().unwrap();
    assert_eq!(
        hex(&predicate.opaque),
        expected["causal_opaque_hex"].as_str().unwrap()
    );

    assert_eq!(fixture["consent_scope_variant"].as_u64(), Some(3));
    let request = ConsentRequest::sign(
        ConsentRequestCore {
            request_id: fixture["request_id"].as_u64().unwrap(),
            requester_pubkey: requester.verifying_key().to_bytes(),
            session_fingerprint,
            valid_until: fixture["valid_until"].as_u64().unwrap(),
            scope: ConsentScope::Interactive,
            reason: fixture["request_reason"].as_str().unwrap().to_owned(),
            causal_binding: Some(predicate),
        },
        &requester,
    );

    assert_eq!(
        hex(&bincode::serialize(&request.core).unwrap()),
        expected["consent_request_core_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(&request.signature),
        expected["consent_request_signature_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(&request.to_bin().unwrap()),
        expected["consent_request_hex"].as_str().unwrap()
    );

    let request_digest = authority_request_digest(&request).unwrap();
    assert_eq!(
        hex(&request_digest),
        expected["request_digest_hex"].as_str().unwrap()
    );

    let response_fixture = &fixture["response"];
    let response = CausalAuthorityResponse::sign_for_request(
        &request,
        response_fixture["approved"].as_bool().unwrap(),
        response_fixture["issued_at_ms"].as_u64().unwrap(),
        response_fixture["reason"].as_str().unwrap(),
        &responder,
    )
    .unwrap();

    assert_eq!(
        hex(&bincode::serialize(&response.core).unwrap()),
        expected["causal_response_core_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(&response.signature),
        expected["causal_response_signature_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(&response.to_bin().unwrap()),
        expected["causal_response_hex"].as_str().unwrap()
    );

    let authority_id = authority_instance_id(&response);
    assert_eq!(
        hex(&authority_id),
        expected["authority_id_hex"].as_str().unwrap()
    );

    let verified = verify_approved_external_action_authority(
        &request,
        &response,
        &[],
        &requester.verifying_key().to_bytes(),
        &responder.verifying_key().to_bytes(),
        &session_fingerprint,
        11_000,
    )
    .unwrap();
    assert_eq!(verified.authority_id, authority_id);
    assert_eq!(verified.request_digest, request_digest);
    assert_eq!(verified.authority, authority);
}
