#!/usr/bin/env python3
from pathlib import Path

path = Path("src/attestation.rs")
text = path.read_text()

old_import = "use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};"
new_import = "use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};"
if text.count(old_import) != 1:
    raise SystemExit(f"import anchor count={text.count(old_import)}")
text = text.replace(old_import, new_import, 1)

old_verify = '''        verifying_key
            .verify(&self.core.canonical_preimage()?, &signature)
            .map_err(|_| AttestationError::InvalidSignature)'''
new_verify = '''        verifying_key
            .verify_strict(&self.core.canonical_preimage()?, &signature)
            .map_err(|_| AttestationError::InvalidSignature)'''
if text.count(old_verify) != 1:
    raise SystemExit(f"verification anchor count={text.count(old_verify)}")
text = text.replace(old_verify, new_verify, 1)

path.write_text(text)
