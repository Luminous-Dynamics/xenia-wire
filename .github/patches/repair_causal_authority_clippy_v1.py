#!/usr/bin/env python3
from pathlib import Path

path = Path("src/authority.rs")
text = path.read_text()

replacements = [
    (
        "reason.as_bytes().len() > MAX_AUTHORITY_RESPONSE_REASON_BYTES",
        "reason.len() > MAX_AUTHORITY_RESPONSE_REASON_BYTES",
    ),
    (
        "self.core.reason.as_bytes().len() > MAX_AUTHORITY_RESPONSE_REASON_BYTES",
        "self.core.reason.len() > MAX_AUTHORITY_RESPONSE_REASON_BYTES",
    ),
    (
        "request.core.reason.as_bytes().len() > MAX_AUTHORITY_REQUEST_REASON_BYTES",
        "request.core.reason.len() > MAX_AUTHORITY_REQUEST_REASON_BYTES",
    ),
]

for old, new in replacements:
    count = text.count(old)
    assert count == 1, (old, count)
    text = text.replace(old, new)

path.write_text(text)
