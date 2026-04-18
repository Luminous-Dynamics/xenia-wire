# papers/

Academic papers associated with the Xenia Protocol.

## Files

- `xenia-paper.md` — Draft of the Xenia wire-protocol paper,
  corresponding to `xenia-wire 0.1.0-alpha.1` + SPEC.md draft-01.
  Pre-alpha; actively soliciting cryptographer and MSP-practitioner
  review. 8 sections (~4,800 words), 2 appendices.
- `refs.bib` — BibTeX references.

## Status

- **xenia-paper.md**: Draft. Ready for review circulation. Target
  venues (decision at end of Week 3): USENIX Security 2027, NDSS
  2027, ACM CCS 2027, IEEE S&P 2027. Fallback: arxiv + a systems-
  conference workshop.

## Converting to LaTeX / PDF

Markdown was chosen for the draft to reduce friction during review
rounds. Before submission, convert via:

```console
$ pandoc papers/xenia-paper.md \
    --citeproc \
    --bibliography=papers/refs.bib \
    --csl=papers/ieee.csl \
    --template=papers/usenix.latex \
    -o papers/xenia-paper.pdf
```

(Templates are venue-specific and are not checked into this
repository — they'll be added when a submission target is chosen.)

## Non-goal

This paper is not a replacement for `SPEC.md`. The spec is the
normative reference for implementers. The paper is the academic
exposition — rationale, empirical evaluation, and design-space
discussion. An implementer should read SPEC.md; a reviewer or
protocol-curious reader should read the paper.
