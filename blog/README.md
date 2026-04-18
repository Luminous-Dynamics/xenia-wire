# blog/

Launch-adjacent content that isn't part of the normative spec or the
academic paper.

- [`BLOG_POST_1.md`](BLOG_POST_1.md) — announcement draft for
  technical audiences (Hacker News, lobste.rs, r/rust). Frames
  Xenia as a Rust-ecosystem artifact seeking crypto review.
- [`BLOG_POST_2.md`](BLOG_POST_2.md) — announcement draft for
  MSP practitioners (r/sysadmin, r/msp, LinkedIn). Frames the
  decentralized-trust pitch via the ConnectWise
  CVE-2024-1709 pattern.

## Posting checklist

Before posting:

- [ ] Double-check all links (crates.io version, GitHub URLs).
- [ ] Confirm `xenia-wire` crate is still the latest version on
      crates.io (bump the cited version in the posts if not).
- [ ] For r/sysadmin + r/msp: respect the subreddit rules on
      self-promotion — many require disclosure and/or prohibit
      bare launches. Add a comment-reply plan, not just a top-
      post.
- [ ] For Hacker News: "Show HN" format is appropriate. Avoid
      hyperbole; the pre-alpha banner is load-bearing and must
      appear in the first paragraph of the comment thread.
- [ ] For lobste.rs: invite-only. Verify you have posting rights
      before drafting the submission.

## Tone guidance

- **No hype.** The protocol is pre-alpha. Overselling it will
  invite reviewers who come looking for holes and find plenty.
- **Specific asks, not vague ones.** Every solicitation should
  name the file/section it wants feedback on.
- **Credit generously.** The crate sits on RustCrypto, LZ4,
  Noise/Signal protocol legacy, and IETF replay-protection work.
  Do not erase the lineage.

## Cross-linking

Both posts link to:

- `https://crates.io/crates/xenia-wire/0.1.0-alpha.3`
- `https://github.com/Luminous-Dynamics/xenia-wire`
- `SPEC.md` on the repo
- `papers/xenia-paper.md` on the repo

If the crate version bumps, update the crates.io link in both posts
before re-publishing anywhere.
