# The single point of failure at the top of your remote-control stack

**Target**: r/sysadmin, r/msp, LinkedIn (MSP audience).
**Status**: draft, not yet posted. Lightly adjust for each venue.
**Length**: ~900 words; roughly 4-minute read.
**Tone**: I operate my own shop; I respect your shop; the pitch is
structural, not hostile to the vendors.

---

If you run a managed service provider shop, you probably remember
February 2024. ConnectWise ScreenConnect had a CVSS-10
authentication-bypass vulnerability (CVE-2024-1709). It was public on
February 19th, exploited in the wild within 24 hours, and by the
end of the week ransomware affiliates — including Black Basta — were
using it to pivot into the customer networks of every MSP running an
unpatched instance.

The technical fix was simple. The structural problem was not.

I don't want to spend this post relitigating the CVE. Every sysadmin
who runs ConnectWise already patched it. Everyone who ran an
internet-facing ScreenConnect without patch discipline has already had
their incident. What I want to talk about is the thing that will make
the *next* one happen the same way.

## The architectural pattern

Modern remote-control tools — ConnectWise, TeamViewer, AnyDesk,
Splashtop — concentrate three things in one vendor:

1. **Identity**. Who the technician is.
2. **Authority**. Whose machines they're allowed to reach.
3. **Authentication**. How they prove they are who they say they
   are.

When those three things live in one vendor's identity provider, one
vendor's license database, and one vendor's authentication layer, you
have a **single architectural point of failure**. Compromise the
vendor at any of the three, and every downstream MSP inherits the
compromise. No amount of endpoint detection, patching, or backup
hygiene changes that. It's not a code property — it's a topology
property.

CVE-2024-1709 is the pattern's canonical example, but the pattern
predates it and will outlast it. Kaseya VSA (July 2021). SolarWinds
Orion (December 2020). And those are only the ones that became
public. The private incident list is longer.

## Why the vendors built it this way

Not out of carelessness. Concentration is the economically rational
choice for a centralized-tenant MSP tool. A single relay server makes
NAT traversal tractable. A single identity provider makes onboarding
fast. A single license database makes seat management easy. Spreading
these across a federated architecture makes everything harder for
the vendor's product team and support organization.

The vendors are not wrong that concentration is cheap to build. They
are wrong that the cost of concentration is purely a product-cost
question. In a world where MSPs are the single-highest-leverage
target for ransomware affiliates, the cost of concentration includes
every breach that propagates through the single point of failure.
That externality is paid by MSPs and their clients, not by the
vendor.

## What could be different

You can build a remote-control protocol where identity lives on the
technician's own device, authority is evaluated against a
decentralized trust graph (MSPs signing their own technicians), and
authentication is a per-session cryptographic ceremony — not a
vendor-issued session token that a breached vendor can mint. The
technology to do this exists. It's been in IETF drafts for years.
It mostly just hasn't been packaged for MSPs.

I'm building part of that package. The protocol I'm working on is
called [Xenia](https://github.com/Luminous-Dynamics/xenia-wire) —
after the Greek covenant between guest and host. A pre-alpha Rust
crate [just landed on crates.io](https://crates.io/crates/xenia-wire).
It specifies:

- The byte-level wire (ChaCha20-Poly1305 AEAD, sliding replay
  window, LZ4-before-seal compression that actually works).
- A signed **consent ceremony** — before the technician can see a
  customer's screen, the customer's device signs a
  `ConsentResponse` naming the scope and time limit. The technician
  can't forge it; the MSP can't forge it; a breached vendor can't
  forge it. Revocation terminates the session asymmetrically.
- Design-space hooks for a post-quantum handshake (ML-KEM-768) and
  a decentralized-identity layer on Holochain. Those are separate
  work tracks, but the architecture is ready to accept them
  without wire-format changes.

It is explicitly *not* a drop-in ConnectWise replacement today. It's
a wire protocol with a spec, a reference implementation, and a
browser demo. It's the bottom of the stack. A full MSP product is a
different conversation — one I'm not currently starting.

## What I want from this post

Two honest things:

**First**: if you operate an MSP and the architecture above resonates
(or doesn't — either is useful), I'd like to know. What does your
threat model actually look like? What keeps you using the vendors you
use? Is it the product, the integrations, the support contract, the
compliance paper trail? The answer shapes whether a Xenia-based
architecture is a thing MSPs would actually adopt, or a thing that
only makes sense to other protocol nerds.

**Second**: if you know a cybersecurity researcher, cryptographer, or
decentralized-identity practitioner who might glance at the spec —
please throw it in front of them. The protocol is
[pre-alpha](https://github.com/Luminous-Dynamics/xenia-wire/blob/main/SPEC.md);
I need the cryptographic review to happen *before* the wire format
freezes, not after.

If any of this sounds interesting and you want to talk through the
architecture for 20 minutes, my calendar is in my GitHub profile.
I'm not pitching a product. I'm trying to figure out if the thing
I'm building matches the problem you actually have.

*— Tristan Stoltz / Luminous Dynamics*

---

## Further reading

- Xenia crate, spec, paper:
  <https://github.com/Luminous-Dynamics/xenia-wire>
- The launch blog post (for a more technical audience):
  [BLOG_POST_1.md](BLOG_POST_1.md)
- Papers — academic draft is in `papers/xenia-paper.md` in the repo;
  empirical section benchmarks bandwidth, head-of-line blocking, and
  LZ4 compression on real mobile hardware.
