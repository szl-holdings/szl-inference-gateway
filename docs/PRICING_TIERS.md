# x402 Pricing Tiers (DRAFT, PROPOSE-ONLY)

Status: leader absorb (Ouroboros Cluster F). Text only in this proposal: no worker change, no route change, no revenue claim. Do not merge without explicit owner GO. Zone-level CF wiring remains owner-gated (Cloudflare Zone:Edit token not yet provided).

## Measured today

- Current gateway price: $0.02 per request (USDC on Base), x402 v2 payment challenge on unpaid POST; fail-closed signed PAYMENT-CONTEXT origin gate validates Ed25519 JWT, exact route, timing, amount, pinned JWKS, and replay state per docs/PAYMENT_CONTEXT_GATE.md.
- Scope discipline carried verbatim from the README: reachability and posture claims only; no quality, latency, SLA, or paid-receipt claims in this document.

## Segment evidence (public sources; REPORTED, not MEASURED by the estate)

- The >= $1 advisory/inference request segment is the durable value segment per the Ouroboros leader pack (Round 2, Cluster F), following public reporting: chainalysis.com/blog/x402-agentic-payments-adoption/ (VERIFIED observable). CoinDesk 2026-07 reporting of Visa/Mastercard/Ripple joining the standard and 75M payments / $24M moved (REPORTED by source, not estate-verified). x402.agiscorecard.com (watch). Fireblocks agent-economy numbers (watch).

## Proposed tier map (draft)

| Tier | Price | Enforcement | State |
|---|---|---|---|
| economy | $0.02/request | current PAYMENT-CONTEXT gate | LIVE (measured) |
| advisory | $1.00 to $10.00/request | same gate; amount pin + route pin per tier | PROPOSED (no implementation) |
| agent-contract | volume/commit terms | out of scope until CF zone wiring | PARKED (owner-gated) |

Tiers are enforced ONLY through the existing signed PAYMENT-CONTEXT origin gate (exact-route + amount + timing + JWKS + replay checks): a tier is a pinned amount/route pair in the gate contract, never a change to admission semantics. Amount-pin and route-pin parameters for the advisory tier are implementation work for a future, code-gated PR.

## Honesty lines

- No revenue, adoption, or volume number for the ESTATE is claimed anywhere above.
- The price table is a proposal; the only priced route that exists today is the $0.02 economy tier.
- External statistics are attributed to their reporting sources and marked REPORTED/watch accordingly.