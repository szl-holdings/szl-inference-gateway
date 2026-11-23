# Signed PAYMENT-CONTEXT origin gate

The production recipe now exposes only recipe/origin_proxy.py on the tunnel
port. llama-server binds to loopback port 11435 and cannot receive public
traffic directly. The proxy exposes GET /health and /v1/models for
read-only posture checks. It forwards only POST
/v1/chat/completions requests that pass authorize_payment_context.

The gate requires two runtime settings:

- PAYMENT_CONTEXT_JWKS_FILE points to an operator-injected Ed25519 JWKS
  document.
- PAYMENT_CONTEXT_JWKS_SHA256 is the exact SHA-256 digest of those bytes.

The key document is never fetched by the recipe or committed to source. Every
paid request must carry a signed PAYMENT-CONTEXT JWT with EdDSA, a pinned
kid, the exact resource audience, scheme=exact, amount 20000, and a bounded
iat/nbf/exp window. The process-local replay cache consumes each token once.
Missing, malformed, wrong-route, unknown-key, bad-signature, wrong-audience,
wrong-amount, expired, or replayed requests receive a fixed HOLD response
and never reach llama-server.

The source gate establishes per-request inference admission. Operators still
need deployment-level negative tests and key-custody review before treating
a live endpoint as independently verified.
