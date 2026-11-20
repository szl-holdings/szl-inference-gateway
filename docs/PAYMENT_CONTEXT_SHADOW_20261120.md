# Cloudflare PAYMENT-CONTEXT signed-claim shadow verification

**SOURCE-ONLY SHADOW — NOT DEPLOYED, NOT PRODUCTION AUTHORIZATION.**

The production recipe currently tunnels directly to raw llama-server.
This PR does not repair the live origin, change Cloudflare, or authorize
inference. The production HOLD is tracked under SZL inference-gateway #7.
Existing $0.02 Cloudflare payment rules are not touched.

Official requirements:
https://developers.cloudflare.com/monetization-gateway/configuration/payment-validation/

The origin must validate the Ed25519 signed PAYMENT-CONTEXT JWT using
pinned public JWKS from https://payments.cloudflare.com/certs and verify
audience, timing, scheme and atomic-unit amount before serving paid content.

## Offline verified scope

The Python module payment_context_shadow.py is pure CPU code with no network
or payment API calls. It consumes an operator-provided sample token, a
preselected hash-pinned public JWKS byte document, exact request method
and full resource URL, and the caller's UTC timestamp. It checks:
- JWT header alg=EdDSA, typ=JWT, pinned kid; no unknown critical metadata.
- Base64url constraints, strict duplicate-free JSON, bounded payload sizes.
- PyJWT/cryptography Ed25519 signature, exact audience and request method.
- Two literal POST inference URLs only, exact scheme and amount 20000
  atomic units, typed iat/nbf/exp and max lifetime of 300 seconds.
- Unknown keys, wrong pins, wrong routes and bad timestamps fail closed.

A successful cryptographic check is labelled CRYPTO_CLAIMS_MATCH_SHADOW_ONLY.
It NEVER returns permission to forward inference, train models or settle
payments. No test account signer or private key is stored in the repo.

## Remaining production authority gates

1. Capture authenticated effective Cloudflare rules with unchanged
   stable IDs and all audiences, URL matchers, methods and pricing.
2. Build and review an origin proxy that is the ONLY network path to
   llama-server, enforces origin PAYMENT-CONTEXT before GPU inference
   and rejects raw alternate routes, streaming/WebSocket bypasses,
   redirects, unknown methods and spoofed health exemptions.
3. Authenticate and pin official public JWKS, respect Cache-Control
   and fail-closed key rotation; source-supplied hash alone is not trust.
4. Add replay defense, per-identity quotas, bounded tokens/body sizes,
   concurrency limits, hard GPU spend caps and real UTC time evidence.
5. Run negative authorization tests on actual deployment, confirm zero
   backend calls for every DENY; source tests alone cannot establish it.
6. Require independent human review, exact-head CI, signed runtime
   receipts, canary/bake/rollback and actual settlement reconciliation.

The source module deliberately contains NO proxy server or callback that
forwards requests; even cryptographically matched claims remain HOLD for
production. No paid job, wallet, key read, DNS change, rule edit or
Cloudflare settlement occurred.

## Test procedure

Install the optional Python package extra origin-shadow or test and run:

    python -m pytest -q tests/test_payment_context_shadow.py

Unit tests generate only synthetic one-time Ed25519 keypairs in memory.
A cryptographic test success does not establish Cloudflare key custody
or the deployed source revision.

## Model advisory scope

Mistral Large 4, Kimi K3.1 Pro and a third-party Gemma4 31B endpoint
(named GPT-6 Astra in Ollama but NOT an official OpenAI Astra model) each
supplied independent public-only design suggestions. No secrets or
private project data were delegated; model agreement is NOT authority.
