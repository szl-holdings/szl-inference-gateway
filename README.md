# SZL Inference Gateway

Production **x402-metered LLM inference on SaladCloud GPUs**. This repository is the complete source of the gateway behind **[inference.a-11-oy.com](https://inference.a-11-oy.com)**: the container boot recipe, supervision and diagnostic fallback, the Cloudflare tunnel wiring, and a fail-closed Python probe used to verify the gateway from the outside.

## Measured live

Observed from the public internet (the same probe this package ships):

- `GET /health` → **HTTP 200** `{"status":"ok"}`
- `GET /v1/models` → **HTTP 200**, model `ternary-bonsai-2-27b-pq2_0` (26.9B parameters, GGUF `PQ2_0` quantization)
- `GET /` → **HTTP 200** llama.cpp web UI
- Unpaid `POST /v1/chat/completions` → **HTTP 402** x402 v2 payment challenge (USDC on Base, $0.02 per request)

Scope: reachability and gateway posture only. No quality, latency, SLA, or paid-receipt claim is made here.

## Architecture

```text
Public client
   |  HTTPS
   v
Cloudflare zone (a-11-oy.com)
   |- x402 monetization worker (zone-wide; payment challenge on POST routes)
   |- Cloudflare Tunnel (cloudflared; tunnel token at runtime, never committed)
          v
SaladCloud GPU container (RTX 4090-class)
   |- llama-server (PrismML-Eng llama.cpp fork, CUDA 12.8 build)
   |     model: Ternary-Bonsai-2-27B-PQ2_0 (7,206,168,928 bytes, from the Hugging Face Hub)
   |- supervision loop (30 s; restarts llama-server / cloudflared)
   |- diagnostic fallback server (port 11434 while llama-server is down)
```

## Why a llama.cpp fork

Mainline llama.cpp (b12359 at the time of the cutover) cannot load the `PQ2_0` quantization family. The [PrismML-Eng fork](https://github.com/PrismML-Eng/llama.cpp) exists for exactly this quant class. The recipe pins release `prism-b12128-d7b2896` (bin-linux-cuda-12.8-x64).

## Deploy

1. Create a SaladCloud container: GPU class >= RTX 4090, instance storage >= 12 GB. Instance storage persists across config-roll restarts, so the 7.2 GB model downloads once.
2. Set the environment: `CLOUDFLARED_TOKEN` = your cloudflared tunnel run token. **Never commit tokens**; the deployed instance receives it at runtime.
3. Container command: `bash -lc recipe/entrypoint.sh`.

The recipe's boot order is the load-bearing part: **model first, server second.** Nothing serves until the full model file is on disk (resume + retry + size gate), the server binary comes from the pinned fork release, all CUDA shared objects are copied onto the loader path next to the binary, and a 30 s supervision loop restarts whatever dies. If the inference server cannot come up, a diagnostic JSON server parks on the port so health probes get an honest diagnosis instead of a dead port.

## Cloudflare + x402 monetization

The monetization worker is zone-wide: it follows any origin behind the zone automatically, so cutover to this origin was a single DNS record change (CNAME to the tunnel) and **rollback is the same single DNS PATCH back**. Pricing lives in the worker (USDC on Base, $0.02 per request). See the [Cloudflare monetization gateway docs](https://developers.cloudflare.com/monetization-gateway/) and the [x402 specification](https://github.com/x402-foundation/x402).

## Python package

```bash
pip install szl-inference-gateway
python -m szl_inference_gateway --base https://inference.a-11-oy.com
```

Prints a fail-closed JSON receipt of the gateway posture (health, served model IDs, x402 challenge details: network, asset, pay-to, amount). Exit code is 1 unless the gateway is healthy. No third-party dependencies; standard library only.

## Repository layout

- `recipe/entrypoint.sh` — the v7 container boot recipe (as deployed)
- `recipe/diag.py` — diagnostic fallback server
- `src/szl_inference_gateway/` — posture probe package
- `tests/` — offline tests (pure parsing; no network)
- `.github/workflows/publish-pypi.yml` — canonical SZL PyPI release path (Trusted Publishing via OIDC; no API tokens anywhere)

## Scope & limits

This repository documents and reproduces the gateway. It does not claim model quality, SLA, uptime, or paid-transaction correctness beyond the receipts linked above. Fail-closed: the probe reports what it measured, or an error - never a fake ready state.

## License

Apache-2.0 (see [LICENSE](LICENSE)). Third-party components used by deployments of this recipe: llama.cpp (MIT, PrismML-Eng fork build), cloudflared (Cloudflare), and the Ternary-Bonsai-2-27B model weights, which carry their own license on the [Hugging Face Hub](https://huggingface.co/prism-ml/Ternary-Bonsai-2-27B-gguf).
