"""Command-line entry point: print a posture receipt as JSON."""
from __future__ import annotations

import argparse
import json
import sys

from .gateway import DEFAULT_BASE_URL, probe_gateway


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="szl_inference_gateway",
        description="Fail-closed posture probe for the x402-metered inference gateway.",
    )
    parser.add_argument("--base", default=DEFAULT_BASE_URL,
                        help="Gateway base URL (default: the live production gateway).")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--allow-unsigned-post", action="store_true",
        help="Explicitly opt into ONE anonymous POST that may generate tokens if the paywall fails.",
    )
    parser.add_argument(
        "--acknowledge-inference-risk", action="store_true",
        help="Second deliberate acknowledgement: origin enforcement is not independently proven.",
    )
    args = parser.parse_args(argv)
    try:
        receipt = probe_gateway(
            args.base, timeout=args.timeout,
            allow_unsigned_post=args.allow_unsigned_post,
            acknowledge_inference_risk=args.acknowledge_inference_risk,
        )
    except ValueError:
        print(json.dumps({
            "admission": {"state": "HOLD", "reason": "EXPLICIT_POST_SCOPE_INVALID"},
            "post_attempted": False,
        }))
        return 2
    print(json.dumps(receipt, indent=2))
    admission = receipt.get("admission")
    return 0 if (
        args.allow_unsigned_post
        and args.acknowledge_inference_risk
        and isinstance(admission, dict)
        and admission.get("state") == "POSTURE_MATCH_NOT_SETTLEMENT"
    ) else 1


if __name__ == "__main__":
    sys.exit(main())
