"""Offline tests for the recipe's model fetch (recipe/entrypoint.sh, section 4).

The block between the ``# >>> fetch_model`` and ``# <<< fetch_model`` markers is
run exactly as written, with a fake ``curl`` on PATH and a small payload in place
of the 7.2 GB model. No network, no GPU, nothing outside a temporary directory.
"""
import hashlib
import os
import re
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

RECIPE = Path(__file__).resolve().parents[1] / "recipe" / "entrypoint.sh"
PAYLOAD = bytes(range(256)) * 64  # 16 KiB stand-in for the model file

FAKE_CURL = textwrap.dedent(
    """\
    import os, sys
    from pathlib import Path

    state = Path(os.environ["FAKE_STATE"])
    args = sys.argv[1:]
    with open(state / "calls", "a") as log:
        log.write(" ".join(args) + "\\n")
    n = sum(1 for _ in open(state / "calls"))
    mode = os.environ.get("FAKE_MODE", "ok")
    payload = (state / "payload").read_bytes()
    out = Path(args[args.index("-o") + 1])
    resume = "-C" in args and args[args.index("-C") + 1] == "-"
    have = out.stat().st_size if out.exists() else 0
    if not resume:
        have = 0

    def write(data):
        with open(out, "ab" if resume else "wb") as f:
            f.write(data)

    if mode == "http_error":  # what --fail does: nothing written, exit 22
        sys.exit(22)
    if mode == "error_body":  # the pre-fix behaviour: an error page and exit 0
        write(b"<html>429 Too Many Requests</html>")
        sys.exit(0)
    if mode == "half_then_rest" and n == 1:
        write(payload[: len(payload) // 2])
        sys.exit(18)  # partial file
    if mode == "corrupt_then_ok" and n == 1:
        write(bytes(len(payload)))  # right size, wrong bytes
        sys.exit(0)
    if mode == "overshoot_then_ok" and n == 1:
        write(payload + b"<html>appended error</html>")
        sys.exit(0)
    write(payload[have:])
    sys.exit(0)
    """
)


def _fetch_block() -> str:
    text = RECIPE.read_text()
    match = re.search(r"^# >>> fetch_model.*?$(.*?)^# <<< fetch_model$", text, re.S | re.M)
    assert match, "fetch_model markers missing from recipe/entrypoint.sh"
    return match.group(1)


@pytest.fixture
def rig(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "payload").write_bytes(PAYLOAD)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    curl.write_text(f"#!{sys.executable}\n" + FAKE_CURL)
    curl.chmod(curl.stat().st_mode | stat.S_IXUSR)
    model = tmp_path / "bonsai.gguf"
    lane = tmp_path / "lane.log"

    def run(mode="ok", attempts=3, sha256=None):
        (state / "calls").write_text("")
        script = textwrap.dedent(
            f"""\
            set -u
            MODEL="{model}"
            MODEL_URL="https://example.invalid/model.gguf"
            MODEL_BYTES={len(PAYLOAD)}
            MODEL_SHA256={sha256 or hashlib.sha256(PAYLOAD).hexdigest()}
            MODEL_ATTEMPTS={attempts}
            MODEL_RETRY_SLEEP=0
            LANE_LOG="{lane}"
            """
        ) + _fetch_block() + "fetch_model\n"
        env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                   FAKE_STATE=str(state), FAKE_MODE=mode)
        done = subprocess.run(["bash", "-c", script], env=env, capture_output=True,
                              text=True, timeout=60)
        calls = [c for c in (state / "calls").read_text().splitlines() if c]
        log = lane.read_text() if lane.exists() else ""
        return done.returncode, calls, log

    run.model = model
    return run


def test_download_is_verified_and_marked(rig):
    rc, calls, log = rig()
    assert rc == 0
    assert rig.model.read_bytes() == PAYLOAD
    assert (rig.model.parent / "bonsai.gguf.sha256").read_text().strip() == hashlib.sha256(PAYLOAD).hexdigest()
    assert not (rig.model.parent / "bonsai.gguf.part").exists()
    assert "MODEL_OK_DOWNLOADED" in log
    assert len(calls) == 1


def test_curl_is_asked_to_fail_on_http_errors_and_resume(rig):
    _, calls, _ = rig()
    args = calls[0].split()
    assert "-fsSL" in args or "--fail" in args
    assert "-C" in args and args[args.index("-C") + 1] == "-"


def test_http_errors_never_produce_a_model(rig):
    rc, calls, log = rig(mode="http_error")
    assert rc == 1
    assert not rig.model.exists()
    assert len(calls) == 3
    assert "MODEL_NOT_READY" in log


def test_an_error_body_is_never_moved_into_place(rig):
    rc, _, log = rig(mode="error_body")
    assert rc == 1
    assert not rig.model.exists()
    assert "MODEL_NOT_READY" in log


def test_a_partial_download_resumes(rig):
    rc, calls, _ = rig(mode="half_then_rest")
    assert rc == 0
    assert rig.model.read_bytes() == PAYLOAD
    assert len(calls) == 2


def test_right_size_wrong_bytes_is_discarded_and_refetched(rig):
    rc, calls, log = rig(mode="corrupt_then_ok")
    assert rc == 0
    assert rig.model.read_bytes() == PAYLOAD
    assert "DL_DIGEST_MISMATCH_1" in log
    assert len(calls) == 2


def test_an_oversized_file_is_discarded_and_refetched(rig):
    rc, calls, log = rig(mode="overshoot_then_ok")
    assert rc == 0
    assert rig.model.read_bytes() == PAYLOAD
    assert "DL_OVERSIZE_1" in log
    assert len(calls) == 2


def test_a_model_verified_earlier_is_not_downloaded_again(rig):
    assert rig()[0] == 0
    rc, calls, log = rig(mode="http_error")
    assert rc == 0
    assert calls == []
    assert "MODEL_OK_VERIFIED_EARLIER" in log


def test_an_unmarked_model_is_hashed_once_then_kept(rig):
    rig.model.write_bytes(PAYLOAD)
    rc, calls, log = rig(mode="http_error")
    assert rc == 0
    assert calls == []
    assert "MODEL_OK_VERIFIED" in log
    assert (rig.model.parent / "bonsai.gguf.sha256").exists()


def test_a_bad_existing_model_is_removed_and_refetched(rig):
    rig.model.write_bytes(b"<html>left by the old recipe</html>")
    rc, calls, log = rig()
    assert rc == 0
    assert rig.model.read_bytes() == PAYLOAD
    assert "MODEL_REJECTED_SZ_" in log
    assert len(calls) == 1


def test_a_stale_marker_does_not_vouch_for_a_different_digest(rig):
    assert rig()[0] == 0
    rc, calls, _ = rig(mode="http_error", sha256="0" * 64)
    assert rc == 1
    assert not rig.model.exists()
    assert not (rig.model.parent / "bonsai.gguf.sha256").exists(), "no marker without a verified model"
    assert len(calls) == 3


def test_recipe_pins_revision_size_and_digest():
    text = RECIPE.read_text()
    url = re.search(r'^MODEL_URL="([^"]+)"$', text, re.M).group(1)
    assert re.search(r"/resolve/[0-9a-f]{40}/", url), "model URL must pin a Hub revision"
    assert re.search(r"^MODEL_BYTES=7206168928$", text, re.M)
    assert re.search(r"^MODEL_SHA256=[0-9a-f]{64}$", text, re.M)
    assert "curl -sL" not in text, "a curl without --fail would write HTTP error bodies"
