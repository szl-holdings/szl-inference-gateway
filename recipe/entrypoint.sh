#!/usr/bin/env bash
# SZL Inference Gateway - v7 container boot recipe (as deployed 2026-11-15),
# plus the fail-closed model fetch of 2026-11-19 (section 4), which a running
# instance only carries after its next deploy.
# The deployed instance receives the cloudflared tunnel token at runtime;
# this script reads it from CLOUDFLARED_TOKEN. Never commit tokens.

set -u
export HOME=/root
export PIP_BREAK_SYSTEM_PACKAGES=1
export HF_HOME=/workspace/hf

if [ -z "$CLOUDFLARED_TOKEN" ]; then
  echo "FATAL: CLOUDFLARED_TOKEN is not set (cloudflared tunnel run token)" >&2
  exit 1
fi

printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf 2>/dev/null || true
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq curl >/dev/null 2>&1 || true

mkdir -p /opt/llama /opt/llama/lib
echo V7_BOOT $(date -u +%H:%M:%S) >> /tmp/lane.log

# 1. Inference server binary: the PrismML-Eng fork of llama.cpp.
#    Mainline llama.cpp cannot load the PQ2_0 quantization family; the fork can.
if [ ! -f /opt/llama/llama-prism-b12128-d7b2896/llama-server ]; then
  curl -fsSL --retry 5 --retry-all-errors -o /tmp/llama.tar.gz https://github.com/PrismML-Eng/llama.cpp/releases/download/prism-b12128-d7b2896/llama-prism-b12128-d7b2896-bin-linux-cuda-12.8-x64.tar.gz > /tmp/llama_install.log 2>&1 || echo LLAMA_DL_FAIL >> /tmp/llama_install.log
  tar -xzf /tmp/llama.tar.gz -C /opt/llama >> /tmp/llama_install.log 2>&1; echo TAR_RC=$? >> /tmp/llama_install.log
fi

# 2. CUDA runtime libraries (when the image does not already carry them).
if ! ls /opt/llama/lib*/libcudart* >/dev/null 2>&1 && ! find /opt/llama -name "libcudart.so*" | grep -q .; then
  curl -fsSL --retry 5 --retry-all-errors -o /tmp/cudart.tar.gz https://github.com/ggml-org/llama.cpp/releases/download/b12359/cudart-llama-b12359-bin-ubuntu-cuda-12.8-x64.tar.gz > /tmp/cudart_install.log 2>&1 || echo CUDART_DL_FAIL >> /tmp/cudart_install.log
  tar -xzf /tmp/cudart.tar.gz -C /opt/llama >> /tmp/cudart_install.log 2>&1; echo CTAR_RC=$? >> /tmp/cudart_install.log
fi

# 3. Loader path: copy every shared object next to the server binary.
LSB=$(find /opt/llama -name llama-server -type f | head -1); LDD=$(dirname "$LSB")
echo LSBIN=$LSB >> /tmp/lane.log
find /opt/llama -name "*.so*" -not -path "$LDD/*" -exec cp -a {} "$LDD"/ \; 2>>/tmp/lane.log
ls "$LDD" >> /tmp/lane.log

# 4. MODEL FIRST: nothing serves until the full model file is on disk and verified.
#    Pinned to Hub revision 839bd570 (no commit since 2026-11-04, so these are the
#    bytes behind the 2026-11-15 cutover): 7,206,168,928 bytes, LFS sha256 3907dc16...
#    --fail keeps an HTTP error body out of the file. A short download resumes; a
#    file of the wrong size or digest is deleted, never moved into place.
MODEL=/root/bonsai.gguf
MODEL_URL="https://huggingface.co/prism-ml/Ternary-Bonsai-2-27B-gguf/resolve/839bd57023c1558945afea70a74fa83c054f35f9/Ternary-Bonsai-2-27B-PQ2_0.gguf"
MODEL_BYTES=7206168928
MODEL_SHA256=3907dc1658db1f78a9826bf8d5bcb8dc65db0d466388937af57f2294fae62ec1
MODEL_ATTEMPTS=6
MODEL_RETRY_SLEEP=20
LANE_LOG=/tmp/lane.log
# >>> fetch_model (tests/test_recipe_fetch_model.py runs this block as written)
model_size() { stat -c%s "$1" 2>/dev/null || echo 0; }
model_ok() { [ "$(model_size "$1")" = "$MODEL_BYTES" ] && [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$MODEL_SHA256" ]; }
fetch_model() {
  local part="$MODEL.part" a
  if [ "$(cat "$MODEL.sha256" 2>/dev/null)" = "$MODEL_SHA256" ] && [ "$(model_size "$MODEL")" = "$MODEL_BYTES" ]; then
    echo MODEL_OK_VERIFIED_EARLIER >> "$LANE_LOG"; return 0
  fi
  rm -f "$MODEL.sha256"
  if [ -e "$MODEL" ]; then
    if model_ok "$MODEL"; then
      echo "$MODEL_SHA256" > "$MODEL.sha256"; echo MODEL_OK_VERIFIED >> "$LANE_LOG"; return 0
    fi
    echo MODEL_REJECTED_SZ_$(model_size "$MODEL") >> "$LANE_LOG"; rm -f "$MODEL"
  fi
  echo DL_START $(date -u +%H:%M:%S) >> "$LANE_LOG"
  for a in $(seq 1 "$MODEL_ATTEMPTS"); do
    curl -fsSL --retry 3 --retry-all-errors -C - -o "$part" "$MODEL_URL" >> "$LANE_LOG" 2>&1
    if [ "$(model_size "$part")" -gt "$MODEL_BYTES" ]; then
      echo DL_OVERSIZE_$a >> "$LANE_LOG"; rm -f "$part"
    elif [ "$(model_size "$part")" = "$MODEL_BYTES" ]; then
      if ! model_ok "$part"; then
        echo DL_DIGEST_MISMATCH_$a >> "$LANE_LOG"; rm -f "$part"
      elif mv "$part" "$MODEL"; then
        echo "$MODEL_SHA256" > "$MODEL.sha256"; echo MODEL_OK_DOWNLOADED >> "$LANE_LOG"; return 0
      fi
    fi
    echo DL_RETRY_$a >> "$LANE_LOG"; sleep "$MODEL_RETRY_SLEEP"
  done
  echo MODEL_NOT_READY >> "$LANE_LOG"
  return 1
}
# <<< fetch_model
fetch_model
echo MODEL_SZ $(model_size "$MODEL") >> /tmp/lane.log

# 5. Inference server.
export LD_LIBRARY_PATH="$LDD:/opt/llama:/opt/llama/lib:$LD_LIBRARY_PATH"
"$LSB" -m /root/bonsai.gguf --alias ternary-bonsai-2-27b-pq2_0 --host 127.0.0.1 --port 11434 -c 8192 -ngl 99 > /tmp/llama_server.log 2>&1 &
echo $! > /root/llama.pid
sleep 40

# 6. Tunnel: cloudflared with the tunnel run token from the environment.
if [ ! -x /root/cloudflared ]; then
  curl -fsSL --retry 3 -o /root/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 >> /tmp/lane.log 2>&1
  chmod +x /root/cloudflared
fi
/root/cloudflared tunnel --no-autoupdate run --token "$CLOUDFLARED_TOKEN" > /tmp/cloudflared.log 2>&1 &
echo $! > /root/cf.pid

# 7. Diagnostic fallback server (recipe/diag.py), parked on :11434 when llama-server
#    is down, so health probes get an honest JSON diagnosis instead of a dead port.
cat > /root/diag.py <<'PYEOF'
import http.server, json, os, subprocess

def tail(path, n=6000):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - n))
            return f.read().decode("utf-8", "replace")
    except Exception as e:
        return "ERR " + repr(e)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            pid = open("/root/llama.pid").read().strip()
            alive = bool(pid) and subprocess.run(["kill", "-0", pid], capture_output=True).returncode == 0
        except Exception:
            alive = False
        body = json.dumps({
            "diag": "v7-fallback", "llama_alive": alive,
            "model_sz": os.path.getsize("/root/bonsai.gguf") if os.path.exists("/root/bonsai.gguf") else -1,
            "lane_log": tail("/tmp/lane.log"), "llama_log": tail("/tmp/llama_server.log"),
            "install_log": tail("/tmp/llama_install.log"), "cudart_log": tail("/tmp/cudart_install.log"),
            "cf_log": tail("/tmp/cloudflared.log", 1500)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

try:
    http.server.ThreadingHTTPServer(("127.0.0.1", 11434), Handler).serve_forever()
except OSError:
    pass
PYEOF

# 8. Supervision loop: restart whatever dies, every 30 seconds.
up() { kill -0 "$(cat /root/$1 2>/dev/null)" 2>/dev/null; }
sleep 30
while true; do
  sleep 30
  up cf.pid || { /root/cloudflared tunnel --no-autoupdate run --token "$CLOUDFLARED_TOKEN" > /tmp/cloudflared.log 2>&1 & echo $! > /root/cf.pid; }
  if ! up llama.pid; then
    kill "$(cat /root/diag.pid 2>/dev/null)" 2>/dev/null; sleep 1
    LSB=$(find /opt/llama -name llama-server -type f | head -1); LDD2=$(dirname "$LSB")
    find /opt/llama -name "*.so*" -exec cp -a {} "$LDD2"/ \; 2>/dev/null
    LD_LIBRARY_PATH="$LDD2:/opt/llama:/opt/llama/lib:$LD_LIBRARY_PATH" "$LSB" -m /root/bonsai.gguf --alias ternary-bonsai-2-27b-pq2_0 --host 127.0.0.1 --port 11434 -c 8192 -ngl 99 > /tmp/llama_server.log 2>&1 &
    echo $! > /root/llama.pid
    echo RETRY_LLAMA_$(date -u +%H:%M:%S) >> /tmp/lane.log
    sleep 25
    if ! up llama.pid; then
      (sleep 2; python3 /root/diag.py >> /tmp/diag_run.log 2>&1) &
      echo $! > /root/diag.pid
    fi
  fi
done
