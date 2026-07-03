# PromptPot

PromptPot is a multi-profile honeypot for exposed local-LLM services. It mimics
common LLM HTTP APIs, records probes and prompts as JSON lines, and works as a
sidecar for T-Pot / Logstash.

It never runs models, downloads model data, proxies traffic, or executes
attacker input.

## Why PromptPot

Many exposed LLM services look alike from the internet: model discovery, an
OpenAI-compatible `/v1/models`, a chat/completions endpoint, and a few product
specific paths. PromptPot lets you bind those surfaces without running a real
model.

## Profiles

| Port | Profile | Typical target | Event type |
| ---: | --- | --- | --- |
| 11434 | `ollama` | Ollama | `OllamaPot` |
| 1234 | `lmstudio` | LM Studio / local OpenAI-compatible API | `LMStudioPot` |
| 8000 | `vllm` | vLLM / FastAPI OpenAI-compatible API | `VLLMPot` |
| 7860 | `gradio` | Gradio / text-generation-webui style apps | `GradioPot` |
| 8188 | `comfyui` | ComfyUI style API | `ComfyUIPot` |

## Quick Start

```sh
docker build -t promptpot:0.1.0 .

docker run -d --name promptpot \
  --restart unless-stopped \
  -p 0.0.0.0:11434:11434 \
  -p 0.0.0.0:1234:1234 \
  -p 0.0.0.0:8000:8000 \
  -p 0.0.0.0:7860:7860 \
  -p 0.0.0.0:8188:8188 \
  -e PROMPTPOT_HOST_IP=203.0.113.10 \
  -e PROMPTPOT_LOG=/data/honeypots/log/promptpot.log \
  -v /path/to/tpotce/data/honeypots/log:/data/honeypots/log \
  promptpot:0.1.0
```

For a T-Pot host:

```sh
export PROMPTPOT_HOST_IP=203.0.113.10
export TPOT_DATA_DIR=/home/tpotadmin/tpotce/data
docker compose up -d --build
```

If one of the ports is already used, remove that published port and remove the
matching listener from `PROMPTPOT_PORTS`. Example for adding only extra LLM
ports while another container already owns `11434`:

```sh
docker run -d --name promptpot-extra \
  --restart unless-stopped \
  -p 0.0.0.0:1234:1234 \
  -p 0.0.0.0:8000:8000 \
  -p 0.0.0.0:7860:7860 \
  -p 0.0.0.0:8188:8188 \
  -e PROMPTPOT_PORTS=1234:lmstudio,8000:vllm,7860:gradio,8188:comfyui \
  -e PROMPTPOT_HOST_IP=203.0.113.10 \
  -e PROMPTPOT_LOG=/data/honeypots/log/promptpot.log \
  -v /path/to/tpotce/data/honeypots/log:/data/honeypots/log \
  promptpot:0.1.0
```

## Configuration

PromptPot can be customized either with environment variables or a JSON config
file. Use `config.example.json` as a starting point.

```sh
docker run -d --name promptpot \
  -e PROMPTPOT_CONFIG=/etc/promptpot/config.json \
  -v ./config.example.json:/etc/promptpot/config.json:ro \
  promptpot:0.1.0
```

| Variable | Default | Description |
| --- | --- | --- |
| `PROMPTPOT_LISTEN_HOST` | `0.0.0.0` | Bind address inside the container |
| `PROMPTPOT_PORTS` | `11434:ollama,1234:lmstudio,8000:vllm,7860:gradio,8188:comfyui` | Comma-separated `port:profile` listeners |
| `PROMPTPOT_HOST_IP` | empty | Public sensor IP written to `dest_ip` |
| `PROMPTPOT_LOG` | `/data/honeypots/log/promptpot.log` | JSONL output path |
| `PROMPTPOT_MAX_BODY_BYTES` | `65536` | Maximum request body bytes stored per event |
| `PROMPTPOT_MODELS` | common small/mid local models | Comma-separated model list returned by model APIs |
| `PROMPTPOT_RESPONSE_TEXT` | empty | Optional harmless response text for completion APIs |
| `PROMPTPOT_CONFIG` | empty | JSON config file for models, ports, and profile responses |

Legacy `LLMPOT_*` variables are still accepted, but new deployments should use
`PROMPTPOT_*`.

## Useful KQL

All PromptPot events:

```kql
type: ("OllamaPot" or "LMStudioPot" or "VLLMPot" or "OpenAIPot" or "GradioPot" or "ComfyUIPot")
```

Prompt-like POST requests:

```kql
sensor: "promptpot" and http.http_method: "POST" and promptpot.prompt: *
```

OpenAI-compatible chat attempts:

```kql
sensor: "promptpot" and http.url: "/v1/chat/completions"
```

Ollama API generation attempts:

```kql
sensor: "promptpot" and http.url: ("/api/generate" or "/api/chat")
```

## T-Pot Notes

Do not bind ports already used by T-Pot containers. Adding PromptPot to a port
changes attribution for that port: traffic that Honeytrap previously captured
will be captured by a PromptPot event type instead. P0f and Suricata can still
observe the same traffic passively.

Install the bundled Kibana dashboard from a T-Pot host:

```sh
python3 scripts/update_kibana.py --api-url http://127.0.0.1:64296
```

## Safety

Collected request bodies are attacker-controlled and can contain prompts,
credentials, exploit payloads, or sensitive copied data. Do not publish raw logs
or production deployment inventory.
