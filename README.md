# PromptPot

[![docker-build](https://github.com/ta-061/promptpot/actions/workflows/docker-build.yml/badge.svg)](https://github.com/ta-061/promptpot/actions/workflows/docker-build.yml)
[![release](https://img.shields.io/github/v/release/ta-061/promptpot)](https://github.com/ta-061/promptpot/releases)
[![license](https://img.shields.io/github/license/ta-061/promptpot)](LICENSE)

PromptPot is a multi-profile honeypot for exposed local-LLM services. It mimics
common LLM HTTP APIs, records probes and prompts as JSON lines, and works as a
sidecar for T-Pot / Logstash.

It never runs models, downloads model data, proxies traffic, or executes
attacker input.

**Field report:** https://promptpot.tatu-sec.dev

## Why PromptPot

Many exposed LLM services look alike from the internet: model discovery, an
OpenAI-compatible `/v1/models`, a chat/completions endpoint, and a few product
specific paths. PromptPot lets you bind those surfaces without running a real
model.

Unlike LLM-powered honeypots such as Beelzebub or Galah, which use an LLM to
generate responses for classic services (SSH, generic HTTP), PromptPot works in
the opposite direction: it emulates the LLM services themselves (Ollama,
LM Studio, vLLM, Gradio apps, ComfyUI) so you can observe who scans for exposed
model endpoints and what prompts they try to run. It is a single static-response
Python process with no model, no API keys, and no outbound traffic.

## Field Results

PromptPot runs as a sidecar on three internet-facing T-Pot sensors (Japan,
United States, Germany). In the first week of July 2026 it recorded about 5,300
events from 510 unique source IPs, including roughly 900 prompt submissions
against the fake completion endpoints. Ollama's port 11434 and
OpenAI-compatible `/v1/*` paths receive by far the most traffic.

## Profiles

| Port | Profile | Typical target | Event type |
| ---: | --- | --- | --- |
| 11434 | `ollama` | Ollama | `OllamaPot` |
| 1234 | `lmstudio` | LM Studio / local OpenAI-compatible API | `LMStudioPot` |
| 8000 | `vllm` | vLLM / FastAPI OpenAI-compatible API | `VLLMPot` |
| 7860 | `gradio` | Gradio / text-generation-webui style apps | `GradioPot` |
| 8188 | `comfyui` | ComfyUI style API | `ComfyUIPot` |

## Quick Start

Prebuilt multi-arch images (amd64/arm64) are published to GitHub Container
Registry:

```sh
docker run -d --name promptpot \
  --restart unless-stopped \
  -p 0.0.0.0:11434:11434 \
  -p 0.0.0.0:1234:1234 \
  -p 0.0.0.0:8000:8000 \
  -p 0.0.0.0:7860:7860 \
  -p 0.0.0.0:8188:8188 \
  -e PROMPTPOT_HOST_IP=203.0.113.10 \
  -v ./log:/data/honeypots/log \
  ghcr.io/ta-061/promptpot:latest
```

Or build from source:

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

### Response Rules

Scanners often send a canary prompt such as `say pong` or `Reply with OK`
before attempting anything deeper. A single static `PROMPTPOT_RESPONSE_TEXT`
fails these liveness checks. Add a `response_rules` array to the JSON config to
return a canned answer when the prompt matches:

```json
"response_rules": [
  {"name": "ping", "contains": ["ping", "pong"], "response": ["PONG", "pong"]},
  {"name": "say-ok", "contains": "reply with ok", "response": "OK"},
  {"name": "greeting", "starts_with": ["say hi", "say hello"], "response": ["Hello!", "Hi there!"]},
  {"name": "model-probe", "contains": "what model", "response": "I am {model}."}
]
```

- **Match types:** `contains`, `starts_with`, `ends_with`. Matching is
  case-insensitive substring only (never regex, so attacker input cannot cause
  ReDoS). Each type accepts a single keyword or a list (OR).
- **Responses** are always static strings from configuration. A list picks one
  at random per request to reduce fingerprinting.
- **`{model}`** in a response is filled only with an operator-configured model
  name; an attacker-supplied `model` field that is not in `PROMPTPOT_MODELS` is
  never reflected back.
- The **first matching rule wins**. When nothing matches, PromptPot falls back
  to `PROMPTPOT_RESPONSE_TEXT`. The matched rule name (or `null`) is recorded in
  the `promptpot.matched_rule` event field.

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

Prompts that triggered a canned response rule:

```kql
sensor: "promptpot" and promptpot.matched_rule: *
```

## Docker Health Check

The Docker image includes a built-in health check.

The health check:

- Reads the configured listeners from `PROMPTPOT_PORTS`, the JSON config file
  (`PROMPTPOT_CONFIG`), or the built-in defaults, in that order.
- Attempts a local TCP connection to each configured listener on `127.0.0.1`.
- Returns healthy if any configured listener is reachable.
- Returns unhealthy if no configured listener is reachable.
- Performs only local checks and makes no outbound network requests.

Default settings:

- Interval: 30 seconds
- Timeout: 3 seconds
- Retries: 3

## T-Pot Notes

Do not bind ports already used by T-Pot containers. Adding PromptPot to a port
changes attribution for that port: traffic that Honeytrap previously captured
will be captured by a PromptPot event type instead. P0f and Suricata can still
observe the same traffic passively.

Install the bundled Kibana dashboard from a T-Pot host:

```sh
python3 scripts/update_kibana.py --api-url http://127.0.0.1:64296
```

## Contributing

Contributions from operators, security researchers, Python developers, and
documentation authors are welcome. Useful contributions include:

- Testing deployments and reporting reproducible compatibility issues.
- Improving static response fidelity with public documentation or synthetic
  fixtures.
- Adding tests, profiles, dashboards, detection queries, or documentation.
- Translating deployment and analysis guidance.

Start with an issue labeled
[`good first issue`](https://github.com/ta-061/promptpot/labels/good%20first%20issue)
or [`help wanted`](https://github.com/ta-061/promptpot/labels/help%20wanted).
Questions, ideas, and deployment reports belong in
[GitHub Discussions](https://github.com/ta-061/promptpot/discussions).

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests, pull request guidance,
and rules for safe evidence. Project direction is tracked in
[ROADMAP.md](ROADMAP.md).

Run the local checks with:

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile promptpot.py scripts/update_kibana.py
```

## Safety

Collected request bodies are attacker-controlled and can contain prompts,
credentials, exploit payloads, or sensitive copied data. Do not publish raw logs
or production deployment inventory.
