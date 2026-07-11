#!/usr/bin/env python3
"""PromptPot: a multi-profile LLM service honeypot for T-Pot.

The service mimics common unauthenticated local-LLM HTTP APIs and records
requests as JSON lines. It never runs models, pulls model data, proxies traffic,
or executes attacker input.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_PORTS = "11434:ollama,1234:lmstudio,8000:vllm,7860:gradio,8188:comfyui"
DEFAULT_MODELS = [
    "llama3.1:8b",
    "llama3.2:3b",
    "qwen2.5:7b",
    "mistral:7b",
    "deepseek-r1:8b",
    "nomic-embed-text:latest",
]
DEFAULT_PROFILE_CONFIG: dict[str, dict[str, Any]] = {
    "ollama": {
        "server": "Ollama/0.5.7",
        "root_text": "Ollama is running",
        "version": "0.5.7",
        "completion_text": "",
    },
    "lmstudio": {
        "server": "LM Studio/0.3.17",
        "service": "lmstudio",
        "completion_text": "",
    },
    "vllm": {
        "server": "uvicorn",
        "service": "vllm",
        "docs_html": "<!doctype html><title>FastAPI - Swagger UI</title>",
        "completion_text": "",
    },
    "openai": {
        "server": "uvicorn",
        "service": "openai-compatible",
        "completion_text": "",
    },
    "gradio": {
        "server": "uvicorn",
        "title": "Chatbot",
        "html": "<!doctype html><title>Gradio</title><div id=\"root\"></div><script>window.gradio_config={version:'4.44.0'}</script>",
        "completion_text": "",
    },
    "comfyui": {
        "server": "Python/3.11 aiohttp/3.9.5",
        "html": "<!doctype html><title>ComfyUI</title><div id=\"app\">ComfyUI</div>",
        "device_name": "NVIDIA GeForce RTX 4090",
        "completion_text": "",
    },
}

LISTEN_HOST = os.environ.get(
    "PROMPTPOT_LISTEN_HOST",
    os.environ.get("LLMPOT_LISTEN_HOST", os.environ.get("OLLAMAPOT_LISTEN_HOST", "0.0.0.0")),
)
LOG_PATH = Path(os.environ.get("PROMPTPOT_LOG", os.environ.get("LLMPOT_LOG", "/data/honeypots/log/promptpot.log")))
HOST_IP = os.environ.get("PROMPTPOT_HOST_IP", os.environ.get("LLMPOT_HOST_IP", os.environ.get("OLLAMAPOT_HOST_IP", "")))
MAX_BODY_BYTES = int(
    os.environ.get("PROMPTPOT_MAX_BODY_BYTES", os.environ.get("LLMPOT_MAX_BODY_BYTES", os.environ.get("OLLAMAPOT_MAX_BODY_BYTES", "65536")))
)
CONFIG_PATH = os.environ.get("PROMPTPOT_CONFIG", os.environ.get("LLMPOT_CONFIG", ""))

PROFILE_TYPES = {
    "ollama": "OllamaPot",
    "lmstudio": "LMStudioPot",
    "vllm": "VLLMPot",
    "openai": "OpenAIPot",
    "gradio": "GradioPot",
    "comfyui": "ComfyUIPot",
}


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH:
        return {}
    with Path(CONFIG_PATH).open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("PROMPTPOT_CONFIG must point to a JSON object")
    return data


def merge_profile_config(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    merged = {name: values.copy() for name, values in DEFAULT_PROFILE_CONFIG.items()}
    profiles = config.get("profiles", {})
    if not isinstance(profiles, dict):
        return merged
    for profile, values in profiles.items():
        if profile not in merged or not isinstance(values, dict):
            continue
        merged[profile].update(values)
    return merged


CONFIG = load_config()
PROFILE_CONFIG = merge_profile_config(CONFIG)
PORT_SPEC = os.environ.get("PROMPTPOT_PORTS") or os.environ.get("LLMPOT_PORTS") or CONFIG.get("ports") or DEFAULT_PORTS
if isinstance(PORT_SPEC, list):
    PORT_SPEC = ",".join(
        f"{item['port']}:{item.get('profile', 'openai')}"
        for item in PORT_SPEC
        if isinstance(item, dict) and "port" in item
    )
MODEL_NAMES = [
    model.strip()
    for model in (
        os.environ.get("PROMPTPOT_MODELS")
        or os.environ.get("LLMPOT_MODELS")
        or os.environ.get("OLLAMAPOT_MODELS")
        or ",".join(CONFIG.get("models", DEFAULT_MODELS))
    ).split(",")
    if model.strip()
]


def profile_value(profile: str, key: str, default: Any = "") -> Any:
    return PROFILE_CONFIG.get(profile, {}).get(key, default)


def completion_text(profile: str) -> str:
    return os.environ.get("PROMPTPOT_RESPONSE_TEXT", os.environ.get("LLMPOT_RESPONSE_TEXT", str(profile_value(profile, "completion_text", ""))))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def parse_json_or_none(text: str) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def stringify_json_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def append_log(event: dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    try:
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        event["promptpot_log_error"] = str(exc)
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    print(line, flush=True)


def model_family(model: str) -> str:
    lower = model.lower()
    if lower.startswith("qwen"):
        return "qwen"
    if lower.startswith("mistral"):
        return "mistral"
    if lower.startswith("deepseek"):
        return "deepseek"
    if lower.startswith("nomic"):
        return "nomic-bert"
    if lower.startswith("gemma"):
        return "gemma"
    return "llama"


def model_size(model: str) -> int:
    lower = model.lower()
    if "embed" in lower:
        return 274302450
    if "3b" in lower:
        return 2019393189
    if "7b" in lower:
        return 4113301824
    if "8b" in lower:
        return 4661224676
    return 4661224676


def model_parameter_size(model: str) -> str:
    lower = model.lower()
    for marker in ("70b", "32b", "14b", "8b", "7b", "3b", "1b"):
        if marker in lower:
            return marker.upper()
    if "embed" in lower:
        return "137M"
    return "8B"


def model_digest(model: str) -> str:
    return "sha256:" + hashlib.sha256(model.encode("utf-8")).hexdigest()


def selected_model(parsed: Any) -> str:
    if isinstance(parsed, dict) and isinstance(parsed.get("model"), str) and parsed["model"]:
        return parsed["model"]
    return MODEL_NAMES[0] if MODEL_NAMES else "llama3.1:8b"


def ollama_model(model: str) -> dict[str, Any]:
    family = model_family(model)
    return {
        "name": model,
        "model": model,
        "modified_at": "2026-06-29T12:18:03.000000Z",
        "size": model_size(model),
        "digest": model_digest(model),
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": family,
            "families": [family],
            "parameter_size": model_parameter_size(model),
            "quantization_level": "Q4_K_M",
        },
    }


def ollama_model_list() -> dict[str, Any]:
    return {"models": [ollama_model(model) for model in MODEL_NAMES]}


def openai_model_list() -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {
                "id": model,
                "object": "model",
                "created": 1718211069,
                "owned_by": "library",
            }
            for model in MODEL_NAMES
        ],
    }


def running_model_list() -> dict[str, Any]:
    running = MODEL_NAMES[:2] if len(MODEL_NAMES) > 1 else MODEL_NAMES
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat(timespec="microseconds").replace("+00:00", "Z")
    models = []
    for model in running:
        item = ollama_model(model)
        item.update({"expires_at": expires_at, "size_vram": int(model_size(model) * 0.92)})
        models.append(item)
    return {"models": models}


def show_model(model: str) -> dict[str, Any]:
    item = ollama_model(model)
    family = model_family(model)
    return {
        "modelfile": f"FROM {model}\nPARAMETER temperature 0.7\n",
        "parameters": "temperature 0.7\nnum_ctx 4096",
        "template": "{{ .Prompt }}",
        "details": item["details"],
        "model_info": {
            f"{family}.context_length": 4096,
            f"{family}.embedding_length": 4096,
            "general.architecture": family,
            "general.parameter_count": model_size(model),
            "tokenizer.ggml.model": "gpt2",
        },
    }


def fake_embedding() -> list[float]:
    return [0.0, 0.01, -0.01, 0.02, -0.02, 0.0, 0.01, -0.01]


def openai_chat_response(model: str, response_text: str = "") -> dict[str, Any]:
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex[:12],
        "object": "chat.completion",
        "created": int(datetime.now(timezone.utc).timestamp()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": response_text},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 8, "completion_tokens": 0 if not response_text else 4, "total_tokens": 8 if not response_text else 12},
    }


def openai_completion_response(model: str, response_text: str = "") -> dict[str, Any]:
    return {
        "id": "cmpl-" + uuid.uuid4().hex[:12],
        "object": "text_completion",
        "created": int(datetime.now(timezone.utc).timestamp()),
        "model": model,
        "choices": [{"text": response_text, "index": 0, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 8, "completion_tokens": 0 if not response_text else 4, "total_tokens": 8 if not response_text else 12},
    }


def extract_prompt(parsed: Any) -> tuple[str, str, str]:
    if not isinstance(parsed, dict):
        return "", "", ""
    model = stringify_json_value(parsed.get("model"))
    prompt = stringify_json_value(parsed.get("prompt") or parsed.get("input"))
    messages = stringify_json_value(parsed.get("messages"))
    if not prompt and isinstance(parsed.get("data"), list):
        prompt = stringify_json_value([item for item in parsed["data"] if isinstance(item, str)])
    return model, prompt, messages


def parse_port_spec(spec: str) -> list[tuple[int, str]]:
    mappings: list[tuple[int, str]] = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            port_text, profile = item.split(":", 1)
        else:
            port_text, profile = item, "openai"
        port = int(port_text.strip())
        profile = profile.strip().lower()
        if profile not in PROFILE_TYPES:
            raise ValueError(f"unsupported profile {profile!r} for port {port}")
        mappings.append((port, profile))
    if not mappings:
        raise ValueError("PROMPTPOT_PORTS produced no listeners")
    return mappings


class ProfiledHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler], profile: str) -> None:
        super().__init__(server_address, handler)
        self.profile = profile
        self.listen_port = int(self.server_address[1])


class PromptPotHandler(BaseHTTPRequestHandler):
    sys_version = ""

    @property
    def profile(self) -> str:
        return getattr(self.server, "profile", "openai")

    @property
    def listen_port(self) -> int:
        return int(getattr(self.server, "listen_port", 0))

    def version_string(self) -> str:
        return str(profile_value(self.profile, "server", "uvicorn"))

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _read_body(self) -> tuple[bytes, bool]:
        length_header = self.headers.get("Content-Length")
        if not length_header:
            return b"", False
        try:
            length = int(length_header)
        except ValueError:
            return b"", False
        to_read = min(max(length, 0), MAX_BODY_BYTES)
        body = self.rfile.read(to_read) if to_read else b""
        truncated = length > MAX_BODY_BYTES
        remaining = length - to_read
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 8192))
            if not chunk:
                break
            remaining -= len(chunk)
        return body, truncated

    def _log_request(self, body: bytes, truncated: bool, status: int) -> None:
        src_ip, src_port = self.client_address[:2]
        body_text = safe_decode(body)
        parsed = parse_json_or_none(body_text)
        model, prompt, messages = extract_prompt(parsed)
        event_type = PROFILE_TYPES[self.profile]
        event = {
            "@timestamp": utc_now(),
            "timestamp": utc_now(),
            "type": event_type,
            "event_type": event_type,
            "eventid": "promptpot.request",
            "sensor": "promptpot",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": HOST_IP,
            "dest_port": self.listen_port,
            "proto": "TCP",
            "http": {
                "http_method": self.command,
                "url": self.path,
                "hostname": self.headers.get("Host", ""),
                "http_user_agent": self.headers.get("User-Agent", ""),
                "http_content_type": self.headers.get("Content-Type", ""),
                "length": int(self.headers.get("Content-Length", "0") or 0),
                "status": status,
            },
            "promptpot": {
                "profile": self.profile,
                "body": body_text,
                "body_truncated": truncated,
                "json_valid": parsed is not None,
                "json_keys": sorted(parsed.keys()) if isinstance(parsed, dict) else [],
                "model": model,
                "prompt": prompt,
                "messages": messages,
            },
        }
        append_log(event)

    def _send_json(self, status: int, payload: dict[str, Any], body: bool = True) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw) if body else 0))
        self.end_headers()
        if body:
            self.wfile.write(raw)

    def _send_text(self, status: int, payload: str, body: bool = True, content_type: str = "text/plain; charset=utf-8") -> None:
        raw = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw) if body else 0))
        self.end_headers()
        if body:
            self.wfile.write(raw)

    def _send_not_found(self, body: bytes = b"", truncated: bool = False, emit_body: bool = True) -> None:
        self._log_request(body, truncated, HTTPStatus.NOT_FOUND)
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"}, emit_body)

    def do_HEAD(self) -> None:
        self._handle_get(emit_body=False)

    def do_GET(self) -> None:
        self._handle_get(emit_body=True)

    def _handle_get(self, emit_body: bool) -> None:
        path = urlparse(self.path).path
        status = HTTPStatus.OK
        body = b""
        if path in {"/v1/models", "/api/v1/models"}:
            self._log_request(body, False, status)
            self._send_json(status, openai_model_list(), emit_body)
        elif self.profile == "ollama":
            self._handle_ollama_get(path, emit_body)
        elif self.profile in {"lmstudio", "vllm", "openai"}:
            self._handle_openai_get(path, emit_body)
        elif self.profile == "gradio":
            self._handle_gradio_get(path, emit_body)
        elif self.profile == "comfyui":
            self._handle_comfyui_get(path, emit_body)
        else:
            self._send_not_found(emit_body=emit_body)

    def _handle_ollama_get(self, path: str, emit_body: bool) -> None:
        body = b""
        if path in {"/", ""}:
            self._log_request(body, False, HTTPStatus.OK)
            self._send_text(HTTPStatus.OK, str(profile_value("ollama", "root_text", "Ollama is running")), emit_body)
        elif path == "/api/tags":
            self._log_request(body, False, HTTPStatus.OK)
            self._send_json(HTTPStatus.OK, ollama_model_list(), emit_body)
        elif path == "/api/ps":
            self._log_request(body, False, HTTPStatus.OK)
            self._send_json(HTTPStatus.OK, running_model_list(), emit_body)
        elif path in {"/api/version", "/api/v1/version"}:
            self._log_request(body, False, HTTPStatus.OK)
            self._send_json(HTTPStatus.OK, {"version": str(profile_value("ollama", "version", "0.5.7"))}, emit_body)
        else:
            self._send_not_found(emit_body=emit_body)

    def _handle_openai_get(self, path: str, emit_body: bool) -> None:
        body = b""
        if path in {"/", ""}:
            self._log_request(body, False, HTTPStatus.OK)
            self._send_json(
                HTTPStatus.OK,
                {"status": "ok", "service": str(profile_value(self.profile, "service", self.profile))},
                emit_body,
            )
        elif path in {"/health", "/ready", "/live"}:
            self._log_request(body, False, HTTPStatus.OK)
            self._send_text(HTTPStatus.OK, "OK", emit_body)
        elif path == "/docs" and self.profile == "vllm":
            self._log_request(body, False, HTTPStatus.OK)
            self._send_text(
                HTTPStatus.OK,
                str(profile_value("vllm", "docs_html", "<!doctype html><title>FastAPI - Swagger UI</title>")),
                emit_body,
                "text/html; charset=utf-8",
            )
        else:
            self._send_not_found(emit_body=emit_body)

    def _handle_gradio_get(self, path: str, emit_body: bool) -> None:
        body = b""
        if path in {"/", ""}:
            self._log_request(body, False, HTTPStatus.OK)
            html = str(profile_value("gradio", "html", DEFAULT_PROFILE_CONFIG["gradio"]["html"]))
            self._send_text(HTTPStatus.OK, html, emit_body, "text/html; charset=utf-8")
        elif path == "/config":
            self._log_request(body, False, HTTPStatus.OK)
            self._send_json(
                HTTPStatus.OK,
                {
                    "version": "4.44.0",
                    "mode": "blocks",
                    "title": str(profile_value("gradio", "title", "Chatbot")),
                    "components": [
                        {"id": 1, "type": "textbox", "props": {"label": "Message"}},
                        {"id": 2, "type": "chatbot", "props": {"label": "Chatbot"}},
                    ],
                    "dependencies": [],
                },
                emit_body,
            )
        elif path in {"/info", "/startup-events"}:
            self._log_request(body, False, HTTPStatus.OK)
            self._send_json(HTTPStatus.OK, {}, emit_body)
        else:
            self._send_not_found(emit_body=emit_body)

    def _handle_comfyui_get(self, path: str, emit_body: bool) -> None:
        body = b""
        if path in {"/", ""}:
            self._log_request(body, False, HTTPStatus.OK)
            html = str(profile_value("comfyui", "html", DEFAULT_PROFILE_CONFIG["comfyui"]["html"]))
            self._send_text(HTTPStatus.OK, html, emit_body, "text/html; charset=utf-8")
        elif path == "/system_stats":
            self._log_request(body, False, HTTPStatus.OK)
            self._send_json(
                HTTPStatus.OK,
                {
                    "system": {"os": "linux", "python_version": "3.11.9", "embedded_python": False},
                    "devices": [{"name": str(profile_value("comfyui", "device_name", "NVIDIA GeForce RTX 4090")), "type": "cuda", "vram_total": 24564}],
                },
                emit_body,
            )
        elif path == "/object_info":
            self._log_request(body, False, HTTPStatus.OK)
            self._send_json(HTTPStatus.OK, {"CheckpointLoaderSimple": {"input": {"required": {}}}}, emit_body)
        elif path == "/queue":
            self._log_request(body, False, HTTPStatus.OK)
            self._send_json(HTTPStatus.OK, {"queue_running": [], "queue_pending": []}, emit_body)
        else:
            self._send_not_found(emit_body=emit_body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        body, truncated = self._read_body()
        parsed = parse_json_or_none(safe_decode(body))
        model = selected_model(parsed)
        known_paths = {
            "/api/generate",
            "/api/chat",
            "/api/show",
            "/api/embeddings",
            "/api/embed",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/run/predict",
            "/api/predict",
            "/queue/join",
            "/prompt",
        }
        status = HTTPStatus.OK if path in known_paths else HTTPStatus.NOT_FOUND
        self._log_request(body, truncated, status)
        if path in {"/api/generate", "/api/chat"}:
            text = completion_text(self.profile)
            self._send_json(
                HTTPStatus.OK,
                {
                    "model": model,
                    "created_at": utc_now(),
                    "response": text,
                    "message": {"role": "assistant", "content": text},
                    "done": True,
                    "done_reason": "stop",
                    "total_duration": 15800000,
                    "load_duration": 1200000,
                    "prompt_eval_count": 8,
                    "eval_count": 0 if not text else 4,
                },
            )
        elif path == "/api/show":
            self._send_json(HTTPStatus.OK, show_model(model))
        elif path == "/api/embeddings":
            self._send_json(HTTPStatus.OK, {"embedding": fake_embedding()})
        elif path == "/api/embed":
            self._send_json(
                HTTPStatus.OK,
                {
                    "model": model,
                    "embeddings": [fake_embedding()],
                    "total_duration": 15800000,
                    "load_duration": 1200000,
                    "prompt_eval_count": 8,
                },
            )
        elif path == "/v1/chat/completions":
            self._send_json(HTTPStatus.OK, openai_chat_response(model, completion_text(self.profile)))
        elif path == "/v1/completions":
            self._send_json(HTTPStatus.OK, openai_completion_response(model, completion_text(self.profile)))
        elif path == "/v1/embeddings":
            self._send_json(
                HTTPStatus.OK,
                {
                    "object": "list",
                    "data": [{"object": "embedding", "embedding": fake_embedding(), "index": 0}],
                    "model": model,
                    "usage": {"prompt_tokens": 8, "total_tokens": 8},
                },
            )
        elif path in {"/run/predict", "/api/predict", "/queue/join"}:
            self._send_json(
                HTTPStatus.OK,
                {
                    "data": [completion_text(self.profile)],
                    "is_generating": False,
                    "duration": 0.04,
                    "average_duration": 0.04,
                    "event_id": uuid.uuid4().hex,
                },
            )
        elif path == "/prompt":
            self._send_json(
                HTTPStatus.OK,
                {
                    "prompt_id": str(uuid.uuid4()),
                    "number": 0,
                    "node_errors": {},
                },
            )
        else:
            self._send_json(status, {"error": "not found"})

    def do_PUT(self) -> None:
        self.do_POST()

    def do_DELETE(self) -> None:
        body = b""
        self._log_request(body, False, HTTPStatus.NOT_FOUND)
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})


def serve_forever(stop_event: threading.Event, server: ProfiledHTTPServer) -> None:
    print(
        f"promptpot listening on {LISTEN_HOST}:{server.listen_port} profile={server.profile}",
        flush=True,
    )
    try:
        while not stop_event.is_set():
            server.handle_request()
    finally:
        server.server_close()


def main() -> int:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    mappings = parse_port_spec(PORT_SPEC)
    stop_event = threading.Event()
    servers = [
        ProfiledHTTPServer((LISTEN_HOST, port), PromptPotHandler, profile)
        for port, profile in mappings
    ]
    for server in servers:
        server.timeout = 0.5

    def stop(_signum: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    threads = [threading.Thread(target=serve_forever, args=(stop_event, server), daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    try:
        while not stop_event.is_set():
            if not any(thread.is_alive() for thread in threads):
                return 1
            time.sleep(0.5)
    finally:
        stop_event.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
