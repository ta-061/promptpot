#!/usr/bin/env python3

import json
import os
import socket
import sys
from pathlib import Path

DEFAULT_PORTS = (
    "11434:ollama,"
    "1234:lmstudio,"
    "8000:vllm,"
    "7860:gradio,"
    "8188:comfyui"
)


def load_config():
    config_path = (
        os.getenv("PROMPTPOT_CONFIG")
        or os.getenv("LLMPOT_CONFIG")
    )

    if not config_path:
        return {}

    try:
        with Path(config_path).open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass

    return {}


def parse_port_spec(spec):
    ports = []

    # Handle JSON config format
    if isinstance(spec, list):
        for item in spec:
            if isinstance(item, dict) and "port" in item:
                ports.append(int(item["port"]))
        return ports

    # Handle PROMPTPOT_PORTS env format
    if isinstance(spec, str):
        for item in spec.split(","):
            item = item.strip()

            if not item:
                continue

            if ":" in item:
                port_text, _ = item.split(":", 1)
            else:
                port_text = item

            ports.append(int(port_text.strip()))

    return ports


def main():
    config = load_config()

    port_spec = (
        os.getenv("PROMPTPOT_PORTS")
        or os.getenv("LLMPOT_PORTS")
        or config.get("ports")
        or DEFAULT_PORTS
    )

    try:
        ports = parse_port_spec(port_spec)
    except (ValueError, TypeError):
        return 1

    # PromptPot runs all listeners in one process.
    # If any configured listener accepts a local TCP connection,
    # consider the container healthy without generating HTTP traffic.
    for port in ports:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return 0
        except OSError:
            continue

    return 1


if __name__ == "__main__":
    sys.exit(main())
