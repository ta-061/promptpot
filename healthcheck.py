#!/usr/bin/env python3

import os
import socket
import sys

DEFAULT_PORTS = (
    "11434:ollama,"
    "1234:lmstudio,"
    "8000:vllm,"
    "7860:gradio,"
    "8188:comfyui"
)


def parse_port_spec(spec: str) -> list[int]:
    ports = []

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


def main() -> int:
    port_spec = (
        os.getenv("PROMPTPOT_PORTS")
        or os.getenv("LLMPOT_PORTS")
        or DEFAULT_PORTS
    )

    try:
        ports = parse_port_spec(port_spec)
    except (ValueError, TypeError):
        return 1

    for port in ports:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return 0
        except OSError:
            continue

    return 1


if __name__ == "__main__":
    sys.exit(main())