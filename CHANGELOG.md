# Changelog

## Unreleased

- Add keyword/pattern-based `response_rules` so completion endpoints can answer
  scanner liveness prompts (e.g. "say pong") with configurable static text. The
  matched rule name is recorded in the `promptpot.matched_rule` event field.
- Report an actionable startup error when a request-body size environment
  variable is non-numeric or negative.
- Return the representation length in HEAD response headers without sending a
  response body.

## 0.1.0

- Initial PromptPot release.
- Multi-profile support for Ollama, LM Studio, vLLM, Gradio, and ComfyUI style
  services.
- JSONL logging designed for T-Pot / Logstash ingestion.
- T-Pot Kibana dashboard installer.
- Configurable models, ports, profile responses, and capped body capture.
- Prebuilt multi-arch images (amd64/arm64) on GitHub Container Registry.
