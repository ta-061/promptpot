# PromptPot Roadmap

This roadmap communicates direction rather than fixed delivery dates. Open an
issue or GitHub Discussion before starting a large item.

## Current Priorities

- Establish response and JSONL compatibility tests for every profile.
- Collect minimal, synthetic fixtures that document real service response
  shapes without exposing captured traffic.
- Improve configuration validation and operator-facing error messages.
- Document repeatable T-Pot and standalone deployment checks.
- Keep the container small, multi-architecture, and dependency-free.

## Next

- Add profiles for commonly exposed local-LLM services based on observed need.
- Version and document the JSONL event schema.
- Expand Kibana dashboards and reusable detection queries.
- Add a configurable container health check that works when default listeners
  are disabled.
- Publish sanitized aggregate field observations and analysis methods.

## Later

- Evaluate upstream T-Pot integration with its maintainers.
- Provide documented export paths for additional analysis platforms.
- Recognize recurring contributors and delegate ownership of profiles or
  integrations as the community grows.

## Non-Goals

PromptPot will not execute attacker input, run or download models, proxy to a
real inference service, require external APIs, or add mandatory telemetry.
