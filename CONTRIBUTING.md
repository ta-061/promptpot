# Contributing

Contributions that improve fidelity, logging quality, and deployment safety are
welcome.

## Good Contributions

- New profiles for common exposed LLM services.
- More realistic but harmless response shapes.
- Better T-Pot / Kibana integration.
- Documentation for safe deployment and analysis.
- Tests that validate response formats and JSONL logging.

## Boundaries

Do not add behavior that executes attacker input, proxies to real services,
downloads models, launches model runtimes, or publishes collected payloads.

## Local Checks

```sh
python3 -m py_compile promptpot.py scripts/update_kibana.py
docker build -t promptpot:0.1.0 .
```
