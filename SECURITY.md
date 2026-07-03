# Security Policy

PromptPot is honeypot software. Run it only on infrastructure you own or are
explicitly authorized to monitor.

## Sensitive Data

Collected request bodies are attacker-controlled and can include prompts,
credentials, exploit payloads, or copied private data. Do not publish raw logs,
live server IPs, SSH configuration, keys, `.env` files, or exact production
inventory.

## Reporting Issues

If you find a security issue in PromptPot itself, open a private advisory or
contact the maintainers privately before publishing details.

## Operational Notes

- PromptPot does not execute attacker input.
- PromptPot does not run, download, or proxy real models.
- Binding a port changes attribution for that port. In T-Pot, traffic that
  Honeytrap previously captured on that port will be captured by PromptPot
  instead.
- P0f and Suricata can still observe the same traffic passively.
