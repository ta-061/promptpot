# Security Policy

PromptPot is honeypot software. Run it only on infrastructure you own or are
explicitly authorized to monitor.

## Sensitive Data

Collected request bodies are attacker-controlled and can include prompts,
credentials, exploit payloads, or copied private data. Do not publish raw logs,
live server IPs, SSH configuration, keys, `.env` files, or exact production
inventory.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you find a security issue in PromptPot itself, please report it privately —
do not open a public issue.

1. Go to
   [Security Advisories](https://github.com/ta-061/promptpot/security/advisories/new)
   and submit a private vulnerability report ("Report a vulnerability" on the
   repository's Security tab).
2. Include the affected profile/endpoint, a reproduction, and the impact you
   expect (e.g. log injection, resource exhaustion, response spoofing).

You should get an initial response within 7 days. Once a fix is released, the
advisory will be published with credit to the reporter unless you prefer to
stay anonymous.

Because PromptPot parses attacker-controlled input by design, bugs like crashes
on malformed requests, log-file injection, or unbounded resource use are all in
scope. Reports about the intentionally fake responses (e.g. "the model list is
not real") are not vulnerabilities.

## Operational Notes

- PromptPot does not execute attacker input.
- PromptPot does not run, download, or proxy real models.
- Binding a port changes attribution for that port. In T-Pot, traffic that
  Honeytrap previously captured on that port will be captured by PromptPot
  instead.
- P0f and Suricata can still observe the same traffic passively.
