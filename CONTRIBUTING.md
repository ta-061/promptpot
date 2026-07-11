# Contributing to PromptPot

Thank you for helping improve PromptPot. Contributions do not have to be code:
deployment feedback, response-fidelity research, documentation, dashboards,
and safe test fixtures are all useful.

Please read the [Code of Conduct](CODE_OF_CONDUCT.md) and the project
[roadmap](ROADMAP.md) before starting a larger change.

## Find Work

- Issues labeled `good first issue` are small, well-scoped entry points.
- Issues labeled `help wanted` are ready for community ownership but may need
  more domain knowledge.
- Use GitHub Discussions for questions, design ideas, deployment reports, and
  work that is not yet specific enough to become an issue.
- Comment on an issue before starting work so effort is not duplicated. A
  maintainer will assign it when possible.

For a substantial change, open an issue or Discussion first. Small fixes,
tests, and documentation corrections can go directly to a pull request.

## Development Setup

PromptPot has no runtime dependencies outside the Python standard library.
Use Python 3.11 or newer.

```sh
git clone https://github.com/ta-061/promptpot.git
cd promptpot
python3 -m unittest discover -s tests -v
python3 -m py_compile promptpot.py scripts/update_kibana.py
```

Run one local listener on an unprivileged port:

```sh
PROMPTPOT_LISTEN_HOST=127.0.0.1 \
PROMPTPOT_PORTS=18080:ollama \
PROMPTPOT_LOG=/tmp/promptpot.log \
python3 promptpot.py
```

In another terminal:

```sh
curl http://127.0.0.1:18080/api/tags
```

Docker changes should also pass:

```sh
docker build -t promptpot:dev .
```

## Project Structure

- `promptpot.py`: listeners, service profiles, response generation, and JSONL
  logging.
- `tests/`: unit and local HTTP integration tests.
- `scripts/update_kibana.py`: T-Pot Kibana dashboard installer.
- `config.example.json`: example profile and listener configuration.

## Adding or Changing a Profile

A profile change should:

1. Emulate only unauthenticated discovery or inference API behavior.
2. Return static, harmless responses without executing or forwarding input.
3. Preserve the existing JSONL event contract.
4. Include tests for the main success path and an unknown path.
5. Document the profile, default port, and event type.
6. Explain the source used to validate response fidelity without including
   credentials, private endpoints, or copyrighted response collections.

Do not add code that executes attacker input, proxies to real services,
downloads models, launches model runtimes, or makes outbound requests in
response to traffic.

## Safe Evidence and Fixtures

Never submit raw honeypot logs. They may contain credentials, personal data,
attacker payloads, live sensor addresses, or copied private content.

Use a minimal synthetic fixture whenever possible. If observed traffic is
needed to explain a compatibility issue, remove source and destination
addresses, hostnames, identifiers, credentials, prompts, timestamps, and any
deployment inventory before posting it. Maintainers may reject evidence that
cannot be reviewed safely.

## Pull Requests

Keep each pull request focused on one change. Before opening it:

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile promptpot.py scripts/update_kibana.py
```

In the pull request description:

- Link the issue with `Fixes #123` when applicable.
- Describe externally visible behavior changes.
- List the checks you ran.
- Confirm that no sensitive or production data is included.
- Update documentation and `CHANGELOG.md` for user-visible changes.

Maintainers aim to acknowledge new issues and pull requests within seven days.
Review may request changes to maintain response fidelity, log compatibility,
or deployment safety.
