## Summary

Describe the problem and the focused change made to solve it.

Fixes #

## Validation

- [ ] `python3 -m unittest discover -s tests -v`
- [ ] `python3 -m py_compile promptpot.py scripts/update_kibana.py`
- [ ] Docker build completed, or this change does not affect the container

## Safety and compatibility

- [ ] No raw honeypot logs, credentials, prompts, live sensor IPs, or private deployment data are included.
- [ ] The change does not execute attacker input, proxy requests, run models, download data, or introduce request-triggered outbound traffic.
- [ ] User-visible behavior and JSONL schema changes are documented.
