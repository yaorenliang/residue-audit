# Security policy

## Reporting

Use GitHub private vulnerability reporting on this repository.
Do not open a public issue for a vulnerability.

## Scope

This project only reads files and JSON. A vulnerability here means one of:

- a check reports `pass` for an input it should have flagged,
- a check modifies anything outside the root it was given,
- a crash or resource exhaustion triggered by crafted input.

The last one matters: `residue` is expected to run on incident-response hosts
where the input is attacker-controlled.
