# Docs

| Document                                                | What                                                  |
|---------------------------------------------------------|-------------------------------------------------------|
| [ARCHITECTURE.md](ARCHITECTURE.md)                      | Target architecture, data model, decision log         |
| [SECURITY_OWASP_TOP10.md](SECURITY_OWASP_TOP10.md)      | OWASP Top 10 verification & security architecture     |
| [THREAT_MODEL_STRIDE.md](THREAT_MODEL_STRIDE.md)        | STRIDE threat model, DFD diagram, threat mitigations  |

ADRs (`docs/adr/`) and generated API docs land in later PRs. The API contract itself is
served by the running backend at `/q/openapi` and `/q/swagger-ui`.
