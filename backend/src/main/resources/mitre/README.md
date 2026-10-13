# MITRE ATT&CK Enterprise dataset

`enterprise-attack-19.2.json.gz` is the Enterprise ATT&CK release 19.2 STIX 2.1 bundle from
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
(`enterprise-attack/enterprise-attack-19.2.json`), compressed with `gzip -9 -n`.

- SHA-256 of the JSON: `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`
- `attack.AttackDatasetInitializer` imports it at start-up when the stored release is missing or
  older than `app.attack.bundled-version`; `BundledAttackDatasetTest` checks the checksum.

To move to a newer release: download the JSON, check its SHA-256, gzip it here under its version,
then update `app.attack.bundled-version` and `app.attack.bundled-resource` defaults in
`AppConfig.Attack` and `application.yaml`, and the version and checksum in
`BundledAttackDatasetTest`. An administrator can also load a newer release without a deploy:
`POST /api/attack/dataset`.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation.
