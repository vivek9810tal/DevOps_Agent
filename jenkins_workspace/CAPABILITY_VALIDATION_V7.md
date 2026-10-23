# Capability validation v7

| Case | Type | Selected | Expected | Result |
|---|---|---|---|---|
| Python pytest config | python | pytest | pytest | PASS |
| Python unittest | python | unittest | unittest | PASS |
| Python tox | python | tox | tox | PASS |
| Node real tests | node | npm test | npm test | PASS |
| Node placeholder | node | NOT_CONFIGURED | NOT_CONFIGURED | PASS |
| Go tests | go | go test | go test | PASS |
| Rust tests | rust | cargo test | cargo test | PASS |
| No Python tests | python | NOT_CONFIGURED | NOT_CONFIGURED | PASS |

At runtime the selected strategy and evidence are archived in `reports/test-discovery.json`.