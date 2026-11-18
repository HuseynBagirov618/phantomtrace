# PhantomTrace evaluation

## Repeatable checks

Run from the repository root with Python 3.11 or higher:

```sh
make test
make eval MANIFEST=/path/to/evaluation.json SPLIT=development
make eval MANIFEST=/path/to/evaluation.json SPLIT=held_out
```

Copy [the manifest template](../../datasets/manifests/evaluation.example.json) and fill it with sanitized EVTX exports and independent labels. Run development and validation before freezing the rules. Keep held-out labels and captures out of tuning and run that split only after the freeze. Set each evidence SHA-256 from the original file bytes. Paths are relative to the manifest. Keep sensitive EVTX and labels in local case storage.

Label records using `<source_sha256>:<Windows channel>:<EventRecordID>`. A detection label has a `rule` and a `record` for the expected indicator seed. An edge label has a `kind`, `from`, and `to`. An incident group is an array of record locators independently observed in one incident. Include benign records that should remain outside these groups. Separate actions you intended to observe from evidence you could actually identify. An unsupported label fails evaluation instead of being silently removed.

The optional `verified_policy` map accepts the capability keys `logon`, `process_lineage`, `powershell_content`, `scheduled_tasks`, `network_process_link`, and `file_creation`. Give each a verifiable source for its policy assertion. `boot_ranges` use an exact host name, timezone-aware bounds, and a reference to the corresponding boot evidence.

The evaluator writes `data/eval.json` and `data/eval.md`. It compares native indicators, indicators grouped in ten minute UTC buckets by host and source, and the hard identifier graph. Each ratio includes its numerator and denominator. For purity, each predicted group contributes its largest overlap with one labeled group, divided by the sum of all predicted group sizes. Naive grouping leaves missing source IPs unmerged. A zero denominator means the ratio is undefined. The JSON includes a missed edge or false merge example when present.

## Public parser smoke test

Python 3.12 on Linux x86_64 with `python-evtx==0.7.4`. Sources came from [python-evtx's public test data](https://github.com/williballenthin/python-evtx/tree/master/tests/data). Files were retained outside this repository.

| Input | Source SHA-256 | Parsed | Normalized | New on replay |
| --- | --- | ---: | ---: | ---: |
| Security EVTX | `5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d` | 2,261 | 583 | 0 |
| System EVTX | `ccb83cfefc9038017224cd97b800b66e248fe14529649ddf47907e5a2021449e` | 1,601 | 5 | 0 |

These are parser smoke results. The public files were not labeled for the PhantomTrace incident scenario. The synthetic demo and tests exercise the graph and review paths without serving as Windows lab evidence.
