# ADR-001: Windows-only MVP scope

## Status
Accepted

## Decision
PhantomTrace v0.1 will be a Windows-only MVP.

The MVP will not include:
- Zeek
- PCAP correlation
- Sigma compatibility
- DuckDB or Parquet
- STIX, Attack Flow, or Timesketch export

The MVP will focus on:
- Evidence custody
- SHA-256 hashing
- Immutable raw evidence storage
- Windows EVTX parsing
- Scoped LogonId and ProcessGuid joins
- Hard edges
- Explicit gaps
- Timeline and incident review

## Reason
The first version must prove the relationship engine, not become a huge unfinished parser museum.

## Consequences
Any extra idea goes to v1.1 unless it directly supports the Windows-only MVP.