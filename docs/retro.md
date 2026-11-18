# PhantomTrace weekly retro

## Week 1 · Ingestion and custody

Filename-based routing rejected otherwise valid exports. It also left out Security 4688 and 4698 and Sysmon 3. Routing now uses provider and channel, and individual parse failures no longer discard good records. The browser timeline resolves normalized events to audited, hash-checked raw XML. Two public EVTX files replayed successfully. The user's Scenario M and benign twin were unavailable for the lab gate.

## Week 2 · Coverage and relationships

One file per assumed boot cannot establish a cross-channel session. It also cannot rule out restarts. PhantomTrace leaves a gap unless a boot range can be established and never uses PIDs as process identifiers. Scheduled task registration can be associated with a session through the task's SubjectLogonId. A direct process-to-task edge requires different evidence.

## Week 3 · Review and tracing

Synthetic cases exercise concurrent sessions and before/after review. Browser testing found a task linked directly to a session could disappear when a separate process link was rejected. The incident now retains independently supported stages. Raw EVTX validation of the complete incident and concurrent controls remains pending.

## Week 4 · Reproduction

The evaluation harness accepts hash-pinned EVTX manifests and separate dataset splits. It reports raw counts and examples without treating an undefined denominator as zero accuracy. Genuine labels and held-out captures are required before a freeze or release claim. Zeek, Sigma, extra export formats, and performance scoring remain outside the Windows MVP.
