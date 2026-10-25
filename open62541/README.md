# open62541 adapter (open62541 v1.5.9)

The adapter contract is docs/CLIENT_CONTRACT.md; this file lists what is
specific to the open62541 adapter.

## Historical events (`client history-read-events`, `client history-update-events`)

- Sent with the raw `UA_Client_Service_historyRead` / `UA_Client_Service_historyUpdate`
  (ReadEventDetails, UpdateEventDetails, DeleteEventDetails built from the flags).
  `UA_Client_HistoryRead_events` of v1.5.9 is not used: it follows continuation
  points by itself and stops on any status other than Good, `GoodNoData` included,
  so `--num-values`, `--continuation-point` and `--scenario continue` could not be
  honoured with it.
- WhereClause with `--of-type` and `--min-severity`: element 0 is `And(1, 2)`
  (the root, Part 4 §7.7.1), element 1 OfType, element 2
  GreaterThanOrEqual(Severity, UInt16).
- `--scenario continue`: per node, pages follow continuation points up to
  `--max-pages` (default 8, `--num-values` 0 becomes 2), then the last continuation
  point seen is released and reused, as `history-read --scenario continue` does.
  The item carries the last page's `statusCode` / `continuationPoint` and the
  events of all pages in order next to `pages`. Without any continuation point no
  release is sent and `releaseStatusCode` / `reuseAfterReleaseStatusCode` are null.
- Event fields are printed as the server returns them (name = the select path of
  the same index); fewer fields than select clauses are not padded.
- Input errors (exit 2, before connecting): `--release-continuation-point` without
  `--continuation-point`, and `--continuation-point` with more than one `--node`.
- `history-update-events` without `--select` sends the keys of the `--event`
  objects in first-seen order; a key an event lacks is a null Variant. A value
  without `"type"` is a String (JSON string), Boolean, Double (JSON number) or
  LocalizedText (`{"text"}`); typed values use the §12 literal parser, plus
  `{"locale","text"}` for LocalizedText and `{"ns","name"}` for QualifiedName.
- The open62541 server has no event store (v1.5.9 ships none), so the adapter's
  server serves no `History.Events` fixture and does not advertise the
  `history-events` server features.
- `opcua-interop-open62541 test` runs the unit tests of the select-path, filter,
  perform-type and event-value helpers.
