# I-9 block-log index

`BlockIndex` maps a height to the offset and length of that body in an
append-only log. A read uses the span. It does not scan the log.

`rebuild` walks the log and must reproduce the same spans, so a crash
during append is repaired by a scan. A gap in heights and a truncated
tail are errors. The index does not delete bodies.

No consensus change.
