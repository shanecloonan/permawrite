# I-4 checkpointed fast sync

`FastSync` still links every header from the local tip to the remote tip.
A checkpoint is installed only when its height and header id are on that
linked chain. Bodies at or below the checkpoint are not downloaded.
Bodies above it are checked with the same predicate as a full pull.

A checkpoint that names a different header, sits above the remote tip, or
is followed by a body that fails the check does not move the tip and does
not record a state root.

No consensus change. Path A and F-A are unchanged.
