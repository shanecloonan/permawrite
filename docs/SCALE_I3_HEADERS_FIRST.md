# I-3 headers-first sync

`HeaderFirstSync` downloads header windows before bodies. Each header
must continue the previous id. Only a fully linked range is allowed to
ask for bodies, and `body_matches` has to accept every body. A bad
`prev`, a missing header, or a body that does not match leaves the local
tip where it was. A broken header does not trigger a body request.

These sync headers are height + id + previous id. They are not consensus
`BlockHeader`s. BLS checks stay in `mfn-light`. Path A and F-A are
unchanged.
