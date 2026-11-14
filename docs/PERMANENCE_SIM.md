# Permanence simulation

`mfn-cli permanence-sim` runs one file forward for 20 years.

Parameters that keep it alive:

| Parameter | Value | Why |
| --- | --- | --- |
| Shards | 12 | Four data shards and eight parity shards. |
| Repair threshold | 4 | Any four shards rebuild the file. |
| Operators | 12 | One shard each at the start. |
| Losses per year | 3 | Three operators leave and are replaced. Nine shards remain, which is still above the threshold, so repair can copy the three missing shards. |
| Repair | on | Without the copy, the losses stack and the file drops below four shards in year 4. |
| Endowment | `required_endowment` for 1 MiB at replication 3, default schedule | Repair runs only while `endowment_annual_runway` is healthy. An empty balance refuses repair and the file is lost. |
| Annual cost | `first_year_cost_base_units` for that same file | Debited once a year. The default opening balance covers more than 20 of these debits. |

The command prints `files_alive`, `files_lost`, `annual_cost`, `endowment`, and `runway_years`. It does not change consensus parameters and it does not spend from a live treasury.
