# Key performance indicators (PRD N8, PRF-001) and the release gate (N9, PRF-002)

Each KPI has a threshold and a measurement method. `pytest -m perf` (tests/perf) measures
the first four plus a large table memory check on every release tag, before the AMI is
built; a release that misses a threshold does not ship until it is explained or fixed.
Each release's numbers are kept in `perf-results.json` with the release evidence.

| KPI | Threshold | How it is measured | Test |
|---|---|---|---|
| Journey replay time versus recorded time | at most 2 times the recorded duration | Report per journey (`recorded_wall_ms`, `replayed_wall_ms`): the replay attempt's wall clock over the recording's, first navigation to last settled step, first attempt only (retry time excluded, spec 17). A journey an engineer drove includes their pauses, so the release test drives it from code, the worst case. Release test: a six step checkout journey against the sample application answering with 150 ms latency, replayed 60 times; the worst ratio counts | `test_kpi_replay_time_within_twice_the_recorded_time` |
| Database reconciliation throughput | at least 1 million rows per minute per table | Run log: rows over elapsed time for the table, source and target both hashed. Stated with its variables (spec 17): 1,000,000 rows, 10 columns (integer, text, numeric, timestamp, timestamptz), about 130 bytes per row, PostgreSQL 16 hash pushdown, a 4 vCPU runner with source and target on it. The source is read as shipped: 75,000 rows a second, a 100 ms pause, one core (decisions 100, 101); the target is uncapped. Release test: two such tables in one run, and the slower counts: the second, which starts by paying for the first one's last read, as every table after the first does | `test_kpi_database_throughput` |
| Report generation after the checks finish | under 60 seconds for 500 journeys | Time to build and write the JSON and HTML report from 500 journeys and 4,000 findings | `test_kpi_report_for_500_journeys_under_a_minute` |
| Runs failing for tool reasons, not real differences | under 2 % of runs | In the field: run history (`liftproof runs`), counting runs that end with exit code 2 or carry flakes. Release test: 60 replays against an unchanged target, where any run that does not pass first time, cleanly, is the tool's failure | `test_kpi_tool_failures_under_two_percent` |
| Time from AMI launch to first recorded journey | under 30 minutes for a new engineer | Timed by hand on a fresh instance for each release, from launching the stack to the first `liftproof record` finishing, following only the deployment guide. Recorded in the release evidence | manual |

The suite also holds the streaming design in place (spec 17): drilling into differences
spread over 13 buckets of a 1,000,000 row table must not grow the process by 200 MB or
more (`test_large_table_drill_down_streams`). XML is canonicalised here (no engine has
C14N, docs/canonical-v1.md), so its documents cross the network: reconciling 400 documents
of about 210 KB, about 85 MB a side, must not grow the process by 200 MB or more either
(`test_xml_documents_stream`, which also records the XML read in MB a second as a figure,
not a threshold). A table with an XML column is fetched 25 rows at a time on each side;
5,000, the PostgreSQL fallback's batch, grew the process by 328 MB on that table.

XML tables fall short of the throughput KPI, which is stated for a table hashed in the
database. Canonicalising runs under the interpreter lock, so source, target and every
worker (`database.workers` are threads) share one core. Measured on the development container with the source
as shipped: 200,000 rows of a 110 byte document each went through at 262,000 rows a minute
(319,000 fetching 5,000 rows at a time), against 1.34 million for the same table with the
column as text, hashed in the database.

## First results (development container, 4 vCPU)

| KPI | Result | Threshold |
|---|---|---|
| Replay time ratio (worst of 60) | 1.18 (median 1.05) | 2.0 |
| Database throughput | 1.23 million rows per minute, the source read as shipped, on the second of two tables (1.72 million on the first; 3.78 million with the source uncapped; 2.69 million first measured) | 1 million |
| Report generation, 500 journeys | 0.31 s | 60 s |
| Tool failure rate | 0 of 60 | under 2 % |
| Large table drill-down memory | 52 MB | under 200 MB |
| XML table memory, 400 documents of about 210 KB a side | 33 MB (15.9 MB of XML a second, source and target together) | under 200 MB |

Building the suite found four problems, fixed with it: replay sat out the whole step
timeout after a page load (about 10 s per journey); recording snapshotted a step before
the data a navigation fetched had rendered; the PostgreSQL hash query computed each row
hash twice and each column rendering three times (0.58 million rows per minute before);
and drill-down held every row key and hash of the mismatched buckets at once (565 MB).
