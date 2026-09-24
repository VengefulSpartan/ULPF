# Running TRACELOG on another machine, and measuring it

Written to be followed on a laptop that has never seen this project. Every command is one
line, and each step says what you should see.

## 0. What the machine needs

- **Python 3.10 or newer** (3.11 or 3.12 recommended). `python3 --version`
- **git**, and about 2 GB of free disk for a 100,000-event benchmark run.
- Nothing else. No database server, no message broker, no cloud account.
- Optional: Docker, if you would rather not install Python packages.

## 1. Get the code onto the machine

From GitHub, once the repository is pushed:

```bash
git clone <repository url> tracelog && cd tracelog
```

Or copy the folder from the machine that has it, leaving behind what does not travel:

```bash
rsync -av --exclude .venv --exclude data --exclude .git \
      --exclude node_modules --exclude '__pycache__' SIH26/ /media/usb/tracelog/
```

`data/` holds the database from the other machine — leave it behind and the new machine starts
clean, which is what you want before measuring anything.

## 2. Install

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell):

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`orjson` is a compiled wheel; if it will not install on this machine, the pipeline falls back to
the standard library and everything still works, about 5 % slower.

## 3. Check the install before trusting any number

```bash
pytest -q
```

**Expect `287 passed`.** If tests fail, stop here — a number from a broken build is worse than no
number.

```bash
python scripts/evaluate_unseen_formats.py
```

**Expect `85 correct, 18 missed, 0 WRONG`** over 103 fields in 13 log formats no parser has a pack
for. The zero is the claim the whole product rests on.

## 4. Run it

```bash
python run_app.py
```

- API: <http://127.0.0.1:8000>, interactive docs at `/docs`
- Dashboard: <http://localhost:8501>
- Syslog receivers: UDP and TCP on port 5514

Open the dashboard, press **Load sample dataset** on the Overview page, and the cards fill in.
Then, in a second terminal with the virtual environment active:

```bash
python scripts/send_sample_attack.py --host 127.0.0.1 --port 5514
```

Events appear live in the Explorer. (Those lines are samples, clearly labelled as such, not
captured traffic.)

With Docker instead of Python:

```bash
docker compose up --build
sh scripts/check_image.sh     # optional: checks the image holds no secret, database or compiler
```

Same ports, and syslog is published on 514 as well as 5514. For a machine with no internet access,
see [AIRGAP.md](AIRGAP.md).

## 5. Measure the throughput

**First write down what you are measuring on.** A rate without hardware beside it means nothing.

```bash
lscpu | grep -E 'Model name|^CPU\(s\)|Thread'      # Linux
sysctl -n machdep.cpu.brand_string; sysctl -n hw.ncpu   # macOS
```

Then the three runs worth having. Each one uses a throwaway database and writes nothing into
`data/`.

**One process, everything on** — the number to quote as the per-process rate:

```bash
python scripts/benchmark.py -n 100000 -b 1000 --read
```

**All cores, sharded** — one ingest worker per core, each with its own database and its own hash
chain, which is how the design scales:

```bash
python scripts/benchmark.py -n 50000 -b 1000 -w 4        # -w = number of shards
```

**Without the full-text index** — what a pure forwarder deployment looks like:

```bash
SEARCH_INDEX=false python scripts/benchmark.py -n 100000 -b 1000
```

Save any run as data with `--json > bench-<machine>.json`.

### What the output means

```
ingest   100,000 events in 61.668s
         1,622 events/s  ->  140.1M/day on this machine
         batch latency p50 577.0 ms, p99 1071.89 ms (batch of 1000)
         parsing alone 92.1 us/line, about 14.9% of the time
```

Each of those events was decoded, parsed, normalised to OCSF 1.1.0, archived byte-for-byte with
its SHA-256, linked into the hash chain, indexed and committed durably. That is the work behind
the rate, and it is what makes the number comparable — or not — to someone else's.

The read section times what a person waits for: the Explorer page, a search over the archive, a
filter by address, the dashboard, an export and a full chain verification.

### What to record for the deck

| | |
|---|---|
| CPU model, cores, RAM | from step 5 |
| Python version | `python --version` |
| Events per second, one process | from the first run |
| Events per second, N shards | from the second run |
| p50 / p99 batch latency | from the first run |
| Read timings | from `--read` |

One billion events a day is 11,574 events/s sustained. Multiply your own rate by 86,400 and quote
that, with the hardware next to it.

## 6. If something goes wrong

- **`Address already in use`** — something else holds 8000, 8501 or 5514. Stop it, or edit the
  ports in `.env` and `config/tracelog.yaml`.
- **`python-multipart` error on startup** — `pip install -r requirements.txt` again inside the
  activated virtual environment; the upload endpoint needs it.
- **The dashboard shows nothing** — the API is not running. `curl http://127.0.0.1:8000/health`
  should answer `{"status":"healthy","service":"TRACELOG API",...}`.
- **The benchmark is much slower than expected** — check the machine is not on battery saver, and
  that the project is not on a network drive or an external USB disk; SQLite in WAL mode wants a
  local disk.
- **Windows and the `-w` flag** — shards use separate processes, which on Windows means the
  benchmark must be started from a terminal, not from inside an editor's run button.
