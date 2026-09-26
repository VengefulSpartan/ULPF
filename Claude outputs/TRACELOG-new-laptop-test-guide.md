# Running every TRACELOG test on the new Windows laptop

This guide covers all of TRACELOG's checks: the tests, the evaluations and the benchmarks. You run
them on the new laptop with one command, then read and compare the results. It also has you run the
same command on your current laptop first, so the two machines can be compared number for number.

**Time needed:** about 45 minutes of setup the first time (WSL and Docker downloads), then 15–25
minutes for the full run. Leave the laptop alone while it runs.

| Stage | Where | What you get |
|---|---|---|
| 1. Push and take a reference run | Current laptop (Ubuntu) | The new code on GitHub, and `results/old-laptop` |
| 2. Prepare Windows | New laptop, Windows | WSL 2 with Ubuntu, Docker Desktop, full power |
| 3. Get the code and install | New laptop, inside Ubuntu | `~/SIH26` with its own Python environment |
| 4. Run everything | New laptop, inside Ubuntu | `results/new-laptop/summary.md` |
| 5. Read the results | New laptop | What each number means and what it should be |
| 6. Compare the laptops | New laptop | A side-by-side table with ratios |
| 7. Send them back | — | The numbers go into the audit, README and deck |

---

## 1. On your current laptop: push, then take a reference run

The one-command runner (`scripts/run_all_checks.py`) is in your folder as the newest commit, one
ahead of GitHub. Push it so the new laptop can clone it:

```bash
cd ~/Desktop/SIH26
git push origin main
git status -sb            # should say: ## main...origin/main   (nothing ahead)
```

Then run everything once here, so you have something to compare against:

```bash
source .venv/bin/activate
python scripts/run_all_checks.py --out results/old-laptop
```

This takes 15–25 minutes. If Docker isn't installed on this laptop, the container check says
"skipped"; everything else runs. When it finishes, zip the folder and put the zip somewhere you can
reach from the new laptop (pendrive, Drive, email). If `zip` is missing, run
`sudo apt install -y zip` first.

```bash
cd results && zip -r old-laptop.zip old-laptop && cd ..
```

`results/` is ignored by git, so none of this can be pushed by accident.

---

## 2. On the new laptop: prepare Windows

TRACELOG runs under **WSL 2** (Ubuntu inside Windows). The benchmark numbers there are close to native Linux, as long as the code sits
in the Linux file system (step 3).

**Power first, because it changes every throughput number:**

- Plug the charger in.
- Settings → System → Power & battery → Power mode: **Best performance**.
- Settings → System → Power & battery → Screen and sleep: while plugged in, never sleep.

**Install WSL with Ubuntu.** Open PowerShell as Administrator:

```powershell
wsl --install -d Ubuntu-24.04
```

Restart when asked. Ubuntu opens and asks for a Linux username and password: pick any. Check it is WSL 2:

```powershell
wsl -l -v            # the VERSION column must say 2
```

**Check WSL can see every CPU.** Inside Ubuntu:

```bash
nproc                # should equal the laptop's logical processors (Task Manager → Performance → CPU)
free -g              # WSL gets half the RAM by default, which is plenty
```

If `nproc` is lower than it should be, create `C:\Users\<you>\.wslconfig` containing:

```ini
[wsl2]
processors=16        # the laptop's logical processor count
```

Then run `wsl --shutdown` in PowerShell and reopen Ubuntu.

**Install Docker Desktop** from docker.com. In its Settings:

- General → **Use the WSL 2 based engine**: on.
- Resources → WSL integration → **Ubuntu-24.04**: on.

Then check it from inside Ubuntu:

```bash
docker version       # must show both Client and Server
docker run --rm hello-world
```

---

## 3. On the new laptop: get the code and install

Everything from here runs **inside Ubuntu**, not PowerShell.

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip git zip unzip
cd ~
git clone https://github.com/VengefulSpartan/ULPF.git SIH26
cd SIH26
git log --oneline -1   # must be: "Run every check on a new machine with one command and compare machines"
```

If the repository is private, git asks for your GitHub username and a **personal access token**
(GitHub → Settings → Developer settings → Personal access tokens), not your password.

> **Clone into `~` (your Linux home), never under `/mnt/c/...`.** WSL reaches Windows drives through a
> slow bridge, so SQLite on `C:` runs several times slower and every throughput number comes out
> wrong. If the code is on a Windows drive, the summary prints a warning.

Install Python packages into a fresh environment. `pyarrow` is optional for TRACELOG but needed
here, otherwise the Parquet tests are skipped:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt pyarrow
```

A two-minute smoke test before the long run:

```bash
python scripts/run_all_checks.py --quick --out results/new-laptop-quick
```

It should end with `0 failed`. If anything fails here, stop and send me `results/new-laptop-quick`.

---

## 4. Run everything

Close other heavy programs (browsers with many tabs, games, video calls), make sure Docker Desktop
is running, then:

```bash
cd ~/SIH26 && source .venv/bin/activate
python scripts/run_all_checks.py --out results/new-laptop
```

It prints each check as it goes and ends with a line like
`9 checks in 18.4 min, 0 failed. Summary: results/new-laptop/summary.md`.

What it runs, in order:

| # | Check | What the runner executes | About |
|---|---|---|---|
| 1 | Test suite | `pytest -q` | 1 min |
| 2 | Formats with no parser | `scripts/evaluate_unseen_formats.py --json --learned` | seconds |
| 3 | One line traced end to end | `scripts/trace_line.py` | seconds |
| 4 | Throughput, one process | `scripts/benchmark.py -n 100000 -b 1000 --read`, three times | 2–5 min |
| 5 | Throughput, forwarder mode | the same with `SEARCH_INDEX=false`, once | 1 min |
| 6 | Throughput, sharded | `scripts/benchmark.py -n 50000 -w N` for N = 2, 4, 8 … up to your CPU count | 2–5 min |
| 7 | Real third-party logs | `scripts/evaluate_public_samples.py` (downloads Elastic's and Loghub's samples the first time, with git) | 2–4 min |
| 8 | Detector on synthetic days | `scripts/evaluate_baseline.py`, seeds 1, 2, 3 | 2 min |
| 9 | Container image | `sh scripts/check_image.sh`: builds the image, checks what is inside, starts it with no network | 3–6 min |

Every check uses a throwaway database: nothing is written into `data/`, and none of the documents
in `docs/` are rewritten. The reports all go into the results folder.

Useful options:

| Option | Does |
|---|---|
| `--quick` | Smaller runs, about 2 minutes; skips real logs and the container |
| `--skip container,public` | Leaves out named checks (`tests, unseen, trace, benchmark, public, baseline, container`) |
| `--repeat 5` | Five one-process benchmark runs instead of three, if the spread is wide |
| `--workers 2,4,8,16` | Choose the shard counts yourself |
| `--no-fetch` | Reuse real-log samples already downloaded |

To run a single check by hand, use the command in the table above, with the environment activated.

---

## 5. Read the results

Open the summary. From Ubuntu:

```bash
cd ~/SIH26/results/new-laptop && explorer.exe .
```

That opens the folder in Windows Explorer, where any markdown viewer or VS Code shows
`summary.md`. The folder holds:

| File | What it is |
|---|---|
| `summary.md` | The one page to read: the machine, every result, pass or fail |
| `summary.json` | The same as data, used by `--compare` |
| `machine.json` | CPU, cores, memory, OS, WSL, power, package versions, git commit |
| `pytest.log`, `unseen_formats.json`, `trace_line.log` | Raw output of checks 1–3 |
| `benchmark_single_1.json` … `_3.json`, `benchmark_no_index.json`, `benchmark_<N>_shards.json` | Raw benchmark output |
| `public_samples.json`, `PUBLIC_SAMPLES.md` | The real-log evaluation and its full report |
| `ml_evaluation.log`, `ML_EVALUATION.md` | The detector evaluation and its full report |
| `container.log` | Every line of the image check |

### Check the machine table first

| Row | Should say | If not |
|---|---|---|
| CPU, cores | The new laptop's processor | — |
| Under WSL | yes | — |
| On mains power | yes, or unknown (WSL often can't tell) | Plug in and rerun the benchmark |
| Packages | pandas, numpy, pyarrow all listed | `pip install -r requirements.txt pyarrow` |
| No warning about a Windows drive | — | Re-clone into `~` (step 3) |

### The claims: must be identical on every machine

These don't depend on the hardware. Any difference from this table is a bug or a broken install,
not a faster CPU.

| Check | Expected result |
|---|---|
| Test suite | **305 passed, 0 failed, 0 skipped** |
| Formats with no parser | **85 correct, 18 missed, 0 wrong** over 13 formats; learned parsers **2200/2200**, 0 wrong |
| One line traced | Raw SHA-256 starts **3150bb1390e5e004** (it depends only on the line) |
| Real third-party logs | **17,768 lines from 43 sources, 0 crashes, 0 invalid OCSF, 17,768/17,768 archived and chained, chain verified**; against Elastic: 8,693 agree, 711 disagree (3 unexplained), 4,229 left empty |
| Detector, synthetic days | **3 seeds: 6/6, 6/6, 6/6** detectable attacks caught; designed misses missed; false flags 1, 1, 1; findings valid, chain verified, rerun wrote nothing |
| Container image | Every line `ok`, no `FAIL`; image size reported |

### The measurements: these are what the new CPU changes

| Result | What it means | Reference: 2 shared cloud vCPUs |
|---|---|---|
| Throughput, one process | Events per second through the whole path: decode, parse, OCSF, SHA-256, hash chain, index, committed to disk. Median of 3 runs, with the slowest and fastest beside it. | 1,818–2,466 events/s |
| Batch latency p50 / p99 | How long a batch of 1,000 events takes, typically and at worst | about 400 / 480 ms |
| Forwarder mode | The same without the full-text search index, for a pure forwarder | about 3,100 events/s |
| Read-side timings | What a person waits for: Explorer page, search, address filter, dashboard, OCSF export, full chain verification | e.g. dashboard about 160 ms |
| Throughput, sharded | Several writers in parallel, each with its own database and chain; how the design scales across cores | 4,739–5,316 events/s with 2 shards |
| Scaling table | Events/s for each shard count, per shard, speed-up over one process, million events per day | — |
| 1 billion a day | Needs 11,574 events/s sustained; the summary says reached or not | not reached |

What to expect on a stronger CPU:

- **One process:** faster in proportion to single-core speed, not core count. It uses one core.
- **Shards:** should climb almost in step up to the number of *physical* cores, then flatten.
  Hyper-threads add a little; a laptop that heats up adds nothing.
- **A wide spread** between the three one-process runs (more than about 10%) usually means the
  laptop is throttling or something else was running. Let it cool and rerun with `--repeat 5`.

---

## 6. Compare the two laptops

Copy the zip from step 1 into the new laptop's results folder. If it's in your Windows Downloads
folder:

```bash
cp /mnt/c/Users/<your-windows-username>/Downloads/old-laptop.zip ~/SIH26/results/
cd ~/SIH26/results && unzip old-laptop.zip && cd ~/SIH26
python scripts/run_all_checks.py --compare results/old-laptop results/new-laptop
```

It prints a table and also saves it as `results/new-laptop/compare-with-old-laptop.md`. It shows:

- both CPUs and core counts;
- each measurement from both laptops;
- the **ratio**, new ÷ old: above 1 means faster for events per second, below 1 means faster for
  milliseconds;
- every claim's PASS or FAIL on both.

---

## 7. Send the results back

Zip the new results folder and share it, or just `summary.md` and the comparison table:

```bash
cd ~/SIH26/results && zip -r new-laptop.zip new-laptop
explorer.exe .
```

I'll put the new numbers into the compliance audit, the README, the architecture document and the
deck. The rule for quoting them: always with the hardware beside the number. For example:
"N events/s per process and M with K shards, on <CPU>, <cores> cores, Windows 11 with WSL 2,
median of 3 runs". Never a rounder number than a run produced.

---

## Optional: see it working, not just measured

These aren't measurements, but they're worth five minutes on the new laptop:

```bash
python run_app.py                                           # API on :8000, dashboard on :8501
python scripts/send_sample_attack.py --host 127.0.0.1 --port 5514   # in a second Ubuntu window
```

Open <http://localhost:8501> in a Windows browser; WSL forwards localhost. For a longer, sustained
benchmark that shows thermal throttling if there is any:

```bash
python scripts/benchmark.py -n 500000 -b 1000
```

---

## If something goes wrong

| Symptom | Fix |
|---|---|
| `python3 -m venv` fails | `sudo apt install -y python3-venv` |
| `pip install` fails on a package | `pip install --upgrade pip`, then install again |
| Test suite shows skipped tests | `pip install pyarrow` in the activated environment |
| "Real third-party logs: script failed" | It needs git and internet the first time; rerun, or `--skip public` |
| "Container image: skipped" | Docker Desktop isn't running, or WSL integration for Ubuntu-24.04 is off |
| `Cannot connect to the Docker daemon` | Start Docker Desktop; Settings → Resources → WSL integration → Ubuntu-24.04 on |
| The summary warns about a Windows drive | Re-clone into `~/SIH26` (step 3) and run again |
| Throughput lower than on the old laptop | Check "On mains power", the Windows power mode, and that nothing else was running; rerun the benchmark alone with `--skip tests,unseen,trace,public,baseline,container --repeat 5` |
| The laptop went to sleep mid-run | Set sleep to never while plugged in, then rerun |
| Anything else | Send me the results folder: each check's raw output is in it |
