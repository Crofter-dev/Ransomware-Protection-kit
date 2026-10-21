# Behavior-Based Ransomware Detector

Watches a folder, scores bursts of file activity with a LightGBM model,
applies plain rules to decide what to do, and writes a short incident
summary. It looks at *behavior* (how fast files are written, renamed and
turned random), not at file signatures, so it can flag ransomware it has
never seen.

> **Safety first.** It runs as a **dry run** by default and only prints what it
> would do. Nothing is killed unless you pass `--enforce`. The included
> attack simulator is a safe, reversible fake. Never test with real malware
> outside an isolated virtual machine.

## How it works

```
file_monitor  ->  detector  ->  decision_engine  ->  response_actions  ->  explainer
(watchdog)       (LightGBM      (rules decide)       (only with           (template, or an
                  score 0-1)                          --enforce)           optional local model)
```

| Part | What it does |
|---|---|
| `file_monitor.py` | Watches a folder and groups events into 3-second windows |
| `feature_extraction.py` | Turns a window into 11 numbers (write/rename rate, entropy change, extension changes...) |
| `detector.py` | LightGBM scores a window from 0 (normal) to 1 (ransomware-like) |
| `decision_engine.py` | Rules: ignore, alert, kill, or kill and isolate. No AI, every decision lists its reasons |
| `response.py` | Kills a process, quarantines files, simulated host isolation |
| `explainer.py` | Writes the incident summary. A local model is optional and only words the text, it never decides |
| `orchestrator.py` | Runs the whole pipeline |

Decision safeguards: dry run by default, protected PIDs are never killed,
known backup and archive tools only raise an alert, and with no process
identified the tool only alerts.

## Setup

Python 3.10+ (CPU only, no GPU needed).

```bash
pip install -r requirements.txt
```

## Run it

From the `src` folder:

```bash
python orchestrator.py --watch-dir ../watched            # dry run
python orchestrator.py --watch-dir ../watched --enforce  # really stop processes
```

Then, in another terminal, trigger the safe simulator against a test folder
(see `simulator.py`; `--revert` restores the files).

## Optional: plain-language summaries from a local model

The summary works without any AI. To have a small local model reword it
(runs on your own machine, no cloud, no API key):

1. Install [Ollama](https://ollama.com).
2. `ollama pull hf.co/Qwen/Qwen3-1.7B-GGUF:Q8_0`
3. Check the name with `ollama list`, then:

```bash
python explainer.py --local-model <name from ollama list>
python orchestrator.py --watch-dir ../watched --local-model <name>
```

If Ollama runs on another machine or port, add `--ollama-host http://HOST:PORT`.
The model's text is labeled as model-written and is not part of the decision.
If the model is unavailable, the tool falls back to the template summary.

## Training your own model

The data comes from our own monitor, with scenarios labeled by what they did:

```bash
python dataset.py --scenarios 300 --out ../data/windows.csv   # build the dataset
python compare.py --csv ../data/windows.csv                    # compare models
python model.py --real-logs ../data/windows.csv                 # retrain, saves ../models/ransomware_lgbm.txt
```

Compare scores use grouped cross-validation (windows from the same scenario
never land in both train and test).

## Tests

```bash
python tests/test_pipeline.py
```

Covers the decision rules, the explainer (including a fake local model server)
and dry-run versus enforce against a throwaway process.

## Known limitations

- The data comes from a simulator, not real ransomware. Real validation needs
  real samples inside an isolated virtual machine.
- The monitor reads file contents just after an event, so under a very fast burst
  the "files became random" signal can read as zero. The model leans on that signal.
- A userspace watcher gets no process ID, so the tool usually alerts rather than kills.
  `isolate_host` is simulated and not wired to a real firewall.
