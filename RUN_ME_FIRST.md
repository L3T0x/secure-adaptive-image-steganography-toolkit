# Supervisor Quick Check

This package contains the FYP system for the Secure Adaptive Image
Steganography Toolkit. It is intended to let a supervisor quickly verify that
the system can run before the FYP 2 testing/write-up stage.

## 1. Requirements

- Python 3.11 or later.
- Internet access only if installing dependencies for the first time.
- Optional: GUI dependencies if the desktop interface needs to be tested.

## 2. Install

From inside the extracted `STEGFYP_SYSTEM` folder:

```bash
python -m pip install ".[dev,gui]"
```

If the GUI is not needed:

```bash
python -m pip install ".[dev]"
```

## 3. Fast Verification

Run the automated tests:

```bash
python -m pytest -q
```

Expected result:

```text
6 passed
```

Generate baseline-vs-primary comparison evidence:

```bash
python baseline_primary_comparison.py --samples 10 --output-dir evidence/baseline_primary_comparison_sample_10
```

Expected result:

- JSON report: `evidence/baseline_primary_comparison_sample_10/baseline_primary_comparison.json`
- Markdown report: `evidence/baseline_primary_comparison_sample_10/baseline_primary_comparison.md`

The comparison demonstrates:

- PNG LSB replacement vs PNG LSB matching.
- JPEG standard DCT vs JPEG robust DCT with Reed-Solomon ECC.
- Transform failures are reported as failures, not as robustness successes.

## 4. Existing Evidence Included

The package already includes:

- `evidence/test_results.md`
- `evidence/baseline_primary_comparison/`
- `evidence/baseline_primary_comparison_sample_10/`
- `datasets/BOSSbase_1.01_manifest.json`
- `datasets/bossbase_runs/sample_30/`

The included BOSSbase evidence is a 30-image BOSSbase-sourced sample benchmark
converted into PNG/JPEG carriers, not a claim that all 10,000 BOSSbase images
were evaluated.

## 5. BOSSbase Note

The full `BOSSbase_1.01.zip` archive is not included because it is about 1.67 GB.
The package includes the manifest, hash, official source URL, and sample
benchmark evidence.

To rerun the BOSSbase sample from the official archive, place
`BOSSbase_1.01.zip` at:

```text
datasets/BOSSbase_1.01.zip
```

Then run:

```bash
python bossbase_benchmark.py --archive datasets/BOSSbase_1.01.zip --output-dir datasets/bossbase_runs/sample_30 --limit 30 --formats PNG,JPEG
```

The detector AUC, transformation-survival, and resistance-score outputs in the
included evidence should be described as preliminary findings until the final
FYP 2 evaluation sample is fixed and reported. Secure fail-closed behavior is
not counted as robustness success; robustness success means the original
authenticated payload was recovered after the transformation.

## 6. CLI And GUI

CLI help:

```bash
stegtoolkit --help
```

GUI launch:

```bash
stegtoolkit-gui
```

If the console scripts are not available after installation, run the Python
modules directly from the project folder:

```bash
python main.py --help
python gui.py
```
