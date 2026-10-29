# Submission Notes

## What This Package Demonstrates

- PNG and JPEG embedding/extraction on unmodified carriers.
- Mandatory cryptographic protection with Argon2id and AES-GCM.
- Fail-closed behavior for wrong passwords and tampered ciphertext.
- Explainable rule-based engine/parameter selection.
- Feature-based rich residual ensemble steganalysis with ROC/AUC reporting.
- Transformation-aware robustness checks and bounded resistance-score reporting.
- BOSSbase-sourced PNG/JPEG benchmark evidence.
- Baseline-vs-primary comparison evidence.
- Automated pytest evidence.

## Included Evidence Scope

- Automated tests: `python -m pytest -q` -> `6 passed`.
- Baseline-vs-primary evidence:
  `evidence/baseline_primary_comparison_sample_10/`.
- BOSSbase-sourced benchmark evidence:
  `datasets/bossbase_runs/sample_30/`.

The BOSSbase sample uses 30 source images converted into both PNG and JPEG
carriers, producing 60 evaluated cover/stego pairs. This is expanded sample
evidence for supervisor review, not a claim that all 10,000 BOSSbase images
were evaluated.

## Accurate Report Wording

Use:

> The evaluation used BOSSbase 1.01 as the source image family. Since BOSSbase
> images are provided as grayscale PGM files and the toolkit scope is PNG/JPEG,
> selected BOSSbase images were converted into PNG and JPEG carriers before
> embedding and evaluation.

Use:

> PNG embedding preserved extraction on unmodified carriers, while destructive
> post-processing resulted in payload corruption or authenticated fail-closed
> behavior.

Use:

> JPEG robust DCT selection with Reed-Solomon ECC showed limited recompression
> survival in the included sample evidence, especially compared with the
> standard DCT baseline.

Use:

> The current detector AUC, transformation-survival, and resistance-score
> results are preliminary implementation findings until the final FYP 2
> evaluation sample and direct baseline comparison are fixed and reported.

Use:

> A failed authenticated extraction after transformation is secure fail-closed
> behavior, not a robustness success. Robustness success is counted only when
> the original authenticated payload is recovered after the transformation.

Use:

> AES-GCM provides authenticated confidentiality and integrity for the encrypted
> payload envelope. Formal key-committing AEAD is treated as future work.

Do not claim:

- That all 10,000 BOSSbase images were evaluated unless the full benchmark is
  actually run.
- That PNG survived all destructive post-processing transforms.
- That fail-closed extraction failure is the same thing as robustness.
- That the AEAD construction is formally key-committing.
