# BOSSbase-Sourced Benchmark Summary

- Created UTC: `2026-07-03T02:56:16.152995+00:00`
- Archive: `C:\Users\User\Documents\Playground\datasets\BOSSbase_1.01.zip`
- Archive SHA-256: `9823e888d4cfa36e94a58676416ea840de3edf1eb663f605451abae3ba8c8524`
- Source format: `PGM grayscale`
- Toolkit carrier formats: `PNG, JPEG`
- Evaluated cover/stego pairs: `60`

## Method Note

BOSSbase 1.01 images are stored as grayscale PGM files. For this PNG/JPEG toolkit, each selected source image is converted into the evaluated carrier format before embedding. This benchmark therefore supports the wording "BOSSbase-sourced PNG/JPEG carriers" rather than claiming the original PGM files were embedded directly.

## Interpretation Note

These detector AUC, transformation-survival, and resistance-score outputs are preliminary implementation evidence for the documented sample. A failed authenticated extraction after transformation is recorded as secure fail-closed behavior, not as a robustness success. Robustness success is counted only when the original authenticated payload is recovered.

## Aggregate

| Carrier | Pairs | Roundtrip | Wrong Password Fail-Closed | Transform Success | Mean ROC AUC | Mean SSIM | Mean Resistance |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| JPEG | 30 | 30/30 | 30/30 | 17/180 | 0.291370 | 0.981624 | 68.91 |
| PNG | 30 | 30/30 | 30/30 | 0/180 | 0.216077 | 0.999994 | 66.67 |

## Per-Pair Results


| Source | Carrier | Roundtrip | Detector | ROC AUC | SSIM | PSNR | Resistance |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: |
| 1 | PNG | True | rich_residual_ensemble | 0.297790 | 0.999993 | 79.23 | 66.67 |
| 1 | JPEG | True | rich_residual_ensemble | 0.278627 | 0.983575 | 36.70 | 71.67 |
| 2 | PNG | True | rich_residual_ensemble | 0.206844 | 0.999991 | 79.41 | 66.67 |
| 2 | JPEG | True | rich_residual_ensemble | 0.286539 | 0.988774 | 44.47 | 66.29 |
| 3 | PNG | True | rich_residual_ensemble | 0.215911 | 0.999995 | 79.27 | 66.67 |
| 3 | JPEG | True | rich_residual_ensemble | 0.253425 | 0.983323 | 37.00 | 71.67 |
| 4 | PNG | True | rich_residual_ensemble | 0.214647 | 0.999994 | 79.17 | 66.67 |
| 4 | JPEG | True | rich_residual_ensemble | 0.260073 | 0.980210 | 36.54 | 71.56 |
| 5 | PNG | True | rich_residual_ensemble | 0.215692 | 0.999994 | 79.30 | 66.67 |
| 5 | JPEG | True | rich_residual_ensemble | 0.254096 | 0.976142 | 37.55 | 65.87 |
| 6 | PNG | True | rich_residual_ensemble | 0.214756 | 0.999995 | 79.28 | 66.67 |
| 6 | JPEG | True | rich_residual_ensemble | 0.260292 | 0.981776 | 34.00 | 71.61 |
| 7 | PNG | True | rich_residual_ensemble | 0.211760 | 0.999994 | 79.48 | 66.67 |
| 7 | JPEG | True | rich_residual_ensemble | 0.248463 | 0.982267 | 34.89 | 71.63 |
| 8 | PNG | True | rich_residual_ensemble | 0.209450 | 0.999995 | 79.35 | 66.67 |
| 8 | JPEG | True | rich_residual_ensemble | 0.248338 | 0.981964 | 36.28 | 71.62 |
| 9 | PNG | True | rich_residual_ensemble | 0.215053 | 0.999996 | 79.19 | 66.67 |
| 9 | JPEG | True | rich_residual_ensemble | 0.287210 | 0.975102 | 35.84 | 71.39 |
| 10 | PNG | True | rich_residual_ensemble | 0.209263 | 0.999996 | 79.45 | 66.67 |
| 10 | JPEG | True | rich_residual_ensemble | 0.254346 | 0.982686 | 35.63 | 71.65 |
| 11 | PNG | True | rich_residual_ensemble | 0.210933 | 0.999995 | 79.28 | 66.67 |
| 11 | JPEG | True | rich_residual_ensemble | 0.248322 | 0.982676 | 37.46 | 71.64 |
| 12 | PNG | True | rich_residual_ensemble | 0.214959 | 0.999994 | 79.35 | 66.67 |
| 12 | JPEG | True | rich_residual_ensemble | 0.256016 | 0.982246 | 39.35 | 71.63 |
| 13 | PNG | True | rich_residual_ensemble | 0.213196 | 0.999996 | 79.13 | 66.67 |
| 13 | JPEG | True | rich_residual_ensemble | 0.258232 | 0.981760 | 36.82 | 71.61 |
| 14 | PNG | True | rich_residual_ensemble | 0.212759 | 0.999992 | 79.27 | 66.67 |
| 14 | JPEG | True | rich_residual_ensemble | 0.305406 | 0.982406 | 37.51 | 66.08 |
| 15 | PNG | True | rich_residual_ensemble | 0.212369 | 0.999993 | 79.44 | 66.67 |
| 15 | JPEG | True | rich_residual_ensemble | 0.569583 | 0.978573 | 37.65 | 61.31 |
| 16 | PNG | True | rich_residual_ensemble | 0.213789 | 0.999991 | 79.14 | 66.67 |
| 16 | JPEG | True | rich_residual_ensemble | 0.266846 | 0.988312 | 42.49 | 66.28 |
| 17 | PNG | True | rich_residual_ensemble | 0.224681 | 0.999993 | 78.95 | 66.67 |
| 17 | JPEG | True | rich_residual_ensemble | 0.266299 | 0.979878 | 34.67 | 71.55 |
| 18 | PNG | True | rich_residual_ensemble | 0.212805 | 0.999993 | 79.47 | 66.67 |
| 18 | JPEG | True | rich_residual_ensemble | 0.249867 | 0.983872 | 37.51 | 66.13 |
| 19 | PNG | True | rich_residual_ensemble | 0.214147 | 0.999995 | 79.29 | 66.67 |
| 19 | JPEG | True | rich_residual_ensemble | 0.253488 | 0.981541 | 35.25 | 71.61 |
| 20 | PNG | True | rich_residual_ensemble | 0.212166 | 0.999993 | 79.04 | 66.67 |
| 20 | JPEG | True | rich_residual_ensemble | 0.563231 | 0.977886 | 39.76 | 61.71 |
| 21 | PNG | True | rich_residual_ensemble | 0.208842 | 0.999993 | 79.31 | 66.67 |
| 21 | JPEG | True | rich_residual_ensemble | 0.279782 | 0.979878 | 35.40 | 66.00 |
| 22 | PNG | True | rich_residual_ensemble | 0.215068 | 0.999995 | 79.24 | 66.67 |
| 22 | JPEG | True | rich_residual_ensemble | 0.302846 | 0.974791 | 34.40 | 65.83 |
| 23 | PNG | True | rich_residual_ensemble | 0.215255 | 0.999993 | 79.42 | 66.67 |
| 23 | JPEG | True | rich_residual_ensemble | 0.251163 | 0.986835 | 35.64 | 66.23 |
| 24 | PNG | True | rich_residual_ensemble | 0.209357 | 0.999993 | 79.22 | 66.67 |
| 24 | JPEG | True | rich_residual_ensemble | 0.266237 | 0.983995 | 36.47 | 66.13 |
| 25 | PNG | True | rich_residual_ensemble | 0.213102 | 0.999993 | 79.21 | 66.67 |
| 25 | JPEG | True | rich_residual_ensemble | 0.259184 | 0.983786 | 36.13 | 66.13 |
| 26 | PNG | True | rich_residual_ensemble | 0.213976 | 0.999997 | 79.12 | 66.67 |
| 26 | JPEG | True | rich_residual_ensemble | 0.315049 | 0.974877 | 35.18 | 71.38 |
| 27 | PNG | True | rich_residual_ensemble | 0.216473 | 0.999997 | 79.31 | 66.67 |
| 27 | JPEG | True | rich_residual_ensemble | 0.251007 | 0.987505 | 39.30 | 77.36 |
| 28 | PNG | True | rich_residual_ensemble | 0.205377 | 0.999993 | 79.31 | 66.67 |
| 28 | JPEG | True | rich_residual_ensemble | 0.251038 | 0.985036 | 39.09 | 66.17 |
| 29 | PNG | True | rich_residual_ensemble | 0.214506 | 0.999997 | 79.45 | 66.67 |
| 29 | JPEG | True | rich_residual_ensemble | 0.243485 | 0.981222 | 33.54 | 71.60 |
| 30 | PNG | True | rich_residual_ensemble | 0.217393 | 0.999994 | 79.47 | 66.67 |
| 30 | JPEG | True | rich_residual_ensemble | 0.452608 | 0.975819 | 34.97 | 65.86 |
