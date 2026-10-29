# Secure Adaptive Image Steganography Evaluation Report

## Executive Summary

- Carrier format: `JPEG`
- Resistance status: **Moderate Resistance**
- Final resistance score: **71.60 / 100**
- ROC AUC: **0.591837**
- Transform survival: **2/6**

## Carrier And Embedding Configuration

| Field | Value |
| --- | --- |
| capacity_bits | 886235 |
| channels | 3 |
| format | JPEG |
| height | 1080 |
| non_zero_ac_count | 886235 |
| robust_non_zero_ac_count | 515014 |
| width | 1920 |
| selected.capacity_bits | 25750 |
| selected.carrier_format | JPEG |
| selected.ecc_symbols | 64 |
| selected.engine_name | JPEGEngine |
| selected.non_zero_ac_count | 886235 |
| selected.payload_rate_bpnzac | 0.05 |
| selected.payload_size_bits | 736 |
| selected.required_embedding_bits | 1248 |
| selected.robust_mode | True |
| selected.robust_non_zero_ac_count | 515014 |
| selected.use_ecc | True |

## Perceptual Quality

| Metric | Value | Interpretation |
| --- | ---: | --- |
| SSIM | 0.998336 | Structural similarity; closer to 1 is better. |
| PSNR | 44.93 dB | Higher values indicate lower visible distortion. |
| MSE | 2.089966 | Lower values indicate lower pixel error. |

## Transformation Robustness

| Transform | Parameters | Outcome | Notes |
| --- | --- | --- | --- |
| jpeg_recompression | jpeg_quality=75 | FAIL-CLOSED | Reed-Solomon correction failed; payload integrity could not be recovered. |
| jpeg_recompression | jpeg_quality=85 | PASS |  |
| jpeg_recompression | jpeg_quality=90 | PASS |  |
| resize | default | FAIL-CLOSED | Reed-Solomon correction failed; payload integrity could not be recovered. |
| crop | default | FAIL-CLOSED | Reed-Solomon correction failed; payload integrity could not be recovered. |
| noise | noise_seed=1337 | FAIL-CLOSED | Reed-Solomon correction failed; payload integrity could not be recovered. |

## Steganalysis Reporting

| Metric | Value |
| --- | ---: |
| Detector | mean_absolute_difference_proxy |
| ROC AUC | 0.591837 |
| TPR @ 1.0% FPR | 0.142857 |
| TPR @ 0.1% FPR | 0.142857 |
| Confusion Matrix | `[[7, 0], [7, 0]]` |

## Resistance Score Decomposition

| Component | Score |
| --- | ---: |
| Quality | 99.83 |
| Robustness | 33.33 |
| Evasion | 81.63 |
| Final | 71.60 |

## Method Note

This report follows a social-media-style steganography evaluation pattern: measure perceptual distortion, apply realistic post-processing transforms, verify authenticated extraction, and report threshold-independent detector behavior with ROC/AUC. Failures after destructive transforms are classified as secure fail-closed when the authenticated envelope is not recovered.
