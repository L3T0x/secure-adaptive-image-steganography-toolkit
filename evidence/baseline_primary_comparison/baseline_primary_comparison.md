# Baseline vs Primary Comparison

- Seed: `baseline-primary-comparison-seed`

## Results

| Family | Variant | Method | Roundtrip | Transform | Transform Roundtrip | SSIM | PSNR |
| --- | --- | --- | ---: | --- | ---: | ---: | ---: |
| PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2026 | False | 0.999998 | 79.11 |
| PNG | primary | lsb_matching | True | gaussian_noise_seed_2026 | False | 0.999998 | 79.11 |
| JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999717 | 56.44 |
| JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.982811 | 38.22 |

## Interpretation

- PNG results should be described as successful extraction on unmodified carriers.
- PNG post-processing failures should be described as payload corruption after destructive transformation.
- JPEG robust mode with ECC is the primary configuration for lossy recompression scenarios.
- These results are comparison evidence, not a claim of universal robustness.
