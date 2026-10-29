# Baseline vs Primary Comparison

- Seed prefix: `baseline-primary-comparison-seed`
- Samples: `10`
- JPEG transform check: `q90`

## Aggregate

| Family | Variant | Method | Samples | Roundtrip | Transform Roundtrip | Mean SSIM | Mean PSNR |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| JPEG | baseline | standard_dct | 10 | 10/10 | 0/10 | 0.999685 | 56.24 |
| JPEG | primary | robust_dct_with_reed_solomon_ecc | 10 | 10/10 | 10/10 | 0.980685 | 37.66 |
| PNG | baseline | lsb_replacement | 10 | 10/10 | 0/10 | 0.999997 | 78.07 |
| PNG | primary | lsb_matching | 10 | 10/10 | 0/10 | 0.999997 | 78.07 |

## Detailed Results

| Sample | Family | Variant | Method | Roundtrip | Transform | Transform Roundtrip | SSIM | PSNR |
| ---: | --- | --- | --- | ---: | --- | ---: | ---: | ---: |
| 1 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2027 | False | 0.999997 | 78.01 |
| 1 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2027 | False | 0.999997 | 78.01 |
| 1 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999704 | 56.28 |
| 1 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.982375 | 38.12 |
| 2 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2028 | False | 0.999997 | 77.97 |
| 2 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2028 | False | 0.999997 | 77.97 |
| 2 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999696 | 56.15 |
| 2 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.982168 | 38.03 |
| 3 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2029 | False | 0.999997 | 78.28 |
| 3 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2029 | False | 0.999997 | 78.28 |
| 3 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999668 | 56.03 |
| 3 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.980355 | 37.56 |
| 4 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2030 | False | 0.999996 | 78.03 |
| 4 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2030 | False | 0.999996 | 78.03 |
| 4 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999654 | 55.98 |
| 4 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.978808 | 37.31 |
| 5 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2031 | False | 0.999997 | 78.08 |
| 5 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2031 | False | 0.999997 | 78.08 |
| 5 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999704 | 56.64 |
| 5 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.980775 | 37.64 |
| 6 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2032 | False | 0.999997 | 77.70 |
| 6 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2032 | False | 0.999997 | 77.70 |
| 6 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999668 | 55.98 |
| 6 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.980882 | 37.66 |
| 7 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2033 | False | 0.999997 | 77.93 |
| 7 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2033 | False | 0.999997 | 77.93 |
| 7 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999680 | 56.20 |
| 7 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.980647 | 37.49 |
| 8 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2034 | False | 0.999996 | 78.10 |
| 8 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2034 | False | 0.999996 | 78.10 |
| 8 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999667 | 56.33 |
| 8 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.980317 | 37.59 |
| 9 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2035 | False | 0.999997 | 78.30 |
| 9 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2035 | False | 0.999997 | 78.30 |
| 9 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999700 | 56.27 |
| 9 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.981407 | 37.84 |
| 10 | PNG | baseline | lsb_replacement | True | gaussian_noise_seed_2036 | False | 0.999996 | 78.28 |
| 10 | PNG | primary | lsb_matching | True | gaussian_noise_seed_2036 | False | 0.999996 | 78.28 |
| 10 | JPEG | baseline | standard_dct | True | jpeg_recompression_q90 | False | 0.999706 | 56.51 |
| 10 | JPEG | primary | robust_dct_with_reed_solomon_ecc | True | jpeg_recompression_q90 | True | 0.979119 | 37.37 |

## Interpretation

- PNG results should be described as successful extraction on unmodified carriers.
- PNG post-processing failures should be described as payload corruption after destructive transformation.
- JPEG robust mode with ECC is the primary configuration for lossy recompression scenarios.
- These results are comparison evidence, not a claim of universal robustness.
