# P4 DualPI2

A P4/BMv2 implementation of DualPI2 for experiments with programmable L4S bottlenecks.

**Author:** Arman Babaei

## Contents

- `dualpi2.p4`: the P4 implementation.

## Target

The program is written for P4_16 using the BMv2 `v1model` architecture.

A typical compile command with `p4c` is:

```bash
p4c-bm2-ss --p4v 16 dualpi2.p4 -o dualpi2.json
```

## Research basis

The implementation follows the PI2 and Dual Queue Coupled AQM design line used for L4S:

- Koen De Schepper, Olga Bondarenko, Ing-Jyh Tsang, and Bob Briscoe, “PI²: A Linearized AQM for both Classic and Scalable TCP,” ACM CoNEXT 2016. DOI: 10.1145/2999572.2999578.
- Koen De Schepper, Olga Albisser, Olivier Tilmans, and Bob Briscoe, “Dual Queue Coupled AQM: Deployable Very Low Queuing Delay for All,” 2022. arXiv:2209.01078.

## Attribution

Implementation by Arman Babaei.
