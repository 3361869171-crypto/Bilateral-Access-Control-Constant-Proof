# Bilateral Access Control System (MoniPoly & PS Signature)

This repository contains the official C++ implementation and experimental benchmark for the paper:
**"A Secure Bilateral Access Control System with Fine-grained Policy and Constant-size Proof"**.

It provides a three-scheme comparison:
- **Scheme A (Main)**: MoniPoly (`system_mine/`, `--commit=moni`)
- **Scheme B (Ablation)**: Pedersen commitment (`system_mine/`, `--commit=ped`)
- **Scheme C (Baseline)**: CRO-ABME (`system_compare/cro-abme-bn254/`), a C++/MIRACL port based on Huang & Si (IEEE IoT-J 2024).

## 1. Dependencies
- Linux x86_64, `g++` (C++17), `make`
- **MIRACL**: Not distributed here due to AGPLv3. Download from [MIRACL GitHub](https://github.com/miracl/MIRACL), extract it as `./MIRACL-master/`, and run `./build_miracl.sh`.

## 2. Build & Quick Start
```bash
# 0) Build MIRACL
./build_miracl.sh

# 1) Interactive Mode (Scheme A / B)
make -C system_mine
./system_mine/main --commit=moni
./system_mine/main --commit=ped

# 2) Non-interactive Benchmark (Scheme A / B)
./system_mine/main --bench --commit=moni --attrs 10 --reps 5
./system_mine/main --bench --commit=ped  --attrs 10 --reps 5

# 3) Scheme C (Baseline)
make -C system_compare/cro-abme-bn254
./system_compare/cro-abme-bn254/cro-abme-bn254 --attrs 10 --reps 5
```

## License & Acknowledgements

- Core code is licensed under the MIT License (see LICENSE file).
- Scheme C (`system_compare/cro-abme-bn254/`) is a C++/MIRACL port based on the algorithm by Huang & Si (IEEE IoT-J 2024, DOI: 10.1109/JIOT.2024.3513326). The original Python implementation is not redistributed.
- MIRACL is a third-party library (AGPLv3) and is not included in this repository.
