# PIRANHAS — Artifact Documentation

## Overview

In this paper, we address two key challenges in **remote attestation (RA)** protocols:

1. **Public verifiability**, and
2. **Privacy protection**.

We present **PIRANHAS**, a *publicly verifiable, asynchronous, and anonymous attestation scheme* for both individual devices and swarms.

Our approach leverages **zk-SNARKs** to transform any classical symmetric RA scheme into a **non-interactive, publicly verifiable, and privacy-preserving** construction.
Verifiers can confirm the validity of attestations without learning any identifying information about participating devices.

**PIRANHAS** also supports **aggregation of RA proofs** across the entire network using recursive zk-SNARKs.
We provide an **open-source implementation** using both the **Noir** and **Plonky2** frameworks, and we compare their practicality.
We achieve an **aggregation runtime of 356 ms**.

🔗 **Repository:** [https://anonymous.4open.science/r/piranhas](https://anonymous.4open.science/r/piranhas)
📄 The repository includes all code required to reproduce the results presented in **Section V** (Tables III and IV).

---

## Description & Requirements

### Access

The implementation is publicly available at:
👉 [https://anonymous.4open.science/r/piranhas](https://anonymous.4open.science/r/piranhas)

> **Note:** A permanent GitHub link and Zenodo DOI will be added in the camera-ready version.

### Hardware Dependencies

None.

### Software Dependencies

All experiments are reproducible on **commodity hardware** running **Linux** or **macOS**.
Benchmark scripts and pre-configured inputs are provided for all ZK circuits.

**Required proving backends:**

* Circom
* Noir / Ultra_Honk
* Plonky2

To run benchmarks, execute `benchmark.sh` in each corresponding directory.

---

## Installation & Configuration

Below are the installation steps for all required backends on Unix-based systems.

### 1. Install Node.js

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh | bash
source ~/.bashrc
nvm install v22
```

### 2. Install snarkjs

```bash
npm install -g snarkjs
```

### 3. Install Rust

```bash
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```

### 4. Install Circom

```bash
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
```

### 5. Install Noir

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup -v 1.0.0-beta.3
```

### 6. Install Barretenberg

```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
bbup -v 0.82.0
```

---

## Experiment Workflow

We implemented PIRANHAS using three zkSNARK proving backends:

* **Groth16** (Circom)
* **Ultra_Honk** (Noir)
* **Plonky2**

All results presented in **Section V** can be reproduced using the provided benchmark scripts for each backend.

---

## Major Claims

We benchmarked our implementations on commodity hardware.
This README focuses on the quantitative results reported in **Table III** and **Table IV** of **Section V**.

* **(C1)**:
  The proposed protocol $\Pi_\text{ranha}$, when implemented using **Groth16**, achieves sub-second proving time on a laptop and remains practical on constrained hardware (e.g., Raspberry Pi Zero 2 W).
  Its performance matches the state of the art.
  Supported by **Experiment E1**.

* **(C2)**:
  The proposed aggregatable (recursive) zkSNARK proofs $\Pi_\text{ranhas}$ are practical on commodity hardware.
  Supported by **Experiments E2** and **E3** using **Ultra_Honk** and **Plonky2**, respectively.

---

## Evaluation

### Experiment (E1) — Groth16 Performance

**Estimated time:** ~1 human minute + 1–2 compute minutes
**Preparation:** Install Circom and SnarkJS.

#### Execution

```bash
cd circom
./benchmark.sh
```

#### Example Output

```
Step 1: Install NPM dependencies
Step 2: Compile circuit (attest.circom)
Step 4: Generate witness using input.json
Witness generated in 129 ms
Step 5: Generate new Powers of Tau 
Step 6: Prepare phase 2 for Groth16
Step 7: Setup Groth16 proving key
Step 8: Export verification key
Step 9: Prove using Groth16
Proof generated in 841 ms
Step 10: Verify the proof
[INFO]  snarkJS: OK!
Verification completed in 466 ms
```

Performance metrics for **Table IV** (Groth16) are visible in the output.

---

### Experiment (E2) — Ultra_Honk Performance

**Estimated time:** ~1 human minute + 2–5 compute minutes

#### Preparation

Ensure correct versions:

```
bb --version ==> 0.82.0
nargo --version ==> 1.0.0-beta.3
```

If needed:

```bash
noirup -v 1.0.0-beta.3
bbup -v 0.82.0
```

#### Execution

```bash
cd noir
./run_benchmark.sh [1-5]
```

**Available benchmarks:**

1. `attest-(Pi-zkRA)`
2. `recurse-(R1)`
3. `aggregate-(R2)`
4. `optimized-(R2+R1)`
5. `optimized-(2xR2+R1)`

Benchmarks 1, 3, and 5 correspond to **Table III (Ultra_Honk)** under
columns $\relation_\att$, $\relation_\agg$, and $2×\relation_\agg$.

#### Example Output

```
Step 1 — Executing Nargo  
Step 2 — Writing Verification Key  
Step 3 — Proving  
Step 4 — Verifying Proof
```

Performance metrics appear in log lines such as:

```
Proving phase took 12588 ms
Verification phase took 40 ms
```

---

### Experiment (E3) — Plonky2 Performance

**Estimated time:** ~1 human minute + 2–15 compute minutes

#### Preparation

```bash
cd plonky2/plonky2-examples/examples
rustup override set nightly
cargo build --release
```

#### Execution

```bash
./benchmarks.sh [optional # of runs]
```

Recommended: start with 5–10 runs for quicker initial results.

#### Example Output

```
Running 3 iterations...
Completed 1 run...
Completed 2 runs...
Completed 3 runs...

Averages after 3 runs 
(successful runs per label shown):
dev 1 (3 runs): avg = 1.7196s
dev 2 (3 runs): avg = 1.4318s
dev 1 optional (3 runs): avg = 0.5328s
dev 2 optional 2 (3 runs): avg = 0.4941s
dev 3 aggr (3 runs): average = 0.5196s
Verification time = 0.0047s
```

Performance metrics for **Table III (Plonky2)** correspond to:

* $\relation_\att$: e.g., `dev 1/2 avg = 1.72s / 1.43s`
* $\relation_\agg$: e.g., `dev 3 aggr avg = 0.52s`
* Verification: `0.0047s`
