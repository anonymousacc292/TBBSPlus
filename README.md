# Threshold BBS+
This repository provides the artifacts regarding our submission #1286, including the following,

**Implementation** 
We provide implementations of our scheme, SET-BBS+, and the state-of-the-art WMC24 for both n-out-of-n and t-out-of-n scenarios. Additionally, we have modified the open-source code of DKL+23 to support these scenarios as well. 

 **Reproduction of Our Experiment Results** 
We provide the two methods for reproducing the performance comparison between our work and the state-of-the-art are provided in Tables 3 and 4 of our original submission. Two methods include the following:
* Using Docker to reproduce our results in few minutes without installing prerequisites.
* Configuring and deploying our code on Ubuntu and macOS.

## Implementation
The code for the main protocols is located as follows:
  * `src/n_out_of_n/setbbsplus` n-out-of-n SET-BBS+ 
  * `src/t_out_of_n/setbbsplus` t-out-of-n SET-BBS+ 
  * `src/n_out_of_n/wmc24` n-out-of-n WMC24
  * `src/t_out_of_n/wmc24` t-out-of-n WMC24
  * `crypto/bbs_plus/src/threshold/threshold_bbs_plus.rs` n-out-of-n and t-out-of-n DKL+23
  
## Instructions for Reproduction

### Depolyment via Docker

1. Install Docker. Official guideline (https://docs.docker.com/get-started/get-docker/)
2. Pull our image.
    ```sh
        docker pull mengling333666/meng:escrow
    ```
3. Run the container.     
    ```sh
        docker run -it mengling333666/meng:escrow /bin/bash
    ```

### Depolyment via Source Code

#### On Ubuntu 24.04.1

1. Install prerequisites
    ```sh
        apt-get update  
        apt-get install -y git curl build-essential libclang-dev libgmp-dev libssl-dev python3
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
2. Clone the repository
   ```sh
        git clone https://github.com/anonymousacc292/TBBSPlus.git
   ```
3. Compile the `prime` submodule
    ```sh
        cd ${repo_path}/prime/src/lib
        bash prime.sh
    ```
4. Compile the repository
    ```sh
        cd ${repo_path}
        cargo build
    ```
#### On macOS Sonoma 14.0
Steps 2, 3, and 4 are identical to the above.
1. Install prerequisite
    ```sh
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        brew install git curl llvm gmp openssl python
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
### Instructions for Running Experiments
A quick method to evaluate the performance of the signing phase for SET-BBS+, the state-of-the-art WMC24, and DKL+23 in both n-out-of-n and t-out-of-n scenarios.

```sh
    cd ${repo_path}
    python3 fast_run.py
```
The detailed commands for running the experiments are as follows:
#### N-OUT-OF-N
*  The signing phase of SET-BBS+ and WMC24
    ```sh
    RUSTFLAGS="-Awarnings" cargo bench --bench n_out_of_n_sign
    ```
*  The key generation phase of SET-BBS+ and WMC24
    ```sh
    RUSTFLAGS="-Awarnings" cargo bench --bench n_out_of_n_keygen
    ```
*  The client phase of SET-BBS+ and WMC24
    ```sh
    RUSTFLAGS="-Awarnings" cargo bench --bench n_out_of_n_client
    ```
*  The signing, key generation phase and client phase of of DKL+23
    ```sh
    cd crypto
    RUSTFLAGS="-Awarnings" cargo test --release --package bbs_plus --lib -- threshold::threshold_bbs_plus::tests::signing_n_out_of_n --exact --show-output 
    ```
#### T-OUT-OF-N
*  The signing phase of SET-BBS+ and WMC24
    ```sh
    RUSTFLAGS="-Awarnings" cargo bench --bench t_out_of_n_sign
    ```
*  The key generation phase of SET-BBS+ and WMC24
    ```sh
    RUSTFLAGS="-Awarnings" cargo bench --bench t_out_of_n_keygen
    ```
*  The client phase of SET-BBS+ and WMC24
    ```sh
    RUSTFLAGS="-Awarnings" cargo bench --bench t_out_of_n_client
    ```
*  The signing, key generation phase and client phase of of DKL+23
    ```sh
    cd crypto
    RUSTFLAGS="-Awarnings" cargo test --release --package bbs_plus --lib -- threshold::threshold_bbs_plus::tests::signing_t_out_of_n --exact --show-output 
    ```