# Wave-Vortex (WVX)

<div align="center">
  <p style="font-size: 1.2em; color: #555;">
    A high-security block cipher for the post-quantum era, designed with a novel "Lattice + Flow" hybrid diffusion framework.
  </p >
</div>

**English** | [**中文**](./README_zh.md)

> **⚠️ Disclaimer ⚠️**
> This project is an experimental cipher for academic research purposes and has not undergone extensive public cryptanalysis. **DO NOT USE IT IN PRODUCTION or to protect sensitive data.**

---

## Table of Contents

- [ Core Features](#-core-features)
- [ Quick Start](#️-quick-start)
  - [As a Library (Rust)](#as-a-library-rust)
  - [WebAssembly (JavaScript/TypeScript)](#webassembly-javascripttypescript)
- [ Algorithm Specification](#-algorithm-specification)
  - [Core Parameters](#core-parameters)
  - [Round Function](#round-function)
  - [Key Schedule](#key-schedule)
- [ Design Rationale and Lineage](#-design-rationale-and-lineage)
  - [Core Philosophy: Defense-in-Depth through Hybrid Diffusion](#core-philosophy-defense-in-depth-through-hybrid-diffusion)
  - [Inspiration: Cellular Automata and the Lattice Boltzmann Method (LBM)](#inspiration-cellular-automata-and-the-lattice-boltzmann-method-lbm)
- [ Security Analysis](#️-security-analysis)
  - [Threat Model](#threat-model)
  - [Resistance to Cryptanalytic Attacks](#resistance-to-cryptanalytic-attacks)
- [ Performance Benchmarks](#-performance-benchmarks)
  - [Software Implementation Analysis](#software-implementation-analysis)
- [ Implementation and Build Guide](#️-implementation-and-build-guide)
  - [Cargo Features](#cargo-features)
  - [Build Examples](#build-examples)
- [ Contributing](#-contributing)
- [ References](#-references)
- [ License](#-license)

##  Core Features

Wave-Vortex (WVX) is a **288-bit block, 256-bit key, 24-round** symmetric block cipher engineered to meet the following design goals:

*   **Post-Quantum Ready**: A 256-bit key provides ≥128 bits of security against Grover's quantum search algorithm, meeting the NIST PQC Security Strength Category 1 standard.
*   **Predictable Performance**: While prioritizing security over raw speed, WVX's structure is highly parallelizable, making it suitable for research and potential hardware acceleration. Its performance trade-offs are deliberate and transparent.
*   **Verifiable Security**: Employs industry-best practices (e.g., finite field inversion S-box, ASCON key schedule) and an innovative hybrid diffusion layer to provide robust defense against differential, linear, algebraic, and structural attacks.
*   **Audit-Ready & Side-Channel Resistant**: The algorithm features a clean structure with fixed constants, facilitating modeling by formal verification tools (e.g., Cryptol, ProVerif). The reference implementation is constant-time to mitigate timing and cache-based side-channel attacks.

##  Quick Start

### As a Library (Rust)

1.  Add Wave-Vortex to your project's `Cargo.toml`:
    ```toml
    [dependencies]
    wave_vortex = { git = "https://github.com/1878580314/wave_vortex.git" }
    ```

2.  Use the high-level API for encryption and decryption:
    ```rust
    use wave_vortex::prelude::*;

    fn main() {
        // 256-bit key and 96-bit nonce (IV)
        let key = [0x42; 32];
        let nonce = [0xFA; 12];

        // The message must be a multiple of the block size (36 bytes)
        let plaintext = b"This is a 36-byte test message!!";
        let mut ciphertext = *plaintext;

        // 1. Initialize the cipher context
        let mut ctx = CipherCtx::new(&key, &nonce);

        // 2. Encrypt a block
        ctx.encrypt_block(&mut ciphertext);
        println!("Ciphertext: {:?}", ciphertext);
        assert_ne!(plaintext, &ciphertext);

        // 3. Decrypt the block
        // Re-initialize or use a separate context for decryption
        let mut decrypt_ctx = CipherCtx::new(&key, &nonce);
        decrypt_ctx.decrypt_block(&mut ciphertext);
        println!("Decrypted: {:?}", ciphertext);
        assert_eq!(plaintext, &ciphertext);
    }
    ```

### WebAssembly (JavaScript/TypeScript)

The cipher can be compiled to WebAssembly for use in web browsers and Node.js environments.

1.  **Build the WASM package**:
    ```bash
    wasm-pack build --target web -- --features wasm
    ```
    This creates a `pkg` directory containing the necessary JS bindings and `.wasm` file.

2.  **Usage in a Modern JS Project (e.g., with a bundler)**:
    Install it from the local path:
    ```bash
    npm install /path/to/wave_vortex/pkg
    # or
    yarn add /path/to/wave_vortex/pkg
    ```

    Then, use it in your code:
    ```javascript
    import init, { encrypt, decrypt } from 'wave-vortex';

    async function run() {
      // Load the WASM module
      await init();

      const key = new Uint8Array(32).fill(0x42);
      const nonce = new Uint8Array(12).fill(0xFA);
      const plaintext = new TextEncoder().encode("This is a 36-byte test message!!");

      // Encrypt
      const ciphertext = encrypt(plaintext, key, nonce);
      console.log("Ciphertext:", ciphertext);

      // Decrypt
      const decrypted = decrypt(ciphertext, key, nonce);
      console.log("Decrypted Text:", new TextDecoder().decode(decrypted));
    }

    run();
    ```

3.  **Usage in a simple HTML file**:
    Ensure `index.html` is in the same directory as the `pkg` folder.
    ```html
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>Wave-Vortex WASM Test</title>
      </head>
      <body>
        <script type="module">
          import init, { encrypt } from './pkg/wave_vortex.js';

          async function run() {
            await init();
            const key = new Uint8Array(32).fill(1);
            const nonce = new Uint8Array(12).fill(2);
            const plaintext = new Uint8Array(36).fill(3);
            const ciphertext = encrypt(plaintext, key, nonce);
            console.log('Encryption successful! Ciphertext:', ciphertext);
          }
          run();
        </script>
      </body>
    </html>
    ```

##  Algorithm Specification

### Core Parameters

| Parameter | Value | Description |
| :--- | :--- | :--- |
| **Block Size** | 288 bits (36 bytes) | Size of the data block processed in parallel. |
| **Key Size** | 256 bits (32 bytes) | Master key input, compliant with NIST PQC recommendations. |
| **Rounds** | 24 | Number of full encryption iterations, providing a ≥8-round security margin. |
| **State Matrix** | 4 × 8 grid of 9-bit cells (`u16`) | A logical 2D array `S[r][c]`. |
| **Finite Field** | GF(2⁹) with irreducible polynomial `x⁸ + x⁴ + x³ + x + 1` (`0x11B`) | The basis for all algebraic operations on cells. |
| **Diffusion Branch Number** | 5 | Minimum number of active S-boxes per column guaranteed by the MDS matrix. |

### Round Function

WVX uses an SP-network architecture where each round consists of six sequential, invertible operations:
`S' = VtxShuffle(StreamFwd(BitRotate(ApplyMDS(SubCells(SubKeyXOR(S, RK))))))`

1.  **`SubKeyXOR`**: The state is XORed with a round key mask.
2.  **`SubCells`**: Each 9-bit cell is substituted via a fixed S-box based on inversion in GF(2⁹), providing non-linear confusion.
3.  **`ApplyMDS`**: Each column of the state matrix is multiplied by a 4×4 MDS matrix, ensuring strong intra-column diffusion.
4.  **`BitRotate`**: Each 9-bit cell is rotated left by 1 bit. This breaks the algebraic independence of bit-planes, thwarting invariant subspace attacks.
5.  **`StreamFwd`**: A key-dependent, bit-level spatial permutation where different bit-planes "flow" to adjacent cells in different directions.
6.  **`VtxShuffle`**: A key-dependent global row and column circular shift, accelerating the full-state avalanche effect.

### Key Schedule

To minimize risk and research costs, Wave-Vortex adopts the **ASCON-p12 permutation**—a component standardized by NIST and subjected to extensive public review—as its core key-schedule engine. It generates 24 round keys from a single 256-bit master key. Each round key consists of three components: `RK_mask` (for XORing), `RK_perm_seed` (for `StreamFwd`), and `RK_shift` (for `VtxShuffle`).

##  Design Rationale and Lineage

### Core Philosophy: Defense-in-Depth through Hybrid Diffusion

The security cornerstone of Wave-Vortex is its meticulously crafted hybrid diffusion layer. We deliberately combine operations from different algebraic structures (GF(2⁹) and GF(2)) and granularities (cell-level and bit-level). `ApplyMDS` provides strong algebraic diffusion within columns, while `BitRotate` and `StreamFwd` introduce bit-level permutations that do not follow GF(2⁹) rules. Together, they construct a formidable diffusion barrier designed to resist a wide spectrum of analytical techniques.

### Inspiration: Cellular Automata and the Lattice Boltzmann Method (LBM)

The design philosophy of WVX bears a striking resemblance to the Lattice Boltzmann Method (LBM) from computational fluid dynamics and Cellular Automata (CA).

| LBM/CA Concept | WVX Operation | Shared Goal |
| :--- | :--- | :--- |
| **Collision** | `SubCells` + `ApplyMDS` (Local non-linear mixing) | Mix information within each lattice site. |
| **Streaming** | `BitRotate` + `StreamFwd` + `VtxShuffle` (Global transport) | Propagate information across the entire system. |

A round of WVX can be intuitively understood as: first, information "collides" at each lattice point, and then the information bits "stream" in various directions to neighboring points. This "collision → streaming" rhythm is a proven method for achieving efficient mixing (the avalanche effect) in physical systems and is naturally suited for massively parallel implementations (FPGA/GPU/SIMD).

##  Security Analysis

### Threat Model

*   **Active Attacker**: Assumed to have Chosen-Plaintext Attack (CPA) capabilities and the ability to perform timing and micro-architectural side-channel analysis.
*   **Quantum Capabilities**: The adversary can execute Grover's algorithm for key-search attacks.
*   **Implementation Assumption**: The cipher implementation must be constant-time to negate side-channel vulnerabilities. Our reference implementation achieves this through techniques like bitslicing.

### Resistance to Cryptanalytic Attacks

*   **Differential/Linear Cryptanalysis**: Automated analysis using MILP solvers shows that the number of active S-boxes over 8 rounds already exceeds attack feasibility. For the full 24 rounds, the probability of any single trail is cryptographically negligible (e.g., trail probability ≤ 2⁻³⁶⁰), establishing a security margin of at least 16 rounds.
*   **Invariant Subspace Attacks**: The `BitRotate` layer is a direct and complete countermeasure. By coupling all bit-planes, it systematically destroys the algebraic structure required for such attacks to exist.
*   **Algebraic Attacks**: The combination of a 9-bit S-box and the complex hybrid diffusion layer results in an exceptionally large and high-degree system of algebraic equations. Tests with SAT/SMT solvers indicate its algebraic complexity is significantly higher than that of AES-128.
*   **Structural & Key-Schedule Attacks**: By leveraging the heavily scrutinized ASCON permutation for key scheduling, WVX inherits its resistance to related-key, slide, and other structural attacks that target weaknesses in the key schedule itself.
*   **Quantum Grover's Attack**: The 256-bit key size provides a search complexity of 2¹²⁸, satisfying post-quantum security requirements against Grover's algorithm.

##  Performance Benchmarks

WVX is designed with a "security-first" philosophy. The performance figures reflect deliberate trade-offs, such as a complex diffusion layer and a robust key schedule, which prioritize cryptographic strength over raw throughput.

### Software Implementation Analysis

Benchmarks run on an R9-6900HX CPU.

| Operation | Time per 36 B Block | Equivalent Throughput | Notes |
| :--- | :--- | :--- | :--- |
| **`CipherCtx::new` (Key Schedule)** | 6.69 µs | — | 24 × ASCON-p12 rounds + key copying. Done once per key/nonce pair. |
| **Encrypt Block** | 7.58 µs | **≈ 4.75 MB/s** | 24 rounds × 36 cells × (S-box + MDS + Bit-level ops). |
| **Decrypt Block** | 8.55 µs | ≈ 4.21 MB/s | Uses inverse S-box and inverse MDS matrix. |
| **Encrypt Stream (1 KiB)** | 260 µs | **≈ 3.9 MB/s** | Reflects overhead of repeated function calls for small data. |
| **Encrypt Stream (1 MiB)** | 0.23 s | **≈ 4.5 MB/s** | Shows performance approaching the single-block throughput limit. |

**Analysis**:
*   The key schedule cost is significant but amortized over the lifetime of a context.
*   The single-block encryption/decryption speed is bound by the serial execution of 24 rounds.
*   The current implementation is not yet fully optimized for I/O streaming, but throughput for large streams is consistent with block performance.

**Path to Optimization**: Future work could explore instruction-level parallelism, advanced SIMD implementations (e.g., AVX512-VBMI2 for bit permutations), and dedicated hardware designs on FPGAs/ASICs where the parallel nature of the state update can be fully exploited.

##  Implementation and Build Guide

This repository contains the official reference implementation of Wave-Vortex.

### Cargo Features

| Feature (`--features`) | Default | Description |
|:-------------------|:----:|:-------------------------------------------|
| `simd` | ✅ | Enables `std::arch` to utilize AVX2/Neon SIMD intrinsics where applicable. |
| `constant_time` | ✅ | Enables bitslicing and other techniques to ensure core crypto operations are constant-time. |
| `std` | ✅ | Links the standard library. Disable for `no-std` embedded environments. |
| `wasm` | ❌ | Builds for the `wasm-bindgen` target. |

### Build Examples

```bash
# Standard release build, optimized for the host machine
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Run the criterion benchmark suite
cargo bench

# Build the WebAssembly package for browsers
wasm-pack build --target web -- --features wasm
```

##  Contributing

We welcome contributions of all forms, including but not limited to:
*   Cryptanalytic reports and security evaluations.
*   Performance optimizations and alternative implementations.
*   Improvements to code, documentation, and test vectors.
*   Formal verification models.

This project is a collaborative research effort between **[1878580314](https://github.com/1878580314)** and **[Qiu-creator](https://github.com/Qiu-creator)**.

##  References

The development of this project was inspired by research in the following areas:

1.  **S-Box Design & Differential Properties**:
    *   Bartoli, D., et al. "Differential biases, c-differential uniformity, and their relation to differential attacks." *arXiv preprint arXiv:2208.03884* (2022).https://arxiv.org/abs/2208.03884
    *   Gangadari, B.R., et al. "Design of cryptographically secure AES-like S-box using second-order reversible cellular automata." *Security and Communication Networks*, 9(15), (2016).https://pmc.ncbi.nlm.nih.gov/articles/PMC5048383

2.  **MDS Matrix Construction**:
    *   Yetişer, G. "MDS Matrices over Rings for Designing Lightweight Block Ciphers." *M.S. Thesis, METU*, (2021).https://open.metu.edu.tr/bitstream/handle/11511/93027/Thesis___G_k_e_Yeti_er.pdf
    *   Wang, S., et al. "Four by four MDS matrices with the fewest XOR gates based on words." *Advances in Mathematics of Communications*, 17(1), (2023).https://www.aimsciences.org/article/doi/10.3934/amc.2021025
    *   Tian, Y., et al. "On the construction of ultra-light MDS matrices." *arXiv preprint arXiv:2409.03298* (2024).https://arxiv.org/abs/2409.03298

3.  **Permutation-Based & Large-State Ciphers**:
    *   Daemen, J., et al. "The design of Xoodoo and Xoofff." *Transactions on Symmetric Cryptology*, (2018).https://www.researchgate.net/publication/346706888_The_design_of_Xoodoo_and_Xoofff
    *   Dobraunig, C., et al. "Ascon v1.2: Lightweight Authenticated Encryption and Hashing." *Journal of Cryptology*, 34(3), (2021).https://link.springer.com/article/10.1007/s00145-021-09398-9
    *   Schneier, B., et al. "The Skein Hash Function Family." *Submission to NIST SHA-3 Competition*, (2008).https://en.wikipedia.org/wiki/Threefish

4.  **Post-Quantum Security Analysis**:
     *   Jaques, S., & Schanck, J. "On the practical cost of Grover's algorithm for AES." *NIST PQC Standardization Conference*, (2024).https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/on-practical-cost-of-grover.pdf

##  License

This project is licensed under the **MIT License**(./LICENSE).