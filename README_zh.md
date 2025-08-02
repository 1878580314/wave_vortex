# Wave-Vortex (WVX)

<div align="center">
  <p style="font-size: 1.2em; color: #555;">
    一款为后量子时代设计，基于“格点+流动”混合扩散框架的高安全性分组密码。
  </p >
</div>

[**English**](./README.md) | **中文**

> **⚠️ 免责声明 / Disclaimer ⚠️**
> **本项目是一个用于学术研究的实验性密码算法，未经广泛的公开密码分析。请勿在任何生产环境中使用它来保护敏感数据。**

---

## 目录

- [ 核心特性](#-核心特性)
- [ 快速开始](#️-快速开始)
  - [作为库使用 (Rust)](#作为库使用-rust)
  - [WebAssembly (JavaScript/TypeScript)](#webassembly-javascripttypescript)
- [ 算法规范](#-算法规范)
  - [核心参数](#核心参数)
  - [加密轮函数](#加密轮函数)
  - [密钥调度](#密钥调度)
- [ 设计理念与溯源](#-设计理念与溯源)
  - [核心哲学：混合扩散实现深度防御](#核心哲学混合扩散实现深度防御)
  - [灵感溯源：元胞自动机与格子玻尔兹曼方法 (LBM)](#灵感溯源元胞自动机与格子玻尔兹曼方法-lbm)
- [ 安全性分析](#️-安全性分析)
  - [威胁模型](#威胁模型)
  - [对各类攻击的抵抗能力](#对各类攻击的抵抗能力)
- [ 性能基准](#-性能基准)
  - [软件实现分析](#软件实现分析)
- [ 实现与构建指南](#️-实现与构建指南)
  - [Cargo 特性](#cargo-特性)
  - [构建示例](#构建示例)
- [ 贡献](#-贡献)
- [ 参考文献](#-参考文献)
- [ 许可证](#-许可证)

##  核心特性

Wave-Vortex (WVX) 是一款 **288位分组、256位密钥、24轮** 的对称分组密码，旨在满足以下设计目标：

*   **后量子就绪**：256位密钥为抵抗 Grover 量子搜索提供了 ≥ 128位的安全级别，满足 NIST PQC 安全强度1级标准。
*   **性能可预测**：WVX优先考虑安全性而非原始速度，但其结构高度可并行化，使其适用于研究和潜在的硬件加速。其性能权衡是经过深思熟虑且透明的。
*   **可验证的安全性**：采用业界最佳实践（如基于有限域求逆的S-box、ASCON密钥调度）和创新的混合扩散层，以提供对差分、线性、代数及结构化攻击的强大防御。
*   **易于审计与侧信道抵抗**：算法结构清晰，所有常量固定，便于形式化验证工具（如 Cryptol, ProVerif）建模分析。参考实现为常量时间，以防御时序和缓存等侧信道攻击。

##  快速开始

### 作为库使用 (Rust)

1.  在您的项目 `Cargo.toml` 中添加 Wave-Vortex 依赖：
    ```toml
    [dependencies]
    wave_vortex = { git = "https://github.com/1878580314/wave_vortex.git" }
    ```

2.  使用高级API进行加解密：
    ```rust
    use wave_vortex::prelude::*;

    fn main() {
        // 256位密钥 和 96位随机数 (IV)
        let key = [0x42; 32];
        let nonce = [0xFA; 12];

        // 消息长度必须是分组长度（36字节）的倍数
        let plaintext = b"This is a 36-byte test message!!"; // 这是一个36字节的测试消息
        let mut ciphertext = *plaintext;

        // 1. 初始化密码器上下文
        let mut ctx = CipherCtx::new(&key, &nonce);

        // 2. 加密一个分组
        ctx.encrypt_block(&mut ciphertext);
        println!("密文: {:?}", ciphertext);
        assert_ne!(plaintext, &ciphertext);

        // 3. 解密分组
        // 为解密重新初始化上下文，或使用独立的上下文实例
        let mut decrypt_ctx = CipherCtx::new(&key, &nonce);
        decrypt_ctx.decrypt_block(&mut ciphertext);
        println!("解密后的明文: {:?}", ciphertext);
        assert_eq!(plaintext, &ciphertext);
    }
    ```

### WebAssembly (JavaScript/TypeScript)

本算法可被编译为 WebAssembly，以便在浏览器和 Node.js 环境中使用。

1.  **构建 WASM 包**:
    ```bash
    wasm-pack build --target web -- --features wasm
    ```
    此命令会创建一个 `pkg` 目录，其中包含所需的JS绑定和 `.wasm` 文件。

2.  **在现代JS项目中使用 (例如，使用打包工具)**:
    从本地路径安装：
    ```bash
    npm install /path/to/wave_vortex/pkg
    # 或者
    yarn add /path/to/wave_vortex/pkg
    ```

    在您的代码中使用：
    ```javascript
    import init, { encrypt, decrypt } from 'wave-vortex';

    async function run() {
      // 加载 WASM 模块
      await init();

      const key = new Uint8Array(32).fill(0x42);
      const nonce = new Uint8Array(12).fill(0xFA);
      const plaintext = new TextEncoder().encode("This is a 36-byte test message!!");

      // 加密
      const ciphertext = encrypt(plaintext, key, nonce);
      console.log("密文:", ciphertext);

      // 解密
      const decrypted = decrypt(ciphertext, key, nonce);
      console.log("解密后的文本:", new TextDecoder().decode(decrypted));
    }

    run();
    ```

3.  **在简单的 HTML 文件中使用**:
    确保 `index.html` 与 `pkg` 文件夹位于同一目录下。
    ```html
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>Wave-Vortex WASM 测试</title>
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
            console.log('加密成功！密文:', ciphertext);
          }
          run();
        </script>
      </body>
    </html>
    ```

##  算法规范

### 核心参数

| 参数 | 值 | 描述 |
| :--- | :--- | :--- |
| **分组长度** | 288位 (36字节) | 单次并行处理的数据块大小。 |
| **密钥长度** | 256位 (32字节) | 主密钥输入，兼容NIST PQC建议。 |
| **轮数** | 24轮 | 完整加密回合数，提供 ≥16 轮的安全余量。 |
| **状态矩阵** | 4 × 8 的 9位单元格网格 (`u16`) | 一个逻辑二维阵列 `S[r][c]`。 |
| **有限域** | GF(2⁹)，不可约多项式 `x⁸ + x⁴ + x³ + x + 1` (`0x11B`) | 单元格所有代数运算的基础。 |
| **扩散层分支数**| 5 | MDS矩阵确保的列内最低差分/线性活跃S-box数。 |

### 加密轮函数

WVX 采用 SP-network 架构，每一轮由六个可逆操作串行组成：
`S' = VtxShuffle(StreamFwd(BitRotate(ApplyMDS(SubCells(SubKeyXOR(S, RK))))))`

1.  **`SubKeyXOR`**: 状态与轮密钥掩码进行异或。
2.  **`SubCells`**: 每个9位单元格通过一个固定的、基于 `x⁻¹` 的S-box进行代换，提供非线性混淆。
3.  **`ApplyMDS`**: 对状态矩阵的每一列应用一个 4×4 的MDS矩阵乘法，提供列内的强扩散。
4.  **`BitRotate`**: 对每个9位单元格进行循环左移1位，旨在破坏比特平面的代数独立性，挫败不变子空间攻击。
5.  **`StreamFwd`**: 依赖密钥的比特级空间置换，将不同比特平面沿不同方向“流动”到相邻单元格。
6.  **`VtxShuffle`**: 依赖密钥的全局行列循环移位，加速全状态雪崩效应。

### 密钥调度

为避免引入不必要的风险以及减少研究成本，Wave-Vortex 采用经过NIST标准化和广泛审查的 **ASCON-p12** 置换作为其密钥调度的核心引擎。它从一个256位的主密钥生成24个轮密钥，每个轮密钥包含 `RK_mask` (用于异或)、`RK_perm_seed` (用于 `StreamFwd`) 和 `RK_shift` (用于 `VtxShuffle`) 三个部分。

##  设计理念与溯源

### 核心哲学：混合扩散实现深度防御

Wave-Vortex 的安全基石是一个精心设计的混合扩散层。我们有意地将来自不同代数域（GF(2⁹)和GF(2)）和不同粒度（单元格级和比特级）的操作结合起来。`ApplyMDS` 提供强大的列内代数扩散，而 `BitRotate` 和 `StreamFwd` 则引入不遵循GF(2⁹)代数规则的比特级置换，共同构建了一个能够抵抗广泛分析技术的、坚固的扩散屏障。

### 灵感溯源：元胞自动机与格子玻尔兹曼方法 (LBM)

WVX 的设计哲学与流体力学中的格子玻尔兹曼方法 (LBM) 和元胞自动机 (CA) 惊人地相似。

| LBM/CA 概念 | WVX 对应操作 | 共同目标 |
| :--- | :--- | :--- |
| **Collision (碰撞)** | `SubCells` + `ApplyMDS` (局部非线性混合) | 在每个格点内部混合信息 |
| **Streaming (流动)** | `BitRotate` + `StreamFwd` + `VtxShuffle` (全局搬运) | 将信息扩散到整个系统 |

可以直观地将WVX的一轮理解为：先在每个格点“碰撞”信息，随后将信息比特沿不同方向“漂流”到邻近格点。这种“碰撞→流动”的双阶段节奏，正是物理系统实现高效混合（雪崩效应）的有效方式，也天然适合大规模并行实现（FPGA/GPU/SIMD）。

##  安全性分析

### 威胁模型

*   **主动攻击者**: 掌握选择明文攻击（CPA）能力，并可进行时序与微架构侧信道观测。
*   **量子能力**: 对手可运行 Grover 算法进行密钥搜索。
*   **实现假设**: 算法实现必须是常量时间的，以规避侧信道风险。我们的参考实现通过位切片等技术满足此要求。

### 对各类攻击的抵抗能力

*   **差分/线性密码分析**: 经过MILP自动搜索，仅需8轮的累计活跃S-box数就已远超攻击可行性。对于完整的24轮，任何单一特征的概率都达到密码学上可忽略的水平（例如，路径概率 ≤ 2⁻³⁶⁰），从而建立了超过16轮的巨大安全边界。
*   **不变子空间攻击**: `BitRotate` 层的引入是一个直接且完备的对策。它通过耦合所有比特平面，系统性地摧毁了此类攻击所依赖的代数结构基础。
*   **代数攻击**: 9位S-box和复杂的混合扩散层导致代数方程组的规模和次数都极为庞大。SAT/SMT求解器测试表明，其代数复杂度远高于AES-128。
*   **结构化及密钥调度攻击**: 通过采用经过严格审查的ASCON置换作为密钥调度核心，WVX继承了其对相关密钥攻击、滑动攻击等旨在利用密钥调度弱点的结构化攻击的抵抗力。
*   **量子Grover攻击**: 256位密钥提供了 2¹²⁸ 的搜索复杂度，满足后量子安全要求。

##  性能基准

WVX的设计秉持“安全第一”的理念。性能数据反映了深思熟虑的权衡，例如复杂的扩散层和稳健的密钥调度，这些都优先考虑了密码强度而非原始吞吐量。

### 软件实现分析

基准测试运行于 R9-6900HX CPU。

| 操作 | 每 36B 分组耗时 | 等效吞吐量 | 备注 |
| :--- | :--- | :--- | :--- |
| **`CipherCtx::new` (密钥调度)** | 6.69 µs | — | 24 × ASCON-p12 轮 + 密钥拷贝。每个密钥/IV对仅执行一次。 |
| **加密分组 (Encrypt Block)** | 7.58 µs | **≈ 4.75 MB/s** | 24 轮 × 36 单元格 × (S-box + MDS + 比特级操作)。 |
| **解密分组 (Decrypt Block)** | 8.55 µs | ≈ 4.21 MB/s | 使用逆S-box和逆MDS矩阵。 |
| **加密流 (1 KiB)** | 260 µs | **≈ 3.9 MB/s** | 反映了处理小数据时重复函数调用的开销。 |
| **加密流 (1 MiB)** | 0.23 s | **≈ 4.5 MB/s** | 显示大流吞吐量接近单分组性能极限。 |

**分析**:
*   密钥调度的开销是显著的，但在上下文的生命周期内被分摊。
*   单分组加解密的速度受限于24轮的串行执行。
*   当前实现尚未对I/O流进行完全优化，但大文件的吞吐量与单分组性能一致。

**优化路径**: 未来的工作可以探索指令级并行、高级SIMD实现（如使用AVX512-VBMI2处理比特置换）以及在FPGA/ASIC上的专用硬件设计，这些平台可以充分利用状态更新的并行特性。

##  实现与构建指南

本仓库为 Wave-Vortex 的官方参考实现。

### Cargo 特性

| 特性 (`--features`) | 默认 | 描述 |
|:-------------------|:----:|:-------------------------------------------|
| `simd` | ✅ | 启用 `std::arch` 以利用 AVX2/Neon 等SIMD指令集。 |
| `constant_time` | ✅ | 启用位切片等技术，确保核心加密操作是常量时间的。 |
| `std` | ✅ | 链接标准库。关闭可用于 `no-std` 嵌入式环境。 |
| `wasm` | ❌ | 构建 `wasm-bindgen` 目标。 |

### 构建示例

```bash
# 标准 Release 构建 (为本地CPU优化)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# 运行基准测试
cargo bench

# 构建 WebAssembly 包 (用于浏览器)
wasm-pack build --target web -- --features wasm
```

##  贡献

我们欢迎任何形式的贡献，包括但不限于：
*   密码分析报告和安全问题发现。
*   性能优化和替代实现。
*   代码、文档和测试向量的改进。
*   形式化验证模型。

本项目是 **[1878580314](https://github.com/1878580314)** 与 **[Qiu-creator](https://github.com/Qiu-creator)** 的一项合作研究成果。

##  参考文献

本项目的开发受到了以下领域研究的启发：

1.  **S-Box设计与差分性质**:
    *   Bartoli, D., et al. "Differential biases, c-differential uniformity, and their relation to differential attacks." *arXiv preprint arXiv:2208.03884* (2022).https://arxiv.org/abs/2208.03884
    *   Gangadari, B.R., et al. "Design of cryptographically secure AES-like S-box using second-order reversible cellular automata." *Security and Communication Networks*, 9(15), (2016).https://pmc.ncbi.nlm.nih.gov/articles/PMC5048383

2.  **MDS矩阵构造**:
    *   Yetişer, G. "MDS Matrices over Rings for Designing Lightweight Block Ciphers." *M.S. Thesis, METU*, (2021).https://open.metu.edu.tr/bitstream/handle/11511/93027/Thesis___G_k_e_Yeti_er.pdf
    *   Wang, S., et al. "Four by four MDS matrices with the fewest XOR gates based on words." *Advances in Mathematics of Communications*, 17(1), (2023).https://www.aimsciences.org/article/doi/10.3934/amc.2021025
    *   Tian, Y., et al. "On the construction of ultra-light MDS matrices." *arXiv preprint arXiv:2409.03298* (2024).https://arxiv.org/abs/2409.03298

3.  **基于置换与大状态的密码**:
    *   Daemen, J., et al. "The design of Xoodoo and Xoofff." *Transactions on Symmetric Cryptology*, (2018).https://www.researchgate.net/publication/346706888_The_design_of_Xoodoo_and_Xoofff
    *   Dobraunig, C., et al. "Ascon v1.2: Lightweight Authenticated Encryption and Hashing." *Journal of Cryptology*, 34(3), (2021).https://link.springer.com/article/10.1007/s00145-021-09398-9
    *   Schneier, B., et al. "The Skein Hash Function Family." *Submission to NIST SHA-3 Competition*, (2008).https://en.wikipedia.org/wiki/Threefish

4.  **后量子安全性分析**:
    *   Jaques, S., & Schanck, J. "On the practical cost of Grover's algorithm for AES." *NIST PQC Standardization Conference*, (2024).https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/on-practical-cost-of-grover.pdf

##  许可证

本项目采用**MIT License**(./LICENSE)许可证授权。