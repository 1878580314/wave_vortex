use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand::{RngCore, thread_rng};
use std::io::Cursor;
use wave_vortex::{
    CipherCtx, decrypt_block_ctx, decrypt_stream, derive_key_from_password, encrypt_block_ctx,
    encrypt_stream,
};

// --- 准备测试数据 ---

/// 生成随机的32字节数据，用作明文块或密钥
fn gen_32_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// 生成随机的16字节数据，用作盐
fn gen_16_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

// --- 基准测试函数 ---

/// 基准测试核心块加密/解密操作
fn bench_block_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Block Operations");

    // 准备数据
    let key = gen_32_bytes();
    let plaintext = gen_32_bytes();

    // 1. 基准测试密钥调度 (CipherCtx::new)
    group.bench_function("Key Schedule (CipherCtx::new)", |b| {
        b.iter(|| CipherCtx::new(black_box(&key)))
    });

    // 准备上下文，后续测试将重用它
    let ctx = CipherCtx::new(&key);
    let ciphertext = encrypt_block_ctx(&ctx, &plaintext);

    // 2. 基准测试块加密
    group.bench_function("Encrypt Block (with context)", |b| {
        b.iter(|| encrypt_block_ctx(black_box(&ctx), black_box(&plaintext)))
    });

    // 3. 基准测试块解密
    group.bench_function("Decrypt Block (with context)", |b| {
        b.iter(|| decrypt_block_ctx(black_box(&ctx), black_box(&ciphertext)))
    });

    group.finish();
}

/// 基准测试流式加解密
fn bench_stream_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Stream Operations Throughput");
    let password = b"a-very-strong-and-long-password-for-testing";

    // 测试不同大小的数据样本
    for &size_kb in &[1, 1024, 32 * 1024] {
        // 1KB, 1MB, 32MB
        let size_bytes = size_kb * 1024;
        let mut data = vec![0u8; size_bytes];
        thread_rng().fill_bytes(&mut data);

        // 设置吞吐量，criterion 会自动计算 bytes/sec
        group.throughput(Throughput::Bytes(size_bytes as u64));

        // 1. 基准测试流式加密
        group.bench_with_input(
            BenchmarkId::new("Encrypt Stream", format!("{} KiB", size_kb)),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut reader = Cursor::new(data);
                    let mut writer = Cursor::new(Vec::with_capacity(data.len() + 64));
                    encrypt_stream(&mut reader, &mut writer, black_box(password))
                })
            },
        );

        // 准备加密后的数据用于解密测试
        let mut encrypted_data = Vec::new();
        let mut reader = Cursor::new(&data);
        encrypt_stream(&mut reader, &mut encrypted_data, password).unwrap();

        // 2. 基准测试流式解密
        group.bench_with_input(
            BenchmarkId::new("Decrypt Stream", format!("{} KiB", size_kb)),
            &encrypted_data,
            |b, data| {
                b.iter(|| {
                    let mut reader = Cursor::new(data);
                    // 预分配容量以避免重新分配的开销
                    let mut writer = Cursor::new(Vec::with_capacity(data.len()));
                    decrypt_stream(&mut reader, &mut writer, black_box(password))
                })
            },
        );
    }
    group.finish();
}

/// 基准测试密钥派生函数
fn bench_key_derivation(c: &mut Criterion) {
    let password = b"a-very-strong-and-long-password-for-testing";
    let salt = gen_16_bytes();

    c.bench_function("Key Derivation (PBKDF2 100k rounds)", |b| {
        b.iter(|| derive_key_from_password(black_box(password), black_box(&salt)))
    });
}

// --- 注册基准测试组 ---

criterion_group!(
    benches,
    bench_block_operations,
    bench_stream_operations,
    bench_key_derivation
);
criterion_main!(benches);
