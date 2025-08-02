use statrs::statistics::{Data, Distribution};
use wave_vortex::{SBOX, encrypt_block};

// --- 分析与测试函数 ---

// 计算DDT
fn compute_ddt(sbox: &[u16; 512]) -> (f64, u32) {
    let mut ddt = vec![vec![0u32; 512]; 512];
    for x in 0..512 {
        for delta in 1..512 {
            let xp = x ^ delta;
            let out_delta = (sbox[x as usize] ^ sbox[xp as usize]) as usize;
            ddt[delta][out_delta] += 1;
        }
    }
    let max_count = *ddt.iter().flat_map(|row| row.iter()).max().unwrap_or(&0);
    let max_dp = max_count as f64 / 512.0;
    (max_dp, max_count)
}

// 计算LAT
fn compute_lat(sbox: &[u16; 512]) -> f64 {
    let mut max_abs_w = 0i32;
    for a in 1..512 {
        for b in 1..512 {
            let mut w: i32 = 0;
            for x in 0..512 {
                let in_parity = ((a as u16 & x as u16).count_ones() & 1) as i32;
                let out_parity = ((b as u16 & sbox[x as usize] as u16).count_ones() & 1) as i32;
                w += if in_parity == out_parity { 1 } else { -1 };
            }
            max_abs_w = max_abs_w.max(w.abs());
        }
    }
    max_abs_w as f64 / 512.0 // Bias is L/N, N=512
}

// 汉明距离
fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x ^ y).count_ones())
        .sum()
}

// 十六进制字符串表示
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

// 雪崩测试单消息
fn run_avalanche_for_message(
    msg: &[u8; 32],
    encrypt_fn: impl Fn(&[u8; 32]) -> [u8; 36],
) -> (Vec<u32>, Vec<(usize, String, String, String, String)>) {
    let h_base = encrypt_fn(msg);
    let base_hex = bytes_to_hex(&h_base);
    let pt_hex = bytes_to_hex(msg);

    let mut dists = Vec::with_capacity(msg.len() * 8);
    let mut zero_cases = Vec::new();

    for bit in 0..(msg.len() * 8) {
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        let mut flipped = *msg;
        flipped[byte_idx] ^= 1 << bit_idx;
        let h_flip = encrypt_fn(&flipped);
        let dist = hamming_distance(&h_base, &h_flip);
        dists.push(dist);

        if dist == 0 {
            let flipped_pt_hex = bytes_to_hex(&flipped);
            let flip_ct_hex = bytes_to_hex(&h_flip);
            zero_cases.push((
                bit,
                pt_hex.clone(),
                flipped_pt_hex,
                base_hex.clone(),
                flip_ct_hex,
            ));
        }
    }
    (dists, zero_cases)
}

// 统计分析
fn calculate_stats(dists: &[u32]) -> (f64, f64, u32, u32) {
    if dists.is_empty() {
        return (0.0, 0.0, 0, 0);
    }
    let data = Data::new(dists.iter().map(|&x| x as f64).collect::<Vec<_>>());
    let mean = data.mean().unwrap_or(0.0);
    let stdev = data.std_dev().unwrap_or(0.0);
    let min = *dists.iter().min().unwrap_or(&0);
    let max = *dists.iter().max().unwrap_or(&0);
    (mean, stdev, min, max)
}
pub fn run() {
    // S-box分析
    // 注意：我们直接从库中引用 SBOX 常量
    let sbox = &SBOX;
    println!("--- S-Box Analysis ---");
    let (max_dp, max_count) = compute_ddt(sbox);
    println!(
        "Max DP (Differential Probability) = {:.4} ({}/512)",
        max_dp, max_count
    );
    let max_bias = compute_lat(sbox);
    println!("Max Bias (Linear Approximation) = {:.4}\n", max_bias);

    // 雪崩测试
    println!("--- Avalanche Test ---");
    let messages: Vec<[u8; 32]> = vec![
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ],
        [0; 32],
        [0xFF; 32],
        *b"This is a 32-byte test string!!!",
        *b"Wave-Vortex Avalanche Test Suite",
    ];

    let test_key = [0x42; 32];
    let mut all_dists = Vec::new();
    let mut all_zero_cases = Vec::new();

    println!("Testing {} messages...", messages.len());
    for msg in &messages {
        let (dists, zero_cases) = run_avalanche_for_message(msg, |pt| encrypt_block(pt, &test_key));
        all_dists.extend(dists);
        all_zero_cases.extend(zero_cases);
    }

    let (mean, stdev, min, max) = calculate_stats(&all_dists);
    println!(
        "Overall Results: Mean={:.4}, StdDev={:.4}, Min={}, Max={}",
        mean, stdev, min, max
    );

    // 输出零距离案例详情
    println!("Total zero-distance cases found: {}", all_zero_cases.len());
    if !all_zero_cases.is_empty() {
        println!("--- Details of Zero Distance Cases ---");
        for (bit, pt_hex, flipped_pt_hex, base_ct_hex, flip_ct_hex) in all_zero_cases {
            println!("- Bit flipped: {}", bit);
            println!("  Original PT:  {}", pt_hex);
            println!("  Flipped PT:   {}", flipped_pt_hex);
            println!("  Original CT:  {}", base_ct_hex);
            println!("  Flipped CT:   {}", flip_ct_hex);
        }
        println!();
    }

    // 验证SAC (输出288位，期望均值为144)
    println!("--- Strict Avalanche Criterion (SAC) Validation ---");
    let expected_mean = (36 * 8) as f64 / 2.0;
    println!(
        "Expected mean distance for 288-bit output: {:.1}",
        expected_mean
    );

    if (mean - expected_mean).abs() < 5.0 && stdev > 5.0 && min > 0 {
        println!("SAC-like properties check: PASSED ✅");
        println!(
            "(Mean is close to 144, standard deviation is reasonable, and no zero distances were found)."
        );
    } else {
        println!("SAC-like properties check: FAILED ❌");
        if min == 0 {
            println!("Reason: At least one zero-distance case was found, which violates SAC.");
        }
        if (mean - expected_mean).abs() >= 5.0 {
            println!(
                "Reason: The mean distance ({:.4}) deviates significantly from the expected value of {}.",
                mean, expected_mean
            );
        }
        if stdev <= 5.0 {
            println!(
                "Reason: The standard deviation ({:.4}) is too low, suggesting poor output distribution.",
                stdev
            );
        }
    }
}
