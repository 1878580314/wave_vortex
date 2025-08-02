use once_cell::sync::Lazy;
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, thread_rng};
use sha2::Sha256;
use std::io::{Cursor, Read, Result as IoResult, Write};
use wasm_bindgen::prelude::*;
// --- 常量定义 ---
const MASK_9: u16 = (1 << 9) - 1; // 9-bit mask: 0x1FF
const ROWS: usize = 4;
const COLS: usize = 8;
const CELLS: usize = ROWS * COLS;
const DIRS: usize = 9;
const ROUNDS: usize = 24;
// --- 文件加密相关常量 ---
const SALT_SIZE: usize = 16;
const PLAINTEXT_BLOCK_SIZE: usize = 32;
const CIPHERTEXT_BLOCK_SIZE: usize = 36;
const IV_SIZE: usize = PLAINTEXT_BLOCK_SIZE; // IV大小必须等于明文块大小
const PBKDF2_ROUNDS: u32 = 100_000; // 密钥派生迭代次数

// 预计算的S-box
#[rustfmt::skip]
pub const SBOX: [u16; 512] = [
    0xb5, 0x63, 0x1a1, 0xc2, 0x1f7, 0xf8, 0x1d6, 0xc1, 0x40, 0x1c7, 0x19b, 0x19, 0x94, 0x64, 0xd0, 0x197,
 0x114, 0x1ca, 0x1a2, 0x1d1, 0x1ba, 0xaf, 0xa6, 0x127, 0x61, 0x90, 0x6a, 0x1fe, 0x1e6, 0x16f, 0xb9, 0x17f,
 0x11c, 0x8, 0x1c6, 0x84, 0xf1, 0xe2, 0x15f, 0xfe, 0x16e, 0x1be, 0x14b, 0x160, 0x1e2, 0x1ae, 0x1f8, 0xf6,
 0x1c0, 0x6f, 0xac, 0x1e, 0x108, 0x7e, 0xe9, 0xb4, 0x176, 0x195, 0x17c, 0x1c, 0x1b6, 0x11b, 0x12d, 0x46,
 0xd2, 0x117, 0x190, 0x111, 0xc5, 0x29, 0x30, 0x18c, 0x132, 0x0, 0x65, 0x66, 0x9e, 0x126, 0x137, 0x1dc,
 0x1b, 0x155, 0x1a3, 0x1b1, 0x2, 0x8a, 0x179, 0xee, 0x1bb, 0x26, 0x1f2, 0xe0, 0x45, 0xce, 0xf9, 0x1d4,
 0x69, 0x115, 0xa2, 0x10a, 0x4d, 0x14c, 0x16d, 0xf2, 0x4e, 0xe1, 0x194, 0x53, 0xad, 0x13, 0x1d2, 0x164,
 0x184, 0x148, 0xd8, 0x1ef, 0x2b, 0x175, 0x10c, 0x19a, 0x6d, 0x1e7, 0x119, 0x16c, 0x57, 0xb2, 0x1b8, 0x31,
 0x187, 0x15a, 0x1a, 0x1c5, 0x172, 0x2e, 0xb6, 0x150, 0x1d, 0xbf, 0x144, 0x62, 0x1bc, 0x1c1, 0x20, 0xdc,
 0x3, 0x1f5, 0x5e, 0x87, 0x10d, 0x1cb, 0xb, 0x186, 0x1ce, 0x2a, 0x9f, 0x97, 0x1a9, 0x116, 0x13b, 0xd,
 0xc7, 0x1d9, 0x131, 0x153, 0x196, 0x1e9, 0x1a6, 0xca, 0x3f, 0x192, 0x152, 0xa0, 0x181, 0x154, 0x166, 0x5d,
 0x9, 0x68, 0x141, 0x1ab, 0x1ea, 0xd7, 0x4, 0x16a, 0xbe, 0x1fa, 0xd5, 0x5b, 0xfc, 0x1a8, 0xf5, 0xfb,
 0xe, 0x15c, 0x7b, 0xff, 0x12f, 0x189, 0x2f, 0xc9, 0x170, 0x1aa, 0x1c9, 0x1c8, 0x11d, 0x14a, 0x34, 0x5,
 0x76, 0x19e, 0x163, 0x14f, 0x1bf, 0x1d0, 0x43, 0x106, 0x12a, 0xf4, 0x109, 0xa3, 0x59, 0x8b, 0x1b4, 0x180,
 0x1ee, 0x37, 0x104, 0x103, 0x28, 0x1f9, 0x1df, 0x18b, 0x125, 0x18e, 0x82, 0x49, 0x83, 0xc8, 0xdd, 0x60,
 0xc3, 0x92, 0x11, 0x191, 0x178, 0x120, 0x7a, 0x55, 0x8e, 0x17, 0x17e, 0x118, 0x10f, 0x147, 0xdb, 0x193,
 0xe8, 0x110, 0x134, 0x1f6, 0x1a0, 0x8c, 0x1c3, 0xcb, 0x149, 0x14, 0x8f, 0x1b0, 0x1b3, 0xb3, 0x9b, 0x1da,
 0x6b, 0x161, 0x11a, 0xcc, 0x7, 0xbc, 0xc6, 0x5c, 0x1c2, 0xde, 0x10e, 0x124, 0x1ed, 0x145, 0xe5, 0x70,
 0x158, 0x16b, 0x21, 0x2c, 0x27, 0xd3, 0x136, 0x11f, 0x1e4, 0x4f, 0xa1, 0x22, 0x96, 0x146, 0x18f, 0x4b,
 0x10b, 0x1fd, 0x42, 0x81, 0xa9, 0x67, 0x167, 0xfd, 0x39, 0x1b7, 0x17d, 0x6, 0xaa, 0x15b, 0x3a, 0x133,
 0x7c, 0x17a, 0x91, 0xab, 0x105, 0x72, 0x19d, 0x1cd, 0x1de, 0x6e, 0x173, 0x157, 0x3c, 0x130, 0x18, 0x1e3,
 0x1b9, 0xea, 0x113, 0x1cc, 0xfa, 0xf, 0x14e, 0x12b, 0x44, 0xf3, 0x56, 0x140, 0x1d5, 0x1b2, 0x121, 0x1a4,
 0xf7, 0xd9, 0x169, 0x95, 0x1ad, 0x16, 0x58, 0x100, 0x75, 0x15d, 0x2d, 0xe4, 0x93, 0x135, 0xd6, 0x99,
 0x7d, 0x71, 0x24, 0xf0, 0x4c, 0x162, 0x18d, 0x1ac, 0x156, 0x9a, 0x15e, 0x1f0, 0x1ff, 0xda, 0x9d, 0xed,
 0x13c, 0xeb, 0x198, 0x1dd, 0x3e, 0x52, 0x50, 0x1e5, 0x36, 0x1d8, 0x18a, 0x139, 0x1e8, 0x112, 0x11e, 0x1e0,
 0x128, 0xd1, 0x13f, 0x80, 0xc0, 0x13d, 0x1a7, 0x88, 0x1b5, 0xae, 0x165, 0xb0, 0x171, 0x51, 0x1f4, 0x107,
 0x5a, 0x143, 0x10, 0xd4, 0x7f, 0x5f, 0xcf, 0x6c, 0xc4, 0x142, 0x38, 0x13a, 0x12, 0x85, 0x12c, 0xdf,
 0x19c, 0x1db, 0x98, 0x138, 0x129, 0x73, 0x48, 0x188, 0x1ec, 0x1af, 0x35, 0x13e, 0xc, 0xa5, 0x123, 0x8d,
 0xb8, 0xa8, 0x77, 0x1fc, 0x14d, 0xba, 0x86, 0xec, 0x23, 0x32, 0x122, 0x174, 0x3d, 0x1, 0x1eb, 0x17b,
 0x199, 0x78, 0x41, 0x54, 0x9c, 0x1d3, 0x1bd, 0x1f3, 0x1fb, 0xb7, 0x79, 0x1cf, 0x182, 0x1a5, 0xa7, 0x47,
 0xb1, 0x89, 0xcd, 0x1d7, 0x168, 0xe7, 0x15, 0x25, 0xe6, 0x151, 0x33, 0x1f1, 0x159, 0x3b, 0xef, 0xbd,
 0x19f, 0x177, 0x1c4, 0xe3, 0x4a, 0xa4, 0x1f, 0x102, 0x185, 0xbb, 0x101, 0x183, 0x12e, 0xa, 0x74, 0x1e1
];
// 逆S-box
#[rustfmt::skip]
pub const INV_SBOX: [u16; 512] = [
    0x49, 0x1cd, 0x54, 0x90, 0xb6, 0xcf, 0x13b, 0x114, 0x21, 0xb0, 0x1fd, 0x96, 0x1bc, 0x9f, 0xc0, 0x155,
 0x1a2, 0xf2, 0x1ac, 0x6d, 0x109, 0x1e6, 0x165, 0xf9, 0x14e, 0xb, 0x82, 0x50, 0x3b, 0x88, 0x14e, 0x1f6,
 0x8e, 0x122, 0x12b, 0x1c8, 0x174, 0x45, 0x59, 0x124, 0xe4, 0x1e4, 0x99, 0x181, 0xeb, 0xec, 0x3f, 0x46,
 0x1d, 0x7f, 0x1c9, 0x1ea, 0xce, 0x45, 0x188, 0xe1, 0x1aa, 0x138, 0x13e, 0x1ed, 0x14c, 0x1cc, 0x184, 0xa8,
 0x8, 0x1d2, 0x48, 0x132, 0xd6, 0x44, 0x3f, 0xe1, 0x1b6, 0xeb, 0x1f4, 0x12f, 0x174, 0xd, 0x4c, 0x129,
 0x186, 0x19d, 0x185, 0x6b, 0x1d3, 0xf7, 0x15a, 0x7c, 0x166, 0x9e, 0x1a0, 0xbb, 0x117, 0xaf, 0xf1, 0x1a5,
 0xef, 0x18, 0x8b, 0x1, 0xd, 0x4a, 0x4b, 0x135, 0xb1, 0x60, 0x1a, 0x110, 0x1a7, 0x78, 0x149, 0x31,
 0x11f, 0x171, 0x145, 0x1b5, 0x7a, 0x168, 0xd0, 0x1c2, 0x1d1, 0x1da, 0xf6, 0xc2, 0x140, 0x170, 0x35, 0x1a4,
 0x193, 0x133, 0xea, 0xec, 0x1c8, 0x85, 0x1c6, 0x93, 0x197, 0xe1, 0x55, 0xdd, 0x105, 0xbf, 0xf8, 0x10a,
 0x19, 0x1a2, 0xf1, 0x94, 0xc, 0x163, 0x96, 0x9b, 0x1b2, 0x16f, 0x9a, 0x9e, 0x1d4, 0x9e, 0x4c, 0x9a,
 0xab, 0x12a, 0x8b, 0xdb, 0x1f5, 0xbd, 0x16, 0xde, 0x1c1, 0x134, 0x13c, 0x143, 0x1ca, 0x6c, 0x199, 0x15,
 0x19b, 0x1e0, 0x7d, 0xb6, 0x37, 0x49, 0x86, 0x1d9, 0x1c0, 0x1e, 0x1c5, 0x1f9, 0x115, 0x1ef, 0xb8, 0x89,
 0x194, 0x7, 0x3, 0x173, 0x4, 0x44, 0x116, 0xa0, 0xed, 0xc7, 0xa7, 0x107, 0x113, 0x1e2, 0x5d, 0x1a6,
 0xe, 0xf3, 0x40, 0x125, 0x1a3, 0xba, 0x16e, 0xb5, 0x145, 0x161, 0x17d, 0xfe, 0x8f, 0xee, 0x119, 0x1af,
 0x5b, 0x69, 0x1e7, 0x1f3, 0x1cb, 0x11e, 0x1e8, 0x1e5, 0x168, 0x36, 0x151, 0x81, 0x1c7, 0xdf, 0x57, 0xee,
 0x173, 0x172, 0x67, 0x1e9, 0xd9, 0xbe, 0xc6, 0x160, 0x5, 0x5e, 0x154, 0xbf, 0xbc, 0x137, 0x27, 0xc3,
 0x167, 0x1fa, 0x1f7, 0xfb, 0xe2, 0x144, 0xd7, 0x19f, 0xce, 0xda, 0x63, 0x130, 0x76, 0x94, 0x11a, 0xfc,
 0x101, 0x43, 0x18d, 0x152, 0x1a2, 0x61, 0x9d, 0x41, 0xfb, 0x7a, 0x112, 0x3d, 0x8e, 0xcc, 0x18e, 0x127,
 0xf5, 0x15e, 0x1ca, 0x1be, 0x11b, 0xe8, 0x4d, 0x17, 0x190, 0x1b4, 0xd8, 0x157, 0x1ae, 0x184, 0x1fc, 0xc4,
 0x14d, 0xa2, 0x48, 0x13f, 0x102, 0x16d, 0x126, 0x4e, 0x1b3, 0x18b, 0x1ab, 0x4c, 0x180, 0x195, 0x1bb, 0x192,
 0x15b, 0xb2, 0x1a9, 0x1a1, 0x8a, 0x11d, 0x12d, 0xfd, 0x71, 0x108, 0xcd, 0x99, 0x65, 0x1c4, 0x178, 0xd3,
 0x87, 0x1e9, 0xaa, 0xa3, 0xad, 0x19d, 0x178, 0x14b, 0xf9, 0x1ec, 0x81, 0x13d, 0xc1, 0x169, 0x145, 0x59,
 0x2b, 0x111, 0x175, 0xd2, 0x6f, 0x19a, 0xae, 0x136, 0x1e4, 0x162, 0xb7, 0x121, 0x7b, 0x66, 0x28, 0x1d,
 0xc8, 0x19c, 0x23, 0x14a, 0x95, 0x75, 0x38, 0x1f1, 0xf4, 0x15a, 0x141, 0x1cf, 0x13a, 0x13a, 0xfa, 0x1f,
 0xdf, 0xac, 0x1dc, 0x1fb, 0x11f, 0x1f8, 0x97, 0x98, 0x1b7, 0x44, 0x18a, 0xe7, 0x1db, 0x176, 0xe9, 0x12e,
 0x42, 0x67, 0xa9, 0xc3, 0x6a, 0x39, 0xa4, 0xf, 0x182, 0x1d0, 0x1c2, 0xa, 0x1b0, 0x12e, 0xd1, 0x1f0,
 0x104, 0x54, 0x1ac, 0x52, 0x15f, 0x1dd, 0xa6, 0x196, 0xbd, 0x1d3, 0xc9, 0xb3, 0x177, 0x164, 0x16a, 0x1b9,
 0x10b, 0x6b, 0x15d, 0x10c, 0xde, 0x198, 0x14c, 0x139, 0x35, 0x150, 0x14, 0x166, 0x8c, 0x1d6, 0x29, 0xd4,
 0x30, 0x8d, 0xfa, 0x106, 0x1f2, 0xe8, 0x1c8, 0x9, 0xcb, 0xca, 0xf2, 0x95, 0x153, 0xf9, 0x98, 0x1db,
 0xd5, 0x6d, 0x6e, 0x1d5, 0x1a5, 0x15c, 0x13b, 0x1e3, 0x189, 0xa1, 0xf9, 0x1b1, 0x4f, 0x1fb, 0x148, 0xe6,
 0x18f, 0x1ff, 0x123, 0x14f, 0x188, 0x187, 0x1c, 0x1d9, 0x18c, 0x1bd, 0xb4, 0x1ce, 0x1b8, 0x11c, 0xe0, 0x1b5,
 0x17b, 0x1eb, 0x1a0, 0x1d7, 0x19e, 0x142, 0x103, 0x4, 0x85, 0xe5, 0x1e, 0x1d8, 0x105, 0x131, 0x50, 0x17c,
];
const INV_MDS_C1: u16 = 0x119;
const INV_MDS_C2: u16 = 0x23;
// 格点流动向量
const VEC: [(i8, i8); 9] = [
    (0, 0),
    (0, 1),
    (0, -1),
    (1, 0),
    (-1, 0),
    (1, 1),
    (1, -1),
    (-1, 1),
    (-1, -1),
];
// ASCON-p12 轮常数
const RC: [u64; 12] = [
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
];
// --- 辅助函数 ---
#[inline(always)]
fn gf_mul(mut a: u16, mut b: u16) -> u16 {
    let mut res = 0;
    for _ in 0..9 {
        if b & 1 != 0 {
            res ^= a;
        }
        let carry = a & 0x100;
        a = (a << 1) & MASK_9;
        if carry != 0 {
            a ^= 0x11;
        }
        b >>= 1;
    }
    res & MASK_9
}
fn generate_perm(seed: u64) -> [usize; 9] {
    let mut seq = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    let mut hash = seed;
    for i in (1..9).rev() {
        hash = hash.wrapping_mul(0x517cc1b727220a95) ^ (hash >> 31);
        let j = (hash % (i as u64 + 1)) as usize;
        seq.swap(i, j);
    }
    seq
}
fn stream_fwd(cells: &[u16; CELLS], perm: &[usize; 9]) -> [u16; CELLS] {
    let mut nxt = [0u16; CELLS];
    for (idx, &val) in cells.iter().enumerate() {
        let r = idx / COLS;
        let c = idx % COLS;
        for d0 in 0..DIRS {
            if (val >> d0) & 1 != 0 {
                let (dr, dc) = VEC[perm[d0]];
                let nr = (r as i8 + dr).rem_euclid(ROWS as i8) as usize;
                let nc = (c as i8 + dc).rem_euclid(COLS as i8) as usize;
                nxt[nr * COLS + nc] |= 1 << d0;
            }
        }
    }
    nxt
}
fn vtx_shuffle(cells: &[u16; CELLS], s: u16) -> [u16; CELLS] {
    let mut out = [0u16; CELLS];
    let s_usize = s as usize;
    for r in 0..ROWS {
        for c in 0..COLS {
            let src_r = (r + ROWS - s_usize % ROWS) % ROWS;
            let src_c = (c + COLS - s_usize % COLS) % COLS;
            out[r * COLS + c] = cells[src_r * COLS + src_c];
        }
    }
    out
}
fn inv_vtx_shuffle(cells: &[u16; CELLS], s: u16) -> [u16; CELLS] {
    let mut out = [0u16; CELLS];
    let s_usize = s as usize;
    for r in 0..ROWS {
        for c in 0..COLS {
            let src_r = (r + s_usize % ROWS) % ROWS;
            let src_c = (c + s_usize % COLS) % COLS;
            out[r * COLS + c] = cells[src_r * COLS + src_c];
        }
    }
    out
}
fn inv_stream_fwd(cells: &[u16; CELLS], perm: &[usize; 9]) -> [u16; CELLS] {
    let mut nxt = [0u16; CELLS];
    for (idx, &val) in cells.iter().enumerate() {
        let r = idx / COLS;
        let c = idx % COLS;
        for d0 in 0..DIRS {
            if (val >> d0) & 1 != 0 {
                let (dr, dc) = VEC[perm[d0]];
                let nr = (r as i8 - dr).rem_euclid(ROWS as i8) as usize;
                let nc = (c as i8 - dc).rem_euclid(COLS as i8) as usize;
                nxt[nr * COLS + nc] |= 1 << d0;
            }
        }
    }
    nxt
}
#[inline(always)]
fn ascon_round(s: &mut [u64; 5], rc: u64) {
    s[2] ^= rc;
    s[0] ^= s[4];
    s[4] ^= s[3];
    s[2] ^= s[1];
    let mut t = [0u64; 5];
    for i in 0..5 {
        t[i] = s[i] ^ (!s[(i + 1) % 5] & s[(i + 2) % 5]);
    }
    for i in 0..5 {
        s[i] = t[i];
    }
    s[1] ^= s[0];
    s[0] ^= s[4];
    s[3] ^= s[2];
    s[2] = !s[2];
    s[0] ^= s[0].rotate_right(19) ^ s[0].rotate_right(28);
    s[1] ^= s[1].rotate_right(61) ^ s[1].rotate_right(39);
    s[2] ^= s[2].rotate_right(1) ^ s[2].rotate_right(6);
    s[3] ^= s[3].rotate_right(10) ^ s[3].rotate_right(17);
    s[4] ^= s[4].rotate_right(7) ^ s[4].rotate_right(41);
}
fn ascon_p(state: &mut [u64; 5], rnds: usize) {
    let start_round = 12 - rnds;
    for i in start_round..12 {
        ascon_round(state, RC[i]);
    }
}
fn key_schedule(master_key: &[u8; 32]) -> Vec<([u8; 36], [usize; 9], u16)> {
    let iv: u64 = 0x80400c0600000000;
    let k0 = u64::from_le_bytes(master_key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(master_key[8..16].try_into().unwrap());
    let k2 = u64::from_le_bytes(master_key[16..24].try_into().unwrap());
    let k3 = u64::from_le_bytes(master_key[24..32].try_into().unwrap());
    let mut s = [iv, k0, k1, k2, k3];
    ascon_p(&mut s, 12);
    let mut subs = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        ascon_p(&mut s, 12);
        let shift = (s[0] & 0x7) as u16;
        let perm_seed = s[0] ^ s[1];
        let perm = generate_perm(perm_seed);
        let mut mask = [0u8; 36];
        let mut state_bytes = [0u8; 40];
        for (i, chunk) in s.iter().enumerate() {
            state_bytes[i * 8..(i + 1) * 8].copy_from_slice(&chunk.to_le_bytes());
        }
        mask.copy_from_slice(&state_bytes[0..36]);
        subs.push((mask, perm, shift));
    }
    subs
}
fn pack_state(cells: &[u16; CELLS]) -> [u8; 36] {
    let mut out = [0u8; 36];
    let mut bit_pos = 0;
    for &cell in cells.iter() {
        for bit in 0..9 {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if (cell >> bit) & 1 != 0 {
                out[byte_idx] |= 1 << bit_idx;
            }
            bit_pos += 1;
        }
    }
    out
}
fn unpack_state(ct: &[u8; 36]) -> [u16; CELLS] {
    let mut cells = [0u16; CELLS];
    let mut bit_pos = 0;
    for cell_idx in 0..CELLS {
        let mut val = 0u16;
        for bit in 0..9 {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            val |= (((ct[byte_idx] >> bit_idx) & 1) as u16) << bit;
            bit_pos += 1;
        }
        cells[cell_idx] = val;
    }
    cells
}

// --- 1. CipherCtx: 轮密钥缓存 ---
#[derive(Clone)]
struct RoundKey {
    mask_cells: [u16; CELLS],
    perm: [usize; 9],
    shift: u16,
}
#[derive(Clone)]
pub struct CipherCtx {
    rounds: [RoundKey; ROUNDS],
}
impl CipherCtx {
    pub fn new(master_key: &[u8; 32]) -> Self {
        let subs = key_schedule(master_key);
        let mut rounds: [RoundKey; ROUNDS] = array_init::array_init(|_| RoundKey {
            mask_cells: [0u16; CELLS],
            perm: [0; 9],
            shift: 0,
        });
        for (i, (mask, perm, shift)) in subs.into_iter().enumerate() {
            rounds[i] = RoundKey {
                mask_cells: unpack_state(&mask),
                perm,
                shift,
            };
        }
        Self { rounds }
    }
}
// --- 2. T-Tables for S-box + MDS ---
static T0: Lazy<[[u16; 4]; 512]> = Lazy::new(|| {
    let mut t = [[0u16; 4]; 512];
    for x in 0..512 {
        let s = SBOX[x];
        t[x] = [
            gf_mul(0x1, s),
            gf_mul(0x8, s),
            gf_mul(0x4, s),
            gf_mul(0x2, s),
        ];
    }
    t
});
static T1: Lazy<[[u16; 4]; 512]> = Lazy::new(|| {
    let mut t = [[0u16; 4]; 512];
    for x in 0..512 {
        let s = SBOX[x];
        t[x] = [
            gf_mul(0x2, s),
            gf_mul(0x1, s),
            gf_mul(0x8, s),
            gf_mul(0x4, s),
        ];
    }
    t
});
static T2: Lazy<[[u16; 4]; 512]> = Lazy::new(|| {
    let mut t = [[0u16; 4]; 512];
    for x in 0..512 {
        let s = SBOX[x];
        t[x] = [
            gf_mul(0x4, s),
            gf_mul(0x2, s),
            gf_mul(0x1, s),
            gf_mul(0x8, s),
        ];
    }
    t
});
static T3: Lazy<[[u16; 4]; 512]> = Lazy::new(|| {
    let mut t = [[0u16; 4]; 512];
    for x in 0..512 {
        let s = SBOX[x];
        t[x] = [
            gf_mul(0x8, s),
            gf_mul(0x4, s),
            gf_mul(0x2, s),
            gf_mul(0x1, s),
        ];
    }
    t
});
// --- 2. 查表版 MDS ---
static MUL_1: Lazy<[u16; 512]> = Lazy::new(|| {
    let mut t = [0u16; 512];
    for x in 0..512 {
        t[x] = x as u16;
    }
    t
});
static MUL_2: Lazy<[u16; 512]> = Lazy::new(|| {
    let mut t = [0u16; 512];
    for x in 0..512 {
        t[x] = gf_mul(0x02, x as u16);
    }
    t
});
static MUL_4: Lazy<[u16; 512]> = Lazy::new(|| {
    let mut t = [0u16; 512];
    for x in 0..512 {
        t[x] = gf_mul(0x04, x as u16);
    }
    t
});
static MUL_8: Lazy<[u16; 512]> = Lazy::new(|| {
    let mut t = [0u16; 512];
    for x in 0..512 {
        t[x] = gf_mul(0x08, x as u16);
    }
    t
});
static MUL_23: Lazy<[u16; 512]> = Lazy::new(|| {
    let mut t = [0u16; 512];
    for x in 0..512 {
        t[x] = gf_mul(INV_MDS_C2, x as u16);
    }
    t
});
static MUL_119: Lazy<[u16; 512]> = Lazy::new(|| {
    let mut t = [0u16; 512];
    for x in 0..512 {
        t[x] = gf_mul(INV_MDS_C1, x as u16);
    }
    t
});
#[inline]
fn apply_mds_lookup(cells: &[u16; CELLS]) -> [u16; CELLS] {
    let mut out = [0u16; CELLS];
    for c in 0..COLS {
        let a = cells[0 * COLS + c] as usize;
        let b = cells[1 * COLS + c] as usize;
        let d = cells[2 * COLS + c] as usize;
        let e = cells[3 * COLS + c] as usize;
        let r0 = MUL_1[a] ^ MUL_2[b] ^ MUL_4[d] ^ MUL_8[e];
        let r1 = MUL_8[a] ^ MUL_1[b] ^ MUL_2[d] ^ MUL_4[e];
        let r2 = MUL_4[a] ^ MUL_8[b] ^ MUL_1[d] ^ MUL_2[e];
        let r3 = MUL_2[a] ^ MUL_4[b] ^ MUL_8[d] ^ MUL_1[e];
        out[0 * COLS + c] = r0;
        out[1 * COLS + c] = r1;
        out[2 * COLS + c] = r2;
        out[3 * COLS + c] = r3;
    }
    out
}
#[inline]
fn apply_inv_mds_lookup(cells: &[u16; CELLS]) -> [u16; CELLS] {
    let mut out = [0u16; CELLS];
    for c in 0..COLS {
        let a = cells[0 * COLS + c] as usize;
        let b = cells[1 * COLS + c] as usize;
        let d = cells[2 * COLS + c] as usize;
        let e = cells[3 * COLS + c] as usize;
        let r0 = MUL_119[a] ^ MUL_23[b];
        let r1 = MUL_119[b] ^ MUL_23[d];
        let r2 = MUL_119[d] ^ MUL_23[e];
        let r3 = MUL_23[a] ^ MUL_119[e];
        out[0 * COLS + c] = r0;
        out[1 * COLS + c] = r1;
        out[2 * COLS + c] = r2;
        out[3 * COLS + c] = r3;
    }
    out
}

#[inline]
fn apply_sub_mds_fused(cells: &[u16; CELLS]) -> [u16; CELLS] {
    let mut out = [0u16; CELLS];
    for c in 0..COLS {
        let i0 = cells[0 * COLS + c] as usize;
        let i1 = cells[1 * COLS + c] as usize;
        let i2 = cells[2 * COLS + c] as usize;
        let i3 = cells[3 * COLS + c] as usize;
        let contrib0 = T0[i0];
        let contrib1 = T1[i1];
        let contrib2 = T2[i2];
        let contrib3 = T3[i3];
        out[0 * COLS + c] = contrib0[0] ^ contrib1[0] ^ contrib2[0] ^ contrib3[0];
        out[1 * COLS + c] = contrib0[1] ^ contrib1[1] ^ contrib2[1] ^ contrib3[1];
        out[2 * COLS + c] = contrib0[2] ^ contrib1[2] ^ contrib2[2] ^ contrib3[2];
        out[3 * COLS + c] = contrib0[3] ^ contrib1[3] ^ contrib2[3] ^ contrib3[3];
    }
    out
}
// --- 3. S‑box 代换：高速查表 + 可选常时位切片 ---
#[inline]
fn subcells_32(cells: &mut [u16; CELLS]) {
    #[cfg(feature = "constant_time")]
    {
        subcells_bitslice_32(cells);
        return;
    }
    for v in cells.iter_mut() {
        *v = SBOX[*v as usize];
    }
}
#[inline]
fn inv_subcells_32(cells: &mut [u16; CELLS]) {
    #[cfg(feature = "constant_time")]
    {
        inv_subcells_bitslice_32(cells);
        return;
    }
    for v in cells.iter_mut() {
        *v = INV_SBOX[*v as usize];
    }
}
// --- 3. 位切片 S-box (常数时间) ---
#[inline]
fn subcells_bitslice_32(cells: &mut [u16; CELLS]) {
    let mut in_planes = [0u32; 9];
    for lane in 0..CELLS {
        let v = cells[lane];
        for b in 0..9 {
            if (v >> b) & 1 != 0 {
                in_planes[b] |= 1u32 << lane;
            }
        }
    }
    let mut out_planes = [0u32; 9];
    for v in 0..512u16 {
        let mut mask = 0xFFFF_FFFFu32;
        for b in 0..9 {
            let bit_is_one = ((v >> b) & 1) != 0;
            mask &= if bit_is_one {
                in_planes[b]
            } else {
                !in_planes[b]
            };
        }
        if mask == 0 {
            continue;
        }
        let s = SBOX[v as usize];
        for b in 0..9 {
            if ((s >> b) & 1) != 0 {
                out_planes[b] |= mask;
            }
        }
    }
    for lane in 0..CELLS {
        let mut v = 0u16;
        for b in 0..9 {
            let bit = (out_planes[b] >> lane) & 1;
            v |= (bit as u16) << b;
        }
        cells[lane] = v;
    }
}
#[inline]
fn inv_subcells_bitslice_32(cells: &mut [u16; CELLS]) {
    let mut in_planes = [0u32; 9];
    for lane in 0..CELLS {
        let v = cells[lane];
        for b in 0..9 {
            if (v >> b) & 1 != 0 {
                in_planes[b] |= 1u32 << lane;
            }
        }
    }
    let mut out_planes = [0u32; 9];
    for v in 0..512u16 {
        let mut mask = 0xFFFF_FFFFu32;
        for b in 0..9 {
            let bit_is_one = ((v >> b) & 1) != 0;
            mask &= if bit_is_one {
                in_planes[b]
            } else {
                !in_planes[b]
            };
        }
        if mask == 0 {
            continue;
        }
        let s = INV_SBOX[v as usize];
        for b in 0..9 {
            if ((s >> b) & 1) != 0 {
                out_planes[b] |= mask;
            }
        }
    }
    for lane in 0..CELLS {
        let mut v = 0u16;
        for b in 0..9 {
            let bit = (out_planes[b] >> lane) & 1;
            v |= (bit as u16) << b;
        }
        cells[lane] = v;
    }
}
// --- 4. 优化后的轮函数 ---
#[inline]
fn encrypt_round_ctx(cells: &mut [u16; CELLS], rk: &RoundKey) {
    for i in 0..CELLS {
        cells[i] ^= rk.mask_cells[i];
    }
    *cells = apply_sub_mds_fused(cells);
    for i in 0..CELLS {
        cells[i] = ((cells[i] << 1) | (cells[i] >> 8)) & MASK_9;
    }
    *cells = stream_fwd(cells, &rk.perm);
    *cells = vtx_shuffle(cells, rk.shift);
}
#[inline]
fn decrypt_round_ctx(cells: &mut [u16; CELLS], rk: &RoundKey) {
    *cells = inv_vtx_shuffle(cells, rk.shift);
    *cells = inv_stream_fwd(cells, &rk.perm);
    for i in 0..CELLS {
        cells[i] = ((cells[i] >> 1) | (cells[i] << 8)) & MASK_9;
    }
    *cells = apply_inv_mds_lookup(cells);
    inv_subcells_32(cells);
    for i in 0..CELLS {
        cells[i] ^= rk.mask_cells[i];
    }
}
// --- 5. 新的基于上下文的块API ---
pub fn encrypt_block_ctx(ctx: &CipherCtx, pt: &[u8; 32]) -> [u8; 36] {
    let mut bit_pos = 0;
    let mut cells = [0u16; CELLS];
    for cell_idx in 0..CELLS {
        let mut val = 0u16;
        for bit in 0..9 {
            if bit_pos < 256 {
                let byte_idx = bit_pos / 8;
                let bit_idx = bit_pos % 8;
                val |= (((pt[byte_idx] >> bit_idx) & 1) as u16) << bit;
                bit_pos += 1;
            }
        }
        cells[cell_idx] = val;
    }
    for r in 0..ROUNDS {
        encrypt_round_ctx(&mut cells, &ctx.rounds[r]);
    }
    pack_state(&cells)
}
pub fn decrypt_block_ctx(ctx: &CipherCtx, ct: &[u8; 36]) -> [u8; 32] {
    let mut cells = unpack_state(ct);
    for r in (0..ROUNDS).rev() {
        decrypt_round_ctx(&mut cells, &ctx.rounds[r]);
    }
    let mut pt = [0u8; 32];
    let mut bit_pos = 0;
    for cell_idx in 0..CELLS {
        for bit in 0..9 {
            if bit_pos < 256 {
                let byte_idx = bit_pos / 8;
                let bit_idx = bit_pos % 8;
                let bit_val = (cells[cell_idx] >> bit) & 1;
                pt[byte_idx] |= (bit_val as u8) << bit_idx;
                bit_pos += 1;
            } else {
                break;
            }
        }
        if bit_pos >= 256 {
            break;
        }
    }
    pt
}
// --- 公共 API ---
/// 加密一个32字节的明文块。
pub fn encrypt_block(pt: &[u8; 32], master_key: &[u8; 32]) -> [u8; 36] {
    let ctx = CipherCtx::new(master_key);
    encrypt_block_ctx(&ctx, pt)
}
/// 解密一个36字节的密文块。
pub fn decrypt_block(ct: &[u8; 36], master_key: &[u8; 32]) -> [u8; 32] {
    let ctx = CipherCtx::new(master_key);
    decrypt_block_ctx(&ctx, ct)
}

// --- 高级文件加密 API ---
pub fn derive_key_from_password(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ROUNDS, &mut key);
    key
}

pub fn encrypt_stream_with_ctx(
    reader: &mut impl Read,
    writer: &mut impl Write,
    ctx: &CipherCtx,
) -> IoResult<()> {
    let mut iv = [0u8; IV_SIZE];
    thread_rng().fill_bytes(&mut iv);
    writer.write_all(&iv)?;
    let mut prev_cipher_block = iv;
    let mut buffer = [0u8; PLAINTEXT_BLOCK_SIZE];
    let mut has_data = false;
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 && !has_data {
            // 空输入：不加密
            break;
        }
        has_data = true;
        let mut block_to_encrypt: [u8; PLAINTEXT_BLOCK_SIZE];
        if bytes_read == PLAINTEXT_BLOCK_SIZE {
            block_to_encrypt = buffer;
        } else {
            // 不满：填充
            let padding_val = if bytes_read == 0 {
                PLAINTEXT_BLOCK_SIZE as u8 // 额外全填充块
            } else {
                (PLAINTEXT_BLOCK_SIZE - bytes_read) as u8
            };
            block_to_encrypt = [padding_val; PLAINTEXT_BLOCK_SIZE];
            if bytes_read > 0 {
                block_to_encrypt[..bytes_read].copy_from_slice(&buffer[..bytes_read]);
            }
        }
        let mut xor_block = [0u8; PLAINTEXT_BLOCK_SIZE];
        for i in 0..PLAINTEXT_BLOCK_SIZE {
            xor_block[i] = block_to_encrypt[i] ^ prev_cipher_block[i];
        }
        let cipher_block = encrypt_block_ctx(ctx, &xor_block);
        writer.write_all(&cipher_block)?;
        prev_cipher_block.copy_from_slice(&cipher_block[..PLAINTEXT_BLOCK_SIZE]);
        if bytes_read < PLAINTEXT_BLOCK_SIZE {
            break;
        }
    }
    if !has_data {
        // 空输入：添加全填充块
        let mut padding_block = [PLAINTEXT_BLOCK_SIZE as u8; PLAINTEXT_BLOCK_SIZE];
        for i in 0..PLAINTEXT_BLOCK_SIZE {
            padding_block[i] ^= prev_cipher_block[i];
        }
        let padding_cipher = encrypt_block_ctx(ctx, &padding_block);
        writer.write_all(&padding_cipher)?;
    }
    Ok(())
}

pub fn encrypt_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    password: &[u8],
) -> IoResult<()> {
    let mut salt = [0u8; SALT_SIZE];
    thread_rng().fill_bytes(&mut salt);
    writer.write_all(&salt)?;
    let key = derive_key_from_password(password, &salt);
    let ctx = CipherCtx::new(&key);
    encrypt_stream_with_ctx(reader, writer, &ctx)
}

pub fn decrypt_stream_with_ctx(
    reader: &mut impl Read,
    writer: &mut impl Write,
    ctx: &CipherCtx,
) -> IoResult<()> {
    let mut iv = [0u8; IV_SIZE];
    reader.read_exact(&mut iv)?;
    let mut prev_cipher_block = iv;
    let mut buffer = [0u8; CIPHERTEXT_BLOCK_SIZE];
    let mut temp_decrypted_block = [0u8; PLAINTEXT_BLOCK_SIZE];
    let mut is_first_block = true;
    loop {
        match reader.read_exact(&mut buffer) {
            Ok(()) => {
                let decrypted_xor_block = decrypt_block_ctx(ctx, &buffer);
                let mut current_plaintext_block = [0u8; PLAINTEXT_BLOCK_SIZE];
                for i in 0..PLAINTEXT_BLOCK_SIZE {
                    current_plaintext_block[i] = decrypted_xor_block[i] ^ prev_cipher_block[i];
                }
                if !is_first_block {
                    writer.write_all(&temp_decrypted_block)?;
                }

                temp_decrypted_block = current_plaintext_block;
                prev_cipher_block.copy_from_slice(&buffer[..PLAINTEXT_BLOCK_SIZE]);
                is_first_block = false;
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }

    if is_first_block {
        return Ok(()); 
    }
    // Process the final block for padding
    let last_block = temp_decrypted_block;
    let padding_val = last_block[PLAINTEXT_BLOCK_SIZE - 1];
    if padding_val == 0 || padding_val > PLAINTEXT_BLOCK_SIZE as u8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid PKCS#7 padding: value is zero or too large.",
        ));
    }
    let unpadded_len = PLAINTEXT_BLOCK_SIZE - padding_val as usize;

    for i in unpadded_len..PLAINTEXT_BLOCK_SIZE {
        if last_block[i] != padding_val {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid PKCS#7 padding: bytes do not match padding value.",
            ));
        }
    }

    writer.write_all(&last_block[..unpadded_len])?;

    Ok(())
}

pub fn decrypt_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    password: &[u8],
) -> IoResult<()> {
    let mut salt = [0u8; SALT_SIZE];
    reader.read_exact(&mut salt)?;
    let key = derive_key_from_password(password, &salt);
    let ctx = CipherCtx::new(&key);

    decrypt_stream_with_ctx(reader, writer, &ctx)
}
// --- Wasm 绑定部分 ---
#[wasm_bindgen]
pub fn wasm_encrypt_block(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if plaintext.len() != 32 || key.len() != 32 {
        return Err(JsValue::from_str("Plaintext and key must be 32 bytes."));
    }
    let pt_arr: [u8; 32] = plaintext.try_into().unwrap();
    let key_arr: [u8; 32] = key.try_into().unwrap();
    let ciphertext = encrypt_block(&pt_arr, &key_arr);
    Ok(ciphertext.to_vec())
}
#[wasm_bindgen]
pub fn wasm_decrypt_block(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if ciphertext.len() != 36 || key.len() != 32 {
        return Err(JsValue::from_str(
            "Ciphertext must be 36 bytes and key must be 32 bytes.",
        ));
    }
    let ct_arr: [u8; 36] = ciphertext.try_into().unwrap();
    let key_arr: [u8; 32] = key.try_into().unwrap();
    let plaintext = decrypt_block(&ct_arr, &key_arr);
    Ok(plaintext.to_vec())
}
#[wasm_bindgen]
pub fn wasm_encrypt_stream(data: &[u8], password: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut reader = Cursor::new(data);
    let mut writer = Cursor::new(Vec::new());
    match encrypt_stream(&mut reader, &mut writer, password) {
        Ok(_) => Ok(writer.into_inner()),
        Err(e) => Err(JsValue::from_str(&format!("Encryption failed: {}", e))),
    }
}
#[wasm_bindgen]
pub fn wasm_decrypt_stream(encrypted_data: &[u8], password: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut reader = Cursor::new(encrypted_data);
    let mut writer = Cursor::new(Vec::new());
    match decrypt_stream(&mut reader, &mut writer, password) {
        Ok(_) => Ok(writer.into_inner()),
        Err(e) => Err(JsValue::from_str(&format!(
            "Decryption failed: {}. (Is the password correct?)",
            e
        ))),
    }
}
