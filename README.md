# 🔍 Mutation-Based JPEG Fuzzer
### CAP 6135 – Cyber Lab | Mara Burnside | UCF | May 2026

---

## 📋 Overview

A black-box mutation fuzzer written in Python targeting `jpeg2bmp`, a JPEG-to-BMP conversion utility containing 10 intentionally injected bugs. The fuzzer applies structural JPEG mutations to a seed image, automatically detects crashes, classifies them by bug ID, and saves each unique crash-triggering input for manual verification.

**Result: All 10 bugs discovered in 1,362 iterations with a 57.1% crash rate.**

---

## 📊 Results at a Glance

| Metric | Value |
|---|---|
| Total Iterations | 1,362 |
| Total Crashes | 778 |
| Crash Rate | 57.1% |
| Bugs Discovered | **10 / 10** |
| Mutation Strategies | 20 |
| Timeout Per Run | 3 seconds |

---

## 🐛 Bug Discovery Table

| Bug # | Times Triggered | Category | Status |
|---|---|---|---|
| 1  | 51  | Quantization Table (16-bit) | ✅ Found |
| 2  | 3   | Rare structural trigger     | ✅ Found |
| 3  | 5   | Rare structural trigger     | ✅ Found |
| 4  | 1   | Highly specific input condition | ✅ Found |
| 5  | 15  | Moderate structural         | ✅ Found |
| 6  | 49  | JPEG formatting             | ✅ Found |
| 7  | 66  | Huffman table corruption    | ✅ Found |
| 8  | 33  | Structural / formatting     | ✅ Found |
| 9  | 122 | Huffman table corruption    | ✅ Found |
| 10 | **417** | Bogus JPEG formatting (most common) | ✅ Found |

> Bug #10 was triggered 417 times — indicating bogus JPEG formatting regions are highly susceptible to random mutation. Bugs #2 and #4 required very specific input conditions and were each triggered only a handful of times.

---

## 🛠️ How It Works

### Files

| File | Role |
|---|---|
| `fuzzer_mara1.py` | Main fuzzer script |
| `cross.jpg` | Seed input file |
| `jpeg2bmp` | Target binary (provided) |
| `found/test-N.jpg` | Saved crash-triggering inputs |

### Fuzzing Loop

1. Load `cross.jpg` as the seed input
2. Pick a mutation strategy (adaptive based on bugs found so far)
3. Apply mutation to produce a malformed JPEG
4. Run `./jpeg2bmp mutated.jpg output.bmp` with a 3-second timeout
5. Parse stdout/stderr for `CAP6135 Bug #N` crash identifiers
6. On a new unique bug: save the input to `found/test-N.jpg`
7. Stop early once all 10 bugs are found

---

## 🧬 Mutation Strategies

The fuzzer implements 20 weighted mutation strategies:

| Strategy | Description |
|---|---|
| `mut_random_byte` | Replace one random byte with a random value |
| `mut_interesting_byte` | Replace one byte with a boundary value (0x00, 0x7F, 0xFF…) |
| `mut_interesting_word` | Overwrite 2 bytes with a boundary 16-bit value |
| `mut_interesting_dword` | Overwrite 4 bytes with a boundary 32-bit value |
| `mut_bit_flips` | Flip 1–20 random bits |
| `mut_block_fill` | Fill a random block with a fixed sentinel value |
| `mut_truncate` | Truncate file to a random shorter length |
| `mut_insert_bytes` | Insert a random byte blob at a random position |
| `mut_delete_block` | Delete a small random block of bytes |
| `mut_corrupt_header` | Zero out the first 100 bytes (JPEG header region) |
| `mut_jpeg_marker_corrupt` | Find an 0xFF marker and randomize its type byte |
| `mut_jpeg_length_corrupt` | Replace JPEG segment length fields with boundary values |
| `mut_multi` | Chain 2–5 random mutations together |

### Adaptive Strategy

- **Early phase** (< 4 bugs found): uniform random selection across all strategies
- **Later phase** (4+ bugs found): bias toward JPEG-structural mutations — `mut_jpeg_length_corrupt`, `mut_jpeg_marker_corrupt`, `mut_interesting_word/dword`, `mut_block_fill`, `mut_delete_block`, `mut_multi`

---

## ▶️ Usage

```bash
# 1. Place the seed file and target binary in the same directory
#    cross.jpg   — seed JPEG
#    jpeg2bmp    — target binary (must be executable)

# 2. Run the fuzzer
python3 fuzzer_mara1.py

# 3. Verify a found crash manually
./jpeg2bmp found/test-1.jpg out1.bmp
```

Expected output while running:

```
[*] Seed    : cross.jpg (XXXX bytes)
[*] Target  : ./jpeg2bmp
[*] Iters   : 50,000
-------------------------------------------------------
  [+] Bug # 1 found!  iter=     42  total=1/10  time=0.3s
  [+] Bug # 6 found!  iter=    187  total=2/10  time=1.1s
  ...
[*] All 10 bugs found — stopping early.
```

---

## 🔬 Key Findings

**Unequal trigger distribution** — Bug #10 fired 417 times vs. Bug #4 just once. Certain JPEG formatting regions are far more susceptible to random mutation than others.

**Huffman tables are high-value targets** — Bugs #7 and #9 (Huffman table corruption) were triggered frequently, confirming these segments are particularly fragile under mutation.

**Adaptive weighting works** — Shifting toward structural JPEG mutations after the first four bugs accelerated discovery of the harder-to-reach code paths.

**Mutation fuzzing is effective for format parsers** — Without coverage feedback or grammar awareness, purely mutation-based fuzzing achieved 100% bug coverage by targeting known JPEG structure.

---

## 📁 Output Structure

```
project/
├── fuzzer_mara1.py       # Fuzzer script
├── cross.jpg             # Seed input
├── jpeg2bmp              # Target binary
├── found/
│   ├── test-1.jpg        # Crash trigger for Bug #1
│   ├── test-2.jpg        # Crash trigger for Bug #2
│   └── ...               # test-N.jpg for each bug
└── tmp/
    └── mut_current.jpg   # Current test case (overwritten each iteration)
```

---

## 🖥️ Environment

- **Platform:** UCF Eustis Linux machine
- **Language:** Python 3
- **Course:** CAP 6135 – Malware and Software Vulnerability Analysis
- **Tested with:** `./jpeg2bmp found/test-N.jpg outN.bmp`

---

*CAP 6135 · Cyber Lab · University of Central Florida · May 2026*
