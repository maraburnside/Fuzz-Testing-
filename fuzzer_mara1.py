import os
import re
import random
import shutil
import struct
import subprocess
import time
from collections import defaultdict

# ── Configuration ─────────────────────────────────────────────────────────────
SEED_FILE  = "cross.jpg"
TARGET     = "./jpeg2bmp"
ITERATIONS = 50000
TIMEOUT    = 3          # seconds per run
MAX_BUGS   = 10

# Output directories
FOUND_DIR  = "found"    # stores test-N.jpg trigger files
TMP_DIR    = "tmp"      # temporary working files

os.makedirs(FOUND_DIR, exist_ok=True)
os.makedirs(TMP_DIR,   exist_ok=True)

# ── Load seed file ─────────────────────────────────────────────────────────────
with open(SEED_FILE, "rb") as f:
    seed = bytearray(f.read())

print(f"[*] Seed    : {SEED_FILE} ({len(seed)} bytes)")
print(f"[*] Target  : {TARGET}")
print(f"[*] Iters   : {ITERATIONS:,}")
print("-" * 55)

# ── Interesting values (boundary/edge-case fuzzing) ───────────────────────────
INTERESTING_8  = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
INTERESTING_16 = [0x0000, 0x0001, 0x007F, 0x0080,
                  0x00FF, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]
INTERESTING_32 = [0x00000000, 0x00000001, 0x7FFFFFFF,
                  0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]


# ══════════════════════════════════════════════════════════════════════════════
#  MUTATION FUNCTIONS  (each returns a new bytearray)
# ══════════════════════════════════════════════════════════════════════════════

def mut_random_byte(d):
    """Replace one random byte with a random value."""
    m = bytearray(d)
    m[random.randint(0, len(m) - 1)] = random.randint(0, 255)
    return m


def mut_interesting_byte(d):
    """Replace one random byte with a boundary value."""
    m = bytearray(d)
    m[random.randint(0, len(m) - 1)] = random.choice(INTERESTING_8)
    return m


def mut_interesting_word(d):
    """Overwrite 2 bytes at a random position with a boundary 16-bit value."""
    m = bytearray(d)
    if len(m) < 2:
        return m
    pos = random.randint(0, len(m) - 2)
    struct.pack_into(">H", m, pos, random.choice(INTERESTING_16))
    return m


def mut_interesting_dword(d):
    """Overwrite 4 bytes at a random position with a boundary 32-bit value."""
    m = bytearray(d)
    if len(m) < 4:
        return m
    pos = random.randint(0, len(m) - 4)
    struct.pack_into(">I", m, pos, random.choice(INTERESTING_32))
    return m


def mut_bit_flips(d):
    """Flip 1–20 random bits."""
    m = bytearray(d)
    for _ in range(random.randint(1, 20)):
        idx = random.randint(0, len(m) - 1)
        m[idx] ^= (1 << random.randint(0, 7))
    return m


def mut_block_fill(d):
    """Fill a random block with a fixed value (0x00, 0xFF, 0x7F, or 0x80)."""
    m = bytearray(d)
    start  = random.randint(0, len(m) - 2)
    length = random.randint(1, min(64, len(m) - start))
    val    = random.choice([0x00, 0xFF, 0x7F, 0x80, random.randint(0, 255)])
    for i in range(start, start + length):
        m[i] = val
    return m


def mut_truncate(d):
    """Truncate the file to a random shorter length."""
    m = bytearray(d)
    new_len = random.randint(max(4, len(m) // 4), len(m) - 1)
    return m[:new_len]


def mut_insert_bytes(d):
    """Insert a random blob of bytes at a random position."""
    m    = bytearray(d)
    pos  = random.randint(0, len(m))
    blob = bytearray(random.randint(0, 255) for _ in range(random.randint(1, 32)))
    m[pos:pos] = blob
    return m


def mut_delete_block(d):
    """Delete a small random block of bytes."""
    m      = bytearray(d)
    start  = random.randint(0, len(m) - 2)
    length = random.randint(1, min(32, len(m) - start))
    del m[start:start + length]
    return m


def mut_corrupt_header(d):
    """Zero out the first 100 bytes (hammers JPEG header fields)."""
    m = bytearray(d)
    for i in range(min(100, len(m))):
        m[i] = 0x00
    return m


def mut_jpeg_marker_corrupt(d):
    """Find a JPEG 0xFF marker and randomize the marker-type byte."""
    m       = bytearray(d)
    markers = [i for i in range(len(m) - 1)
               if m[i] == 0xFF and m[i + 1] not in (0x00, 0xD8, 0xD9)]
    if not markers:
        return mut_random_byte(m)
    pos        = random.choice(markers)
    m[pos + 1] = random.randint(0, 255)
    return m


def mut_jpeg_length_corrupt(d):
    """Find JPEG segment length fields and replace with boundary values."""
    m, i, positions = bytearray(d), 0, []
    while i < len(m) - 3:
        if m[i] == 0xFF and m[i + 1] not in (0x00, 0xD8, 0xD9):
            positions.append(i + 2)
            seg_len = (m[i + 2] << 8) | m[i + 3]
            i      += 2 + max(2, seg_len)
        else:
            i += 1
    if not positions:
        return mut_interesting_word(m)
    pos = random.choice(positions)
    if pos + 1 < len(m):
        struct.pack_into(">H", m, pos, random.choice(INTERESTING_16))
    return m


def mut_multi(d):
    """Chain 2–5 random mutations together."""
    m = bytearray(d)
    for _ in range(random.randint(2, 5)):
        m = random.choice(ALL_MUTATIONS)(m)
    return m


# All strategies — duplicated entries = higher selection weight
ALL_MUTATIONS = [
    mut_random_byte,
    mut_random_byte,
    mut_interesting_byte,
    mut_interesting_byte,
    mut_interesting_word,
    mut_interesting_word,
    mut_interesting_dword,
    mut_bit_flips,
    mut_block_fill,
    mut_block_fill,
    mut_truncate,
    mut_insert_bytes,
    mut_delete_block,
    mut_corrupt_header,
    mut_jpeg_marker_corrupt,
    mut_jpeg_marker_corrupt,
    mut_jpeg_length_corrupt,
    mut_jpeg_length_corrupt,
    mut_multi,
    mut_multi,
]


def pick_strategy(bugs_found_count):
    """
    Adaptive strategy: shift toward JPEG-structural mutations
    after the easy bugs are found.
    """
    if bugs_found_count < 4:
        return random.choice(ALL_MUTATIONS)
    structural = [
        mut_jpeg_length_corrupt,
        mut_jpeg_marker_corrupt,
        mut_interesting_word,
        mut_interesting_dword,
        mut_block_fill,
        mut_delete_block,
        mut_multi,
    ]
    return random.choice(structural)


# ══════════════════════════════════════════════════════════════════════════════
#  RUN TARGET
# ══════════════════════════════════════════════════════════════════════════════

def run_target(in_file, out_file):
    """
    Run jpeg2bmp and return (crashed, bug_number_or_None, stderr_text).
    """
    try:
        result = subprocess.run(
            [TARGET, in_file, out_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT
        )
        output = result.stderr.decode(errors="ignore") + \
                 result.stdout.decode(errors="ignore")

        if os.path.exists(out_file):
            os.remove(out_file)

        if result.returncode != 0:
            m = re.search(r"CAP6135\s+Bug\s*#\s*(\d+)", output)
            if m:
                return True, int(m.group(1)), output.strip()
            return True, None, output.strip()
        return False, None, ""

    except subprocess.TimeoutExpired:
        return True, None, "TIMEOUT"
    except Exception as e:
        return True, None, str(e)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN FUZZ LOOP
# ══════════════════════════════════════════════════════════════════════════════

bug_counts    = defaultdict(int)
found         = set()
total_crashes = 0
in_file       = os.path.join(TMP_DIR, "mut_current.jpg")
out_file      = os.path.join(TMP_DIR, "out_current.bmp")
start_time    = time.time()
last_report   = start_time

for i in range(1, ITERATIONS + 1):

    # Mutate
    strategy = pick_strategy(len(found))
    mutated  = strategy(seed)

    # Clamp size
    if len(mutated) < 4:
        mutated.extend(b"\x00" * (4 - len(mutated)))
    if len(mutated) > 8000:
        mutated = mutated[:8000]

    with open(in_file, "wb") as f:
        f.write(mutated)

    crashed, bug_num, stderr = run_target(in_file, out_file)

    if crashed:
        total_crashes += 1
        if bug_num is not None:
            bug_counts[bug_num] += 1
            if bug_num not in found:
                found.add(bug_num)
                save_path = os.path.join(FOUND_DIR, f"test-{bug_num}.jpg")
                shutil.copy(in_file, save_path)
                elapsed = time.time() - start_time
                print(f"  [+] Bug #{bug_num:>2} found! "
                      f"iter={i:>7,}  total={len(found)}/10  "
                      f"time={elapsed:.1f}s")
                print(f"       {stderr[:72]}")
                if len(found) == MAX_BUGS:
                    print("\n[*] All 10 bugs found — stopping early.")
                    break

    # Progress every 5 seconds
    now = time.time()
    if now - last_report >= 5:
        elapsed = now - start_time
        print(f"  [-] iter={i:>7,}  crashes={total_crashes:>5,}  "
              f"bugs={len(found)}/10  rate={i/elapsed:>5.0f}/s")
        last_report = now


# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

elapsed = time.time() - start_time
print("\n" + "=" * 55)
print("  RESULTS SUMMARY")
print("=" * 55)
print(f"  Iterations   : {min(i, ITERATIONS):,}")
print(f"  Total crashes: {total_crashes:,}")
print(f"  Bugs found   : {len(found)}/10  →  {sorted(found)}")
print(f"  Elapsed      : {elapsed:.1f}s")
print("-" * 55)
print(f"  {'Bug #':<8} {'Triggered':<12} {'Saved File'}")
print(f"  {'-'*48}")
for n in range(1, MAX_BUGS + 1):
    count = bug_counts[n]
    fpath = f"{FOUND_DIR}/test-{n}.jpg" if n in found else "—"
    mark  = "✓" if n in found else "✗"
    print(f"  [{mark}] Bug #{n:<3}  {count:<12,}  {fpath}")
print("=" * 55)
print(f"\n[*] Trigger files saved to: {FOUND_DIR}/")
print("[*] Verify each with:  ./jpeg2bmp found/test-N.jpg out.bmp\n")