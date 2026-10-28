#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""
Offline regression tests for the physical Memory Layout builder.

These tests need no device: they feed synthetic /proc/iomem + memblock +
reserved-memory data into build_memory_layout() and assert the invariants that
keep the layout Total from exceeding the board's physical RAM.

Run:
    python tests/test_memory_layout.py
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "internal" / "snapshot-comparison" / "scripts"))
sys.path.insert(0, str(REPO / "internal" / "data-collection" / "scripts"))

import collect                                      # noqa: E402
from compare_snapshots import (                     # noqa: E402
    build_memory_layout,
    derive_dram_banks,
)

MB = 1024 * 1024

_results: list = []


def check(cond: bool, label: str) -> None:
    _results.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def iomem(name: str, start: int, end_inclusive: int, depth: int = 0) -> dict:
    return {
        "name": name,
        "start": start,
        "end": end_inclusive,
        "size_kb": (end_inclusive - start + 1) // 1024,
        "depth": depth,
    }


def total_mb(layout: list) -> float:
    return round(sum(r[3] for r in layout), 2)


# ---------------------------------------------------------------------------
# 1. memblock parsing (both kernel formats)
# ---------------------------------------------------------------------------
def test_parse_memblock_formats() -> None:
    print("\ntest_parse_memblock_formats")

    modern = (
        "   0: 0x0000000080000000..0x000000008fffffff    0 NONE\n"
        "   1: 0x0000000090000000..0x000000009fffffff    0 NOMAP\n"
    )
    p = collect.parse_memblock(modern)
    check(len(p["regions"]) == 2, "modern start..end form yields 2 regions")
    check(p["total_kb"] == 512 * 1024, f"modern total is 512 MB (got {p['total_kb']/1024} MB)")
    check(p["regions"][0]["base"] == hex(0x80000000), "modern base parsed correctly")

    legacy = (
        "   0: 0x0000000080000000 0x0000000010000000 0\n"
        "   1: 0x0000000090000000 0x0000000010000000 0\n"
    )
    p = collect.parse_memblock(legacy)
    check(len(p["regions"]) == 2, "legacy base/size form yields 2 regions")
    check(p["total_kb"] == 512 * 1024, f"legacy total is 512 MB (got {p['total_kb']/1024} MB)")

    # Header/garbage lines must be skipped, not crash or inflate the total.
    noisy = "cnt = 2\nidx base size flags\n" + modern
    p = collect.parse_memblock(noisy)
    check(p["total_kb"] == 512 * 1024, "header lines ignored")
    check(collect.parse_memblock("")["regions"] == [], "empty input yields no regions")


# ---------------------------------------------------------------------------
# 2. DRAM bank derivation
# ---------------------------------------------------------------------------
def test_derive_dram_banks() -> None:
    print("\ntest_derive_dram_banks")

    # Two banks 30 GB apart must not be merged into one span.
    regions = [
        {"base": hex(0x81A60000), "size_kb": 2 * 1024},
        {"base": hex(0x880000000), "size_kb": 1024 * 1024},
    ]
    banks = derive_dram_banks(regions, [])
    check(len(banks) == 2, f"far-apart ranges form 2 banks (got {len(banks)})")

    # Ranges separated by less than the 1 GB threshold merge into one bank.
    regions = [
        {"base": hex(0x80000000), "size_kb": 256 * 1024},
        {"base": hex(0x90000000), "size_kb": 256 * 1024},
    ]
    banks = derive_dram_banks(regions, [])
    check(len(banks) == 1, f"nearby ranges merge into 1 bank (got {len(banks)})")

    # Fallback to iomem System RAM when memblock is unavailable.
    banks = derive_dram_banks([], [iomem("System RAM", 0x80000000, 0x8FFFFFFF)])
    check(len(banks) == 1 and banks[0][0] == 0x80000000,
          "falls back to iomem System RAM when memblock missing")
    check(derive_dram_banks([], []) == [], "no data yields no banks")


# ---------------------------------------------------------------------------
# 3. PCIe / MMIO apertures must be excluded
# ---------------------------------------------------------------------------
def test_pcie_aperture_excluded() -> None:
    print("\ntest_pcie_aperture_excluded")

    # 512 MB of DRAM at 0x80000000, plus a 1 GB PCIe window far below it and a
    # peripheral register block. Only the DRAM may be counted.
    regions = [
        iomem("100000.clock-controller", 0x00100000, 0x002F8FFF),
        iomem("pci@1b40000",             0x40000000, 0x7FFFFFFF),   # 1 GB aperture
        iomem("System RAM",              0x80000000, 0x9FFFFFFF),   # 512 MB DRAM
    ]
    memblock = [{"base": hex(0x80000000), "size_kb": 512 * 1024}]
    reserved = [{"name": "hyp@80000000", "base": hex(0x80000000), "size_kb": 4 * 1024}]

    layout = build_memory_layout(regions, reserved, memblock)
    names = {r[0] for r in layout}
    check("pci@1b40000" not in names, "PCIe aperture excluded from layout")
    check("100000.clock-controller" not in names, "peripheral MMIO excluded from layout")
    check(total_mb(layout) <= 512.0,
          f"total stays within 512 MB DRAM (got {total_mb(layout)} MB)")

    # Without the fix the PCIe window alone would add 1024 MB.
    check(total_mb(layout) < 1024.0, "total not inflated by the 1 GB aperture")


# ---------------------------------------------------------------------------
# 4. Duplicate carve-outs must not be double-counted
# ---------------------------------------------------------------------------
def test_no_double_counting() -> None:
    print("\ntest_no_double_counting")

    # Real-world shape: carve-outs sit *outside* the System RAM blocks (the
    # kernel never maps them), but the same 16 MB range is described twice --
    # once as an anonymous depth-0 "reserved" region in /proc/iomem and once as
    # a named device-tree reserved-memory node. Only one row may be emitted.
    regions = [
        iomem("reserved",   0x80000000, 0x80FFFFFF),   # 16 MB, same as DT node
        iomem("System RAM", 0x81000000, 0x9FFFFFFF),   # 496 MB
    ]
    memblock = [{"base": hex(0x80000000), "size_kb": 512 * 1024}]
    reserved = [{"name": "mpss@80000000", "base": hex(0x80000000), "size_kb": 16 * 1024}]

    layout = build_memory_layout(regions, reserved, memblock)

    # No two rows may overlap.
    srt = sorted(layout, key=lambda x: (x[1], x[2]))
    overlap = 0.0
    for i in range(len(srt) - 1):
        for j in range(i + 1, len(srt)):
            if srt[j][1] >= srt[i][2]:
                break
            overlap += (min(srt[i][2], srt[j][2]) - max(srt[i][1], srt[j][1])) / MB
    check(overlap == 0.0, f"no overlapping rows (overlap={overlap:.2f} MB)")
    check(total_mb(layout) <= 512.0,
          f"total not inflated by the duplicate (got {total_mb(layout)} MB)")
    # The 16 MB appears exactly once, and as the informative named NHLOS row
    # rather than the anonymous "reserved" one.
    mpss = [r for r in layout if r[0] == "mpss"]
    check(len(mpss) == 1 and mpss[0][4] == "nhlos" and mpss[0][3] == 16.0,
          "duplicate range kept once, as the named NHLOS row")
    check(not any(r[0] == "reserved" and r[1] == 0x80000000 for r in layout),
          "anonymous duplicate not also emitted")

    # A carve-out that only *partially* overlaps an existing row must
    # contribute just its uncovered remainder.
    regions2 = [iomem("System RAM", 0x80000000, 0x9FFFFFFF)]        # 512 MB
    memblock2 = [{"base": hex(0x80000000), "size_kb": 768 * 1024}]  # 768 MB bank
    # Node spans 0x9F000000-0xA0FFFFFF: 16 MB inside System RAM, 16 MB beyond.
    reserved2 = [{"name": "ovl@9f000000", "base": hex(0x9F000000),
                  "size_kb": 32 * 1024}]
    layout2 = build_memory_layout(regions2, reserved2, memblock2)
    ovl_mb = sum(r[3] for r in layout2 if r[0] == "ovl")
    check(abs(ovl_mb - 16.0) < 0.01,
          f"partial overlap contributes only its remainder (got {ovl_mb} MB)")
    check(total_mb(layout2) <= 768.0,
          f"partial-overlap total stays within the bank (got {total_mb(layout2)} MB)")


# ---------------------------------------------------------------------------
# 5. Inter-bank holes must not become "Missing" rows
# ---------------------------------------------------------------------------
def test_interbank_gap_not_missing() -> None:
    print("\ntest_interbank_gap_not_missing")

    regions = [
        iomem("System RAM", 0x80000000, 0x8FFFFFFF),     # 256 MB
        iomem("System RAM", 0x880000000, 0x88FFFFFFF),   # 256 MB, 30 GB higher
    ]
    memblock = [
        {"base": hex(0x80000000), "size_kb": 256 * 1024},
        {"base": hex(0x880000000), "size_kb": 256 * 1024},
    ]
    reserved = [{"name": "smem@80000000", "base": hex(0x80000000), "size_kb": 2 * 1024}]

    layout = build_memory_layout(regions, reserved, memblock)
    missing = [r for r in layout if r[4] == "missing"]
    check(all(r[3] <= 1024.0 for r in missing),
          "no multi-GB Missing row emitted for the inter-bank hole")
    check(total_mb(layout) <= 512.0,
          f"total stays at the 512 MB of real DRAM (got {total_mb(layout)} MB)")


# ---------------------------------------------------------------------------
# 6. Degraded input must not crash
# ---------------------------------------------------------------------------
def test_degraded_inputs() -> None:
    print("\ntest_degraded_inputs")

    check(build_memory_layout([], [], []) == [], "empty inputs yield empty layout")

    # memblock missing -> iomem fallback still produces a bounded layout
    regions = [iomem("System RAM", 0x80000000, 0x9FFFFFFF)]
    reserved = [{"name": "hyp@80000000", "base": hex(0x80000000), "size_kb": 4 * 1024}]
    layout = build_memory_layout(regions, reserved, [])
    check(len(layout) > 0 and total_mb(layout) <= 512.0,
          f"iomem-only fallback bounded (got {total_mb(layout)} MB)")

    # Malformed reserved-memory entries are skipped rather than raising
    bad = [
        {"name": "x", "base": "not-hex", "size_kb": 4},
        {"name": "y", "base": hex(0x80000000), "size_kb": 0},
    ]
    layout = build_memory_layout(regions, bad, [])
    check(True, "malformed reserved-memory entries skipped without error")


def main() -> int:
    test_parse_memblock_formats()
    test_derive_dram_banks()
    test_pcie_aperture_excluded()
    test_no_double_counting()
    test_interbank_gap_not_missing()
    test_degraded_inputs()

    passed = sum(1 for ok, _ in _results if ok)
    failed = len(_results) - passed
    print(f"\n{'='*62}\n{passed} passed, {failed} failed, {len(_results)} total")
    if failed:
        for ok, label in _results:
            if not ok:
                print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())