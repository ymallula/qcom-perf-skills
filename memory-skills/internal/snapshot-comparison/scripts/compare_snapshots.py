#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""
snapshot-comparison -- Memory Snapshot Comparison
Compares two MemorySnapshot JSON files and computes deltas for every
memory category.

Usage:
    python compare_snapshots.py --current <snapshot.json> --reference <snapshot.json>
                                [--output-dir <dir>] [--threshold-pct 5.0]
                                [--threshold-mb 50.0]
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_snapshot(path: str) -> dict:
    """Load and validate a MemorySnapshot JSON file."""
    if not os.path.isfile(path):
        print(f"ERROR: --reference is required for comparison.\n"
              f"No baseline snapshot found at: {path}\n\n"
              f"To create a baseline, run:\n"
              f"  python data-collection/scripts/collect.py --output baseline/ --label baseline\n\n"
              f"Then re-run with:\n"
              f"  --current current/snapshot.json --reference baseline/snapshot.json\n\n"
              f"For single-snapshot analysis (no baseline needed), use:\n"
              f"  memory-map     -- physical memory breakdown\n"
              f"  nhlos-carveout-validation -- carveout size validation\n"
              f"  anomaly-rca    -- single-snapshot anomaly detection")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def get_meminfo(snap: dict, key: str, default: int = 0) -> int:
    """Safely get a meminfo value from a snapshot (in kB)."""
    src = snap.get("sources", {}).get("meminfo", {})
    if not src.get("available"):
        return default
    return src.get("parsed", {}).get(key, default)


def get_debugfs_total(snap: dict, subsystem: str) -> int:
    """Get total_kb from a debugfs subsystem."""
    src = snap.get("sources", {}).get("debugfs", {}).get(subsystem, {})
    if not src.get("available"):
        return 0
    return src.get("parsed", {}).get("total_kb", 0)


def get_cma_total(snap: dict) -> int:
    """Sum all CMA used_kb entries."""
    src = snap.get("sources", {}).get("debugfs", {}).get("cma", {})
    if not src.get("available"):
        return 0
    return sum(e.get("used_kb", 0) for e in src.get("parsed", []))


def get_nhlos_total(snap: dict) -> int:
    """Sum all reserved-memory node sizes."""
    src = snap.get("sources", {}).get("reserved_memory", {})
    if not src.get("available"):
        return 0
    return sum(n.get("size_kb", 0) for n in src.get("nodes", []))


def get_slab_total(snap: dict) -> int:
    """Sum all slab total_kb entries."""
    src = snap.get("sources", {}).get("slabinfo", {})
    if not src.get("available"):
        return get_meminfo(snap, "Slab")
    return sum(s.get("total_kb", 0) for s in src.get("parsed", []))


# ---------------------------------------------------------------------------
# Category extraction
# ---------------------------------------------------------------------------

CATEGORIES = [
    ("MemTotal",    lambda s: get_meminfo(s, "MemTotal")),
    ("MemFree",     lambda s: get_meminfo(s, "MemFree")),
    ("Slab",        lambda s: get_slab_total(s)),
    ("Vmalloc",     lambda s: get_meminfo(s, "VmallocUsed")),
    ("PageTables",  lambda s: get_meminfo(s, "PageTables")),
    ("KernelStack", lambda s: get_meminfo(s, "KernelStack")),
    ("AnonPages",   lambda s: get_meminfo(s, "AnonPages")),
    ("Shmem",       lambda s: get_meminfo(s, "Shmem")),
    ("Cached",      lambda s: get_meminfo(s, "Cached")),
    ("Buffers",     lambda s: get_meminfo(s, "Buffers")),
    ("SwapCached",  lambda s: get_meminfo(s, "SwapCached")),
    ("DMA-BUF",     lambda s: get_debugfs_total(s, "dmabuf")),
    ("KGSL",        lambda s: get_debugfs_total(s, "kgsl")),
    ("CMA Used",    lambda s: get_cma_total(s)),
    ("NHLOS Total", lambda s: get_nhlos_total(s)),
]


def _classify_sub_region(name: str) -> str:
    """
    Classify a named sub-region (either a depth>0 /proc/iomem entry nested
    inside a System RAM block, or a depth-0 non-"System RAM" entry that
    falls within the physical RAM address range) into one of two distinct
    UI-filterable categories:
      - "kernel":   actual kernel code/data sections (e.g. "Kernel code",
                    "Kernel data") -- static kernel image footprint.
      - "reserved": generic anonymous "reserved" carve-outs that the kernel
                    doesn't attribute to any specific subsystem (these sit
                    between DDR sub-blocks and are distinct from named NHLOS
                    device-tree carve-outs).
    """
    lname = name.lower()
    if lname.startswith("kernel"):
        return "kernel"
    return "reserved"


# Gaps larger than this are treated as non-populated address space between
# separate DRAM banks/channels rather than unaccounted ("Missing") memory.
GAP_THRESHOLD_MB = 1024.0
_DRAM_BANK_SPLIT_BYTES = int(GAP_THRESHOLD_MB) * 1024 * 1024


def derive_dram_banks(memblock_regions: list, iomem_regions: list,
                      reserved_regions: list | None = None) -> list:
    """
    Determine the physical DRAM bank address ranges for the board.

    /proc/iomem describes the *entire* SoC physical address space -- DRAM,
    peripheral MMIO register windows, and (critically) large PCIe BAR/ECAM
    apertures that can be hundreds of MB or several GB wide. Those apertures
    are address space, not memory, so they must never be folded into the
    physical memory map.

    The authoritative list of populated DRAM is memblock's "memory" list
    (/sys/kernel/debug/memblock/memory), so prefer it. Fall back to the
    extents of /proc/iomem's depth-0 "System RAM" entries when memblock is
    unavailable (e.g. debugfs not mounted).

    IMPORTANT: memblock's "memory" list only contains regions the kernel's
    page allocator actually knows about. Device-tree reserved-memory nodes
    marked "no-map" (e.g. the TrustZone "hyp" region, often the very first
    carve-out at the bottom of DRAM, such as hyp@0x80000000) are deliberately
    kept OUT of memblock because the kernel must never touch them -- but they
    are still physically part of DRAM. Without folding their address ranges
    into the bank spans below, the lowest "no-map" carve-outs would fall
    outside every derived bank and get silently dropped by _in_dram(),
    making the reported Memory Layout appear to start several hundred KB/MB
    above the board's true DRAM base (e.g. 0x80700000 instead of 0x80000000).
    To avoid this, the reserved-memory node spans are merged in alongside
    the memblock/iomem spans before bank boundaries are computed.

    Returns a list of [start, end) byte ranges, each one contiguous DRAM
    bank, sorted by start address.
    """
    spans: list = []
    for r in memblock_regions or []:
        try:
            base = r.get("base")
            base_int = int(base, 16) if isinstance(base, str) else int(base)
            size_bytes = int(r.get("size_kb", 0)) * 1024
        except (TypeError, ValueError):
            continue
        if size_bytes > 0:
            spans.append((base_int, base_int + size_bytes))

    if not spans:
        # Fallback: use the System RAM entries that /proc/iomem reports.
        for r in iomem_regions or []:
            if r.get("depth", 0) == 0 and r.get("name") == "System RAM":
                spans.append((r["start"], r["end"] + 1))

    # Fold in device-tree reserved-memory carve-outs (including "no-map"
    # regions that memblock never sees) so they anchor/extend the DRAM bank
    # boundaries instead of being excluded from them.
    for r in reserved_regions or []:
        try:
            base = r.get("base")
            base_int = int(base, 16) if isinstance(base, str) else int(base)
            size_bytes = int(r.get("size_kb", 0)) * 1024
        except (TypeError, ValueError):
            continue
        if size_bytes > 0:
            spans.append((base_int, base_int + size_bytes))

    if not spans:
        return []

    spans.sort()
    banks: list = []
    for start, end in spans:
        # Merge into the current bank when the hole before it is small enough
        # to be an intra-bank carve-out rather than a separate DRAM interface.
        if banks and start - banks[-1][1] <= _DRAM_BANK_SPLIT_BYTES:
            banks[-1][1] = max(banks[-1][1], end)
        else:
            banks.append([start, end])
    return banks


def build_memory_layout(iomem_regions: list, reserved_regions: list,
                        memblock_regions: list | None = None) -> list:
    """
    Build the physical memory layout (System RAM blocks, kernel code/data
    sections, generic reserved sub-regions from /proc/iomem, and NHLOS
    carve-outs from device-tree reserved-memory nodes), filling address
    gaps with "Missing" entries.

    Every emitted row is constrained to lie inside a real DRAM bank (see
    derive_dram_banks), so the layout's Total reflects the board's physical
    RAM and never includes PCIe/MMIO address-space apertures.

    Returns list of (name, start, end, size_mb, region_type) tuples sorted
    by start address. region_type is one of:
      sysram, kernel, reserved, nhlos, missing.
    These five types map 1:1 to the five filterable categories shown in
    the unified report's "Memory Layout" section.
    """
    layout: list = []

    dram_banks = derive_dram_banks(memblock_regions or [], iomem_regions,
                                   reserved_regions)

    def _in_dram(start: int, end: int) -> bool:
        """True when [start, end) lies wholly inside a single DRAM bank."""
        if not dram_banks:
            return True
        return any(start >= b[0] and end <= b[1] for b in dram_banks)

    # Running set of address ranges already represented by a row. Every row is
    # emitted through _add() so no byte of physical memory is ever counted
    # twice, regardless of how many kernel sources describe the same range.
    _covered: list = []

    def _uncovered(start: int, end: int) -> list:
        """Return [start, end) minus every range already emitted."""
        gaps = [(start, end)]
        for cs, ce in _covered:
            if not gaps:
                break
            nxt = []
            for gs, ge in gaps:
                if ce <= gs or cs >= ge:
                    nxt.append((gs, ge))
                    continue
                if cs > gs:
                    nxt.append((gs, min(cs, ge)))
                if ce < ge:
                    nxt.append((max(ce, gs), ge))
            gaps = nxt
        return gaps

    def _add(name: str, start: int, end: int, region_type: str,
             require_dram: bool = True) -> None:
        """Emit rows for the not-yet-covered parts of [start, end)."""
        if end <= start:
            return
        if require_dram and not _in_dram(start, end):
            return
        for gs, ge in _uncovered(start, end):
            # Decide on the RAW byte span, not the MB-rounded display value.
            # A sub-MB range (as small as a single 4 KB page) rounds to
            # "0.00" MB -- testing `size_mb <= 0` on that rounded value
            # silently discards a genuinely nonzero range of physical
            # memory, making it vanish from the layout entirely (not even
            # emitted as a 0.00 MB row) with no corresponding reduction in
            # the reported Total RAM. Comparing the unrounded byte span
            # instead ensures every real range is represented.
            if ge <= gs:
                continue
            size_mb = round((ge - gs) / 1024 / 1024, 2)
            layout.append((name, gs, ge, size_mb, region_type))
            _covered.append((gs, ge))
        _covered.sort()

    # depth > 0 iomem entries are sub-regions reserved *within* a System RAM
    # block (e.g. "Kernel code", "Kernel data", generic "reserved", etc.)
    sub_entries = [
        (r["name"], r["start"], r["end"] + 1,
         round((r["end"] - r["start"] + 1) / 1024 / 1024, 2))
        for r in iomem_regions if r.get("depth", 0) > 0
    ]

    for r in iomem_regions:
        if r.get("name") != "System RAM" or r.get("depth", 0) != 0:
            continue
        block_start = r["start"]
        block_end   = r["end"] + 1
        if not _in_dram(block_start, block_end):
            continue

        block_subs = sorted(
            [(n, s, e, mb) for n, s, e, mb in sub_entries
             if s >= block_start and e <= block_end],
            key=lambda x: x[1],
        )

        if not block_subs:
            _add("System RAM", block_start, block_end, "sysram")
        else:
            prev = block_start
            for name, s, e, mb in block_subs:
                if s > prev:
                    _add("System RAM", prev, s, "sysram")
                _add(name, s, e, _classify_sub_region(name))
                prev = e
            if prev < block_end:
                _add("System RAM", prev, block_end, "sysram")

    # NHLOS carve-outs from device-tree reserved-memory nodes. These normally
    # sit *outside* the System RAM blocks (the kernel never sees them), but a
    # node that does overlap an already-emitted range contributes only its
    # uncovered remainder so the total cannot be inflated.
    for r in reserved_regions:
        base = r.get("base")
        try:
            base_int = int(base, 16) if isinstance(base, str) else int(base)
        except (TypeError, ValueError):
            continue
        size_kb = r.get("size_kb", 0)
        size_bytes = size_kb * 1024
        if size_bytes <= 0:
            continue
        # A carve-out described in the device tree but not backed by a
        # populated DRAM bank is not part of this board's memory map.
        _add(r.get("name", "?").split("@")[0], base_int, base_int + size_bytes,
             "nhlos")

    if not layout:
        return layout

    # Depth-0 iomem entries that are NOT "System RAM" (typically named
    # "reserved") but that fall inside a populated DRAM bank are real
    # carve-outs living between System RAM blocks (e.g.
    # "acb00000-acffffff : reserved" between two DDR sub-regions). These
    # are added as "kernel"/"reserved" entries (classified the same way as
    # depth>0 sub-entries) so the physical map reflects what the kernel
    # actually reports for that range instead of treating it as an unnamed
    # "Missing" gap.
    #
    # Everything NOT inside a DRAM bank is address space rather than
    # memory -- peripheral MMIO register blocks (clock controllers,
    # I2C/SPI/UART, GIC, pinctrl, ...) and, most importantly, the large
    # PCIe BAR/ECAM apertures which can be 512 MB-1 GB+ each. Including
    # those would inflate the layout Total well past the board's physical
    # RAM, so they are excluded entirely by _in_dram().
    #
    # Critically, the kernel reports most device-tree carve-outs *twice*:
    # once as an anonymous depth-0 "reserved" range in /proc/iomem and
    # again as a named node under /sys/.../reserved-memory (already added
    # above as "nhlos"). Emitting both would double-count that memory and
    # push the layout Total above the board's real RAM size. The named
    # NHLOS row is the more informative of the two, so _add() contributes
    # only the portions of each anonymous range that are not already covered.
    for r in iomem_regions:
        if r.get("depth", 0) != 0 or r.get("name") == "System RAM":
            continue
        name = r.get("name", "reserved")
        _add(name, r["start"], r["end"] + 1, _classify_sub_region(name))

    layout.sort(key=lambda x: x[1])

    # Address gaps between adjacent regions are only meaningful ("missing" /
    # unaccounted memory) when they are small -- comparable in size to a
    # single carve-out. Many Qualcomm SoCs place a second DDR bank/channel
    # at a much higher physical address (e.g. 0xA_00000000), tens of GB
    # away from the first bank. The resulting address-space "hole" between
    # the two banks is NOT missing/unaccounted memory -- it's simply
    # non-populated address space between separate DRAM interfaces, so it
    # must not be reported as a "Missing" carve-out row (which would both
    # alarm the reader and, if summed, wildly inflate the layout's total).
    #
    # Heuristic: drop any gap larger than GAP_THRESHOLD_MB (module-level
    # constant). Real unaccounted carve-outs on these platforms are at most
    # tens/low-hundreds of MB; inter-bank/channel holes are multiple GB, so
    # a 1024 MB (1 GB) cutoff cleanly separates the two cases without
    # needing SoC-specific tables. A gap that spans two different DRAM
    # banks is never reported regardless of size.
    filled: list = []
    prev_end = layout[0][1]
    for entry in layout:
        name, start, end, size_mb, region_type = entry
        if start > prev_end:
            # Compare the RAW byte gap against the threshold, not the
            # MB-rounded value. A gap under ~5 KB rounds to "0.00" MB and
            # fails `0 < gap_mb`, which silently drops a genuinely
            # unaccounted range of physical memory from the layout instead
            # of reporting it as a (small) "Missing" row -- the exact kind
            # of sub-pixel gap this fallback exists to catch.
            gap_bytes = start - prev_end
            gap_mb = round(gap_bytes / 1024 / 1024, 2)
            if gap_bytes <= _DRAM_BANK_SPLIT_BYTES and _in_dram(prev_end, start):
                filled.append(("Missing", prev_end, start, gap_mb, "missing"))
            # gaps > GAP_THRESHOLD_MB, or gaps that are not backed by a
            # populated DRAM bank, are non-populated address space --
            # silently skipped (not part of the physical memory map).
        filled.append(entry)
        if end > prev_end:
            prev_end = end

    return filled


def compute_summary_table(snap: dict) -> dict:
    """
    Compute the hierarchical memory summary table from a snapshot.
    Returns values in kB.
    """
    mem = snap.get("sources", {}).get("meminfo", {})
    parsed = mem.get("parsed", {}) if mem.get("available") else {}

    # System RAM from iomem ranges
    system_ram_kb = 0
    iomem = snap.get("sources", {}).get("iomem", {})
    if iomem.get("available"):
        for r in iomem.get("parsed", {}).get("system_ram_ranges", []):
            try:
                start = int(r["start"], 16)
                end   = int(r["end"], 16)
                system_ram_kb += (end - start + 1) // 1024
            except (ValueError, KeyError):
                pass
    if system_ram_kb == 0:
        system_ram_kb = parsed.get("MemTotal", 0)

    # NHLOS from reserved_memory nodes
    nhlos_kb = 0
    rm = snap.get("sources", {}).get("reserved_memory", {})
    if rm.get("available"):
        nhlos_kb = sum(n.get("size_kb", 0) for n in rm.get("nodes", []))

    # Round Total RAM up to next 1 GB boundary (same as memory-map skill)
    # This accounts for the unaccounted NHLOS gap between named carveouts and actual NHLOS
    one_gb_kb    = 1024 * 1024
    import math
    raw_total_kb = system_ram_kb + nhlos_kb
    total_ram_kb = math.ceil(raw_total_kb / one_gb_kb) * one_gb_kb if raw_total_kb > 0 else 0

    # Actual NHLOS = Total RAM - System RAM (includes unaccounted gap)
    nhlos_kb     = total_ram_kb - system_ram_kb

    mem_total_kb     = parsed.get("MemTotal", 0)
    kernel_static_kb = max(0, system_ram_kb - mem_total_kb)

    # If iomem gave us no useful System RAM range (all-zero addresses, restricted
    # on non-root SSH), system_ram_kb falls back to MemTotal and kernel_static_kb
    # becomes 0. In that case, estimate kernel_static from dmesg vmlinux data.
    _iomem_fallback = (system_ram_kb == mem_total_kb)

    # DMA-BUF and KGSL (must be defined before KDA formula)
    debugfs = snap.get("sources", {}).get("debugfs", {})
    dmabuf_kb = debugfs.get("dmabuf", {}).get("parsed", {}).get("total_kb", 0) \
                if debugfs.get("dmabuf", {}).get("available") else 0
    kgsl_kb   = debugfs.get("kgsl", {}).get("parsed", {}).get("total_kb", 0) \
                if debugfs.get("kgsl", {}).get("available") else 0

    # CMA used (from debugfs cma)
    cma_src = snap.get("sources", {}).get("debugfs", {}).get("cma", {})
    cma_kb = sum(e.get("used_kb", 0) for e in cma_src.get("parsed", [])) \
             if cma_src.get("available") else 0

    # Modules size (from /proc/modules -- now correctly parsed as {total_kb, modules})
    modules_src = snap.get("sources", {}).get("modules", {})
    modules_kb = 0
    if modules_src and modules_src.get("available"):
        parsed_mods = modules_src.get("parsed", {})
        if isinstance(parsed_mods, dict):
            modules_kb = parsed_mods.get("total_kb", 0)
        elif isinstance(parsed_mods, list):
            # Legacy format: list of dicts
            for mod in parsed_mods:
                if isinstance(mod, dict):
                    modules_kb += mod.get("size_kb", 0)

    # KDA = MemTotal - Total_Free - all named categories
    # (residual unaccounted kernel dynamic memory, aligned with reference quickmap.py)
    total_free_kb = (
        parsed.get("MemFree", 0) +
        parsed.get("Cached", 0) +
        parsed.get("Buffers", 0) +
        parsed.get("SwapCached", 0)
    )
    kda_kb = max(0, (
        mem_total_kb
        - total_free_kb
        - parsed.get("Slab", 0)
        - parsed.get("VmallocUsed", 0)
        - parsed.get("KernelStack", 0)
        - parsed.get("PageTables", 0)
        - parsed.get("Percpu", 0)
        - parsed.get("SecPageTables", 0)
        - cma_kb
        - modules_kb
        - parsed.get("AnonPages", 0)
        - parsed.get("Shmem", 0)
        - dmabuf_kb
        - kgsl_kb
    ))

    # Kernel Dynamic = named categories + Modules + CMA + KDA (residual)
    kernel_dynamic_kb = (
        parsed.get("Slab", 0) +
        parsed.get("VmallocUsed", 0) +
        parsed.get("KernelStack", 0) +
        parsed.get("PageTables", 0) +
        parsed.get("Percpu", 0) +
        parsed.get("SecPageTables", 0) +
        modules_kb +
        cma_kb +
        kda_kb
    )

    # User Space Apps = AnonPages + Shmem (process-owned memory)
    user_space_kb = (
        parsed.get("AnonPages", 0) +
        parsed.get("Shmem", 0)
    )

    # Hardware / Driver Buffers = DMA-BUF + KGSL (kernel-driver managed, not in process address space)
    hw_driver_kb = dmabuf_kb + kgsl_kb

    # Total Available = MemFree + Cached + Buffers
    total_available_kb = (
        parsed.get("MemFree", 0) +
        parsed.get("Cached", 0) +
        parsed.get("Buffers", 0)
    )

    # Kernel Static breakdown
    # Source priority:
    # 1. dmesg Memory line (vmlinux, page_structs) -- older kernels
    # 2. /proc/iomem Kernel code/data sections (vmlinux) -- newer kernels
    # 3. Estimate page structs from System RAM (1 struct page per 4KB = 64 bytes)
    dmesg = snap.get("sources", {}).get("dmesg", {})
    iomem_src = snap.get("sources", {}).get("iomem", {})

    vmlinux_kb = 0
    page_structs_kb = 0
    hash_tables_kb = 0

    if dmesg.get("available"):
        d = dmesg.get("parsed", {})
        vmlinux_kb      = d.get("vmlinux_total_kb", 0)
        page_structs_kb = d.get("page_structs_kb", 0)
        hash_tables_kb  = d.get("hash_tables_kb", 0)
        # Note: hash_tables_kb may be 0 if dmesg ring buffer was overwritten
        # (early boot messages pushed out by runtime messages).
        # Hash tables are a boot-time constant -- store for cross-snapshot use.

    # Fallback: get vmlinux from /proc/iomem Kernel code + Kernel data
    if vmlinux_kb == 0 and iomem_src.get("available"):
        iomem_text = ""
        iomem_path = iomem_src.get("path", "")
        if iomem_path and os.path.isfile(iomem_path):
            try:
                iomem_text = open(iomem_path, encoding="utf-8", errors="replace").read()
            except OSError:
                pass
        if iomem_text:
            import re as _re
            for line in iomem_text.splitlines():
                m = _re.match(r"\s*([0-9a-f]+)-([0-9a-f]+)\s*:\s*(Kernel\s+\w+)", line, _re.I)
                if m:
                    size_kb = (int(m.group(2), 16) - int(m.group(1), 16) + 1) // 1024
                    label = m.group(3).lower()
                    if "code" in label or "data" in label:
                        vmlinux_kb += size_kb

    # Fallback: estimate page structs from System RAM
    # Each 4KB page needs one struct page (64 bytes) = 16 pages per MB
    # page_structs = system_ram_kb / 4 * 64 / 1024 = system_ram_kb / 64
    if page_structs_kb == 0 and system_ram_kb > 0:
        page_structs_kb = system_ram_kb // 64  # 64 bytes per struct page, 4KB pages

    # When iomem addresses are all-zero (non-root SSH restriction), kernel_static_kb
    # is 0 because system_ram_kb == MemTotal. Use dmesg vmlinux data as the estimate.
    if _iomem_fallback and kernel_static_kb == 0 and vmlinux_kb > 0:
        kernel_static_kb = vmlinux_kb + page_structs_kb + hash_tables_kb

    if vmlinux_kb > 0 or page_structs_kb > 0 or hash_tables_kb > 0:
        kernel_static_breakdown = {
            "Vmlinux":      vmlinux_kb,
            "Page Structs": page_structs_kb,
            "Hash Tables":  hash_tables_kb,
        }
        accounted = vmlinux_kb + page_structs_kb + hash_tables_kb
        kernel_static_breakdown["Early Boot Reservations"] = max(0, kernel_static_kb - accounted)
    else:
        kernel_static_breakdown = {}

    # NHLOS per-carveout breakdown
    nhlos_nodes = []
    if rm.get("available"):
        nhlos_nodes = [
            {"name": n.get("name", "?"), "size_kb": n.get("size_kb", 0)}
            for n in rm.get("nodes", [])
        ]

    # Kernel Dynamic breakdown (includes Modules, CMA and KDA)
    kernel_dynamic_breakdown = {
        "Slab":          parsed.get("Slab", 0),
        "Vmalloc":       parsed.get("VmallocUsed", 0),
        "KernelStack":   parsed.get("KernelStack", 0),
        "PageTables":    parsed.get("PageTables", 0),
        "Percpu":        parsed.get("Percpu", 0),
        "SecPageTables": parsed.get("SecPageTables", 0),
        "Modules":       modules_kb,
        "CMA":           cma_kb,
        "KDA":           kda_kb,
    }

    # User Space breakdown (process-owned)
    user_space_breakdown = {
        "AnonPages": parsed.get("AnonPages", 0),
        "Shmem":     parsed.get("Shmem", 0),
    }

    # Hardware / Driver Buffers breakdown (with DMA-BUF per-exporter + size groups)
    dmabuf_by_exporter = {}
    dmabuf_by_exporter_detail = {}
    if debugfs.get("dmabuf", {}).get("available"):
        parsed_dmabuf = debugfs.get("dmabuf", {}).get("parsed", {})
        raw = parsed_dmabuf.get("by_allocator", {})
        # Sort by size descending, keep top 10
        dmabuf_by_exporter = dict(
            sorted(raw.items(), key=lambda x: x[1], reverse=True)[:10]
        )
        # Per-exporter size-grouped detail (size_kb × count = total_kb)
        dmabuf_by_exporter_detail = parsed_dmabuf.get("by_exporter_detail", {})

    hw_driver_breakdown = {
        "DMA-BUF":                   dmabuf_kb,
        "DMA-BUF_exporters":         dmabuf_by_exporter,
        "DMA-BUF_exporter_detail":   dmabuf_by_exporter_detail,
        "KGSL":                      kgsl_kb,
    }

    # Top processes by PSS (from procrank -- for standalone report)
    top_processes = []
    ps_src = snap.get("sources", {}).get("process_stats", {})
    if ps_src.get("available"):
        procs = ps_src.get("parsed", [])
        top_processes = sorted(
            [{"name": p.get("name", ""), "pss_kb": p.get("pss_kb", 0),
              "vss_kb": p.get("vss_kb", 0), "rss_kb": p.get("rss_kb", 0)}
             for p in procs if p.get("pss_kb", 0) > 0],
            key=lambda x: x["pss_kb"], reverse=True
        )[:15]

    # Physical Memory Layout (System RAM blocks, kernel-reserved sub-regions,
    # and NHLOS carve-outs) -- from /proc/iomem regions and device-tree
    # reserved-memory nodes, mirroring the reference memmap_Parser.py MemoryLayout sheet.
    # memblock's "memory" list is the authoritative set of populated DRAM
    # banks and is used to exclude PCIe/MMIO address-space apertures from
    # the physical memory map (see derive_dram_banks).
    memory_layout = []
    iomem_regions = iomem.get("parsed", {}).get("regions", []) if iomem.get("available") else []
    reserved_nodes = rm.get("nodes", []) if rm.get("available") else []
    memblock_src = snap.get("sources", {}).get("memblock", {})
    memblock_regions = (memblock_src.get("parsed", {}) or {}).get("regions", []) \
        if memblock_src.get("available") else []
    if iomem_regions and reserved_nodes:
        memory_layout = build_memory_layout(iomem_regions, reserved_nodes,
                                            memblock_regions)

    return {
        "total_ram_kb":                total_ram_kb,
        "system_ram_kb":               system_ram_kb,
        "nhlos_kb":                    nhlos_kb,
        "nhlos_nodes":                 nhlos_nodes,
        "kernel_static_kb":            kernel_static_kb,
        "kernel_static_breakdown":     kernel_static_breakdown,
        "kernel_dynamic_kb":           kernel_dynamic_kb,
        "kernel_dynamic_breakdown":    kernel_dynamic_breakdown,
        "user_space_kb":               user_space_kb,
        "user_space_breakdown":        user_space_breakdown,
        "hw_driver_kb":                hw_driver_kb,
        "hw_driver_breakdown":         hw_driver_breakdown,
        "total_available_kb":          total_available_kb,
        "total_available_breakdown": {
            "MemFree":  parsed.get("MemFree", 0),
            "Cached":   parsed.get("Cached", 0),
            "Buffers":  parsed.get("Buffers", 0),
        },
        "top_processes":               top_processes,
        "memory_layout":               memory_layout,
    }


def compute_categories(cur: dict, ref: dict,
                        threshold_pct: float, threshold_mb: float) -> list:
    """Compute delta for every memory category."""
    results = []
    for name, extractor in CATEGORIES:
        ref_kb = extractor(ref)
        cur_kb = extractor(cur)
        delta_kb = cur_kb - ref_kb
        if ref_kb > 0:
            delta_pct = round((delta_kb / ref_kb) * 100, 2)
        else:
            delta_pct = 0.0
        if delta_pct > threshold_pct:
            trend = "GROWING"
        elif delta_pct < -threshold_pct:
            trend = "SHRINKING"
        else:
            trend = "STABLE"
        results.append({
            "category": name,
            "reference_kb": ref_kb,
            "current_kb": cur_kb,
            "delta_kb": delta_kb,
            "delta_pct": delta_pct,
            "trend": trend,
        })
    return results


def compute_findings(categories: list, threshold_mb: float) -> list:
    """Generate findings for significant changes."""
    findings = []
    for cat in categories:
        abs_delta_mb = abs(cat["delta_kb"]) / 1024
        if cat["trend"] == "GROWING" and abs_delta_mb >= threshold_mb:
            findings.append({
                "severity": "WARNING",
                "message": (
                    f"{cat['category']} grew by {abs_delta_mb:.1f} MB "
                    f"({cat['delta_pct']:+.1f}%) since baseline"
                ),
            })
        elif cat["trend"] == "SHRINKING" and abs_delta_mb >= threshold_mb:
            findings.append({
                "severity": "INFO",
                "message": (
                    f"{cat['category']} reduced by {abs_delta_mb:.1f} MB "
                    f"({cat['delta_pct']:+.1f}%) since baseline"
                ),
            })
    return findings


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def write_json(report: dict, output_dir: str):
    path = os.path.join(output_dir, "snapshot_comparison_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[snapshot-comparison] JSON  -> {path}")


def write_txt(report: dict, output_dir: str):
    path = os.path.join(output_dir, "snapshot_comparison_report.txt")
    lines = [
        "Memory Snapshot Comparison Report",
        "=" * 70,
        f"Current:   {report['current_label']} ({report['current_snapshot_id'][:8]}...)",
        f"Reference: {report['reference_label']} ({report['reference_snapshot_id'][:8]}...)",
        "",
        f"{'Category':<20} {'Reference MB':>14} {'Current MB':>12} {'Delta MB':>10} {'Delta %':>9} {'Trend':<12}",
        "-" * 80,
    ]
    for cat in report["categories"]:
        trend_sym = {"GROWING": "^", "SHRINKING": "v", "STABLE": "-"}.get(cat["trend"], "")
        lines.append(
            f"{cat['category']:<20} "
            f"{cat['reference_kb']/1024:>14.1f} "
            f"{cat['current_kb']/1024:>12.1f} "
            f"{cat['delta_kb']/1024:>+10.1f} "
            f"{cat['delta_pct']:>+9.1f}% "
            f"{trend_sym} {cat['trend']}"
        )
    if report["findings"]:
        lines += ["", "Findings:", "-" * 40]
        for f in report["findings"]:
            lines.append(f"  [{f['severity']}] {f['message']}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"[snapshot-comparison] TXT   -> {path}")


def write_html(report: dict, output_dir: str):
    path = os.path.join(output_dir, "snapshot_comparison_report.html")
    rows = ""
    for cat in report["categories"]:
        delta_mb = cat["delta_kb"] / 1024
        color = ""
        if cat["trend"] == "GROWING":
            color = "background:#ffe0e0"
        elif cat["trend"] == "SHRINKING":
            color = "background:#e0ffe0"
        rows += (
            f"<tr style='{color}'>"
            f"<td>{cat['category']}</td>"
            f"<td style='text-align:right'>{cat['reference_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{cat['current_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{delta_mb:+.1f}</td>"
            f"<td style='text-align:right'>{cat['delta_pct']:+.1f}%</td>"
            f"<td>{cat['trend']}</td>"
            f"</tr>\n"
        )
    findings_html = ""
    for f in report["findings"]:
        color = "#ffe0e0" if f["severity"] == "WARNING" else "#fff8e0"
        findings_html += f"<li style='background:{color};padding:4px'>[{f['severity']}] {f['message']}</li>\n"

    html = f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'>
<title>Memory Snapshot Comparison</title>
<style>body{{font-family:monospace;margin:20px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccc;padding:6px 10px}}
th{{background:#f0f0f0}}</style></head>
<body>
<h1>Memory Snapshot Comparison</h1>
<p><b>Current:</b> {report['current_label']} &nbsp;|&nbsp;
   <b>Reference:</b> {report['reference_label']}</p>
<table>
<tr><th>Category</th><th>Reference MB</th><th>Current MB</th>
    <th>Delta MB</th><th>Delta %</th><th>Trend</th></tr>
{rows}
</table>
{'<h2>Findings</h2><ul>' + findings_html + '</ul>' if findings_html else ''}
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"[snapshot-comparison] HTML  -> {path}")


def write_xlsx(report: dict, output_dir: str):
    try:
        import openpyxl
        from openpyxl.styles import PatternFill, Font
    except ImportError:
        print("[snapshot-comparison] openpyxl not installed -- skipping XLSX")
        return
    path = os.path.join(output_dir, "snapshot_comparison_report.xlsx")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Comparison"
    headers = ["Category", "Reference MB", "Current MB", "Delta MB", "Delta %", "Trend"]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for cat in report["categories"]:
        ws.append([
            cat["category"],
            round(cat["reference_kb"] / 1024, 2),
            round(cat["current_kb"] / 1024, 2),
            round(cat["delta_kb"] / 1024, 2),
            cat["delta_pct"],
            cat["trend"],
        ])
        row = ws.max_row
        if cat["trend"] == "GROWING":
            fill = PatternFill("solid", fgColor="FFE0E0")
        elif cat["trend"] == "SHRINKING":
            fill = PatternFill("solid", fgColor="E0FFE0")
        else:
            fill = None
        if fill:
            for cell in ws[row]:
                cell.fill = fill
    wb.save(path)
    print(f"[snapshot-comparison] XLSX  -> {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Compare two MemorySnapshot JSON files."
    )
    parser.add_argument("--current", required=True,
                        help="Current snapshot.json (state to analyze)")
    parser.add_argument("--reference", required=True,
                        help="Reference snapshot.json (baseline)")
    parser.add_argument("--output-dir", default=".",
                        help="Output directory for reports (default: .)")
    parser.add_argument("--threshold-pct", type=float, default=5.0,
                        help="Delta %% threshold for GROWING/SHRINKING (default: 5.0)")
    parser.add_argument("--threshold-mb", type=float, default=50.0,
                        help="Absolute delta MB threshold for findings (default: 50.0)")
    parser.add_argument("--usecase-name", default="",
                        help="Use-case preset name (e.g. camera_preview_vhdr)")
    parser.add_argument("--usecase-command", default="",
                        help="Shell command that was run on the device for this use-case")
    parser.add_argument("--format", default="json",
                        help="Comma-separated output formats: json,txt,html,xlsx (default: json)")
    args = parser.parse_args()

    cur = load_snapshot(args.current)
    ref = load_snapshot(args.reference)

    os.makedirs(args.output_dir, exist_ok=True)

    categories = compute_categories(cur, ref, args.threshold_pct, args.threshold_mb)
    findings = compute_findings(categories, args.threshold_mb)

    growers = sorted(
        [c for c in categories if c["trend"] == "GROWING"],
        key=lambda x: x["delta_kb"], reverse=True
    )[:5]
    reducers = sorted(
        [c for c in categories if c["trend"] == "SHRINKING"],
        key=lambda x: x["delta_kb"]
    )[:5]

    ref_st = compute_summary_table(ref)
    cur_st = compute_summary_table(cur)

    # Fix: Hash Tables are a boot-time constant. If the current snapshot's dmesg
    # ring buffer was overwritten (hash_tables_kb = 0) but the reference has a
    # valid value, propagate the reference value to the current snapshot.
    ref_ks = ref_st.get("kernel_static_breakdown", {})
    cur_ks = cur_st.get("kernel_static_breakdown", {})
    if (ref_ks.get("Hash Tables", 0) > 0 and cur_ks.get("Hash Tables", 0) == 0
            and cur_ks):
        ref_hash = ref_ks["Hash Tables"]
        cur_ks["Hash Tables"] = ref_hash
        # Reduce Early Boot Reservations by the same amount (it was inflated)
        cur_ks["Early Boot Reservations"] = max(
            0, cur_ks.get("Early Boot Reservations", 0) - ref_hash
        )
        cur_st["kernel_static_breakdown"] = cur_ks

    # Include device info from current snapshot for report header
    device_info = cur.get("device", {})
    device_info["captured_at"] = cur.get("timestamp", "")[:19].replace("T", " ") + " UTC"

    report = {
        "schema_version": "1.0.0",
        "current_snapshot_id": cur.get("snapshot_id", ""),
        "reference_snapshot_id": ref.get("snapshot_id", ""),
        "current_label": cur.get("label", "current"),
        "reference_label": ref.get("label", "reference"),
        "usecase_name": args.usecase_name,
        "usecase_command": args.usecase_command,
        "device": device_info,
        "summary_table": {
            "reference": ref_st,
            "current":   cur_st,
        },
        "categories": categories,
        "top_growers": [
            {"category": c["category"], "delta_kb": c["delta_kb"], "delta_pct": c["delta_pct"]}
            for c in growers
        ],
        "top_reducers": [
            {"category": c["category"], "delta_kb": c["delta_kb"], "delta_pct": c["delta_pct"]}
            for c in reducers
        ],
        "findings": findings,
    }

    fmts = {f.strip().lower() for f in args.format.split(",")}
    if "json" in fmts:
        write_json(report, args.output_dir)
    if "txt" in fmts:
        write_txt(report, args.output_dir)
    if "html" in fmts:
        write_html(report, args.output_dir)
    if "xlsx" in fmts:
        write_xlsx(report, args.output_dir)

    print(f"\n[snapshot-comparison] {len(growers)} grower(s), "
          f"{len(reducers)} reducer(s), {len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())