#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
# =============================================================================
# Skill        : ipcat-memory-layout
# Display Name : IPCat Memory Layout Comparison
# Version      : 0.0.1
# Platform     : Qualcomm Linux
# Description  : Compares the device's physical memory layout (collected from
#                a device dump via internal/data-collection and
#                internal/snapshot-comparison) against the IP Catalog (IPCat)
#                reference memory map for the matching chip, fetched through
#                the `ipcat-mcp-server` MCP server.
#
#                This script does NOT call the MCP server itself -- MCP tools
#                are only reachable from the AI agent session. Instead, the
#                agent fetches the IPCat region list (see README.md in this
#                directory for the exact MCP tool sequence) and saves it to a
#                normalized JSON file. This script then loads that file plus
#                the device's collected memory layout and produces the
#                IPCatLayoutReport JSON consumed by report-generation.
#
# Usage:
#   python scripts/ipcat_layout.py --ipcat ipcat_layout.json \
#                                   --target snapshot.json \
#                                   --output-dir reports/
#
#   # --target may be any of:
#   #   - snapshot.json                    (raw MemorySnapshot, device info only)
#   #   - snapshot_comparison_report.json  (preferred -- has memory_layout)
#   #   - a raw memory_layout.json list
# =============================================================================

import argparse
import json
import os
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def _to_int(value) -> int | None:
    """Parse an address/size value that may be int, hex string, or decimal string."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        try:
            if v.lower().startswith("0x"):
                return int(v, 16)
            # Heuristic: IP Catalog addresses are usually given in hex even
            # without a 0x prefix when they contain a-f; decimal otherwise.
            if re.fullmatch(r"[0-9a-fA-F]+", v) and re.search(r"[a-fA-F]", v):
                return int(v, 16)
            return int(v)
        except ValueError:
            try:
                return int(v, 16)
            except ValueError:
                return None
    return None


def _hex(addr: int) -> str:
    return hex(addr)


# ---------------------------------------------------------------------------
# IPCat region loading / normalization
# ---------------------------------------------------------------------------

# Field name candidates seen across IP Catalog MCP tool responses
# (memory_map_get_memory_map_regions, smmuaperture_list_aperture_granules, etc.)
_NAME_FIELDS  = ["name", "region_name", "region", "carveout_name", "label"]
_START_FIELDS = ["start", "start_address", "base_address", "base_addr", "base", "address"]
_END_FIELDS   = ["end", "end_address", "limit_address", "limit"]
_SIZE_FIELDS  = ["size_mb", "size", "size_bytes", "size_kb"]


def _first_present(d: dict, candidates: list[str]):
    for key in candidates:
        if key in d and d[key] not in (None, ""):
            return d[key]
    return None


def normalize_ipcat_region(raw: dict) -> dict | None:
    """
    Normalize a single IP Catalog region/carveout/aperture record (as returned
    by MCP tools such as memory_map_get_memory_map_regions) into:
        {"name": str, "start": int, "end": int, "size_mb": float}
    Returns None if the record cannot be normalized (missing address info).
    """
    name = _first_present(raw, _NAME_FIELDS) or "unknown"

    start_raw = _first_present(raw, _START_FIELDS)
    start = _to_int(start_raw)
    if start is None:
        return None

    end_raw = _first_present(raw, _END_FIELDS)
    end = _to_int(end_raw)

    size_raw = _first_present(raw, _SIZE_FIELDS)
    size_mb = None
    if size_raw is not None:
        try:
            size_val = float(size_raw)
            # Disambiguate units: explicit field name tells us the unit.
            if "size_mb" in raw and raw.get("size_mb") not in (None, ""):
                size_mb = size_val
            elif "size_kb" in raw and raw.get("size_kb") not in (None, ""):
                size_mb = size_val / 1024
            elif "size_bytes" in raw and raw.get("size_bytes") not in (None, ""):
                size_mb = size_val / 1024 / 1024
            else:
                # Generic "size" field -- assume bytes if large, else MB.
                size_mb = size_val / 1024 / 1024 if size_val > 1_000_000 else size_val
        except (TypeError, ValueError):
            size_mb = None

    if end is None and size_mb is not None:
        end = start + int(round(size_mb * 1024 * 1024))
    if size_mb is None and end is not None and end > start:
        size_mb = round((end - start) / 1024 / 1024, 4)
    if end is None or size_mb is None:
        return None

    return {"name": str(name), "start": start, "end": end, "size_mb": round(size_mb, 4)}


def load_ipcat_regions(path: str) -> list[dict]:
    """
    Load and normalize the IPCat region list produced by the agent after
    querying the ipcat-mcp-server MCP server. Accepts either:
      - a flat list of region dicts
      - {"regions": [...]}  (wrapped)
      - {"rows": [...]}     (paginated MCP tool response passthrough)
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        raw_list = data.get("regions") or data.get("rows") or data.get("results") or []
    elif isinstance(data, list):
        raw_list = data
    else:
        raw_list = []

    regions = []
    for raw in raw_list:
        if not isinstance(raw, dict):
            continue
        norm = normalize_ipcat_region(raw)
        if norm:
            regions.append(norm)
    regions.sort(key=lambda r: r["start"])
    return regions


# ---------------------------------------------------------------------------
# Target (device dump) region loading
# ---------------------------------------------------------------------------

# The physical "Memory Layout" produced by internal/snapshot-comparison
# classifies every address-ordered row into one of 5 region_types:
#   sysram   - plain accessible System RAM (generic DDR background filler
#              between named carve-outs)
#   reserved - generic anonymous reserved sub-range reported by the kernel
#              with no specific name
#   missing  - small unaccounted address gaps (rounding/alignment filler)
#   kernel   - actual kernel code/data static image sections
#   nhlos    - named NHLOS carve-outs from device-tree reserved-memory nodes
#
# All five types are included in the comparison. "sysram" and "reserved"
# device rows are generic DDR filler and are expected to match the
# corresponding unnamed "Region of <parent block>" filler entries on the
# IPCat side (the IP Catalog memory map tool emits these for the address
# ranges between named carve-outs/children of a block) -- see
# normalize_ipcat_region() / load_ipcat_regions() for how those are kept.
def load_target_regions(path: str) -> list[dict]:
    """
    Load the target (device-collected) memory layout. Accepts:
      - snapshot_comparison_report.json  (preferred: summary_table.current.memory_layout)
      - a raw memory_layout.json list of [name, start, end, size_mb, region_type]
      - a raw MemorySnapshot snapshot.json (no layout -- returns [] with a warning)

    All rows (sysram, reserved, missing, kernel, nhlos) are included --
    "System RAM" and generic "reserved" DDR filler rows are expected to be
    matched against the IP Catalog's own unnamed "Region of <block>" filler
    entries (see load_ipcat_regions()).

    Returns a normalized list of {"name", "start", "end", "size_mb", "region_type"}.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    layout = None
    if isinstance(data, dict):
        if "summary_table" in data:
            layout = (data.get("summary_table", {})
                          .get("current", {})
                          .get("memory_layout"))
        elif "memory_layout" in data:
            layout = data.get("memory_layout")
    elif isinstance(data, list):
        layout = data

    if not layout:
        print(f"[ipcat-memory-layout] WARNING: no memory_layout found in {path}. "
              f"Pass a snapshot_comparison_report.json for target region data.",
              file=sys.stderr)
        return []

    regions = []
    for entry in layout:
        try:
            name, start, end, size_mb, region_type = entry
        except (ValueError, TypeError):
            continue
        regions.append({
            "name": name, "start": int(start), "end": int(end),
            "size_mb": float(size_mb), "region_type": region_type,
        })
    regions.sort(key=lambda r: r["start"])
    return regions


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

# Tolerance for considering two addresses "matching" (rounding/page-alignment
# slack). Matching is based on start and end address only -- size is implied
# by (end - start) and is not checked independently.
ADDR_TOLERANCE_BYTES = 4096  # one page


def _overlap_bytes(a_start, a_end, b_start, b_end) -> int:
    return max(0, min(a_end, b_end) - max(a_start, b_start))


# Unnamed "filler" regions emitted by the IP Catalog memory-map tool
# (auto-generated label "Region of <parent block name>") represent whatever
# unlabeled DDR space sits between named carve-outs within that block.
#
# Only the filler INSIDE THE TOP-LEVEL/ROOT memory map itself (e.g.
# "Region of DDR SW Map") is genuine, generic, unallocated DDR background
# that is expected to show up as plain "System RAM" on a healthy device --
# any overlap there is a non-issue.
#
# Filler INSIDE A NAMED CHILD/NESTED BLOCK (e.g. "Region of UEFI_DTB",
# "Region of PIL_REGION", "Region of pIMEM Vault") is a different thing
# entirely: it is leftover/unused space *within* that specific carve-out's
# own small address window (e.g. the 2 MB "UEFI_DTB" wrapper block, most
# of which is consumed by the named "XBL(BOOT)" carve-out, with ~1 MB left
# over). This leftover space is NOT a blanket guarantee of "healthy DDR
# background" -- it's unallocated padding tied to a specific firmware
# block, so it must NOT be auto-matched against System RAM. Per user
# feedback: "Why exactly is Region of UEFI_DTB getting matched against
# System RAM" -- it should not be.
#
# ROOT_FILLER_BLOCK_NAMES lists the known top-level/root memory map name(s)
# whose "Region of <name>" filler is eligible for the lenient System-RAM
# match. Everything else falls through to the strict named-region rule
# (which, since filler regions are unnamed, always evaluates to "No" --
# correctly surfacing the mismatch instead of silently passing it).
ROOT_FILLER_BLOCK_NAMES = {"ddr sw map", "ddr"}


def _is_generic_ipcat_region(name: str) -> bool:
    """
    True only for IP Catalog's auto-generated filler rows that belong to
    the TOP-LEVEL/ROOT memory map (e.g. 'Region of DDR SW Map') -- these
    are genuine open/unallocated DDR background, eligible for the lenient
    "any overlap with System RAM is healthy" rule.

    False for filler rows nested inside a named child block (e.g. 'Region
    of UEFI_DTB', 'Region of PIL_REGION', 'Region of pIMEM Vault') -- these
    are leftover padding specific to that carve-out's own small block and
    must be evaluated under the strict named-region matching rule instead
    (see match_regions()), so they correctly report a mismatch rather than
    silently passing just because a device "System RAM" row happens to
    overlap them.
    """
    n = name.strip().lower()
    if not n.startswith("region of"):
        return False
    parent = n[len("region of"):].strip()
    return parent in ROOT_FILLER_BLOCK_NAMES


# Device sub-regions reported as plain "System RAM" (sysram) are the only
# type that can be considered a genuine, exact tiling of a generic IPCat
# filler span -- IPCat's "Region of <block>" label simply means "unallocated
# DDR background", and a device "System RAM" row filling that same address
# range is the expected/healthy state, so it is reported as Matching = Yes
# for ANY overlap with a filler region (a filler has no fixed boundary of
# its own to hold a System RAM row to).
GENERIC_FILLER_EXACT_MATCH_TYPES = {"sysram"}


def _clip_target_regions_to_ipcat_range(ipcat_regions: list[dict],
                                         target_regions: list[dict]) -> list[dict]:
    """
    Limit the Target (device) region list to the address range actually
    covered by the IPCat reference map, per user requirement: the
    comparison table should only extend up to IPCat's maximum address --
    any Target data beyond that (e.g. additional DDR banks/address space
    the IPCat memory map doesn't describe at all) is ignored entirely.

    Target regions entirely beyond the IPCat max address are dropped.
    A Target region that straddles the IPCat max address boundary is
    clipped so its end does not exceed that boundary.
    """
    if not ipcat_regions:
        return target_regions

    ipcat_max_end = max(r["end"] for r in ipcat_regions)

    clipped: list[dict] = []
    for tg in target_regions:
        if tg["start"] >= ipcat_max_end:
            continue  # entirely beyond IPCat's range -- ignore
        if tg["end"] > ipcat_max_end:
            new_end = ipcat_max_end
            new_size_mb = round((new_end - tg["start"]) / 1024 / 1024, 4)
            tg = {**tg, "end": new_end, "size_mb": new_size_mb}
        clipped.append(tg)
    return clipped


def match_regions(ipcat_regions: list[dict], target_regions: list[dict]) -> list[dict]:
    """
    Tile every IPCat region against every overlapping Target (device)
    region, producing one output row per overlapping (IPCat, Target) pair.
    Both sides of each row are clipped to the exact overlapping address
    sub-range -- i.e. either side (IPCat's "Region of <block>" filler OR
    the device's own row, e.g. "System RAM") is split into as many smaller
    chunks as needed to tile the actual overlap(s) on the other side. This
    correctly handles cases such as:

      - A single large device "System RAM" row spanning across the
        boundary between an IPCat filler gap and the next named IPCat
        carve-out (e.g. a freed-at-runtime "UEFI" reservation) -- the
        System RAM row is split into two tiles, one per IPCat region it
        overlaps, each clipped to that region's own address range.
      - A single device NHLOS carve-out (e.g. "audio-mdsp-carveout")
        straddling the boundary between two IPCat entries (e.g.
        "Audio_Heap" and "Region of DDR SW Map") -- it is split into two
        tiles, one per overlapping IPCat entry, each correctly clipped.

    Matching rules per tile:
      - Generic/filler IPCat region ("Region of <block>") overlapping a
        device `sysram` ("System RAM") row -- always Matching = "Yes"
        (a filler has no fixed carve-out identity to hold a boundary to).
      - Generic/filler IPCat region overlapping any other device row type
        (reserved, missing, kernel, nhlos) -- always Matching = "No", but
        the IPCat side still shows the filler's own name with the
        overlapping sub-range (never blank).
      - Named (non-generic) IPCat region -- Matching = "Yes" only when the
        tile's boundaries exactly equal BOTH the full IPCat region's own
        bounds AND the full Target region's own bounds (i.e. no splitting
        was needed on either side -- a clean 1:1 match), otherwise "No".

    IPCat regions with no overlapping Target region at all, and Target
    regions with no overlapping IPCat region at all, are both still
    included with the opposite side left blank and Matching = "No".
    """
    rows: list[dict] = []
    target_had_overlap: set[int] = set()

    for ip in ipcat_regions:
        is_generic = _is_generic_ipcat_region(ip["name"])

        overlaps: list[tuple[int, int, int, dict]] = []
        for j, tg in enumerate(target_regions):
            ov_start = max(ip["start"], tg["start"])
            ov_end   = min(ip["end"],   tg["end"])
            if ov_end > ov_start:
                overlaps.append((ov_start, ov_end, j, tg))

        if not overlaps:
            rows.append({
                "region":            ip["name"],
                "ipcat_start":       ip["start"],
                "ipcat_end":         ip["end"],
                "ipcat_size_mb":     ip["size_mb"],
                "target_region":     None,
                "target_start":      None,
                "target_end":        None,
                "target_size_mb":    None,
                "matching":          "No",
            })
            continue

        overlaps.sort(key=lambda x: x[0])
        for ov_start, ov_end, j, tg in overlaps:
            target_had_overlap.add(j)
            tile_size_mb = round((ov_end - ov_start) / 1024 / 1024, 4)

            if is_generic:
                matching = "Yes" if tg.get("region_type") in GENERIC_FILLER_EXACT_MATCH_TYPES else "No"
            else:
                # Named (non-generic) IPCat carve-outs must only be matched
                # against an equally "real" named carve-out on the device
                # side -- i.e. region_type == "nhlos" (a device-tree
                # reserved-memory node with its own name). A device row
                # whose address range happens to numerically coincide with
                # a named IPCat region's bounds, but is actually just
                # generic filler (sysram/reserved/missing/kernel), is NOT a
                # real match -- it's a coincidental address overlap, not
                # evidence the carve-out is actually present/reserved on
                # the device. E.g. "Display Config" aligning with a
                # device "reserved" row, or "TAGS" aligning with a
                # "Missing" unaccounted gap, must both report Matching =
                # "No" rather than a false "Yes".
                ip_exact = (abs(ov_start - ip["start"]) <= ADDR_TOLERANCE_BYTES
                            and abs(ov_end - ip["end"]) <= ADDR_TOLERANCE_BYTES)
                tg_exact = (abs(ov_start - tg["start"]) <= ADDR_TOLERANCE_BYTES
                            and abs(ov_end - tg["end"]) <= ADDR_TOLERANCE_BYTES)
                tg_is_named_carveout = tg.get("region_type") == "nhlos"
                matching = "Yes" if (ip_exact and tg_exact and tg_is_named_carveout) else "No"

            # Per user requirement: the IPCat side of every tile always shows
            # the IPCat region's own FULL (un-clipped) address range -- e.g.
            # if "UEFI" (0x9f400000-0xa0000000) is only partially overlapped
            # by a device row, the IPCat columns still show the complete
            # UEFI bounds rather than being chopped down to just the
            # overlapping slice. This naturally produces the visual effect
            # of consecutive tiles against the same IPCat region appearing
            # as "one block" on the IPCat side across multiple rows. The
            # Target side is left as-is, i.e. still clipped to the actual
            # overlap (the device's own sub-region range for this tile).
            # Rows are NOT merged/collapsed into each other -- each tile
            # remains its own output row regardless of Matching status, so
            # "Yes" and "No" tiles for the same IPCat region are never
            # combined.
            rows.append({
                "region":            ip["name"],
                "ipcat_start":       ip["start"],
                "ipcat_end":         ip["end"],
                "ipcat_size_mb":     ip["size_mb"],
                "target_region":     tg["name"],
                "target_start":      ov_start,
                "target_end":        ov_end,
                "target_size_mb":    tile_size_mb,
                "matching":          matching,
            })

    # Target regions with no overlap against any IPCat region at all
    # (extra/unexpected regions found on-device but not described anywhere
    # in the IP Catalog reference).
    for j, tg in enumerate(target_regions):
        if j in target_had_overlap:
            continue
        rows.append({
            "region":            None,
            "ipcat_start":       None,
            "ipcat_end":         None,
            "ipcat_size_mb":     None,
            "target_region":     tg["name"],
            "target_start":      tg["start"],
            "target_end":        tg["end"],
            "target_size_mb":    tg["size_mb"],
            "matching":          "No",
        })

    rows.sort(key=lambda r: (r["ipcat_start"] if r["ipcat_start"] is not None
                              else r["target_start"] if r["target_start"] is not None else 0))
    return rows


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def build_report(rows: list[dict], chip: str, ipcat_path: str, target_path: str) -> dict:
    matched   = sum(1 for r in rows if r["matching"] == "Yes")
    mismatched = len(rows) - matched
    return {
        "report_type":   "IPCatLayoutReport",
        "chip":          chip,
        "ipcat_source":  ipcat_path,
        "target_source": target_path,
        "rows":          rows,
        "summary": {
            "total":      len(rows),
            "matched":    matched,
            "mismatched": mismatched,
        },
    }


def write_json(report: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "ipcat_layout_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[ipcat-memory-layout] JSON  -> {path}")
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare a device's physical memory layout against the IP Catalog "
            "(IPCat) reference memory map for the matching chip."
        )
    )
    parser.add_argument("--ipcat", required=True,
                         help="Path to normalized IPCat region JSON (agent-fetched via MCP)")
    parser.add_argument("--target", required=True,
                         help="Path to snapshot_comparison_report.json (or raw memory_layout.json)")
    parser.add_argument("--chip", default="",
                         help="IP Catalog chip id/alias used to fetch --ipcat (for report metadata)")
    parser.add_argument("--output-dir", default=".",
                         help="Output directory for ipcat_layout_report.json (default: .)")
    args = parser.parse_args()

    if not os.path.isfile(args.ipcat):
        print(f"ERROR: --ipcat file not found: {args.ipcat}")
        return 1
    if not os.path.isfile(args.target):
        print(f"ERROR: --target file not found: {args.target}")
        return 1

    ipcat_regions  = load_ipcat_regions(args.ipcat)
    target_regions = load_target_regions(args.target)

    if not ipcat_regions:
        print(f"ERROR: no usable regions parsed from {args.ipcat}")
        return 1

    # Limit the comparison table to IPCat's own address range -- any Target
    # (device) data beyond IPCat's maximum address is ignored entirely.
    orig_target_count = len(target_regions)
    target_regions = _clip_target_regions_to_ipcat_range(ipcat_regions, target_regions)
    dropped = orig_target_count - len(target_regions)
    if dropped:
        print(f"[ipcat-memory-layout] Ignored {dropped} target region(s) "
              f"beyond IPCat's max address.")

    rows   = match_regions(ipcat_regions, target_regions)
    report = build_report(rows, args.chip, args.ipcat, args.target)
    write_json(report, args.output_dir)

    s = report["summary"]
    print(f"\n[ipcat-memory-layout] {s['total']} region(s): "
          f"{s['matched']} matching, {s['mismatched']} mismatched.")
    return 0


if __name__ == "__main__":
    sys.exit(main())