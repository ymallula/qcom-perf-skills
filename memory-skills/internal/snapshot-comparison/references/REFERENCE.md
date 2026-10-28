# Snapshot Comparison — Reference

Full `SnapshotComparisonReport` schema, memory categories compared, and delta methodology.

---

## SnapshotComparisonReport JSON Schema

```json
{
  "schema_version": "1.0.0",
  "current_snapshot_id": "a3f2c1d0-...",
  "reference_snapshot_id": "b4e3d2c1-...",
  "current_label": "after_test",
  "reference_label": "baseline",
  "delta_seconds": 3600,
  "categories": [
    {
      "category": "MemTotal",
      "reference_kb": 12288000,
      "current_kb": 12288000,
      "delta_kb": 0,
      "delta_pct": 0.0,
      "trend": "STABLE"
    },
    {
      "category": "Slab",
      "reference_kb": 524288,
      "current_kb": 786432,
      "delta_kb": 262144,
      "delta_pct": 50.0,
      "trend": "GROWING"
    }
  ],
  "top_growers": [
    { "category": "Slab", "delta_kb": 262144, "delta_pct": 50.0 }
  ],
  "top_reducers": [],
  "findings": [
    { "severity": "WARNING", "message": "Slab grew by 256 MB (50%) since baseline" }
  ]
}
```

---

## Memory Categories Compared

| Category | Source Field in MemorySnapshot |
|---|---|
| MemTotal | `sources.meminfo.parsed.MemTotal` |
| MemFree | `sources.meminfo.parsed.MemFree` |
| Slab | `sources.meminfo.parsed.Slab` |
| Vmalloc | `sources.meminfo.parsed.VmallocUsed` |
| PageTables | `sources.meminfo.parsed.PageTables` |
| KernelStack | `sources.meminfo.parsed.KernelStack` |
| AnonPages | `sources.meminfo.parsed.AnonPages` |
| Shmem | `sources.meminfo.parsed.Shmem` |
| DMA-BUF | `sources.debugfs.dmabuf.parsed.total_kb` |
| KGSL | `sources.debugfs.kgsl.parsed.total_kb` |
| CMA Used | sum of `sources.debugfs.cma.parsed[*].used_kb` |
| SwapCached | `sources.meminfo.parsed.SwapCached` |
| NHLOS Total | sum of `sources.reserved_memory.nodes[*].size_kb` |

---

## Delta Calculation

```
delta_kb  = current_kb - reference_kb
delta_pct = (delta_kb / reference_kb) x 100   (if reference_kb > 0)

trend = GROWING   if delta_pct > +threshold_pct  (default: +5%)
        SHRINKING if delta_pct < -threshold_pct  (default: -5%)
        STABLE    otherwise
```

Top growers and reducers are ranked by absolute `delta_kb`.

---

## Flagging Thresholds

| Threshold | Default | Description |
|---|---|---|
| `--threshold-pct` | 5.0 | Minimum % change to classify as GROWING or SHRINKING |
| `--threshold-mb` | 50.0 | Minimum absolute MB change to generate a WARNING finding |

A WARNING finding is generated when both thresholds are exceeded simultaneously.

---

## Physical Memory Layout (`summary_table.<ref|cur>.memory_layout`)

In addition to the hierarchical summary table, `compute_summary_table()` also
builds a flat, address-ordered **physical memory layout** -- mirroring the
`MemoryLayout` sheet produced by the legacy `memmap_Parser.py` reference tool.

It is built from three sources:
- `sources.memblock.parsed.regions` -- `/sys/kernel/debug/memblock/memory`, the
  authoritative list of **populated DRAM**. Used to derive the board's DRAM
  bank address ranges (see "DRAM bank bounding" below).
- `sources.iomem.parsed.regions` -- full `/proc/iomem` hierarchy (including
  depth/indentation), used to find `System RAM` blocks (depth 0) and any
  kernel-reserved sub-regions nested inside them (depth > 0, e.g. `Kernel code`).
- `sources.reserved_memory.nodes` -- device-tree `reserved-memory` carve-outs
  (NHLOS regions such as `hyp`, `tz-apps`, `mpss-wlan`, `smem`, etc.).

Each entry is a 5-tuple `[name, start, end, size_mb, region_type]` where
`region_type` is one of:

| region_type | Meaning |
|---|---|
| `sysram`   | Accessible System RAM (HLOS-visible) |
| `kernel`   | Kernel code/data section (static kernel image footprint) |
| `reserved` | Anonymous reserved carve-out the kernel doesn't attribute to a named subsystem |
| `nhlos`    | Named NHLOS carve-out from device-tree reserved-memory |
| `missing`  | Address gap between regions (unaccounted memory) |

Entries are sorted by start address, and gaps between adjacent regions are
filled in as `missing` entries. This layout is rendered in the unified HTML
report as a collapsible "Memory Layout" section and written to a dedicated
`MemoryLayout` sheet in the unified XLSX report.

### Invariant: the layout Total must never exceed physical RAM

Summing the `size_mb` column of every row must approximate
`summary_table.<ref|cur>.total_ram_kb` and must **never exceed** it. Three
rules enforce this; each one corrects a way the raw kernel data would
otherwise inflate the total.

**1. DRAM bank bounding.** `/proc/iomem` describes the *entire* SoC physical
address space, not just memory. Alongside DRAM it lists peripheral MMIO
register windows (clock controllers, I2C/SPI/UART, GIC, pinctrl, ...) and --
most significantly -- **PCIe BAR/ECAM apertures that can be 512 MB to several
GB each**. Those are address space, not memory, and counting them as carve-outs
inflates the total well past the board's real RAM (observed: +1516 MB on a
32 GB board with two PCIe controllers). `derive_dram_banks()` therefore builds
the set of populated DRAM ranges from memblock (falling back to the extents of
`/proc/iomem`'s depth-0 `System RAM` entries when debugfs is unavailable), and
every candidate row must lie wholly inside one of those banks or it is dropped.

Adjacent memblock ranges separated by less than `GAP_THRESHOLD_MB` (1 GB) are
merged into a single bank; a larger hole marks a separate DRAM
interface/channel. On a board with DRAM at both `0x81a60000` and
`0x880000000`, this correctly yields two banks rather than one span covering
the 30 GB hole between them.

**2. Carve-out de-duplication.** The kernel reports most device-tree carve-outs
*twice*: once as an anonymous depth-0 `reserved` range in `/proc/iomem`, and
again as a named node under `/sys/firmware/devicetree/base/reserved-memory`.
Emitting both double-counts that memory. The named NHLOS row is the more
informative of the two, so only the sub-ranges of each anonymous `reserved`
entry that are **not already covered** by an existing row are emitted.

**3. Inter-bank gap suppression.** A `missing` row is only emitted for a gap
that is both smaller than `GAP_THRESHOLD_MB` *and* backed by a populated DRAM
bank. Multi-GB holes between DRAM interfaces are non-populated address space,
not unaccounted memory, and reporting them would both alarm the reader and
inflate the total.

Because carve-outs are rounded to whole MB and some firmware regions sit
outside any memblock range, the Total typically lands a few MB **below**
`total_ram_kb` (observed: -0.1% on both a 6 GB and a 32 GB board). Landing
*above* it indicates a regression in one of the three rules above.

### memblock parsing note

`/sys/kernel/debug/memblock/memory` has two formats across kernel versions:

```
0: 0x0000000081a60000..0x0000000081bbffff    0 NONE     # current: start..end
0: 0x0000000081a60000 0x0000000000160000 0              # older:   base size
```

The `start..end` form must be matched first. Reading the third
whitespace-separated field as a "size" on a modern kernel yields the NUMA node
id (`0`), which makes every region zero-sized and silently degrades the source
to an empty list -- which in turn disables DRAM bank bounding and lets the
PCIe apertures back into the layout.
