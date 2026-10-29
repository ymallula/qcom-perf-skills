# ipcat-memory-layout

Internal component. Compares a device's **physical memory layout** (collected
via `internal/data-collection` + `internal/snapshot-comparison`, the same
layout shown in the report's "Memory Layout" section) against the
**IP Catalog (IPCat)** reference memory map for the matching chip.

Produces an `IPCatLayoutReport` JSON consumed by `internal/report-generation`,
which renders it as the **"IPCat Memory Layout"** table — a sibling of the
existing "Memory Layout" table — with columns:

| IPCat Region | IPCat Start Address | IPCat End Address | IPCat Size (MB) | Target Region | Target Start Address | Target End Address | Target Size (MB) | Matching |
|---|---|---|---|---|---|---|---|---|

`IPCat Region` and `Target Region` are placed immediately before their
respective Start Address columns so each side's name/start/end/size group
reads together, keeping the two address columns properly aligned side by
side for visual comparison.

`Matching` is `Yes` when a region's start address and end address both
agree (within a small tolerance) between the IP Catalog reference and the
device's collected ("Target") layout, otherwise `No` -- see "Matching
rules" below.

---

## Why this script does not call MCP itself

MCP tools (`ipcat-mcp-server`) are only reachable from the **AI agent
session**, not from a standalone Python subprocess. So the workflow splits
into two halves:

1. **Agent-side (MCP calls)** — the AI agent queries `ipcat-mcp-server` for
   the chip's reference memory map and writes a normalized JSON file.
2. **Script-side (this component)** — `ipcat_layout.py` loads that JSON file
   plus the device's already-collected memory layout and performs the
   comparison / matching.

---

## Step 1 — Agent fetches IPCat chip memory map via MCP

### 1a. Resolve the chip

If the user already knows the exact IPCat chip id/alias (e.g. `hana_1.0`),
skip to 1b. Otherwise, help the user pick one:

- If the user gives a device dump, extract the SoC name from
  `device.soc_name` / `device.soc_id` in `snapshot.json` (collected by
  `internal/data-collection`) and use `chips_get_latest_chip` or
  `chips_list_chips` to find the matching chip id/alias.
- Otherwise, **ask the user to select the device(s)** to compare against
  (one or more chips) — e.g. via `chips_list_chips` filtered by family, or
  `chips_list_chip_versions` for a known chip basename.

### 1b. Fetch the reference memory map

Call `memory_map_get_memory_map_regions` for the resolved chip's default
memory-map version (or `swi_map_versions_by_chip` first if you need to pick a
specific processor view / map version). Request top-level regions
(`block_id=None`); request sub-regions per block only if the user wants a
sub-region breakdown.

### 1c. Normalize and save

Write the MCP tool's region list to a JSON file, e.g. `ipcat_layout.json`,
either as a flat list or wrapped as `{"regions": [...]}`. Each region record
should contain (field names are flexible — `ipcat_layout.py` recognizes
several common aliases):

```json
{
  "name": "mpss",
  "start": "0x86000000",
  "end": "0x8C000000",
  "size_mb": 96
}
```

Supported field aliases:

| Concept | Accepted field names |
|---|---|
| Region name | `name`, `region_name`, `region`, `carveout_name`, `label` |
| Start address | `start`, `start_address`, `base_address`, `base_addr`, `base`, `address` |
| End address | `end`, `end_address`, `limit_address`, `limit` |
| Size | `size_mb`, `size`, `size_bytes`, `size_kb` |

Addresses may be hex strings (`"0x86000000"`), bare hex (`"86000000"`), or
decimal.

---

## Step 2 — Run the comparison script

```bash
python internal/ipcat-memory-layout/scripts/ipcat_layout.py \
    --ipcat ipcat_layout.json \
    --target reports/_intermediate/snapshot_comparison_report.json \
    --chip hana_1.0 \
    --output-dir reports/
```

`--target` should point at the `snapshot_comparison_report.json` produced by
`internal/snapshot-comparison` for the device snapshot being analyzed (it
contains `summary_table.current.memory_layout`, the same physical layout
rows shown in the "Memory Layout" HTML table). A raw list-of-tuples
`memory_layout.json` is also accepted.

---

## Inputs

| Flag | Required | Description |
|---|---|---|
| `--ipcat` | Yes | Path to the normalized IPCat region JSON (agent-produced, Step 1c) |
| `--target` | Yes | Path to `snapshot_comparison_report.json` (or raw `memory_layout.json`) |
| `--chip` | No | IPCat chip id/alias used for `--ipcat`, recorded in the report for display |
| `--output-dir` | No | Output directory for `ipcat_layout_report.json` (default: `.`) |

## Outputs

| File | Description |
|---|---|
| `ipcat_layout_report.json` | Structured `IPCatLayoutReport` JSON, rendered by `report-generation` as the "IPCat Memory Layout" table |

---

## Address-range tiling: splitting the Target side to match IPCat

A single Target (device) region can span across the boundary between two
or more IPCat regions. `ipcat_layout.py` handles this by **tiling**: for
every IPCat region, it finds every overlapping Target region and emits
one output row per overlapping pair. Two concrete cases this fixes:

1. **A device "System RAM" row spanning across an IPCat boundary.**
   e.g. IPCat has `"Region of DDR SW Map"` ending at `0x9f400000` followed
   by `"UEFI"` (`0x9f400000`–`0xa0000000`), but the device reports one
   contiguous `"System RAM"` row from `0x98c60000` to `0x9fbf7000`
   (because UEFI's boot-time reservation has since been freed). This
   single device row is tiled into **two** output rows -- one per IPCat
   region it overlaps.
2. **A device NHLOS carve-out straddling an IPCat boundary.**
   e.g. the device's `"audio-mdsp-carveout"` (`0x86240000`–`0x86340000`)
   straddles the boundary between IPCat's `"Audio_Heap"`
   (`0x86200000`–`0x86300000`) and `"Region of DDR SW Map"`
   (`0x86300000`–...). This single device row is tiled into two rows, one
   per overlapping IPCat region.

### IPCat side always shows the region's full, un-clipped bounds

The **Target side** is split/clipped to the actual overlapping sub-range
for each tile, while the **IPCat side of every tile stores that IPCat
region's complete, un-clipped start/end/size** in the underlying JSON
(`ipcat_layout_report.json`) -- never a fragment of it. This means several
consecutive JSON rows for the same IPCat region all carry identical IPCat
Start/End/Size values. For example, `"UEFI"` (`0x9f400000`–`0xa0000000`,
12 MB) overlapping three different device rows produces three JSON rows,
each carrying the full UEFI bounds on the IPCat side paired with its own
distinct Target sub-range:
```json
{"region": "UEFI", "ipcat_start": "0x9f400000", "ipcat_end": "0xa0000000", "ipcat_size_mb": 12.0, "target_region": "System RAM", "target_start": "0x9f400000", "target_end": "0x9fbf7000", "matching": "No"}
{"region": "UEFI", "ipcat_start": "0x9f400000", "ipcat_end": "0xa0000000", "ipcat_size_mb": 12.0, "target_region": "reserved",   "target_start": "0x9fbf7000", "target_end": "0x9fc00800", "matching": "No"}
{"region": "UEFI", "ipcat_start": "0x9f400000", "ipcat_end": "0xa0000000", "ipcat_size_mb": 12.0, "target_region": "System RAM", "target_start": "0x9fc00800", "target_end": "0xa0000000", "matching": "No"}
```

### HTML rendering: IPCat-side cells merged dynamically via JavaScript

In the "IPCat Memory Layout" **HTML table** (`render_ipcat_layout_html()`
in `report-generation/scripts/generate_report.py`), consecutive JSON rows
sharing the same IPCat key (name + start + end) visually merge the
IPCat-side columns (`IPCat Region`, `IPCat Start/End Address`, `IPCat Size
(MB)`) into a single cell group spanning all of those rows -- so `"UEFI"`
visually appears as **one block** on the IPCat side across its three rows.
The **Target-side columns and the `Matching` column are never merged** --
each JSON row still renders as its own table `<tr>`, with its own distinct
Target Region/Start/End/Size and its own independently-evaluated
`Matching` badge (which can differ row-to-row even within the same merged
IPCat block, e.g. `Yes`/`No`/`Yes`).

**Important: the merge is computed dynamically in JavaScript, not
statically as an HTML `rowspan` attribute at render time.** Every row
always renders its own full, independent set of four IPCat-side `<td
class='ipcat-cell'>` cells, each tagged with a shared `data-group`
attribute identifying its merge-group. A `refreshIpcatMerge(tableId)` JS
function (run once on initial page load, and again after every
Matching/Mismatching filter change -- see below) recomputes which rows in
each group are **currently visible** and dynamically sets `rowSpan` only
on the first visible row's cells, hiding (`display:none`, not removing)
the IPCat cells on the other visible rows in that group. This design
specifically avoids a structural bug where a static server-rendered
`rowspan` would break the table's column alignment as soon as the filter
hid the one row carrying the spanned cells while a later row in the same
merge-group remained visible -- the dynamic re-merge on every filter
change guarantees the table structure can never desync from what's
visible. This merging is purely a presentation-layer concern -- the
underlying JSON report (`ipcat_layout_report.json`) still contains one
full row per tile, exactly as described above.

Within a merged IPCat cell group, the cell content is **vertically
centered** (`vertical-align: middle`) across the full height of the
rowspan. Also, a merged IPCat cell group (i.e. one IPCat region split
across 2+ Target sub-regions) is **always styled with the mismatch (red)
background**, regardless of any individual tile's own `Matching` value --
the fact that the IPCat region had to be split at all means the device
does not have a single clean carve-out matching it, so the merged cell
is never shown green. A non-split (single-row) IPCat cell keeps the
normal background tied to that one row's own `Matching` status.

### Centered address/size columns, Matching/Mismatching filter

All eight address/size columns (`IPCat Start/End Address`, `IPCat Size
(MB)`, `Target Start/End Address`, `Target Size (MB)`) are **horizontally
center-aligned** (`text-align: center`) for both header and data cells,
matching the style of the `Matching` badge column.

The table also provides two filter-pill checkboxes above it -- **Matching**
and **Mismatching** -- mirroring the filter pattern used by the "Memory
Layout" section. Checking one or both hides/shows rows by their `Matching`
status (`filterIpcatLayout()` JS function, keyed off each row's
`data-matching` attribute); with neither checked, all rows are shown
(default). The "Showing N of M" counter above the table updates live as
the filter selection changes.

### Matching rules per tile

- **Generic/filler IPCat region** -- only `"Region of DDR SW Map"` (the
  **top-level/root** memory map's own unnamed filler, see
  `_is_generic_ipcat_region()` / `ROOT_FILLER_BLOCK_NAMES` in
  `ipcat_layout.py`) overlapping a device **`sysram`** ("System RAM") row
  always gets `Matching = "Yes"`. A root-level filler region carries no
  specific carve-out identity of its own (it just means "unallocated DDR
  background"), so any overlap with plain System RAM there is the
  expected/healthy state.
- That same root-level generic filler overlapping any **other** device
  row type (`reserved`, `missing`, `kernel`, `nhlos`) -- always
  `Matching = "No"`, but the tile still carries the overlapping filler's
  own name/start/end on the IPCat side (never blank), so the discrepancy
  is visible side-by-side (e.g. the device has an anonymous "reserved"
  region in a spot IPCat describes as open DDR background).
- **Filler nested inside a named child block** -- e.g. `"Region of
  UEFI_DTB"`, `"Region of PIL_REGION"`, `"Region of pIMEM Vault"` -- is
  **not** eligible for the lenient root-filler rule above, even though its
  auto-generated name also starts with `"Region of"`. This filler is
  leftover/unused padding specific to that one small carve-out's own
  address window (e.g. most of the 2 MB `"UEFI_DTB"` block is consumed by
  the named `"XBL(BOOT)"` carve-out, leaving ~1 MB of padding), not
  generic open DDR background -- so it falls through to the **named
  (non-generic) region rule** below, which correctly requires a real
  `nhlos` carve-out match rather than auto-passing against any device
  `"System RAM"` row that happens to overlap it.
- **Named (non-generic) IPCat region** -- `Matching = "Yes"` only when
  **all three** of the following hold, otherwise `"No"`:
  1. The tile's boundaries exactly equal the full IPCat region's own
     bounds (within `±4 KB`).
  2. The tile's boundaries exactly equal the full Target region's own
     bounds (within `±4 KB`) -- i.e. no splitting was needed on either
     side, a clean 1:1 match.
  3. **The Target region's own `region_type` is `"nhlos"`** -- a real,
     named device-tree carve-out. A device row whose address range just
     happens to numerically coincide with a named IPCat region's bounds,
     but is actually generic filler (`sysram`, `reserved`, `missing`,
     `kernel`), is **not** a genuine match -- it's a coincidental address
     overlap, not evidence the carve-out is actually reserved on the
     device. For example, IPCat's `"Display Config"` aligning with a
     device `"reserved"` row, or IPCat's `"TAGS"` aligning with a device
     `"Missing"` unaccounted gap, both correctly report
     `Matching = "No"` rather than a false `"Yes"`.

In every tile the **`IPCat Region` column always shows the IPCat side's
own name** (e.g. `"Region of DDR SW Map"`, `"Audio_Heap"`), while
**`Target Region` always shows the device's own row label** (e.g.
`"System RAM"`, `"audio-mdsp-carveout"`) -- per IP Catalog naming, never
mixed or substituted.

IPCat regions with no overlapping Target region at all (not found
on-device), and Target regions with no overlapping IPCat region at all
(not described in IP Catalog), are both still included with the missing
side left blank and `Matching = "No"`, so nothing is silently dropped.

## Limiting the Target data to IPCat's address range

Per user requirement, the comparison table only covers address space up to
**IPCat's own maximum end address**. Any Target (device) region that falls
entirely beyond that boundary is dropped from the comparison outright
(e.g. an additional DDR bank the IPCat memory map doesn't describe at
all); a Target region that straddles the boundary is clipped so its end
does not exceed it. This keeps the table's address range strictly bounded
by what IPCat itself defines, ignoring any extra device-reported memory
beyond it. See `_clip_target_regions_to_ipcat_range()` in
`ipcat_layout.py`.

## Matching rules summary

Matching is based on **addresses alone** (start and end); size is not
checked independently since it is implied by `end - start`. See "Address-
range tiling" above for the exact per-tile rules -- in short:

- `Region of <block>` (generic filler) tiles: `Yes` iff the Target side is
  `sysram`, else `No`.
- Named IPCat region tiles: `Yes` iff the tile exactly spans both the full
  IPCat region AND the full Target region (within `±4 KB`), else `No`.

---

## Dependencies

- Input: `snapshot_comparison_report.json` from `internal/snapshot-comparison`
  (which in turn depends on `internal/data-collection`)
- Input: IPCat region data fetched by the AI agent via the `ipcat-mcp-server`
  MCP server (tool `memory_map_get_memory_map_regions`, or equivalent)
- Output consumed by: `internal/report-generation`