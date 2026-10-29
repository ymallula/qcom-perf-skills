#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""
report-generation -- Unified Report Generator
Renders any memory skill output JSON into HTML, TXT, and/or Excel reports.
Auto-selects the appropriate template based on the report type in the JSON.

Usage:
    python generate_report.py --input <report.json> [<report2.json> ...]
                              [--format html,txt,xlsx] [--output-dir <dir>]
                              [--unified] [--title <title>]
"""

import argparse
import json
import os
import sys
from datetime import datetime


# ---------------------------------------------------------------------------
# Report type detection
# ---------------------------------------------------------------------------

REPORT_TYPE_MAP = {
    "MemoryMapReport":            "memory_map",
    "CarveoutValidationReport":   "carveout_validation",
    "SnapshotComparisonReport":   "snapshot_comparison",
    "KernelDiffReport":           "kernel_diff",
    "UserspaceDiffReport":        "userspace_diff",
    "RCAReport":                  "rca",
    "IPCatLayoutReport":          "ipcat_layout",
}

def detect_report_type(data: dict) -> str:
    """Detect report type from JSON content."""
    # Check for type field
    if "report_type" in data:
        return REPORT_TYPE_MAP.get(data["report_type"], "unknown")
    # Heuristic detection based on key presence
    if "anomalies" in data and "summary" in data:
        return "rca"
    if "results" in data and "carveout_source" in data:
        return "carveout_validation"
    if "rows" in data and "ipcat_source" in data:
        return "ipcat_layout"
    if "categories" in data and "top_growers" in data:
        return "snapshot_comparison"
    if "slab_diff" in data and "buddy_fragmentation" in data:
        return "kernel_diff"
    if "process_diff" in data and "dmabuf_diff" in data:
        return "userspace_diff"
    if "breakdown" in data and "nhlos_detail" in data:
        return "memory_map"
    return "unknown"


def load_report(path: str) -> tuple[dict, str]:
    """Load a report JSON and detect its type."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    rtype = detect_report_type(data)
    return data, rtype


# ---------------------------------------------------------------------------
# SMAPS breakdown parsing
# ---------------------------------------------------------------------------

def parse_smaps_breakdown(smaps_dir: str, pid: int) -> dict:
    """Parse raw smaps file for a process and return categorized memory breakdown."""
    import glob
    pattern = os.path.join(smaps_dir, f"{pid}_*_smaps.txt")
    files = glob.glob(pattern)
    if not files:
        return {}
    filepath = files[0]
    basename = os.path.basename(filepath)
    proc_name = basename[len(str(pid)) + 1:].replace("_smaps.txt", "")

    segments = []
    current = {}
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line and line[0] in "abcdef0123456789":
                    if current:
                        segments.append(current)
                    parts = line.split()
                    current = {
                        "addr": parts[0],
                        "perms": parts[1] if len(parts) > 1 else "----",
                        "name": parts[-1] if len(parts) > 5 else "unknown",
                        "pss": 0, "anon": 0, "size": 0,
                    }
                elif line.startswith("Size:"):
                    current["size"] = int(line.split()[1])
                elif line.startswith("Pss:"):
                    current["pss"] = int(line.split()[1])
                elif line.startswith("Anonymous:"):
                    current["anon"] = int(line.split()[1])
    except Exception:
        return {}
    if current:
        segments.append(current)

    heap_kb = stack_kb = shared_libs_kb = shared_libs_fb_kb = 0
    shared_libs_anon_kb = anon_kb = other_kb = 0
    anon_buffers: list = []
    shared_libs_map: dict = {}  # basename -> total PSS

    for i, seg in enumerate(segments):
        name, pss, anon = seg["name"], seg["pss"], seg["anon"]
        fb = pss - anon
        if "[heap]" in name:
            heap_kb += pss
        elif "[stack" in name:
            stack_kb += pss
        elif "/dmabuf:" in name:
            pass  # DMA-BUF: PSS is typically 0
        elif ".so" in name or "/lib" in name:
            shared_libs_kb += pss
            shared_libs_fb_kb += fb
            shared_libs_anon_kb += anon
            lib_base = os.path.basename(name)
            shared_libs_map[lib_base] = shared_libs_map.get(lib_base, 0) + pss
        elif name == "unknown" and anon > 0:
            anon_kb += pss
            anon_buffers.append(pss)
        else:
            other_kb += pss

    anon_buffers.sort(reverse=True)
    shared_libs_detail = sorted(
        [{"name": k, "pss_kb": v} for k, v in shared_libs_map.items()],
        key=lambda x: x["pss_kb"], reverse=True,
    )
    return {
        "pid": pid, "name": proc_name,
        "total_pss_kb": sum(s["pss"] for s in segments),
        "heap_kb": heap_kb, "stack_kb": stack_kb,
        "shared_libs_kb": shared_libs_kb,
        "shared_libs_fb_kb": shared_libs_fb_kb,
        "shared_libs_anon_kb": shared_libs_anon_kb,
        "anon_buffers_kb": anon_kb,
        "other_kb": other_kb,
        "anon_buffers": anon_buffers,
        "shared_libs_detail": shared_libs_detail,
    }


def load_smaps_for_snapshot(snapshot_path: str) -> list:
    """Load smaps breakdown for top processes from a snapshot JSON file."""
    if not os.path.isfile(snapshot_path):
        return []
    try:
        with open(snapshot_path, encoding="utf-8") as f:
            snap = json.load(f)
    except Exception:
        return []
    smaps_src = snap.get("sources", {}).get("smaps", {})
    if not smaps_src.get("available"):
        return []
    smaps_dir = smaps_src.get("path", "")
    if not smaps_dir or not os.path.isdir(smaps_dir):
        return []

    # Build PID -> display name from process_stats (more reliable than smaps filename)
    pid_to_name: dict = {}
    proc_stats = snap.get("sources", {}).get("process_stats", {})
    for proc in proc_stats.get("parsed", []):
        pid = proc.get("pid")
        if pid:
            # Use basename of first token of cmdline as display name
            cmdline = proc.get("name", "")
            exe = cmdline.split()[0] if cmdline.strip() else cmdline
            short = exe.split("/")[-1].split("\\")[-1][:40]
            pid_to_name[pid] = short or str(pid)

    breakdowns = []
    for entry in smaps_src.get("parsed", []):
        pid = entry.get("pid")
        if pid:
            bd = parse_smaps_breakdown(smaps_dir, pid)
            if bd:
                # Override name with the one from process_stats if available
                if pid in pid_to_name:
                    bd["name"] = pid_to_name[pid]
                breakdowns.append(bd)
    return breakdowns


# ---------------------------------------------------------------------------
# HTML section renderers
# ---------------------------------------------------------------------------

CSS = """
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; background: #f4f6f9; color: #222; }
h1 { color: #1a3a5c; border-bottom: 3px solid #2c6fad; padding-bottom: 10px; font-size: 1.6em; }
h2 { color: #1a3a5c; margin-top: 0; font-size: 1.1em; }
.section-block { background: #fff; border: 1px solid #c8d8ea; border-radius: 8px;
  margin-bottom: 18px; box-shadow: 0 1px 4px rgba(0,0,0,0.07); overflow: hidden; }
.section-header { background: #1a3a5c; color: white; padding: 10px 16px;
  cursor: pointer; user-select: none; display: flex; align-items: center; gap: 10px; }
.section-header:hover { background: #22507a; }
.section-toggle { font-size: 1.1em; font-weight: bold; min-width: 20px; }
.section-title { font-size: 1em; font-weight: 600; }
.section-body { padding: 16px; }
.section-body.collapsed { display: none; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 13px; }
th, td { border: 1px solid #c0cfe0; padding: 6px 12px; }
th { background: #2c6fad; color: white; font-weight: 600; }
.growing { background: #fde8e8; }
.shrinking { background: #e8f8e8; }
.pass { background: #e8f8e8; }
.over, .under { background: #fef8e0; }
.missing { background: #fde8e8; }
.critical { background: #fde8e8; }
.warning { background: #fef8e0; }
.info { background: #e8f4fd; }
.health-healthy { background: #d4edda; color: #155724; padding: 10px 16px; border-radius: 6px; font-weight: bold; }
.health-degraded { background: #fff3cd; color: #856404; padding: 10px 16px; border-radius: 6px; font-weight: bold; }
.health-critical { background: #f8d7da; color: #721c24; padding: 10px 16px; border-radius: 6px; font-weight: bold; }
.card { border: 1px solid #c0cfe0; border-radius: 6px; padding: 14px; margin: 10px 0; background: #f8fbff; }
.card.critical { border-left: 4px solid #c00; background: #fff5f5; }
.card.warning  { border-left: 4px solid #e6a817; background: #fffdf0; }
.card.info     { border-left: 4px solid #2c6fad; background: #f0f7ff; }
</style>
<script>
function toggleSection(id) {
  var body = document.getElementById(id);
  var btn  = document.getElementById('toggle-' + id);
  if (!body) return;
  var collapsed = body.classList.toggle('collapsed');
  if (btn) btn.textContent = collapsed ? '+' : '\u2212';
}
function toggleRows(cls) {
  var rows = document.querySelectorAll('.' + cls);
  var btn  = document.getElementById('btn-' + cls);
  var open = rows[0] && rows[0].style.display !== 'none';
  rows.forEach(function(r) { r.style.display = open ? 'none' : ''; });
  if (btn) btn.textContent = open ? '+' : '\u2212';
}
function showBatch(batchCls, nextToggleId, currentToggleId) {
  document.querySelectorAll('.' + batchCls).forEach(function(r) { r.style.display = ''; });
  var cur = document.getElementById(currentToggleId);
  if (cur) cur.style.display = 'none';
  if (nextToggleId) {
    var nxt = document.getElementById(nextToggleId);
    if (nxt) nxt.style.display = '';
  }
}
function filterMemoryLayout(tableId) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var checked = Array.prototype.slice.call(
    document.querySelectorAll("input.memlayout-filter[data-table='" + tableId + "']:checked")
  ).map(function(cb) { return cb.value; });
  var rows = table.querySelectorAll('tr.memlayout-row');
  // Recompute the Total row from only the currently-visible rows so the
  // footer always reflects the active filter selection. Every visible row
  // contributes (including "Missing" unaccounted-gap rows) so that the
  // totals always add up to what is actually displayed.
  var tSize = 0, tSys = 0, tCarv = 0, shown = 0;
  rows.forEach(function(row) {
    var show = checked.length === 0 || checked.indexOf(row.getAttribute('data-type')) !== -1;
    row.style.display = show ? '' : 'none';
    if (show) {
      shown++;
      tSize += parseFloat(row.getAttribute('data-size')     || '0');
      tSys  += parseFloat(row.getAttribute('data-sysram')   || '0');
      tCarv += parseFloat(row.getAttribute('data-carveout') || '0');
    }
  });
  var setTxt = function(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val.toFixed(2);
  };
  setTxt(tableId + '-total-size', tSize);
  setTxt(tableId + '-total-sysram', tSys);
  setTxt(tableId + '-total-carveout', tCarv);
  var cnt = document.getElementById(tableId + '-shown-count');
  if (cnt) cnt.textContent = shown;
}
function filterIpcatLayout(tableId) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var checked = Array.prototype.slice.call(
    document.querySelectorAll("input.ipcatlayout-filter[data-table='" + tableId + "']:checked")
  ).map(function(cb) { return cb.value; });
  var rows = table.querySelectorAll('tr.ipcatlayout-row');
  var shown = 0;
  rows.forEach(function(row) {
    var show = checked.length === 0 || checked.indexOf(row.getAttribute('data-matching')) !== -1;
    row.style.display = show ? '' : 'none';
    if (show) shown++;
  });
  var cnt = document.getElementById(tableId + '-shown-count');
  if (cnt) cnt.textContent = shown;
  refreshIpcatMerge(tableId);
}
// Dynamically recompute the IPCat-side rowspan merge for the "IPCat Memory
// Layout" table based on which rows are CURRENTLY VISIBLE (i.e. after the
// Matching/Mismatching filter has hidden some rows). This replaces a
// static server-rendered rowspan (which would desync -- and visibly break
// the table's column alignment -- as soon as the filter hid the one row
// that happened to be carrying the spanned <td> cells while a later row
// in the same merge-group remained visible).
//
// Every row in the table always renders its OWN full, independent set of
// four IPCat-side <td class='ipcat-cell'> cells (never omitted at render
// time) tagged with a shared data-group id. This function, run once on
// initial page load and again after every filter change, does the
// merging purely in the DOM:
//   1. Group rows by data-group (preserving document order).
//   2. Within each group, find the rows currently visible.
//   3. Show the ipcat-cell <td>s only on the FIRST visible row of the
//      group, setting that row's cells' rowSpan to the visible count.
//   4. Hide (display:none) the ipcat-cell <td>s on every other visible
//      row in the group -- the browser's native rowspan handling from
//      step 3 correctly fills those cells' column slots, so the table
//      never loses its column alignment regardless of which rows the
//      filter has hidden.
function refreshIpcatMerge(tableId) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var rows = Array.prototype.slice.call(table.querySelectorAll('tr.ipcatlayout-row'));
  var groups = {};
  var order = [];
  rows.forEach(function(row) {
    var g = row.getAttribute('data-group');
    if (!(g in groups)) { groups[g] = []; order.push(g); }
    groups[g].push(row);
  });
  order.forEach(function(g) {
    var groupRows = groups[g];
    // Reset every row's ipcat-cells to a known baseline first.
    groupRows.forEach(function(row) {
      var cells = row.querySelectorAll('td.ipcat-cell');
      cells.forEach(function(td) { td.rowSpan = 1; td.style.display = 'none'; });
    });
    var visible = groupRows.filter(function(row) { return row.style.display !== 'none'; });
    if (visible.length === 0) return;
    var first = visible[0];
    var firstCells = first.querySelectorAll('td.ipcat-cell');
    firstCells.forEach(function(td) {
      td.style.display = '';
      td.rowSpan = visible.length;
    });
  });
}
</script>
"""


def _progressive_expand_html(row_htmls: list, batch_size: int, prefix: str, ncols: int) -> str:
    """
    Wrap a list of row HTML strings in progressive expansion using <tbody> groups.
    First batch_size rows are always visible.
    Each subsequent batch is hidden behind a 'Show N more' toggle row.
    Clicking the toggle reveals that batch and shows the next toggle (if any).
    """
    if not row_htmls:
        return ""
    batches = [row_htmls[i:i + batch_size] for i in range(0, len(row_htmls), batch_size)]
    html = ""
    for bi, batch in enumerate(batches):
        if bi == 0:
            html += "<tbody>" + "".join(batch) + "</tbody>\n"
        else:
            batch_cls = f"{prefix}-b{bi}"
            toggle_id = f"{prefix}-t{bi}"
            next_toggle_id = f"{prefix}-t{bi + 1}" if bi < len(batches) - 1 else ""
            show_count = len(batch)
            display = "" if bi == 1 else "display:none;"
            html += (
                f"<tbody>"
                f"<tr id='{toggle_id}' style='cursor:pointer;background:#edf3fb;{display}' "
                f"onclick=\"showBatch('{batch_cls}','{next_toggle_id}','{toggle_id}')\">"
                f"<td colspan='{ncols}' style='text-align:center;color:#2c6fad;"
                f"font-size:11px;padding:4px 8px'>"
                f"<span style='font-weight:bold'>+</span> Show {show_count} more</td></tr>"
                f"</tbody>\n"
            )
            html += (
                f"<tbody class='{batch_cls}' style='display:none'>"
                + "".join(batch)
                + "</tbody>\n"
            )
    return html


def render_rca_html(data: dict) -> str:
    s = data.get("summary", {})
    health = s.get("overall_health", "UNKNOWN")
    health_class = f"health-{health.lower()}"
    cards = ""
    for a in data.get("anomalies", []):
        sev = a.get("severity", "INFO").lower()
        evidence_items = "".join(
            f"<li><b>[{e['source']}]</b> {e['finding']}</li>"
            for e in a.get("evidence", [])
        )
        actions = "".join(f"<li>{act}</li>" for act in a.get("recommended_actions", []))
        cards += f"""
<div class='card {sev}'>
  <h3>[{a['severity']}] {a['id']}: {a['title']}</h3>
  <p><b>Confidence:</b> {a['confidence']:.0%} &nbsp; <b>Layer:</b> {a['layer']}</p>
  <p><b>Evidence:</b></p><ul>{evidence_items}</ul>
  <p><b>Hypothesis:</b> {a['hypothesis']}</p>
  <p><b>Recommended actions:</b></p><ol>{actions}</ol>
</div>"""
    return f"""
<div class='{health_class}'>
  <b>Overall Health: {health}</b> &nbsp;|&nbsp;
  Critical: {s.get('critical',0)} &nbsp; Warning: {s.get('warning',0)} &nbsp; Info: {s.get('info',0)}<br>
  Layers: {', '.join(s.get('layers_affected', [])) or 'none'} &nbsp;|&nbsp;
  Mode: {s.get('mode', 'unknown')}
</div>
{cards or '<p>No anomalies detected.</p>'}"""


def render_carveout_html(data: dict) -> str:
    rows = ""
    for r in data.get("results", []):
        size_mb = r.get("actual_size_mb", r.get("actual_size_kb", 0) / 1024)
        rows += (
            f"<tr class='pass'>"
            f"<td>{r.get('name','')}</td>"
            f"<td style='font-family:monospace'>{r.get('base_addr','')}</td>"
            f"<td style='text-align:right'>{size_mb:.2f}</td>"
            f"<td>[OK] FOUND</td>"
            f"</tr>\n"
        )
    s = data.get("summary", {})
    total_mb = s.get("total_actual_mb", 0)
    found = s.get("found", len(data.get("results", [])))
    source = data.get("carveout_source", "")
    return f"""
<p><b>Carve-outs found:</b> {found} &nbsp;|&nbsp; <b>Total size:</b> {total_mb:.2f} MB
   {f"&nbsp;|&nbsp; <b>Source:</b> {source}" if source else ""}</p>
<table>
<tr><th>Carveout</th><th>Base Address</th><th>Size (MB)</th><th>Status</th></tr>
{rows}</table>"""


def render_summary_table_html(data: dict) -> str:
    """Render the hierarchical collapsible memory summary table."""
    st = data.get("summary_table")
    if not st:
        return ""
    ref = st.get("reference", {})
    cur = st.get("current", {})
    ref_label = data.get("reference_label", "Reference")
    cur_label  = data.get("current_label",  "Current")

    # Detect self-comparison (standalone mode): same snapshot_id for both
    is_standalone = (
        data.get("current_snapshot_id") == data.get("reference_snapshot_id")
        and data.get("current_snapshot_id", "") != ""
    )

    def mb(kb):
        return f"{kb/1024:.0f}" if kb else "0"

    def mb_precise(kb):
        """Show MB with 1 decimal for values < 10 MB, KB for values < 1 MB."""
        if not kb:
            return "0"
        if kb < 1024:
            return f"{kb} KB"
        if kb < 10 * 1024:
            return f"{kb/1024:.1f} MB"
        return f"{kb//1024} MB"

    def delta_td(ref_kb, cur_kb):
        if is_standalone:
            return ""  # no delta column in standalone mode
        d = cur_kb - ref_kb
        s = f"{d/1024:+.0f}" if d != 0 else "0"
        color = "#c00" if d > 0 else ("#060" if d < 0 else "#555")
        fw = "font-weight:bold;" if d != 0 else ""
        return f"<td class='num' style='color:{color};{fw}'>{s}</td>"

    # Build NHLOS sub-rows
    nhlos_ref_nodes = {n["name"]: n["size_kb"] for n in ref.get("nhlos_nodes", [])}
    nhlos_cur_nodes = {n["name"]: n["size_kb"] for n in cur.get("nhlos_nodes", [])}
    all_nhlos = sorted(set(nhlos_ref_nodes) | set(nhlos_cur_nodes),
                       key=lambda x: nhlos_cur_nodes.get(x, 0), reverse=True)
    nhlos_sub = ""
    for name in all_nhlos:
        r_kb = nhlos_ref_nodes.get(name, 0)
        c_kb = nhlos_cur_nodes.get(name, 0)
        nhlos_sub += (
            f"<tr class='sub-row nhlos-sub' style='display:none;background:#f5f8ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>NHLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {name}</td>"
            f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>"
            f"{delta_td(r_kb, c_kb)}</tr>\n"
        )
    # Add unaccounted gap row (NHLOS total - sum of named nodes)
    ref_named_sum = sum(nhlos_ref_nodes.values())
    cur_named_sum = sum(nhlos_cur_nodes.values())
    ref_gap = max(0, ref.get("nhlos_kb", 0) - ref_named_sum)
    cur_gap = max(0, cur.get("nhlos_kb", 0) - cur_named_sum)
    if ref_gap > 0 or cur_gap > 0:
        nhlos_sub += (
            f"<tr class='sub-row nhlos-sub' style='display:none;background:#f0f3ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>NHLOS</td>"
            f"<td style='padding-left:28px;color:#888;font-style:italic'>"
            f"&#x2514; HYP + TZ + UEFI Reservations</td>"
            f"<td class='num' style='color:#888'>{mb(ref_gap)}</td>"
            f"<td class='num' style='color:#888'>{mb(cur_gap)}</td>"
            f"{delta_td(ref_gap, cur_gap)}</tr>\n"
        )

    # Human-readable display names for technical kernel field names
    DISPLAY_NAMES = {
        "Slab":          "Slab Allocator",
        "Vmalloc":       "Vmalloc",
        "KernelStack":   "Kernel Stack",
        "PageTables":    "Page Tables",
        "Percpu":        "Per-CPU",
        "SecPageTables": "Secondary Page Tables (Stage-2)",
        "Modules":       "Kernel Modules",
        "CMA":           "CMA (Contiguous Memory)",
        "KDA":           "KDA (Kernel Direct Allocations)",
        "AnonPages":     "Anonymous Pages",
        "Shmem":         "Shared Memory",
        "DMA-BUF":       "DMA-BUF Buffers",
        "KGSL":          "KGSL GPU Memory",
    }

    # Build Kernel Dynamic sub-rows (includes CMA and KDA)
    kd_ref = ref.get("kernel_dynamic_breakdown", {})
    kd_cur = cur.get("kernel_dynamic_breakdown", {})
    kd_sub = ""
    for key in ["Slab", "Vmalloc", "KernelStack", "PageTables", "Percpu", "SecPageTables", "Modules", "CMA", "KDA"]:
        r_kb = kd_ref.get(key, 0)
        c_kb = kd_cur.get(key, 0)
        label = DISPLAY_NAMES.get(key, key)
        # Style KDA differently (italic, grey) to indicate it's a residual
        if key == "KDA":
            kd_sub += (
                f"<tr class='sub-row kd-sub' style='display:none;background:#f0f3ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#888;font-style:italic'>&#x2514; {label}</td>"
                f"<td class='num' style='color:#888'>{mb(r_kb)}</td>"
                f"<td class='num' style='color:#888'>{mb(c_kb)}</td>"
                f"{delta_td(r_kb, c_kb)}</tr>\n"
            )
        else:
            kd_sub += (
                f"<tr class='sub-row kd-sub' style='display:none;background:#f5f8ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
                f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>"
                f"{delta_td(r_kb, c_kb)}</tr>\n"
            )

    # Build User Space sub-rows (AnonPages + Shmem only)
    us_ref = ref.get("user_space_breakdown", {})
    us_cur = cur.get("user_space_breakdown", {})
    us_sub = ""
    for key in ["AnonPages", "Shmem"]:
        r_kb = us_ref.get(key, 0)
        c_kb = us_cur.get(key, 0)
        label = DISPLAY_NAMES.get(key, key)
        us_sub += (
            f"<tr class='sub-row us-sub' style='display:none;background:#f5f8ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
            f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>"
            f"{delta_td(r_kb, c_kb)}</tr>\n"
        )

    # Build Hardware / Driver Buffers sub-rows (DMA-BUF + per-exporter + KGSL)
    hw_ref = ref.get("hw_driver_breakdown", {})
    hw_cur = cur.get("hw_driver_breakdown", {})
    hw_sub = ""

    # DMA-BUF total row (expandable to show exporters)
    dmabuf_r = hw_ref.get("DMA-BUF", 0)
    dmabuf_c = hw_cur.get("DMA-BUF", 0)
    hw_sub += (
        f"<tr class='sub-row hw-sub' style='display:none;background:#f5f8ff' "
        f"onclick=\"toggleRows('dmabuf-exp')\" style='cursor:pointer'>"
        f"<td style='color:#888;font-size:11px;text-align:center'>"
        f"<span id='btn-dmabuf-exp' style='font-weight:bold;cursor:pointer'>+</span></td>"
        f"<td style='padding-left:28px;color:#444'>&#x2514; DMA-BUF Buffers</td>"
        f"<td class='num'>{mb(dmabuf_r)}</td><td class='num'>{mb(dmabuf_c)}</td>"
        f"{delta_td(dmabuf_r, dmabuf_c)}</tr>\n"
    )

    # DMA-BUF per-exporter sub-rows
    ref_exporters = hw_ref.get("DMA-BUF_exporters", {})
    cur_exporters = hw_cur.get("DMA-BUF_exporters", {})
    all_exporters = sorted(
        set(ref_exporters) | set(cur_exporters),
        key=lambda x: cur_exporters.get(x, 0) + ref_exporters.get(x, 0),
        reverse=True
    )
    for exp in all_exporters:
        r_kb = ref_exporters.get(exp, 0)
        c_kb = cur_exporters.get(exp, 0)
        hw_sub += (
            f"<tr class='sub-row hw-sub dmabuf-exp' style='display:none;background:#f0f5ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
            f"<td style='padding-left:44px;color:#555;font-size:12px'>&#x2514; {exp}</td>"
            f"<td class='num' style='font-size:12px'>{mb(r_kb)}</td>"
            f"<td class='num' style='font-size:12px'>{mb(c_kb)}</td>"
            f"{delta_td(r_kb, c_kb)}</tr>\n"
        )

    # KGSL row
    kgsl_r = hw_ref.get("KGSL", 0)
    kgsl_c = hw_cur.get("KGSL", 0)
    hw_sub += (
        f"<tr class='sub-row hw-sub' style='display:none;background:#f5f8ff'>"
        f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
        f"<td style='padding-left:28px;color:#444'>&#x2514; KGSL GPU Memory</td>"
        f"<td class='num'>{mb(kgsl_r)}</td><td class='num'>{mb(kgsl_c)}</td>"
        f"{delta_td(kgsl_r, kgsl_c)}</tr>\n"
    )

    # Build Kernel Static sub-rows (from dmesg -- may be empty if dmesg not collected)
    ks_ref = ref.get("kernel_static_breakdown", {})
    ks_cur = cur.get("kernel_static_breakdown", {})
    ks_has_data = bool(ks_ref) or bool(ks_cur)
    ks_sub = ""
    if ks_has_data:
        # Show Vmlinux as a top-level sub-entry, then its components
        for key in ["Vmlinux", "Page Structs", "Hash Tables", "Early Boot Reservations"]:
            r_kb = ks_ref.get(key, 0)
            c_kb = ks_cur.get(key, 0)
            ks_sub += (
                f"<tr class='sub-row ks-sub' style='display:none;background:#f5f8ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#444'>&#x2514; {key}</td>"
                f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>"
                f"{delta_td(r_kb, c_kb)}</tr>\n"
            )

    # Row styles
    R_TOP  = "background:#d0dff0;font-weight:bold;"          # Total RAM, Total Available
    R_MID  = "background:#e4edf8;"                            # System RAM, NHLOS
    R_HLOS = "background:#edf3fb;"                            # HLOS section header
    R_SUB  = "background:#f0f5fb;"                            # Kernel Static, Kernel Dynamic, User Space

    def expand_btn(cls):
        return f"<span style='display:inline-block;width:18px;text-align:center;font-weight:bold;color:#1a3a5c;cursor:pointer' id='btn-{cls}'>+</span>"

    # In standalone mode: single value column; in comparison mode: ref + cur + delta
    def val_cells(ref_kb, cur_kb):
        if is_standalone:
            return f"<td style='padding:8px 14px;text-align:right'>{mb(cur_kb)}</td>"
        return (f"<td style='padding:8px 14px;text-align:right'>{mb(ref_kb)}</td>"
                f"<td style='padding:8px 14px;text-align:right'>{mb(cur_kb)}</td>"
                f"{delta_td(ref_kb, cur_kb)}")

    def sub_val_cells(r_kb, c_kb):
        if is_standalone:
            return f"<td class='num'>{mb(c_kb)}</td>"
        return f"<td class='num'>{mb(r_kb)}</td><td class='num'>{mb(c_kb)}</td>{delta_td(r_kb, c_kb)}"

    # Rebuild sub-rows using sub_val_cells
    nhlos_sub2 = ""
    for name in all_nhlos:
        r_kb = nhlos_ref_nodes.get(name, 0)
        c_kb = nhlos_cur_nodes.get(name, 0)
        nhlos_sub2 += (
            f"<tr class='sub-row nhlos-sub' style='display:none;background:#f5f8ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>NHLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {name}</td>"
            f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
        )
    if ref_gap > 0 or cur_gap > 0:
        nhlos_sub2 += (
            f"<tr class='sub-row nhlos-sub' style='display:none;background:#f0f3ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>NHLOS</td>"
            f"<td style='padding-left:28px;color:#888;font-style:italic'>&#x2514; HYP + TZ + UEFI Reservations</td>"
            f"{sub_val_cells(ref_gap, cur_gap)}</tr>\n"
        )

    # Rebuild kd_sub, ks_sub, us_sub, hw_sub using sub_val_cells
    kd_sub2 = ""
    for key in ["Slab", "Vmalloc", "KernelStack", "PageTables", "Percpu", "SecPageTables", "Modules", "CMA", "KDA"]:
        r_kb = kd_ref.get(key, 0)
        c_kb = kd_cur.get(key, 0)
        label = DISPLAY_NAMES.get(key, key)
        if key == "KDA":
            kd_sub2 += (
                f"<tr class='sub-row kd-sub' style='display:none;background:#f0f3ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#888;font-style:italic'>&#x2514; {label}</td>"
                f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
            )
        else:
            kd_sub2 += (
                f"<tr class='sub-row kd-sub' style='display:none;background:#f5f8ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
                f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
            )

    ks_sub2 = ""
    if ks_has_data:
        for key in ["Vmlinux", "Page Structs", "Hash Tables", "Early Boot Reservations"]:
            r_kb = ks_ref.get(key, 0)
            c_kb = ks_cur.get(key, 0)
            ks_sub2 += (
                f"<tr class='sub-row ks-sub' style='display:none;background:#f5f8ff'>"
                f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
                f"<td style='padding-left:28px;color:#444'>&#x2514; {key}</td>"
                f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
            )

    us_sub2 = ""
    for key in ["AnonPages", "Shmem"]:
        r_kb = us_ref.get(key, 0)
        c_kb = us_cur.get(key, 0)
        label = DISPLAY_NAMES.get(key, key)
        us_sub2 += (
            f"<tr class='sub-row us-sub' style='display:none;background:#f5f8ff'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
            f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
        )

    # Total Available sub-rows: MemFree, Cached, Buffers
    avail_ref = ref.get("total_available_breakdown", {})
    avail_cur = cur.get("total_available_breakdown", {})
    avail_sub2 = ""
    for key, label in [("MemFree", "Free Memory"), ("Cached", "Page Cache"), ("Buffers", "Buffers")]:
        r_kb = avail_ref.get(key, 0)
        c_kb = avail_cur.get(key, 0)
        avail_sub2 += (
            f"<tr class='sub-row avail-sub' style='display:none;background:#e8f0fa'>"
            f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
            f"<td style='padding-left:28px;color:#444'>&#x2514; {label}</td>"
            f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
        )

    # DMA-BUF exporter detail (size groups per exporter)
    ref_exp_detail = hw_ref.get("DMA-BUF_exporter_detail", {})
    cur_exp_detail = hw_cur.get("DMA-BUF_exporter_detail", {})

    hw_sub2 = (
        f"<tr class='sub-row hw-sub' style='display:none;background:#f5f8ff' "
        f"onclick=\"toggleRows('dmabuf-exp')\">"
        f"<td style='color:#888;font-size:11px;text-align:center'>"
        f"<span id='btn-dmabuf-exp' style='font-weight:bold;cursor:pointer'>+</span></td>"
        f"<td style='padding-left:28px;color:#444'>&#x2514; DMA-BUF Buffers</td>"
        f"{sub_val_cells(dmabuf_r, dmabuf_c)}</tr>\n"
    )
    for exp in all_exporters:
        r_kb = ref_exporters.get(exp, 0)
        c_kb = cur_exporters.get(exp, 0)
        exp_cls = f"dmabuf-exp-{exp.replace(' ','_').replace('/','_')}"
        # Exporter row -- expandable if it has size detail
        r_groups = ref_exp_detail.get(exp, [])
        c_groups = cur_exp_detail.get(exp, [])
        has_detail = bool(r_groups or c_groups)
        exp_btn = (f"<span id='btn-{exp_cls}' style='font-weight:bold;cursor:pointer;display:inline-block;width:14px;text-align:center'>+</span>"
                   if has_detail else "")
        onclick = f"onclick=\"toggleRows('{exp_cls}')\"" if has_detail else ""
        hw_sub2 += (
            f"<tr class='sub-row hw-sub dmabuf-exp' style='display:none;background:#f0f5ff' {onclick}>"
            f"<td style='color:#888;font-size:11px;text-align:center'>{exp_btn}</td>"
            f"<td style='padding-left:44px;color:#555;font-size:12px'>&#x2514; {exp}</td>"
            f"{sub_val_cells(r_kb, c_kb)}</tr>\n"
        )
        # Size-group rows under this exporter
        if has_detail:
            # Merge ref and cur groups by size_kb
            all_sizes = sorted(
                set(g["size_kb"] for g in r_groups) | set(g["size_kb"] for g in c_groups),
                reverse=True
            )
            for size_kb in all_sizes:
                r_g = next((g for g in r_groups if g["size_kb"] == size_kb), None)
                c_g = next((g for g in c_groups if g["size_kb"] == size_kb), None)
                r_cnt = r_g["count"] if r_g else 0
                c_cnt = c_g["count"] if c_g else 0
                r_tot = r_g["total_kb"] if r_g else 0
                c_tot = c_g["total_kb"] if c_g else 0
                # Format: "18 MB × 7 = 126 MB"
                def fmt_size(kb):
                    if kb >= 1024:
                        return f"{kb//1024} MB"
                    return f"{kb} KB"
                label = f"{fmt_size(size_kb)} &times; {c_cnt if c_cnt else r_cnt} = {fmt_size(c_tot if c_tot else r_tot)}"
                # Use mb_precise for size group value cells (avoids 0 for sub-MB values)
                def precise_val_cells(r_kb, c_kb):
                    if is_standalone:
                        return f"<td class='num' style='font-size:11px'>{mb_precise(c_kb)}</td>"
                    d = c_kb - r_kb
                    d_str = (f"+{mb_precise(d)}" if d > 0 else
                             f"-{mb_precise(-d)}" if d < 0 else "0")
                    color = "#c00" if d > 0 else ("#060" if d < 0 else "#555")
                    fw = "font-weight:bold;" if d != 0 else ""
                    return (f"<td class='num' style='font-size:11px'>{mb_precise(r_kb)}</td>"
                            f"<td class='num' style='font-size:11px'>{mb_precise(c_kb)}</td>"
                            f"<td class='num' style='color:{color};{fw};font-size:11px'>{d_str}</td>")
                hw_sub2 += (
                    f"<tr class='sub-row hw-sub dmabuf-exp {exp_cls}' style='display:none;background:#eef2ff'>"
                    f"<td style='color:#aaa;font-size:10px;text-align:center'></td>"
                    f"<td style='padding-left:60px;color:#666;font-size:11px'>&#x2514; {label}</td>"
                    f"{precise_val_cells(r_tot, c_tot)}</tr>\n"
                )

    hw_sub2 += (
        f"<tr class='sub-row hw-sub' style='display:none;background:#f5f8ff'>"
        f"<td style='color:#888;font-size:11px;text-align:center'>HLOS</td>"
        f"<td style='padding-left:28px;color:#444'>&#x2514; KGSL GPU Memory</td>"
        f"{sub_val_cells(kgsl_r, kgsl_c)}</tr>\n"
    )

    # Table header: single-column in standalone, three-column in comparison
    hdr_cols = (
        f"<th style='padding:10px 14px;text-align:right'>Value<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
        if is_standalone else
        f"<th style='padding:10px 14px;text-align:right'>{ref_label}<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
        f"<th style='padding:10px 14px;text-align:right'>{cur_label}<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
        f"<th style='padding:10px 14px;text-align:right'>Delta<br><span style='font-weight:normal;font-size:11px'>(MB)</span></th>"
    )
    hlos_colspan = 4 if is_standalone else 5

    html = f"""
<div style='max-width:{"640px" if is_standalone else "860px"};margin:0 auto'>
<table style='border-collapse:collapse;width:100%;font-family:Segoe UI,Arial,sans-serif;font-size:13px;box-shadow:0 2px 8px rgba(0,0,0,0.1);border-radius:6px;overflow:hidden'>
<thead>
<tr style='background:#1a3a5c;color:white'>
  <th style='padding:10px 14px;text-align:left;width:120px'>Group</th>
  <th style='padding:10px 14px;text-align:left'>Memory Category</th>
  {hdr_cols}
</tr>
</thead>
<tbody>
<tr style='{R_TOP}'>
  <td style='padding:8px 14px;color:#1a3a5c;font-size:11px;text-align:center'></td>
  <td style='padding:8px 14px'>Total RAM</td>
  {val_cells(ref.get("total_ram_kb",0), cur.get("total_ram_kb",0))}
</tr>
<tr style='{R_MID}' onclick="toggleRows('nhlos-sub')" style='cursor:pointer;{R_MID}'>
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{expand_btn("nhlos-sub")} NHLOS</td>
  <td style='padding:8px 14px'>NHLOS Reserved</td>
  {val_cells(ref.get("nhlos_kb",0), cur.get("nhlos_kb",0))}
</tr>
{nhlos_sub2}
<tr style='{R_MID}'>
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'></td>
  <td style='padding:8px 14px'>System RAM</td>
  {val_cells(ref.get("system_ram_kb",0), cur.get("system_ram_kb",0))}
</tr>
<tr style='background:#2c6fad;color:white'>
  <td colspan='{hlos_colspan}' style='padding:5px 14px;font-size:11px;font-weight:600;letter-spacing:1px'>
    &#x25B6; HLOS -- High Level OS
  </td>
</tr>
<tr style='{"cursor:pointer;" if ks_has_data else ""}{R_SUB}' {"onclick=\"toggleRows('ks-sub')\"" if ks_has_data else ""}>
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{"" + expand_btn("ks-sub") if ks_has_data else ""}</td>
  <td style='padding:8px 14px'>Kernel Static Memory</td>
  {val_cells(ref.get("kernel_static_kb",0), cur.get("kernel_static_kb",0))}
</tr>
{ks_sub2}
<tr style='cursor:pointer;{R_SUB}' onclick="toggleRows('kd-sub')">
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{expand_btn("kd-sub")}</td>
  <td style='padding:8px 14px'>Kernel Dynamic Memory</td>
  {val_cells(ref.get("kernel_dynamic_kb",0), cur.get("kernel_dynamic_kb",0))}
</tr>
{kd_sub2}
<tr style='cursor:pointer;{R_SUB}' onclick="toggleRows('hw-sub')">
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{expand_btn("hw-sub")}</td>
  <td style='padding:8px 14px'>Hardware / Driver Buffers</td>
  {val_cells(ref.get("hw_driver_kb",0), cur.get("hw_driver_kb",0))}
</tr>
{hw_sub2}
<tr style='cursor:pointer;{R_SUB}' onclick="toggleRows('us-sub')">
  <td style='padding:8px 14px;color:#555;font-size:11px;text-align:center'>{expand_btn("us-sub")}</td>
  <td style='padding:8px 14px'>User Space Apps</td>
  {val_cells(ref.get("user_space_kb",0), cur.get("user_space_kb",0))}
</tr>
{us_sub2}
<tr style='cursor:pointer;{R_TOP}' onclick="toggleRows('avail-sub')">
  <td style='padding:8px 14px;color:#1a3a5c;font-size:11px;text-align:center'>{expand_btn("avail-sub")}</td>
  <td style='padding:8px 14px;font-weight:bold'>Total Available Memory</td>
  {val_cells(ref.get("total_available_kb",0), cur.get("total_available_kb",0))}
</tr>
{avail_sub2}
</tbody>
</table>
</div>"""
    return html


# Human-readable names for the Detailed Category Deltas table
CATEGORY_DISPLAY_NAMES = {
    "MemTotal":    "Total Memory",
    "MemFree":     "Free Memory",
    "Slab":        "Slab Allocator",
    "Vmalloc":     "Vmalloc",
    "VmallocUsed": "Vmalloc",
    "PageTables":  "Page Tables",
    "KernelStack": "Kernel Stack",
    "AnonPages":   "Anonymous Pages",
    "Shmem":       "Shared Memory",
    "Cached":      "Cached",
    "Buffers":     "Buffers",
    "SwapCached":  "Swap Cached",
    "DMA-BUF":     "DMA-BUF Buffers",
    "KGSL":        "KGSL GPU Memory",
    "CMA Used":    "CMA Used",
    "NHLOS Total": "NHLOS Total",
}


def _render_top_processes_html(st: dict) -> str:
    """Render top processes by PSS as a collapsible section for standalone mode."""
    procs = st.get("current", {}).get("top_processes", [])
    if not procs:
        return ""
    rows = ""
    for i, p in enumerate(procs, 1):
        pss = p.get("pss_kb", 0)
        name = p.get("name", "")
        # Shorten the name: take basename of first token
        exe = name.split()[0] if name.strip() else name
        short = exe.split("/")[-1][:40]
        rows += (
            f"<tr>"
            f"<td style='text-align:right;color:#888;font-size:11px;padding:5px 10px'>{i}</td>"
            f"<td style='padding:5px 10px' title='{name[:100]}'>{short}</td>"
            f"<td style='text-align:right;padding:5px 10px'>{pss/1024:.1f}</td>"
            f"</tr>\n"
        )
    sec_id = "top-procs"
    return f"""
<div style='max-width:640px;margin:12px auto 0'>
<div style='background:#1a3a5c;color:white;padding:8px 14px;border-radius:6px 6px 0 0;
     cursor:pointer;display:flex;align-items:center;gap:8px'
     onclick="var b=document.getElementById('{sec_id}');var btn=document.getElementById('btn-{sec_id}');
              var c=b.style.display==='none';b.style.display=c?'':'none';btn.textContent=c?'\u2212':'+';">
  <span id='btn-{sec_id}' style='font-weight:bold;min-width:16px'>+</span>
  <span style='font-size:0.95em;font-weight:600'>Top Processes by PSS
    <span style='font-weight:normal;font-size:11px;opacity:0.8'>({len(procs)} shown)</span>
  </span>
</div>
<div id='{sec_id}' style='display:none;border:1px solid #c8d8ea;border-top:none;
     border-radius:0 0 6px 6px;background:#fff;padding:8px'>
<table style='width:100%;border-collapse:collapse;font-size:13px'>
<tr style='background:#2c6fad;color:white'>
  <th style='padding:6px 10px;text-align:right;width:32px'>#</th>
  <th style='padding:6px 10px;text-align:left'>Process</th>
  <th style='padding:6px 10px;text-align:right'>PSS (MB)</th>
</tr>
{rows}
</table>
</div>
</div>"""


def render_top_processes_details_html(
        cur_breakdowns: list, ref_breakdowns: list, is_standalone: bool) -> str:
    """Render 'Top Processes Memory Details' section with collapsible rows using native HTML details/summary."""
    if not cur_breakdowns and not ref_breakdowns:
        return ""

    cur_by_name = {bd["name"]: bd for bd in cur_breakdowns}
    ref_by_name = {bd["name"]: bd for bd in ref_breakdowns}

    # Union: cur first, then ref-only
    seen: set = set()
    all_names: list = []
    for bd in cur_breakdowns + ref_breakdowns:
        if bd["name"] not in seen:
            all_names.append(bd["name"])
            seen.add(bd["name"])
    if not all_names:
        return ""

    def _mb(kb):
        return f"{kb / 1024:.1f}"

    def _ds(d):  # delta style
        if d > 0:
            return "color:#c00;font-weight:bold"
        if d < 0:
            return "color:#060;font-weight:bold"
        return "color:#555"

    def _vc(ref_kb, cur_kb):  # value cells
        if is_standalone:
            return f"<td style='text-align:right;padding:5px 10px'>{_mb(cur_kb)}</td>"
        d = cur_kb - ref_kb
        return (
            f"<td style='text-align:right;padding:5px 10px'>{_mb(ref_kb)}</td>"
            f"<td style='text-align:right;padding:5px 10px'>{_mb(cur_kb)}</td>"
            f"<td style='text-align:right;padding:5px 10px;{_ds(d)}'>{d/1024:+.1f}</td>"
        )

    hdr = (
        "<th style='text-align:left;padding:6px 10px'>Category</th>"
        "<th style='text-align:right;padding:6px 10px'>PSS (MB)</th>"
        if is_standalone else
        "<th style='text-align:left;padding:6px 10px'>Category</th>"
        "<th style='text-align:right;padding:6px 10px'>Ref (MB)</th>"
        "<th style='text-align:right;padding:6px 10px'>Cur (MB)</th>"
        "<th style='text-align:right;padding:6px 10px'>Delta (MB)</th>"
    )
    ncols = 2 if is_standalone else 4

    processes_html = ""
    for name in all_names:
        cur = cur_by_name.get(name)
        ref = ref_by_name.get(name)
        cur_total = cur["total_pss_kb"] if cur else 0
        ref_total = ref["total_pss_kb"] if ref else 0

        if cur and ref:
            status, status_bg = "Changed", "#2c6fad"
        elif cur:
            status, status_bg = "New", "#155724"
        else:
            status, status_bg = "Removed", "#721c24"

        delta_total = cur_total - ref_total

        # --- Anonymous Buffers: show by size only (no per-library attribution) ---
        # Attribution via "nearest preceding named mapping" is unreliable across runs
        # (library load order changes with ASLR), so we show raw buffer sizes only.
        cur_bufs = cur["anon_buffers"] if cur else []
        ref_bufs = ref["anon_buffers"] if ref else []
        display_bufs = cur_bufs if cur_bufs else ref_bufs
        proc_safe_anon = name.replace(" ", "_").replace("-", "_").replace(".", "_")
        _anon_rows = [
            f"<tr style='background:#f8f9ff'>"
            f"<td style='padding:3px 8px 3px 24px;font-size:11px;color:#555'>"
            f"&#x2514; {s:,} KB &nbsp;({s/1024:.1f} MB)</td>"
            f"</tr>\n"
            for s in display_bufs
        ]
        seg_rows_html = _progressive_expand_html(_anon_rows, 5, f"anon-{proc_safe_anon}", 1)
        note_row = ""

        anon_ref_kb = ref["anon_buffers_kb"] if ref else 0
        anon_cur_kb = cur["anon_buffers_kb"] if cur else 0
        d_anon = anon_cur_kb - anon_ref_kb
        anon_delta_hint = (f" &nbsp;<span style='{_ds(d_anon)};font-size:12px'>Δ {d_anon/1024:+.1f} MB</span>"
                           if not is_standalone else "")
        anon_section = f"""
<tr>
  <td colspan='{ncols}' style='padding:0;border-top:1px solid #e0e8f0'>
    <details>
      <summary style='padding:6px 12px;cursor:pointer;background:#edf3fb;
                      font-size:13px;list-style:none;display:list-item'>
        <b>Anonymous Buffers</b>
        <span style='color:#888;font-size:12px;margin-left:8px'>
          {_mb(anon_cur_kb) if is_standalone else (_mb(anon_ref_kb) + ' &rarr; ' + _mb(anon_cur_kb))} MB
        </span>{anon_delta_hint}
      </summary>
      <table style='width:100%;border-collapse:collapse'>{seg_rows_html}</table>
    </details>
  </td>
</tr>"""

        # --- Shared Libraries: build per-library breakdown ---
        cur_libs = cur["shared_libs_detail"] if cur else []
        ref_libs = ref["shared_libs_detail"] if ref else []
        # Build merged list of all library names (union of cur + ref), sorted by cur PSS
        seen_l: set = set()
        all_lib_names: list = []
        for lib in cur_libs + ref_libs:
            if lib["name"] not in seen_l:
                all_lib_names.append(lib["name"])
                seen_l.add(lib["name"])
        cur_libs_map = {lib["name"]: lib["pss_kb"] for lib in cur_libs}
        ref_libs_map = {lib["name"]: lib["pss_kb"] for lib in ref_libs}

        def _lib_row(lname):
            c_kb = cur_libs_map.get(lname, 0)
            r_kb = ref_libs_map.get(lname, 0)
            d = c_kb - r_kb
            if is_standalone:
                val = f"<td style='text-align:right;padding:4px 8px;font-size:12px'>{_mb(c_kb)}</td>"
            else:
                val = (
                    f"<td style='text-align:right;padding:4px 8px;font-size:12px'>{_mb(r_kb)}</td>"
                    f"<td style='text-align:right;padding:4px 8px;font-size:12px'>{_mb(c_kb)}</td>"
                    f"<td style='text-align:right;padding:4px 8px;font-size:12px;{_ds(d)}'>{d/1024:+.1f}</td>"
                )
            return (
                f"<tr style='background:#f5f8ff'>"
                f"<td style='padding:4px 8px 4px 24px;font-size:12px;color:#444'>"
                f"&#x2514; {lname}</td>"
                f"{val}</tr>\n"
            )

        lib_hdr_cols = (
            "<th style='text-align:right;padding:4px 8px;font-size:11px'>PSS (MB)</th>"
            if is_standalone else
            "<th style='text-align:right;padding:4px 8px;font-size:11px'>Ref (MB)</th>"
            "<th style='text-align:right;padding:4px 8px;font-size:11px'>Cur (MB)</th>"
            "<th style='text-align:right;padding:4px 8px;font-size:11px'>Delta (MB)</th>"
        )

        proc_safe_libs = name.replace(" ", "_").replace("-", "_").replace(".", "_")
        _all_lib_rows = [_lib_row(n) for n in all_lib_names]
        libs_progressive = _progressive_expand_html(_all_lib_rows, 5, f"libs-{proc_safe_libs}", ncols)

        libs_table = (
            f"<table style='width:100%;border-collapse:collapse'>"
            f"<tr style='background:#2c6fad;color:white'>"
            f"<th style='text-align:left;padding:4px 8px;font-size:11px'>Library</th>"
            f"{lib_hdr_cols}</tr>"
            f"{libs_progressive}"
            f"</table>"
        )

        libs_ref_kb = ref["shared_libs_kb"] if ref else 0
        libs_cur_kb = cur["shared_libs_kb"] if cur else 0
        d_libs = libs_cur_kb - libs_ref_kb
        libs_delta_hint = (f" &nbsp;<span style='{_ds(d_libs)};font-size:12px'>Δ {d_libs/1024:+.1f} MB</span>"
                           if not is_standalone else "")
        shared_libs_section = f"""
<tr>
  <td colspan='{ncols}' style='padding:0;border-top:1px solid #e0e8f0'>
    <details>
      <summary style='padding:6px 12px;cursor:pointer;background:#edf3fb;
                      font-size:13px;list-style:none;display:list-item'>
        <b>Shared Libraries</b>
        <span style='color:#888;font-size:12px;margin-left:8px'>
          {_mb(libs_cur_kb) if is_standalone else (_mb(libs_ref_kb) + ' &rarr; ' + _mb(libs_cur_kb))} MB
        </span>{libs_delta_hint}
        <span style='color:#aaa;font-size:11px;margin-left:8px'>({len(all_lib_names)} libraries)</span>
      </summary>
      {libs_table}
    </details>
  </td>
</tr>"""

        # Build category rows
        cat_rows = ""
        for cat_name, ref_kb, cur_kb in [
            ("Heap",  ref["heap_kb"]  if ref else 0, cur["heap_kb"]  if cur else 0),
            ("Stack", ref["stack_kb"] if ref else 0, cur["stack_kb"] if cur else 0),
        ]:
            cat_rows += (
                f"<tr style='background:#f8fbff'>"
                f"<td style='padding:5px 10px;font-size:13px'>{cat_name}</td>"
                f"{_vc(ref_kb, cur_kb)}"
                f"</tr>\n"
            )
        cat_rows += shared_libs_section
        cat_rows += anon_section
        cat_rows += (
            f"<tr style='background:#f8fbff'>"
            f"<td style='padding:5px 10px;font-size:13px'>Other</td>"
            f"{_vc(ref['other_kb'] if ref else 0, cur['other_kb'] if cur else 0)}"
            f"</tr>\n"
        )
        cat_rows += (
            f"<tr style='background:#e4edf8;font-weight:bold'>"
            f"<td style='padding:6px 10px'>Total PSS</td>"
            f"{_vc(ref_total, cur_total)}"
            f"</tr>\n"
        )

        # Process summary line
        status_badge = (
            f"<span style='background:{status_bg};color:white;padding:2px 8px;"
            f"border-radius:4px;font-size:11px;font-weight:600;margin-left:8px'>{status}</span>"
        )
        if is_standalone:
            summary_line = f"{name} {status_badge} &nbsp; <span style='font-size:12px;opacity:0.8'>{_mb(cur_total)} MB</span>"
        else:
            d_str = f"Δ {delta_total/1024:+.1f} MB"
            summary_line = (
                f"{name} {status_badge} &nbsp;"
                f"<span style='font-size:12px;opacity:0.8'>"
                f"{_mb(ref_total)} &rarr; {_mb(cur_total)} MB &nbsp; {d_str}</span>"
            )

        processes_html += f"""
<details style='margin-bottom:8px;border:1px solid #c8d8ea;border-radius:6px;overflow:hidden'>
  <summary style='background:#1a3a5c;color:white;padding:10px 16px;cursor:pointer;
                  list-style:none;display:list-item;font-size:14px;font-weight:600'>
    {summary_line}
  </summary>
  <div style='padding:0'>
    <table style='width:100%;border-collapse:collapse;font-size:13px'>
      <thead><tr style='background:#2c6fad;color:white'>{hdr}</tr></thead>
      <tbody>{cat_rows}</tbody>
    </table>
  </div>
</details>"""

    return f"""
<h3 style='margin-top:20px'>Top Processes Memory Details
  <span style='font-weight:normal;font-size:12px;color:#888'>({len(all_names)} processes — click to expand)</span>
</h3>
{processes_html}"""


# Ordered list of (region_type, display_label, accent_color) for the
# Memory Layout filter checkboxes and row styling. Order controls the
# left-to-right order of the checkboxes.
MEMORY_LAYOUT_CATEGORIES = [
    ("nhlos",    "NHLOS",      "#6f42c1"),
    ("reserved", "Reserved",   "#e6a817"),
    ("sysram",   "System RAM", "#28a745"),
    ("kernel",   "Kernel",     "#2c6fad"),
    ("missing",  "Missing",    "#c00000"),
]


def render_memory_layout_html(st: dict) -> str:
    """
    Render the physical Memory Layout section (System RAM blocks, kernel
    code/data sections, generic reserved sub-regions, and NHLOS carve-outs
    with address gaps marked as "Missing"), mirroring the reference
    memmap_Parser.py "MemoryLayout" Excel sheet. Uses the current
    snapshot's layout only (a physical memory map is a snapshot property,
    not something that is diffed between two runs).

    Includes 5 filter checkboxes (NHLOS / Reserved / System RAM / Kernel /
    Missing) rendered horizontally above the table. Checking one or more
    boxes filters the table to show only rows of the checked type(s);
    with none checked, all rows are shown (default).
    """
    layout = st.get("current", {}).get("memory_layout", [])
    if not layout:
        return ""

    ROW_STYLE = {
        "sysram":   "background:#e8f8e8",             # green -- accessible System RAM
        "kernel":   "background:#eef2ff",             # light purple -- kernel code/data section
        "reserved": "background:#fff8e6",             # light amber -- generic reserved carve-out
        "nhlos":    "background:#fff",                # default -- NHLOS carve-out
        "missing":  "background:#fde8e8;font-weight:bold;color:#c00",  # red -- address gap
    }

    table_id = "mem-layout-tbl"

    rows = ""
    total_sysram_mb = 0.0
    total_carveout_mb = 0.0
    total_mb = 0.0
    for name, start, end, size_mb, region_type in layout:
        style = ROW_STYLE.get(region_type, "")
        is_sysram = (region_type == "sysram")
        sysram_mb = size_mb if is_sysram else 0
        # Everything that is not accessible System RAM counts toward the
        # carve-out column -- including "Missing" rows, which are small
        # unaccounted gaps *within* the physical RAM range (real reserved
        # space the kernel doesn't attribute to a named region). This
        # matches the reference memmap_Parser.py behaviour.
        #
        # Note: large multi-GB address-space holes between physically
        # discontiguous DDR banks are NOT emitted as "Missing" rows at all
        # (they are dropped upstream in build_memory_layout() by the 1 GB
        # GAP_THRESHOLD_MB filter), so accumulating Missing here cannot
        # inflate the Total beyond the board's real RAM size.
        carveout_mb = size_mb if not is_sysram else 0
        total_sysram_mb += sysram_mb
        total_carveout_mb += carveout_mb
        total_mb += size_mb
        # data-* attributes are read by filterMemoryLayout() to recompute the
        # Total row from only the currently-visible (filtered) rows.
        rows += (
            f"<tr class='memlayout-row' data-type='{region_type}' "
            f"data-size='{size_mb:.2f}' data-sysram='{sysram_mb:.2f}' "
            f"data-carveout='{carveout_mb:.2f}' style='{style}'>"
            f"<td style='padding:5px 10px'>{name}</td>"
            f"<td style='padding:5px 10px;font-family:monospace;font-size:12px'>{hex(start)}</td>"
            f"<td style='padding:5px 10px;font-family:monospace;font-size:12px'>{hex(end)}</td>"
            f"<td style='padding:5px 10px;text-align:right'>{size_mb:.2f}</td>"
            f"<td style='padding:5px 10px;text-align:right'>{sysram_mb:.2f}</td>"
            f"<td style='padding:5px 10px;text-align:right'>{carveout_mb:.2f}</td>"
            f"</tr>\n"
        )

    # Total footer -- values carry element IDs so the filter JS can update
    # them live as categories are checked/unchecked.
    rows += (
        f"<tr class='memlayout-total-row' style='background:#d0dff0;font-weight:bold'>"
        f"<td style='padding:6px 10px'>Total</td>"
        f"<td style='padding:6px 10px'></td>"
        f"<td style='padding:6px 10px'></td>"
        f"<td style='padding:6px 10px;text-align:right'>"
        f"<span id='{table_id}-total-size'>{total_mb:.2f}</span></td>"
        f"<td style='padding:6px 10px;text-align:right'>"
        f"<span id='{table_id}-total-sysram'>{total_sysram_mb:.2f}</span></td>"
        f"<td style='padding:6px 10px;text-align:right'>"
        f"<span id='{table_id}-total-carveout'>{total_carveout_mb:.2f}</span></td>"
        f"</tr>\n"
    )

    # Build the horizontal row of filter checkboxes, one per category.
    # Counts are shown next to each label for quick reference.
    type_counts: dict = {}
    for _n, _s, _e, _mb, rtype in layout:
        type_counts[rtype] = type_counts.get(rtype, 0) + 1

    # Each checkbox is a flex item with flex:1 so the five pills share the
    # full width of the table equally (equidistant), regardless of label length.
    checkboxes_html = ""
    for rtype, label, color in MEMORY_LAYOUT_CATEGORIES:
        count = type_counts.get(rtype, 0)
        checkboxes_html += (
            f"<label style='flex:1 1 0;display:inline-flex;align-items:center;"
            f"justify-content:center;gap:7px;padding:9px 10px;"
            f"border:1.5px solid {color};border-radius:22px;cursor:pointer;"
            f"font-size:12.5px;font-weight:600;color:{color};background:#fff;"
            f"user-select:none;white-space:nowrap;"
            f"box-shadow:0 1px 3px rgba(20,50,90,0.07);transition:background 0.12s ease'>"
            f"<input type='checkbox' class='memlayout-filter' value='{rtype}' "
            f"data-table='{table_id}' style='accent-color:{color};cursor:pointer;margin:0' "
            f"onchange=\"filterMemoryLayout('{table_id}')\">"
            f"{label} <span style='opacity:0.6;font-weight:400'>({count})</span>"
            f"</label>\n"
        )

    return f"""
<div style='max-width:900px;margin:0 auto'>
<div style='display:flex;align-items:stretch;gap:12px;margin:0 0 14px'>
{checkboxes_html}
</div>
<p style='color:#888;font-size:12px;margin:0 0 8px'>
  Showing <b id='{table_id}-shown-count' style='color:#2c6fad'>{len(layout)}</b>
  of {len(layout)} regions -- physical address map (System RAM blocks, kernel
  code/data sections, reserved carve-outs, and NHLOS carve-outs, sorted by address).
  Totals below update with the selected filters.
</p>
<div style='max-height:600px;overflow-y:auto;border:1px solid #d5e0ec;border-radius:6px'>
<table id='{table_id}' style='width:100%;border-collapse:collapse;font-size:13px;margin:0'>
<thead><tr style='background:#2c6fad;color:white'>
  <th style='padding:6px 10px;text-align:left'>Region Name</th>
  <th style='padding:6px 10px;text-align:left'>Start Address</th>
  <th style='padding:6px 10px;text-align:left'>End Address</th>
  <th style='padding:6px 10px;text-align:right'>Size (MB)</th>
  <th style='padding:6px 10px;text-align:right'>SystemRAM (MB)</th>
  <th style='padding:6px 10px;text-align:right'>Carveout (MB)</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>"""


def render_ipcat_layout_html(data: dict) -> str:
    """
    Render the "IPCat Memory Layout" table -- a comparison of the device's
    collected physical memory layout ("Target") against the IP Catalog
    (IPCat) reference memory map for the matching chip, as produced by
    internal/ipcat-memory-layout/scripts/ipcat_layout.py.

    Columns: IPCat Region, IPCat Start Address, IPCat End Address,
             IPCat Size (MB), Target Region, Target Start Address,
             Target End Address, Target Size (MB), Matching.
    """
    rows_data = data.get("rows", [])
    if not rows_data:
        return "<p style='color:#888'>No IPCat layout data available.</p>"

    def _addr(v):
        return hex(v) if isinstance(v, int) else (v if v else "--")

    def _size(v):
        return f"{v:.2f}" if isinstance(v, (int, float)) else "--"

    def _name(v):
        return v if v else "--"

    # Per user requirement: when multiple consecutive output rows share the
    # same IPCat region (identical name + start + end -- e.g. several
    # Target sub-regions tiling across one IPCat region such as "UEFI"),
    # the IPCat-side columns are merged into a single rowspan'd cell group
    # instead of repeating the same IPCat name/start/end/size on every row.
    # The Target-side columns (and the Matching column, which reflects each
    # individual Target overlap) are NEVER merged -- every Target overlap
    # still gets its own full row.
    def _ipcat_key(r):
        return (r.get("region"), r.get("ipcat_start"), r.get("ipcat_end"))

    # First pass: compute consecutive run-length for each row's IPCat key.
    run_start_idx: list[int] = [0] * len(rows_data)
    i = 0
    while i < len(rows_data):
        j = i
        while j + 1 < len(rows_data) and _ipcat_key(rows_data[j + 1]) == _ipcat_key(rows_data[i]):
            j += 1
        for k in range(i, j + 1):
            run_start_idx[k] = i
        i = j + 1

    table_id = "ipcat-layout-tbl"

    # Per user requirement, the IPCat-side merge-via-rowspan must NOT break
    # the table when rows are hidden by the Matching/Mismatching filter.
    # Static Python-rendered rowspan breaks as soon as the row carrying the
    # spanned <td> gets hidden (display:none) while a later row in the same
    # group remains visible -- the browser has no cell to fill that slot in
    # the visible row, misaligning every column to its right.
    #
    # Fix: every row ALWAYS renders its own full, independent set of IPCat
    # <td> cells (tagged with class 'ipcat-cell' and a shared 'data-group'
    # id per merge-group). A JS helper (refreshIpcatMerge(), see CSS/script
    # block) then dynamically shows the IPCat cells only on the first
    # *currently visible* row of each group (setting that row's cells'
    # rowspan to the number of visible rows in the group) and hides the
    # IPCat cells (not the whole <tr>) on the rest. This routine re-runs
    # after every filter change, so the merge always reflects exactly what
    # is visible -- the table structure can never desync from the filter.
    rows_html = ""
    idx = 0
    while idx < len(rows_data):
        run_first = run_start_idx[idx]
        # Count how many rows share this IPCat key starting at run_first.
        run_len = 1
        while run_first + run_len < len(rows_data) and run_start_idx[run_first + run_len] == run_first:
            run_len += 1

        # A merge-group with more than one row is always styled red on the
        # IPCat side (splitting proves no single carve-out cleanly matches
        # the full IPCat region), regardless of any individual tile's own
        # Matching value. A non-split (group size 1) row uses that row's
        # own Matching-based color as before.
        ipcat_bg = "background:#fde8e8;" if run_len > 1 else ""

        for offset in range(run_len):
            r = rows_data[run_first + offset]
            matching = r.get("matching", "No")
            row_style = "background:#e8f8e8" if matching == "Yes" else "background:#fde8e8"
            badge_color = "#155724" if matching == "Yes" else "#721c24"
            badge_bg = "#d4edda" if matching == "Yes" else "#f8d7da"

            row_ipcat_bg = (
                ipcat_bg if run_len > 1
                else ("background:#e8f8e8;" if matching == "Yes" else "background:#fde8e8;")
            )

            ipcat_cells = (
                f"<td class='ipcat-cell' style='padding:5px 10px;text-align:center;vertical-align:middle;{row_ipcat_bg}'>{_name(r.get('region'))}</td>"
                f"<td class='ipcat-cell' style='padding:5px 10px;font-family:monospace;font-size:12px;text-align:center;vertical-align:middle;{row_ipcat_bg}'>{_addr(r.get('ipcat_start'))}</td>"
                f"<td class='ipcat-cell' style='padding:5px 10px;font-family:monospace;font-size:12px;text-align:center;vertical-align:middle;{row_ipcat_bg}'>{_addr(r.get('ipcat_end'))}</td>"
                f"<td class='ipcat-cell' style='padding:5px 10px;text-align:center;vertical-align:middle;{row_ipcat_bg}'>{_size(r.get('ipcat_size_mb'))}</td>"
            )

            # data-matching is read by filterIpcatLayout() so the Matching /
            # Mismatching filter checkboxes can show/hide rows client-side.
            # data-group identifies this row's merge-group for
            # refreshIpcatMerge() to recompute the visible-rowspan merge.
            rows_html += (
                f"<tr class='ipcatlayout-row' data-matching='{matching}' data-group='{run_first}' style='{row_style}'>"
                f"{ipcat_cells}"
                f"<td style='padding:5px 10px;text-align:center'>{_name(r.get('target_region'))}</td>"
                f"<td style='padding:5px 10px;font-family:monospace;font-size:12px;text-align:center'>{_addr(r.get('target_start'))}</td>"
                f"<td style='padding:5px 10px;font-family:monospace;font-size:12px;text-align:center'>{_addr(r.get('target_end'))}</td>"
                f"<td style='padding:5px 10px;text-align:center'>{_size(r.get('target_size_mb'))}</td>"
                f"<td style='padding:5px 10px;text-align:center'>"
                f"<span style='background:{badge_bg};color:{badge_color};padding:2px 10px;"
                f"border-radius:10px;font-size:11px;font-weight:600'>{matching}</span></td>"
                f"</tr>\n"
            )

        idx = run_first + run_len

    s = data.get("summary", {})
    chip = data.get("chip", "")
    total = s.get("total", len(rows_data))
    matched_count = s.get("matched", 0)
    mismatched_count = s.get("mismatched", 0)
    summary_line = (
        f"<p style='color:#555;font-size:12px;margin:0 0 8px'>"
        f"{f'<b>Chip:</b> {chip} &nbsp;|&nbsp; ' if chip else ''}"
        f"<b>Total regions:</b> {total} &nbsp;|&nbsp; "
        f"Showing <b id='{table_id}-shown-count' style='color:#2c6fad'>{total}</b> of {total}</p>"
    )

    # Filter checkboxes -- let the user show only Matching or only
    # Mismatching rows (or both, the default). Mirrors the filter-pill
    # pattern used by the "Memory Layout" section's filterMemoryLayout().
    filter_pills = (
        f"<label style='flex:1 1 0;display:inline-flex;align-items:center;"
        f"justify-content:center;gap:7px;padding:9px 10px;"
        f"border:1.5px solid #28a745;border-radius:22px;cursor:pointer;"
        f"font-size:12.5px;font-weight:600;color:#28a745;background:#fff;"
        f"user-select:none;white-space:nowrap;"
        f"box-shadow:0 1px 3px rgba(20,50,90,0.07)'>"
        f"<input type='checkbox' class='ipcatlayout-filter' value='Yes' "
        f"data-table='{table_id}' style='accent-color:#28a745;cursor:pointer;margin:0' "
        f"onchange=\"filterIpcatLayout('{table_id}')\">"
        f"Matching <span style='opacity:0.6;font-weight:400'>({matched_count})</span>"
        f"</label>\n"
        f"<label style='flex:1 1 0;display:inline-flex;align-items:center;"
        f"justify-content:center;gap:7px;padding:9px 10px;"
        f"border:1.5px solid #c00000;border-radius:22px;cursor:pointer;"
        f"font-size:12.5px;font-weight:600;color:#c00000;background:#fff;"
        f"user-select:none;white-space:nowrap;"
        f"box-shadow:0 1px 3px rgba(20,50,90,0.07)'>"
        f"<input type='checkbox' class='ipcatlayout-filter' value='No' "
        f"data-table='{table_id}' style='accent-color:#c00000;cursor:pointer;margin:0' "
        f"onchange=\"filterIpcatLayout('{table_id}')\">"
        f"Mismatching <span style='opacity:0.6;font-weight:400'>({mismatched_count})</span>"
        f"</label>\n"
    )

    return f"""
<div style='max-width:1000px;margin:0 auto'>
<div style='display:flex;align-items:stretch;gap:12px;margin:0 0 10px;max-width:420px'>
{filter_pills}
</div>
{summary_line}
<div style='max-height:600px;overflow-y:auto;border:1px solid #d5e0ec;border-radius:6px'>
<table id='{table_id}' style='width:100%;border-collapse:collapse;font-size:13px;margin:0'>
<thead><tr style='background:#2c6fad;color:white'>
  <th style='padding:6px 10px;text-align:center'>IPCat Region</th>
  <th style='padding:6px 10px;text-align:center'>IPCat Start Address</th>
  <th style='padding:6px 10px;text-align:center'>IPCat End Address</th>
  <th style='padding:6px 10px;text-align:center'>IPCat Size (MB)</th>
  <th style='padding:6px 10px;text-align:center'>Target Region</th>
  <th style='padding:6px 10px;text-align:center'>Target Start Address</th>
  <th style='padding:6px 10px;text-align:center'>Target End Address</th>
  <th style='padding:6px 10px;text-align:center'>Target Size (MB)</th>
  <th style='padding:6px 10px;text-align:center'>Matching</th>
</tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>
</div>
<script>
// Apply the IPCat-side rowspan merge on initial page render (every row is
// rendered with its own full set of IPCat cells by default -- this call
// establishes the initial merged/grouped appearance before any filter
// interaction, and is safe to re-run any number of times).
refreshIpcatMerge('{table_id}');
</script>"""


def render_comparison_html(data: dict) -> str:
    # Detect standalone mode (self-comparison)
    is_standalone = (
        data.get("current_snapshot_id") == data.get("reference_snapshot_id")
        and data.get("current_snapshot_id", "") != ""
    )

    # Summary table at the top
    summary_html = render_summary_table_html(data)

    if is_standalone:
        # In standalone mode: memory breakdown + top processes, no delta table.
        # Memory Layout is rendered as its own top-level section (see
        # build_unified_html) rather than nested inside this summary.
        top_procs_html = _render_top_processes_html(data.get("summary_table", {}))
        smaps_html = render_top_processes_details_html(
            data.get("_smaps_cur", []), [], True)
        return summary_html + top_procs_html + smaps_html

    rows = ""
    for cat in data.get("categories", []):
        trend = cat.get("trend", "STABLE")
        css = {"GROWING": "growing", "SHRINKING": "shrinking"}.get(trend, "")
        display_name = CATEGORY_DISPLAY_NAMES.get(cat["category"], cat["category"])
        rows += (
            f"<tr class='{css}'>"
            f"<td>{display_name}</td>"
            f"<td style='text-align:right'>{cat['reference_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{cat['current_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{cat['delta_kb']/1024:+.1f}</td>"
            f"<td style='text-align:right'>{cat['delta_pct']:+.1f}%</td>"
            f"<td>{trend}</td>"
            f"</tr>\n"
        )
    # Memory Layout is rendered as its own top-level section (see
    # build_unified_html) rather than nested inside this summary.
    return f"""
<p><b>Current:</b> {data.get('current_label','')} &nbsp;|&nbsp;
   <b>Reference:</b> {data.get('reference_label','')}</p>
{summary_html}"""


def render_kernel_diff_html(data: dict) -> str:
    bd = data.get("buddy_fragmentation", {})
    slab_rows = ""
    for s in data.get("slab_diff", [])[:50]:
        css = "warning" if s.get("flagged") else ""
        slab_rows += (
            f"<tr class='{css}'>"
            f"<td>{s['name']}</td>"
            f"<td style='text-align:right'>{s['ref_kb']}</td>"
            f"<td style='text-align:right'>{s['cur_kb']}</td>"
            f"<td style='text-align:right'>{s['delta_kb']:+}</td>"
            f"<td style='text-align:right'>{s['delta_pct']:+.1f}%</td>"
            f"<td>{'[!]' if s.get('flagged') else ''}</td>"
            f"</tr>\n"
        )
    findings = "".join(
        f"<li class='{f['severity'].lower()}'>[{f['severity']}] {f['message']}</li>"
        for f in data.get("findings", [])
    )
    return f"""
<h3>Buddy Fragmentation</h3>
<p>Reference: {bd.get('reference_index',0):.4f} &rarr;
   Current: {bd.get('current_index',0):.4f}
   (delta: {bd.get('fragmentation_index_delta',0):+.4f})</p>
<h3>Slab Changes (top 50 by delta)</h3>
<table><tr><th>Slab</th><th>Ref KB</th><th>Cur KB</th>
<th>Delta KB</th><th>Delta %</th><th>Flag</th></tr>
{slab_rows}</table>
{'<h3>Findings</h3><ul>' + findings + '</ul>' if findings else ''}"""


def _short_name(cmdline: str) -> str:
    """Return a short readable process name from a full cmdline string."""
    # Take the first token (the executable), then basename
    exe = cmdline.split()[0] if cmdline.strip() else cmdline
    # Strip path
    name = exe.split("/")[-1].split("\\")[-1]
    # Truncate to 40 chars
    return name[:40]


def render_userspace_diff_html(data: dict) -> str:
    # Filter out 0-delta processes and sort by |delta_pss_kb| descending
    all_procs = data.get("process_diff", [])
    changed = sorted(
        [p for p in all_procs if p.get("delta_pss_kb", 0) != 0],
        key=lambda x: abs(x.get("delta_pss_kb", 0)),
        reverse=True
    )
    total_changed = len(changed)

    def proc_row(p):
        css = "warning" if p.get("flagged") else ""
        short = _short_name(p["name"])
        full  = p["name"][:80] + ("..." if len(p["name"]) > 80 else "")
        return (
            f"<tr class='{css}'>"
            f"<td title='{full}'>{short}</td>"
            f"<td style='text-align:right'>{p['ref_pss_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{p['cur_pss_kb']/1024:.1f}</td>"
            f"<td style='text-align:right'>{p['delta_pss_kb']/1024:+.1f}</td>"
            f"<td style='text-align:right'>{p['delta_pct']:+.1f}%</td>"
            f"<td>{'[!]' if p.get('flagged') else ''}</td>"
            f"</tr>\n"
        )

    subtitle = f"({total_changed} processes changed" + (f", {len(all_procs)-total_changed} unchanged hidden" if len(all_procs) > total_changed else "") + ")"

    dma = data.get("dmabuf_diff", {})
    kgsl = data.get("kgsl_diff", {})
    findings = "".join(
        f"<li class='{f['severity'].lower()}'>[{f['severity']}] {f['message']}</li>"
        for f in data.get("findings", [])
    )

    if not changed:
        proc_table = "<p style='color:#888'>No process PSS changes detected.</p>"
    else:
        all_proc_rows = [proc_row(p) for p in changed]
        proc_rows_html = _progressive_expand_html(all_proc_rows, 5, "proc", 6)
        proc_table = f"""
<table><tr><th>Process</th><th>Ref PSS MB</th><th>Cur PSS MB</th>
<th>Delta MB</th><th>Delta %</th><th>Flag</th></tr>
{proc_rows_html}
</table>"""

    # New and exited processes
    new_procs = data.get("new_processes", [])
    exited_procs = data.get("exited_processes", [])

    def _proc_row_simple(p):
        return (
            f"<tr>"
            f"<td title='{p.get('name','')[:80]}'>{_short_name(p.get('name',''))}</td>"
            f"<td style='text-align:right'>{p.get('pss_kb',0)/1024:.1f}</td>"
            f"</tr>\n"
        )

    new_exited_section = ""
    if new_procs:
        rows_new = "".join(_proc_row_simple(p) for p in
                           sorted(new_procs, key=lambda x: x.get("pss_kb", 0), reverse=True))
        new_exited_section += f"""
<h3>New Processes <span style='font-weight:normal;font-size:12px;color:#888'>({len(new_procs)} appeared since baseline)</span></h3>
<table><tr><th>Process</th><th>PSS (MB)</th></tr>
{rows_new}</table>"""
    if exited_procs:
        rows_exited = "".join(_proc_row_simple(p) for p in
                              sorted(exited_procs, key=lambda x: x.get("pss_kb", 0), reverse=True))
        new_exited_section += f"""
<h3>Exited Processes <span style='font-weight:normal;font-size:12px;color:#888'>({len(exited_procs)} present in baseline only)</span></h3>
<table><tr><th>Process</th><th>PSS (MB)</th></tr>
{rows_exited}</table>"""

    smaps_html = render_top_processes_details_html(
        data.get("_smaps_cur", []), data.get("_smaps_ref", []), False)
    return f"""
<h3>Process PSS Changes <span style='font-weight:normal;font-size:12px;color:#888'>{subtitle}</span></h3>
{proc_table}
{new_exited_section}
{smaps_html}"""


def _section_title_for(rtype: str, data: dict) -> str:
    """Return section title, using 'Memory Summary' for standalone snapshots."""
    titles = {
        "rca":                 "Root Cause Analysis",
        "carveout_validation": "NHLOS Carveout Validation",
        "snapshot_comparison": "Memory Delta Summary",
        "kernel_diff":         "Kernel Memory Changes",
        "userspace_diff":      "Userspace Memory Changes",
        "ipcat_layout":        "IPCat Memory Layout",
    }
    title = titles.get(rtype, f"Report ({rtype})")
    # Override for standalone mode (self-comparison)
    if rtype == "snapshot_comparison":
        is_standalone = (
            data.get("current_snapshot_id") == data.get("reference_snapshot_id")
            and data.get("current_snapshot_id", "") != ""
        )
        if is_standalone:
            title = "Memory Summary"
    return title


SECTION_RENDERERS = {
    "rca":                 ("Root Cause Analysis",          render_rca_html),
    "carveout_validation": ("NHLOS Carveout Validation",    render_carveout_html),
    "snapshot_comparison": ("Memory Delta Summary",         render_comparison_html),
    "kernel_diff":         ("Kernel Memory Changes",        render_kernel_diff_html),
    "userspace_diff":      ("Userspace Memory Changes",     render_userspace_diff_html),
    "ipcat_layout":        ("IPCat Memory Layout",          render_ipcat_layout_html),
}


# ---------------------------------------------------------------------------
# Unified HTML report
# ---------------------------------------------------------------------------

def render_device_info_html(device: dict, max_width: str = "640px") -> str:
    """Render a compact device info table for the top of the report."""
    if not device:
        return ""
    model    = device.get("model", "")
    kernel   = device.get("kernel_version", "")
    os_name  = device.get("os_name", "")
    build_id = device.get("build_id", "")
    soc_name = device.get("soc_name", "")   # e.g. QCS6490 from /sys/devices/soc0/machine
    soc_rev  = device.get("soc_revision", "")
    serial          = device.get("serial", "")
    network_address = device.get("network_address", "")
    transport_type  = device.get("transport_type", "")
    ts              = device.get("captured_at", "")

    # Build SoC string: "QCS6490 rev 1.0" or just "QCS6490"
    soc_str = soc_name
    if soc_rev and soc_name:
        soc_str += f" rev {soc_rev}"

    row_styles = ["background:#e4edf8;", "background:#f0f5fb;"]
    row_idx = [0]
    rows = ""
    def row(label, value):
        if not value:
            return ""
        style = row_styles[row_idx[0] % 2]
        row_idx[0] += 1
        return (f"<tr style='{style}'>"
                f"<td style='color:#555;font-size:12px;padding:6px 20px;white-space:nowrap;font-weight:500'>{label}</td>"
                f"<td style='padding:6px 20px;font-size:12px'>{value}</td>"
                f"</tr>\n")

    rows += row("Machine", model)
    rows += row("SoC", soc_str)
    rows += row("OS", os_name)
    rows += row("Build", build_id)
    rows += row("Kernel", kernel)
    # Show "Network Address" for SSH transport, "Device ID" for ADB transport
    if transport_type == "ssh":
        rows += row("Network Address", network_address)
    else:
        rows += row("Device ID", serial)
    rows += row("Captured", ts)

    if not rows:
        return ""

    return f"""
<div style='max-width:{max_width};margin:0 auto 16px'>
<div style='background:#fff;border:1px solid #c8d8ea;border-radius:6px;
     overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)'>
<div style='background:#2c6fad;color:white;padding:8px 16px;font-size:11px;font-weight:600;letter-spacing:0.5px'>
  &#x1F4BB; Device Information
</div>
<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:13px;width:100%'>
<thead>
<tr style='background:#1a3a5c;color:white'>
  <th style='padding:8px 14px;text-align:left;font-weight:600;width:140px'>Field</th>
  <th style='padding:8px 14px;text-align:left;font-weight:600'>Value</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>"""


def render_usecase_details_html(data: dict, max_width: str = "860px") -> str:
    """Render Use Case Details block for comparison reports."""
    usecase_name = data.get("usecase_name", "")
    usecase_cmd  = data.get("usecase_command", "")
    cur_label    = data.get("current_label", "")
    ref_label    = data.get("reference_label", "")

    if not usecase_name and not usecase_cmd:
        return ""

    row_styles = ["background:#e4edf8;", "background:#f0f5fb;"]
    row_idx = [0]
    rows = ""
    def row(label, value, mono=False):
        if not value:
            return ""
        style = row_styles[row_idx[0] % 2]
        row_idx[0] += 1
        val_style = "font-family:monospace;font-size:11px" if mono else "font-size:12px"
        return (f"<tr style='{style}'>"
                f"<td style='color:#555;font-size:12px;padding:6px 20px;white-space:nowrap;font-weight:500'>{label}</td>"
                f"<td style='padding:6px 20px;{val_style}'>{value}</td>"
                f"</tr>\n")

    rows += row("Use-Case", usecase_name)
    rows += row("Command", usecase_cmd, mono=True)
    rows += row("Baseline", ref_label)
    rows += row("Active", cur_label)

    return f"""
<div style='max-width:{max_width};margin:0 auto 16px'>
<div style='background:#fff;border:1px solid #c8d8ea;border-radius:6px;
     overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)'>
<div style='background:#2c6fad;color:white;padding:8px 16px;font-size:11px;font-weight:600;letter-spacing:0.5px'>
  &#x1F9EA; Use Case Details
</div>
<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:13px;width:100%'>
<thead>
<tr style='background:#1a3a5c;color:white'>
  <th style='padding:8px 14px;text-align:left;font-weight:600;width:140px'>Field</th>
  <th style='padding:8px 14px;text-align:left;font-weight:600'>Value</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>"""


def render_findings_html(sections: list[tuple[str, str, dict]]) -> str:
    """Collect findings from all loaded reports and render as a unified section."""
    SEV_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    SEV_COLORS = {
        "CRITICAL": ("#c00",    "#fff5f5", "#fde8e8"),
        "WARNING":  ("#e6a817", "#fffdf0", "#fef8e0"),
        "INFO":     ("#2c6fad", "#f0f7ff", "#e8f4fd"),
    }
    SOURCE_LABELS = {
        "snapshot_comparison": "Memory Delta",
        "userspace_diff":      "Userspace Diff",
        "kernel_diff":         "Kernel Diff",
        "rca":                 "RCA",
        "carveout_validation": "Carveout",
    }

    all_findings = []
    for rtype, path, data in sections:
        source_label = SOURCE_LABELS.get(rtype, rtype)
        for f in data.get("findings", []):
            all_findings.append({
                "severity": f.get("severity", "INFO"),
                "message":  f.get("message", ""),
                "source":   source_label,
            })

    if not all_findings:
        return ""

    # Sort by severity
    all_findings.sort(key=lambda x: SEV_ORDER.get(x["severity"], 99))

    counts = {s: sum(1 for f in all_findings if f["severity"] == s) for s in SEV_ORDER}
    summary_badges = ""
    for sev, cnt in counts.items():
        if cnt == 0:
            continue
        color, _, bg = SEV_COLORS.get(sev, ("#555", "#fff", "#f8f8f8"))
        summary_badges += (
            f"<span style='background:{bg};color:{color};border:1px solid {color};"
            f"padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;"
            f"margin-right:6px'>{sev}: {cnt}</span>"
        )

    rows = ""
    for f in all_findings:
        sev = f["severity"]
        color, bg_card, bg_row = SEV_COLORS.get(sev, ("#555", "#fff", "#f8f8f8"))
        icon = {"CRITICAL": "&#x26A0;", "WARNING": "&#x26A0;", "INFO": "&#x2139;"}.get(sev, "")
        rows += (
            f"<tr style='background:{bg_row}'>"
            f"<td style='padding:8px 12px;white-space:nowrap'>"
            f"<span style='color:{color};font-weight:600;font-size:12px'>{icon} {sev}</span></td>"
            f"<td style='padding:8px 12px;color:#555;font-size:12px;white-space:nowrap'>"
            f"{f['source']}</td>"
            f"<td style='padding:8px 12px;font-size:13px'>{f['message']}</td>"
            f"</tr>\n"
        )

    return f"""
<div style='margin-bottom:8px'>{summary_badges}</div>
<table style='border-collapse:collapse;width:100%;font-size:13px'>
<thead>
<tr style='background:#1a3a5c;color:white'>
  <th style='padding:8px 12px;text-align:left;white-space:nowrap'>Severity</th>
  <th style='padding:8px 12px;text-align:left;white-space:nowrap'>Source</th>
  <th style='padding:8px 12px;text-align:left'>Message</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>"""


def build_unified_html(sections: list[tuple[str, str, dict]], title: str) -> str:
    """
    Build a single unified HTML report.
    Section order: snapshot_comparison -> kernel_diff -> userspace_diff -> findings -> rca -> others
    Kernel/Userspace/Findings sections are collapsed by default.
    Summary and RCA are always visible.
    """
    # Sort sections into desired order
    ORDER = ["snapshot_comparison", "kernel_diff", "userspace_diff", "rca"]
    def sort_key(item):
        rtype = item[0]
        return ORDER.index(rtype) if rtype in ORDER else len(ORDER)
    sections = sorted(sections, key=sort_key)

    # Sections that start collapsed
    COLLAPSED_BY_DEFAULT = {"kernel_diff", "userspace_diff"}

    body = ""
    sec_id = 0
    for rtype, path, data in sections:
        sec_id += 1
        sid = f"sec-{sec_id}"
        _, renderer = SECTION_RENDERERS.get(
            rtype, (f"Report ({rtype})", lambda d: f"<pre>{json.dumps(d, indent=2)}</pre>")
        )
        section_title = _section_title_for(rtype, data)
        collapsed = "collapsed" if rtype in COLLAPSED_BY_DEFAULT else ""
        btn_char  = "+" if rtype in COLLAPSED_BY_DEFAULT else "\u2212"
        content   = renderer(data)

        body += f"""
<div class='section-block'>
  <div class='section-header' onclick="toggleSection('{sid}')">
    <span class='section-toggle' id='toggle-{sid}'>{btn_char}</span>
    <span class='section-title'>{section_title}</span>
  </div>
  <div class='section-body {collapsed}' id='{sid}'>
    {content}
  </div>
</div>
"""

        # Memory Layout is rendered as its own top-level section (sibling of
        # Memory Summary) rather than nested inside it, so it gets its own
        # collapsible card with the same visual treatment.
        if rtype == "snapshot_comparison":
            layout_content = render_memory_layout_html(data.get("summary_table", {}))
            if layout_content:
                sec_id += 1
                lsid = f"sec-{sec_id}"
                body += f"""
<div class='section-block'>
  <div class='section-header' onclick="toggleSection('{lsid}')">
    <span class='section-toggle' id='toggle-{lsid}'>\u2212</span>
    <span class='section-title'>Memory Layout</span>
  </div>
  <div class='section-body' id='{lsid}'>
    {layout_content}
  </div>
</div>
"""

    # Unified Findings section (collapsed by default, after userspace_diff)
    findings_content = render_findings_html(sections)
    if findings_content:
        sec_id += 1
        sid = f"sec-{sec_id}"
        total_findings = sum(len(d.get("findings", [])) for _, _, d in sections)
        body += f"""
<div class='section-block'>
  <div class='section-header' onclick="toggleSection('{sid}')">
    <span class='section-toggle' id='toggle-{sid}'>+</span>
    <span class='section-title'>Findings
      <span style='font-weight:normal;font-size:12px;opacity:0.8;margin-left:8px'>({total_findings} total)</span>
    </span>
  </div>
  <div class='section-body collapsed' id='{sid}'>
    {findings_content}
  </div>
</div>
"""

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract device info and use-case details from the first snapshot_comparison section
    device_html = ""
    usecase_html = ""
    for rtype, path, data in sections:
        if rtype == "snapshot_comparison":
            dev = data.get("device", {})
            is_standalone = (
                data.get("current_snapshot_id") == data.get("reference_snapshot_id")
                and data.get("current_snapshot_id", "") != ""
            )
            max_width = "640px" if is_standalone else "860px"
            if dev:
                device_html = render_device_info_html(dev, max_width)
            if not is_standalone:
                usecase_html = render_usecase_details_html(data, max_width)
            break

    return f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>{title}</title>{CSS}</head>
<body style='max-width:1100px;margin:0 auto'>
<h1>{title}</h1>
<p style='color:#888;font-size:0.85em'>Generated: {ts}</p>
{device_html}
{usecase_html}
{body}
</body></html>"""


# ---------------------------------------------------------------------------
# Individual report HTML
# ---------------------------------------------------------------------------

def build_single_html(rtype: str, data: dict, title: str) -> str:
    section_title, renderer = SECTION_RENDERERS.get(
        rtype, (f"Report ({rtype})", lambda d: f"<pre>{json.dumps(d, indent=2)}</pre>")
    )
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>{title}</title>{CSS}</head>
<body>
<h1>{title}</h1>
<p style='color:#888'>Generated: {ts}</p>
{renderer(data)}
</body></html>"""


# ---------------------------------------------------------------------------
# TXT writers
# ---------------------------------------------------------------------------

def build_txt(rtype: str, data: dict) -> str:
    lines = [f"Report Type: {rtype}", "=" * 60, ""]
    if rtype == "rca":
        s = data.get("summary", {})
        lines += [
            f"Overall Health: {s.get('overall_health')}",
            f"Critical: {s.get('critical',0)}  Warning: {s.get('warning',0)}  Info: {s.get('info',0)}",
            "",
        ]
        for a in data.get("anomalies", []):
            lines += [
                f"[{a['severity']}] {a['id']}: {a['title']}",
                f"  Confidence: {a['confidence']:.0%}",
                f"  Hypothesis: {a['hypothesis']}",
                "",
            ]
    elif rtype == "carveout_validation":
        s = data.get("summary", {})
        lines.append(f"Carve-outs found: {s.get('found', 0)}  Total: {s.get('total_actual_mb', 0):.2f} MB")
        lines.append("")
        for r in data.get("results", []):
            size_mb = r.get("actual_size_mb", r.get("actual_size_kb", 0) / 1024)
            lines.append(f"  [OK] FOUND  {r.get('name',''):<30} {size_mb:.2f} MB")
    elif rtype == "snapshot_comparison":
        lines.append(f"{'Category':<20} {'Ref MB':>10} {'Cur MB':>10} {'Delta MB':>10} {'Trend'}")
        for cat in data.get("categories", []):
            lines.append(
                f"{cat['category']:<20} {cat['reference_kb']/1024:>10.1f} "
                f"{cat['current_kb']/1024:>10.1f} {cat['delta_kb']/1024:>+10.1f} "
                f"{cat['trend']}"
            )
    else:
        lines.append(json.dumps(data, indent=2)[:2000])
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# XLSX writer
# ---------------------------------------------------------------------------

def write_xlsx_unified(sections: list[tuple[str, str, dict]], output_path: str):
    try:
        import openpyxl
        from openpyxl.styles import PatternFill, Font
    except ImportError:
        print("[report-generation] openpyxl not installed -- skipping XLSX")
        return
    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # remove default sheet

    for rtype, path, data in sections:
        sheet_name = rtype[:31]  # Excel sheet name limit
        ws = wb.create_sheet(sheet_name)
        ws.append([f"Source: {path}"])
        ws.append([])

        if rtype == "rca":
            ws.append(["ID", "Severity", "Title", "Confidence", "Layer", "Hypothesis"])
            for cell in ws[ws.max_row]:
                cell.font = Font(bold=True)
            for a in data.get("anomalies", []):
                ws.append([a["id"], a["severity"], a["title"],
                           f"{a['confidence']:.0%}", a["layer"], a["hypothesis"]])
                sev_colors = {"CRITICAL": "FFE0E0", "WARNING": "FFF8E0", "INFO": "E8F4FD"}
                fill_color = sev_colors.get(a["severity"])
                if fill_color:
                    for cell in ws[ws.max_row]:
                        cell.fill = PatternFill("solid", fgColor=fill_color)

        elif rtype == "carveout_validation":
            ws.append(["Carveout", "Base Address", "Size (MB)", "Status"])
            for cell in ws[ws.max_row]:
                cell.font = Font(bold=True)
            for r in data.get("results", []):
                size_mb = r.get("actual_size_mb", r.get("actual_size_kb", 0) / 1024)
                ws.append([r.get("name"), r.get("base_addr"),
                           round(size_mb, 2), "FOUND"])

        elif rtype == "snapshot_comparison":
            ws.append(["Category", "Reference MB", "Current MB", "Delta MB", "Delta %", "Trend"])
            for cell in ws[ws.max_row]:
                cell.font = Font(bold=True)
            for cat in data.get("categories", []):
                ws.append([cat["category"],
                           round(cat["reference_kb"] / 1024, 2),
                           round(cat["current_kb"] / 1024, 2),
                           round(cat["delta_kb"] / 1024, 2),
                           cat["delta_pct"], cat["trend"]])

            # MemoryLayout sheet -- physical address map (System RAM, kernel-static
            # sub-regions, NHLOS carve-outs, and address gaps), mirroring the
            # reference memmap_Parser.py "MemoryLayout" Excel sheet.
            layout = data.get("summary_table", {}).get("current", {}).get("memory_layout", [])
            if layout:
                ws_layout = wb.create_sheet("MemoryLayout")
                ws_layout.append(["Carveout Name", "Start address", "End address",
                                   "Size (MB)", "SystemRAM Size (MB)", "Carveout Size (MB)"])
                for cell in ws_layout[ws_layout.max_row]:
                    cell.font = Font(bold=True)
                sysram_fill   = PatternFill("solid", fgColor="C6EFCE")
                kernel_fill   = PatternFill("solid", fgColor="D9D9F3")
                reserved_fill = PatternFill("solid", fgColor="FFF2CC")
                missing_fill  = PatternFill("solid", fgColor="FFC7CE")
                REGION_FILLS = {
                    "sysram":   sysram_fill,
                    "kernel":   kernel_fill,
                    "reserved": reserved_fill,
                    "missing":  missing_fill,
                }
                total_size = total_sys = total_carv = 0.0
                for name, start, end, size_mb, region_type in layout:
                    is_sysram = (region_type == "sysram")
                    # Everything that is not accessible System RAM counts as a
                    # carve-out, including "Missing" unaccounted-gap rows (see
                    # render_memory_layout_html for the full rationale).
                    carveout_mb = size_mb if not is_sysram else 0
                    sysram_mb = size_mb if is_sysram else 0
                    total_size += size_mb
                    total_sys += sysram_mb
                    total_carv += carveout_mb
                    ws_layout.append([name, hex(start), hex(end), size_mb, sysram_mb, carveout_mb])
                    row = ws_layout.max_row
                    fill = REGION_FILLS.get(region_type)
                    if fill:
                        for cell in ws_layout[row]:
                            cell.fill = fill
                            if region_type == "missing":
                                cell.font = Font(color="CC0000", bold=True)
                ws_layout.append(["Total", "", "", round(total_size, 2),
                                   round(total_sys, 2), round(total_carv, 2)])
                for cell in ws_layout[ws_layout.max_row]:
                    cell.font = Font(bold=True)
                for col_letter in ("A", "B", "C"):
                    ws_layout.column_dimensions[col_letter].width = 20
                for col_letter in ("D", "E", "F"):
                    ws_layout.column_dimensions[col_letter].width = 16

        elif rtype == "kernel_diff":
            ws.append(["Slab", "Ref KB", "Cur KB", "Delta KB", "Delta %", "Flagged"])
            for cell in ws[ws.max_row]:
                cell.font = Font(bold=True)
            for s in data.get("slab_diff", []):
                ws.append([s["name"], s["ref_kb"], s["cur_kb"],
                           s["delta_kb"], s["delta_pct"], s.get("flagged", False)])

        elif rtype == "userspace_diff":
            ws.append(["Process", "Ref PSS KB", "Cur PSS KB", "Delta PSS KB", "Delta %", "Status"])
            for cell in ws[ws.max_row]:
                cell.font = Font(bold=True)
            for p in data.get("process_diff", []):
                ws.append([p["name"], p["ref_pss_kb"], p["cur_pss_kb"],
                           p["delta_pss_kb"], p["delta_pct"],
                           "FLAGGED" if p.get("flagged") else ""])
            for p in data.get("new_processes", []):
                ws.append([p["name"], 0, p.get("pss_kb", 0), p.get("pss_kb", 0), "", "NEW"])
                ws[ws.max_row][5].fill = PatternFill("solid", fgColor="E8F8E8")
            for p in data.get("exited_processes", []):
                ws.append([p["name"], p.get("pss_kb", 0), 0, -p.get("pss_kb", 0), "", "EXITED"])
                ws[ws.max_row][5].fill = PatternFill("solid", fgColor="FDE8E8")

        elif rtype == "ipcat_layout":
            ws.append(["IPCat Region", "IPCat Start Address", "IPCat End Address", "IPCat Size (MB)",
                       "Target Region", "Target Start Address", "Target End Address",
                       "Target Size (MB)", "Matching"])
            for cell in ws[ws.max_row]:
                cell.font = Font(bold=True)
            match_fill    = PatternFill("solid", fgColor="D4EDDA")
            mismatch_fill = PatternFill("solid", fgColor="F8D7DA")

            def _addr_cell(v):
                return hex(v) if isinstance(v, int) else ("" if v is None else v)

            for r in data.get("rows", []):
                ws.append([
                    r.get("region") or "",
                    _addr_cell(r.get("ipcat_start")),
                    _addr_cell(r.get("ipcat_end")),
                    r.get("ipcat_size_mb") if r.get("ipcat_size_mb") is not None else "",
                    r.get("target_region") or "",
                    _addr_cell(r.get("target_start")),
                    _addr_cell(r.get("target_end")),
                    r.get("target_size_mb") if r.get("target_size_mb") is not None else "",
                    r.get("matching", "No"),
                ])
                fill = match_fill if r.get("matching") == "Yes" else mismatch_fill
                for cell in ws[ws.max_row]:
                    cell.fill = fill
            for col_letter in ("A", "E"):
                ws.column_dimensions[col_letter].width = 24
            for col_letter in ("B", "C", "F", "G"):
                ws.column_dimensions[col_letter].width = 20
            for col_letter in ("D", "H", "I"):
                ws.column_dimensions[col_letter].width = 14

    wb.save(output_path)
    print(f"[report-generation] XLSX  -> {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate HTML/TXT/XLSX reports from memory skill output JSONs."
    )
    parser.add_argument("--input", nargs="+", required=True,
                        help="One or more report JSON files")
    parser.add_argument("--format", default="html,txt",
                        help="Comma-separated output formats: html,txt,xlsx (default: html,txt)")
    parser.add_argument("--output-dir", default=".",
                        help="Output directory (default: .)")
    parser.add_argument("--unified", action="store_true",
                        help="Combine all inputs into a single multi-section HTML report")
    parser.add_argument("--title", default="Memory Analysis Report",
                        help="Title for the unified report")
    parser.add_argument("--snapshot-current", default="",
                        help="Current snapshot.json path (enables Top Processes Memory Details section)")
    parser.add_argument("--snapshot-reference", default="",
                        help="Reference snapshot.json path (enables Top Processes Memory Details section)")
    args = parser.parse_args()

    formats = [f.strip().lower() for f in args.format.split(",")]
    os.makedirs(args.output_dir, exist_ok=True)

    # Load all input reports
    loaded = []
    for path in args.input:
        if not os.path.isfile(path):
            print(f"[report-generation] WARNING: {path} not found -- skipping")
            continue
        data, rtype = load_report(path)
        loaded.append((rtype, path, data))
        print(f"[report-generation] Loaded {rtype} from {path}")

    if not loaded:
        print("ERROR: No valid report files found.")
        sys.exit(1)

    # Load smaps breakdowns if snapshot paths provided
    cur_breakdowns = load_smaps_for_snapshot(args.snapshot_current) if args.snapshot_current else []
    ref_breakdowns = load_smaps_for_snapshot(args.snapshot_reference) if args.snapshot_reference else []
    if cur_breakdowns or ref_breakdowns:
        for _, _, data in loaded:
            data["_smaps_cur"] = cur_breakdowns
            data["_smaps_ref"] = ref_breakdowns
        print(f"[report-generation] Loaded smaps: {len(cur_breakdowns)} current + {len(ref_breakdowns)} reference processes")

    if args.unified:
        # Single unified HTML
        if "html" in formats:
            html = build_unified_html(loaded, args.title)
            out = os.path.join(args.output_dir, "unified_report.html")
            with open(out, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"[report-generation] HTML  -> {out}")
        if "xlsx" in formats:
            out = os.path.join(args.output_dir, "unified_report.xlsx")
            write_xlsx_unified(loaded, out)
    else:
        # Individual reports per input
        for rtype, path, data in loaded:
            base = os.path.splitext(os.path.basename(path))[0]
            title = f"{rtype.replace('_', ' ').title()} Report"
            if "html" in formats:
                html = build_single_html(rtype, data, title)
                out = os.path.join(args.output_dir, f"{base}.html")
                with open(out, "w", encoding="utf-8") as f:
                    f.write(html)
                print(f"[report-generation] HTML  -> {out}")
            if "txt" in formats:
                txt = build_txt(rtype, data)
                out = os.path.join(args.output_dir, f"{base}.txt")
                with open(out, "w", encoding="utf-8") as f:
                    f.write(txt)
                print(f"[report-generation] TXT   -> {out}")
            if "xlsx" in formats:
                out = os.path.join(args.output_dir, f"{base}.xlsx")
                write_xlsx_unified([(rtype, path, data)], out)

    print(f"\n[report-generation] Done. {len(loaded)} report(s) processed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())