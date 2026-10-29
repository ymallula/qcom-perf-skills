# Qualcomm Linux Memory Skills

AI-powered memory accounting and analysis framework for Qualcomm Linux SoCs.
Designed to be used through natural language prompts to an AI agent (Cline, Cursor, etc.).
Runs entirely from the **host machine** — no installation required on the target device.

**Supported devices:** Qualcomm Linux (QLI) devices

**Supported transports:** ADB (primary) · SSH (secondary)

**Supported host platforms:** Windows · Linux

---

## Quick Start (2 Minutes)

### Prerequisites
```bash
pip install -r requirements.txt
```
See [TRANSPORT.md](TRANSPORT.md) for ADB/SSH setup.

### Your First Analysis
```bash
# Step 1: Connect device
adb devices

# Step 2: Tell the agent
"Give me a memory report for the connected device"

# Step 3: View report
# Open results/snapshot_<timestamp>/reports/snapshot_report.html
```

### Common Tasks

| Task | Prompt |
|------|--------|
| Memory report | `"Give me a memory report for device <serial>"` |
| Compare vs baseline | `"Compare device against results/baseline/"` |
| Measure use-case (preset) | `"How much memory does the camera use?"` |
| Measure user-launched use-case | `"I want to measure memory of a use-case I'll launch manually"` |
| Measure user-launched (clean baseline) | `"Measure memory of my use-case — reboot first for a clean baseline"` |
| Offline compare | `"Compare results/build_v2/ against results/build_v1/"` |

See [Analysis Modes](#analysis-modes) below for detailed instructions.

---

## Repository Structure

```
memory-skills/
├── skills/                    ← One unified skill (agent-discoverable)
│   └── memory-analysis/
├── internal/                  ← Internal pipeline components (not agent-discoverable)
│   ├── data-collection/
│   ├── snapshot-comparison/
│   ├── kernel-diff/
│   ├── userspace-diff/
│   ├── anomaly-rca/
│   ├── report-generation/
│   ├── memory-map/
│   ├── nhlos-carveout-validation/
│   └── ipcat-memory-layout/
├── common/                    ← Shared schemas
├── tests/                     ← Validation tests
├── README.md
├── TRANSPORT.md
├── TROUBLESHOOTING.md
└── ARCHITECTURE.md
```

The `skills/memory-analysis/` directory contains `SKILL.md` and is
discoverable by agents. Internal components are invoked by the skill
and are not independently accessible.

---

## Analysis Modes

**Skill:** `skills/memory-analysis/SKILL.md`

One unified skill with four modes — auto-detected from the parameters you provide.

### Mode 1: Snapshot
Single memory snapshot from a connected device. No baseline required.

```
Device → Collect → Memory Breakdown → snapshot_report.html
```

**Example prompts:**
```
"Give me a memory report for the connected device"
"What is the memory usage on this board?"
"Show me the memory breakdown for device 0426df75"
"Memory report for device at 192.168.1.100, user=root"
```

---

### Mode 2: Workload Impact
Measure the memory footprint of a specific workload.
Collects idle baseline, runs the workload, then compares.

```
Device (idle) → Collect Baseline → Start Workload → Wait 15s
             → Collect Active → Compare → workload_impact_report.html
```

**Step 1** — Add your workload to `skills/memory-analysis/usecases/presets.json`:
```json
"my_workload": {
  "name": "My Workload",
  "description": "What this does",
  "setup": ["systemctl start cam-server", "sleep 3"],
  "command": "the command to run on the device",
  "wait_sec": 15,
  "teardown": ["pkill myapp"]
}
```

**Step 2** — Tell the agent:
```
"How much memory does the camera use?"
"Measure memory impact of camera_h264_encoding"
"Run the camera and tell me the memory impact"
"Measure memory impact of: gst-launch-1.0 qtiqmmfsrc ..."
```

---

### Mode 3: Regression Test
Compare a connected device against a pre-collected reference snapshot.

```
Live Device + Pre-collected Reference → Compare → regression_report.html
```

**Example prompts:**
```
"Is this device using more memory than the reference?"
"Compare device 0426df75 against the golden baseline in results/golden/"
"Regression test: collect from device and compare with results/build_v1/"
```

---

### Mode 4: Snapshot Comparison (Offline)
Compare two previously collected snapshots — no device required.

```
Snapshot A + Snapshot B → Compare → comparison_report.html
```

**Example prompts:**
```
"Compare results/build_v2/ against results/build_v1/"
"Offline comparison: current=results/camera_active/ reference=results/baseline/"
"Compare two snapshots: A=data/device_A/ B=data/device_B/"
```

---

## Tell the agent

Connect your device and describe the task in plain English.
The agent will use the `memory-analysis` skill and auto-detect the appropriate mode.

### Transport Selection

The agent will ask you to choose a transport if it cannot auto-detect:

**ADB (primary — Qualcomm Linux devices):**
```
Connect USB cable → adb devices → tell the agent the serial number
```
If multiple devices are connected, the agent will list them and ask you to select one.

**SSH (secondary — any Linux device):**
```
Tell the agent: "use SSH, device at 192.168.1.100, user=root"
```
The agent will prompt for hostname, username, and password.

### What the AI agent will ask you

If information is missing, the agent will ask:
- **"Which transport? ADB or SSH?"** (if ADB is not available or multiple devices are connected)
- **"Which device?"** (if multiple ADB devices are connected — shows list to select from)
- **"SSH hostname, username, and password?"** (if SSH transport is selected)
- **"What command should I run on the device?"** (for use-case mode)
- **"Where is the reference snapshot?"** (for compare modes)
- **"How long should I wait for the use-case to stabilize?"** (default: 15s)

---

## What the report shows

The unified HTML report includes:

### Device Information
```
Machine:   Qualcomm Technologies, Inc. Shikra CQM EVK
SoC:       QCS6490
OS:        Qualcomm Linux Reference Distro 2.0
Kernel:    6.18.37
```

### Use Case Details (comparison mode only)
```
Use-Case:  glmark2_es2_wayland
Command:   XDG_RUNTIME_DIR=/run/user/1000 glmark2-es2-wayland
Baseline:  baseline_idle
Active:    glmark2_es2_wayland
```

### Memory Summary Table
Hierarchical breakdown with expandable rows:
```
Total RAM                    4,096 MB
[+] NHLOS Reserved             349 MB  → mpss, cdsp, hyp, tz, ...
    System RAM               3,747 MB
▶ HLOS — High Level OS
    Kernel Static Memory       261 MB  → Vmlinux, Page Structs, Hash Tables
[+] Kernel Dynamic Memory      235 MB  → Slab, Vmalloc, Modules, CMA, KDA
[+] Hardware / Driver Buffers    8 MB  → DMA-BUF, KGSL GPU
[+] User Space Apps            211 MB  → Anonymous Pages, Shared Memory
[+] Total Available Memory   3,001 MB  → Free Memory, Page Cache, Buffers
```

### Detailed Sections (collapsible, comparison mode only)
- **Userspace Memory Changes** -- per-process PSS, new/exited processes, DMA-BUF
- **Kernel Memory Changes** -- slab allocator, buddy fragmentation
- **Root Cause Analysis** -- anomaly detection with confidence scores

---

## Skill Pipeline (underlying components)

Each analysis mode orchestrates the following skills in sequence:

| Component | Purpose | Script |
|---|---|---|
| **memory-analysis** | Unified skill entry point (4 modes) | `skills/memory-analysis/scripts/run.py` |
| **data-collection** | Collect memory data from device via ADB or SSH | `internal/data-collection/scripts/collect.py` |
| **snapshot-comparison** | Compute memory deltas between two snapshots | `internal/snapshot-comparison/scripts/compare_snapshots.py` |
| **kernel-diff** | Analyze kernel slab and buddy allocator changes | `internal/kernel-diff/scripts/analyze_kernel_diff.py` |
| **userspace-diff** | Analyze per-process PSS, DMA-BUF, KGSL changes | `internal/userspace-diff/scripts/analyze_userspace_diff.py` |
| **anomaly-rca** | Root cause analysis and anomaly detection | `internal/anomaly-rca/scripts/analyze_rca.py` |
| **report-generation** | Generate unified HTML/XLSX report | `internal/report-generation/scripts/generate_report.py` |
| **memory-map** | Physical memory layout (NHLOS + HLOS breakdown) | `internal/memory-map/scripts/` |
| **nhlos-carveout-validation** | Parse and report NHLOS carveout layout from device tree | `internal/nhlos-carveout-validation/scripts/` |
| **ipcat-memory-layout** | Compare device memory layout against IP Catalog (IPCat) reference map | `internal/ipcat-memory-layout/scripts/ipcat_layout.py` |

---

## Data Collection

Files collected from device per snapshot:

| File | Source | Used for |
|---|---|---|
| `meminfo.txt` | `/proc/meminfo` | All memory categories |
| `iomem.txt` | `/proc/iomem` | System RAM calculation |
| `dmabuf_bufinfo.txt` | `/sys/kernel/debug/dma_buf/bufinfo` | DMA-BUF by allocator |
| `kgsl_alloc.txt` | `/sys/class/kgsl/kgsl/page_alloc` | KGSL GPU total |
| `memblock.txt` | `/sys/kernel/debug/memblock/memory` | Accurate Total RAM |
| `procrank.txt` | `procrank -p` | Process PSS ranking (Qualcomm Linux) |
| `proc_stats_fallback.txt` | `/proc/*/smaps_rollup` | Process PSS ranking (standard Linux) |
| `dmesg.txt` | `dmesg` / `journalctl -k` | Kernel Static breakdown |
| `swapinfo.txt` | `/proc/swaps` | Swap/Zram usage |
| `zramstat.txt` | `/sys/block/zram0/mm_stat` | Zram compression savings |
| `smaps/<pid>_smaps.txt` | `/proc/<pid>/smaps` | Top-5 process mapping detail |
| `reserved-memory/*.bin` | DT reserved-memory | NHLOS carveout list |

---

## Requirements & Compatibility

### Host Machine

| Requirement | Notes |
|---|---|
| **Python 3.10+** | Required for all scripts — `pip install -r requirements.txt` |
| **ADB** | Optional — required only for ADB transport (Qualcomm Linux devices) |
| **paramiko** | Optional — required only for SSH transport (`pip install paramiko`) |
| **OS** | Windows, Linux |

### Device

| Requirement | Notes |
|---|---|
| **OS** | Any Linux distribution |
| **Transport** | ADB (Qualcomm Linux) or SSH (any Linux) |
| **Privilege** | Root recommended for complete data collection (debugfs, slabinfo, procrank) |

### Qualcomm-Specific Features

These features are **only available on Qualcomm Linux devices**:
- KGSL GPU memory tracking
- NHLOS carveout breakdown
- `procrank` process memory ranking

On generic Linux (via SSH), these features are unavailable but basic memory accounting (Total RAM, Kernel, Userspace, DMA-BUF) still works.

| Feature | Qualcomm Linux | Generic Linux (SSH) |
|---|---|---|
| Total RAM, Kernel, Userspace | ✅ | ✅ |
| DMA-BUF by allocator | ✅ | ✅ (if debugfs available) |
| KGSL GPU memory | ✅ | ❌ |
| NHLOS carveout breakdown | ✅ | ❌ |
| Per-process PSS | ✅ (procrank) | ✅ (smaps_rollup) |

## Quick Commands

```bash
# Snapshot — current memory state
python skills/memory-analysis/scripts/run.py --serial <serial>

# Workload (Preset) — measure memory impact
python skills/memory-analysis/scripts/run.py --workload camera_h264_encoding --serial <serial>

# Workload (User-Launched, Interactive) — single command, guided workflow
python skills/memory-analysis/scripts/run.py --user-launched --interactive --serial <serial>

# Workload (User-Launched, Interactive + Reboot) — clean baseline
python skills/memory-analysis/scripts/run.py --user-launched --interactive --reboot --serial <serial>

# Regression — compare device against reference
python skills/memory-analysis/scripts/run.py --reference results/golden/ --serial <serial>

# Comparison — compare two pre-collected snapshots
python skills/memory-analysis/scripts/run.py --current results/build_v2/ --reference results/build_v1/
```


## Documentation

| File | Description |
|---|---|
| `README.md` | This file — overview, quick-start, and compatibility |
| `TRANSPORT.md` | ADB and SSH transport configuration |
| `TROUBLESHOOTING.md` | Common issues and solutions |
| `ARCHITECTURE.md` | Skill dependency graph and data flow |
