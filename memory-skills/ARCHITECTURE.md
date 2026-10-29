# Architecture

---

## Overview

Memory-skills is a **host-side analysis framework** that connects to Qualcomm Linux devices
via ADB or SSH, collects memory diagnostic data, and generates comprehensive HTML reports.

```
┌─────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                             │
│                                                                 │
│  ┌──────────┐    ┌─────────────────────────────────────────┐   │
│  │  Agent   │───▶│           Memory Skills                 │   │
│  │ (Cline / │    │                                         │   │
│  │  Cursor) │    │         memory-analysis                 │   │
│  └──────────┘    │  (snapshot / workload /                 │   │
│                  │   regression / comparison)              │   │
│                  └──────────────┬──────────────────────────┘   │
│                                 │                               │
│                    ┌────────────▼────────────┐                  │
│                    │   Internal Components   │                  │
│                    │  data-collection        │                  │
│                    │  snapshot-comparison    │                  │
│                    │  kernel-diff            │                  │
│                    │  userspace-diff         │                  │
│                    │  anomaly-rca            │                  │
│                    │  report-generation      │                  │
│                    └────────────┬────────────┘                  │
└─────────────────────────────────┼───────────────────────────────┘
                                  │ ADB or SSH
                    ┌─────────────▼────────────┐
                    │     TARGET DEVICE        │
                    │  Qualcomm Linux (QLI)    │
                    │  /proc  /sys  debugfs    │
                    └──────────────────────────┘
```

---

## Analysis Modes (Unified Skill)

One skill with four modes, auto-detected from the parameters provided:

| Mode | Description | Device Required |
|------|-------------|-----------------|
| `snapshot` | Single snapshot memory accounting | Yes (live) |
| `workload` | Measure memory impact of a workload | Yes (live) |
| `regression` | Compare live device vs pre-collected reference | Yes (live) |
| `comparison` | Compare two pre-collected snapshots | No |

**Entry point:** `skills/memory-analysis/scripts/run.py`

---

## Internal Pipeline Components

These components are invoked by the `memory-analysis` skill. Users do not interact with them directly.

```
data-collection
    │
    └──▶ snapshot.json
              │
              ├──▶ snapshot-comparison ──▶ snapshot_comparison_report.json
              │                                        │
              ├──▶ kernel-diff ──────────▶ kernel_diff_report.json
              │                                        │
              ├──▶ userspace-diff ───────▶ userspace_diff_report.json
              │                                        │
              └──▶ anomaly-rca ◀──────────────────────┘
                       │
                       └──▶ rca_report.json
                                  │
                       ┌──────────▼──────────┐
                       │  report-generation  │
                       └──────────┬──────────┘
                                  │
                       unified_report.html
```

---

## Skill Dependency Graph

```
memory-analysis (Mode: snapshot)
├── data-collection          (collect snapshot)
├── snapshot-comparison      (self-comparison for memory breakdown)
└── report-generation        (generate snapshot_report.html)

memory-analysis (Mode: workload)
├── data-collection          (collect baseline + active snapshots)
├── snapshot-comparison      (compute memory delta)
├── kernel-diff              (analyze kernel changes)
├── userspace-diff           (analyze process changes)
├── anomaly-rca              (root cause analysis)
└── report-generation        (generate workload_impact_report.html)

memory-analysis (Mode: regression)
├── data-collection          (collect current snapshot from live device)
├── snapshot-comparison      (compare current vs reference)
├── kernel-diff              (analyze kernel changes)
├── userspace-diff           (analyze process changes)
├── anomaly-rca              (root cause analysis)
└── report-generation        (generate regression_report.html)

memory-analysis (Mode: comparison)
├── snapshot-comparison      (compare two pre-collected snapshots)
├── kernel-diff              (analyze kernel changes)
├── userspace-diff           (analyze process changes)
├── anomaly-rca              (root cause analysis)
└── report-generation        (generate comparison_report.html)
```

---

## Data Flow

### 1. Data Collection

```
Device (/proc, /sys, debugfs)
    │
    │  ADB pull / SSH sftp
    ▼
Raw files (meminfo.txt, slabinfo.txt, vmstat.txt, ...)
    │
    │  Normalization (parse + validate)
    ▼
snapshot.json  ◀── MemorySnapshot JSON contract
```

### 2. Comparison & Analysis

```
snapshot.json (current)  ──┐
                           ├──▶ snapshot-comparison ──▶ snapshot_comparison_report.json
snapshot.json (reference) ─┘         │
                                      ├──▶ kernel-diff ──▶ kernel_diff_report.json
                                      │
                                      └──▶ userspace-diff ──▶ userspace_diff_report.json
                                                                        │
                                                           anomaly-rca ◀┘
                                                                │
                                                         rca_report.json
```

### 3. Report Generation

```
snapshot_comparison_report.json ──┐
kernel_diff_report.json ──────────┤
userspace_diff_report.json ───────┼──▶ report-generation ──▶ unified_report.html
rca_report.json ──────────────────┤                                    │
snapshot.json (current) ──────────┤                                    │
snapshot.json (reference) ────────┘                                    ▼
                                                              Browser (HTML report)
```

---

## Directory Structure

```
memory-skills/
│
├── README.md                    # Overview and quick-start
├── TRANSPORT.md                 # ADB and SSH transport configuration
├── TROUBLESHOOTING.md           # Common issues and solutions
├── ARCHITECTURE.md              # This file
├── requirements.txt             # Python dependencies
│
├── skills/                      # Agent-discoverable skill
│   └── memory-analysis/         # Unified skill (all 4 modes)
│       ├── SKILL.md
│       ├── scripts/
│       │   └── run.py           # Unified entry point (mode auto-detected)
│       └── usecases/
│           └── presets.json     # Named workload presets
│
├── internal/
│   ├── data-collection/         # Supporting: collect from device
│   │   ├── README.md
│   │   ├── scripts/
│   │   │   └── collect.py       # Interactive transport selection (ADB/SSH)
│   │   └── references/
│   │
│   ├── snapshot-comparison/     # Supporting: compute memory delta
│   │   ├── README.md
│   │   ├── scripts/
│   │   │   └── compare_snapshots.py
│   │   └── references/
│   │
│   ├── kernel-diff/             # Supporting: kernel slab/buddy analysis
│   │   ├── README.md
│   │   └── scripts/
│   │       └── analyze_kernel_diff.py
│   │
│   ├── userspace-diff/          # Supporting: per-process PSS analysis
│   │   ├── README.md
│   │   └── scripts/
│   │       └── analyze_userspace_diff.py
│   │
│   ├── anomaly-rca/             # Supporting: root cause analysis
│   │   ├── README.md
│   │   ├── scripts/
│   │   │   └── analyze_rca.py
│   │   └── references/
│   │
│   ├── report-generation/       # Supporting: HTML/XLSX report generation
│   │   ├── README.md
│   │   └── scripts/
│   │       └── generate_report.py
│   │
│   ├── memory-map/              # Supporting: physical memory layout
│   │   ├── README.md
│   │   └── scripts/
│   │       └── memory_map.py
│   │
│   ├── nhlos-carveout-validation/ # Supporting: NHLOS carveout layout reporter
│   │   ├── README.md
│   │   └── scripts/
│   │       └── validate.py
│   │
│   └── ipcat-memory-layout/     # Supporting: IPCat vs device memory layout comparison
│       ├── README.md
│       └── scripts/
│           └── ipcat_layout.py
│
├── common/                      # Shared JSON schemas
│   └── schema/
│       ├── memory-snapshot.schema.json
│       ├── snapshot-comparison-report.schema.json
│       ├── kernel-diff-report.schema.json
│       ├── userspace-diff-report.schema.json
│       ├── rca-report.schema.json
│       └── carveout-validation-report.schema.json
│
├── results/                     # Output directory (generated)
│   └── <usecase_name>/
│       ├── baseline/
│       │   └── snapshot.json
│       ├── active/
│       │   └── snapshot.json
│       └── reports/
│           ├── snapshot_comparison_report.json
│           ├── kernel_diff_report.json
│           ├── userspace_diff_report.json
│           ├── rca_report.json
│           └── unified_report.html
│
└── tests/                       # Test suite (device-side allocators)
    ├── kernel/
    │   └── test_kmalloc_module.c
    └── userspace/
        ├── test_dmabuf_alloc.c
        ├── test_malloc_alloc.c
        ├── test_mmap_alloc.c
        └── test_shmem_alloc.c
```

---

## Transport Abstraction

The `data-collection` skill abstracts the transport layer so all analysis modes
work identically regardless of whether ADB or SSH is used:

```
collect.py
    │
    ├── AdbTransport    ──▶ adb shell / adb pull
    │
    └── SshTransport    ──▶ paramiko exec_command / sftp.get
```

Both transports implement the same interface:
- `shell(cmd)` — Run a command on the device
- `pull(remote, local)` — Copy a file from device to host
- `pull_dir(remote_dir, local_dir)` — Copy a directory recursively

---

## MemorySnapshot JSON Contract

The `snapshot.json` file is the **central data contract** consumed by all analysis skills.
It is produced by `data-collection` and consumed by `snapshot-comparison`, `kernel-diff`,
`userspace-diff`, `anomaly-rca`, and `report-generation`.

The schema is defined in `data-collection/scripts/collect.py` and `common/schema/`.

