---
name: edr-analysis
description: "Analyze an EDR product's detection mechanisms — hooks, callbacks, telemetry, rules, and behavioral monitoring. Use when reverse engineering endpoint detection and response products."
metadata:
  version: "0.1.0"
---

# EDR Product Analysis

## Overview

Systematic methodology for reverse engineering Endpoint Detection and Response (EDR) products. Extracts the complete detection surface: userland hooks, kernel callbacks, ETW telemetry, embedded rules, and behavioral monitoring patterns.

## Prerequisites

- Target EDR installed in an analysis VM (snapshot before and after installation)
- Clean system baseline files in `baselines/` (ntdll, kernel32, syscall table)
- Revav tools installed: `pip install -e .`

## Methodology

### Phase 1: Component Inventory

Identify all EDR components installed on the system:

1. **Services**: `sc query type=all state=all` — find EDR service names, binaries, start types
2. **Drivers**: `driverquery /v` or `fltmc instances` — find kernel drivers and minifilter altitudes
3. **Processes**: `tasklist /svc` — map running processes to services
4. **DLLs**: Check for injected DLLs in common targets (explorer.exe, svchost.exe, lsass.exe)
5. **Registry**: `HKLM\SYSTEM\CurrentControlSet\Services\<edr>` — driver/service config
6. **Scheduled tasks**: `schtasks /query /fo LIST /v` — recurring analysis or update tasks
7. **Network endpoints**: `netstat -anob` — cloud connectivity, update channels, telemetry sinks

Write the inventory to `kb/profiles/<product>.yaml` using the product_profile template.

### Phase 2: Hook Extraction

Run the hook scanner against the target system:

```bash
revav scan --target <pid_or_path> --agents hook --baseline baselines/ntdll_clean.json --output kb/catalog/
```

Manually verify:
- Compare ntdll.dll in-memory vs on-disk (`!chkimg ntdll` in WinDbg)
- Check for IAT modifications in key processes
- Look for syscall stub patches (does the `syscall` instruction still point to the kernel?)
- Identify the hooking module (which DLL installed each hook?)

Key APIs to check for hooks:
- **Process**: NtCreateProcess, NtCreateThread, NtCreateThreadEx, NtResumeThread
- **Memory**: NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtMapViewOfSection
- **File**: NtCreateFile, NtWriteFile, NtSetInformationFile
- **Registry**: NtCreateKey, NtSetValueKey, NtDeleteKey
- **Network**: connect, WSASend, HttpSendRequest
- **Injection**: NtQueueApcThread, NtSetContextThread, NtSuspendThread

### Phase 3: Kernel Callback Enumeration

```bash
revav scan --target <pid_or_path> --agents callback --output kb/catalog/
```

Enumerate:
- `PsSetCreateProcessNotifyRoutine(Ex)` — process creation/termination monitoring
- `PsSetCreateThreadNotifyRoutine(Ex)` — thread creation monitoring
- `PsSetLoadImageNotifyRoutine(Ex)` — image (DLL/EXE) load monitoring
- `ObRegisterCallbacks` — object (process/thread handle) access monitoring
- `CmRegisterCallbackEx` — registry operation monitoring
- Minifilter registrations (`fltmc instances`) — file system monitoring
- WFP callout drivers — network traffic inspection
- ETW threat intelligence provider subscription

### Phase 4: Telemetry Mapping

```bash
revav scan --target <pid_or_path> --agents telemetry --output kb/catalog/
```

Identify:
- ETW providers the EDR subscribes to (use `logman query providers`)
- WMI event subscriptions (`Get-WMIObject -Namespace root\Subscription -Class __EventFilter`)
- Cloud telemetry endpoints (packet capture or proxy the EDR's HTTPS traffic)
- Local log file paths and formats
- Event forwarding configuration

### Phase 5: Rule and Behavioral Extraction

```bash
revav scan --target <pid_or_path> --agents rule,behavior --output kb/catalog/
```

- Extract YARA rules from scanning engine binaries
- Identify behavioral correlation rules (parent-child process trees that trigger alerts)
- Map file system paths under active monitoring
- Identify memory scanning triggers and patterns

### Phase 6: ATT&CK Mapping and Coverage Analysis

```bash
revav analyze --catalog kb/catalog/<product>.json --output kb/layers/
```

Map all extracted mechanisms to MITRE ATT&CK techniques. Score detection confidence per technique based on mechanism quality (inline hook > IAT hook, kernel callback > userland hook).

## Output

- `kb/profiles/<product>.yaml` — product component inventory
- `kb/catalog/<product>.json` — full detection mechanism catalog
- `kb/layers/<product>.json` — ATT&CK Navigator coverage layer
- Reports via `revav report --profile kb/profiles/<product>.yaml`

## Tools Used

- `revav.tools.hook_scanner` — automated hook detection
- `revav.tools.callback_enum` — kernel callback enumeration
- `revav.tools.rule_parser` — YARA/Sigma rule extraction
- `revav.tools.behavior_map` — behavioral pattern mapping
- `revav.tools.etw_mapper` — ETW provider and telemetry mapping
- `revav.tools.attack_mapper` — ATT&CK technique correlation
- `revav.tools.coverage_scorer` — detection confidence scoring
