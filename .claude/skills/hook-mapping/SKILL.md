---
name: hook-mapping
description: "Identify and catalog userland API hooks installed by security products — inline hooks, IAT hooks, EAT hooks, syscall stub patches. Use when analyzing how a product intercepts API calls."
metadata:
  version: "0.1.0"
---

# Userland Hook Mapping

## Overview

Identifies userland API hooks installed by security products. Compares in-memory function prologues against clean baselines to detect inline hooks (JMP patches), IAT modifications, EAT redirections, and syscall stub patches.

## Hook Types

### Inline Hooks (JMP Patches)
The product overwrites the first bytes of a function with a JMP to its own handler.
- **Detection**: Compare first 16 bytes of function prologue against clean baseline
- **Indicators**: `E9` (JMP rel32), `FF 25` (JMP [addr]), `48 B8 ... FF E0` (MOV RAX, addr; JMP RAX)
- **Quality**: High — intercepts all callers including direct syscall wrappers

### IAT Hooks (Import Address Table)
The product modifies the Import Address Table of target processes to redirect API calls.
- **Detection**: Compare IAT entries against known-good export addresses
- **Indicators**: IAT entry points to EDR module instead of ntdll/kernel32
- **Quality**: Medium — only intercepts calls through the IAT, not direct calls

### EAT Hooks (Export Address Table)
The product modifies the Export Address Table of system DLLs.
- **Detection**: Compare EAT entries against on-disk DLL exports
- **Indicators**: Export RVA points outside the DLL's address range
- **Quality**: Medium — affects GetProcAddress resolution

### Syscall Stub Patches
The product modifies ntdll syscall stubs to intercept before the kernel transition.
- **Detection**: Compare syscall stub pattern against expected `mov r10, rcx; mov eax, <SSN>; syscall; ret`
- **Indicators**: Modified syscall number, inserted JMP before syscall instruction
- **Quality**: High — intercepts even direct ntdll calls

## Methodology

### Step 1: Establish Baseline
```bash
# Use clean baselines from baselines/ directory
# Or capture from a clean system:
python -m revav.tools.hook_scanner --capture-baseline --output baselines/
```

The baseline contains:
- Export addresses for ntdll.dll, kernel32.dll, kernelbase.dll
- First 32 bytes of each exported function
- Syscall numbers for each Nt* function
- IAT structure of common target processes

### Step 2: Scan Target System
```bash
python -m revav.tools.hook_scanner \
    --input <pid_or_path> \
    --baseline baselines/ntdll_clean.json \
    --output kb/catalog/hooks_<product>.json
```

### Step 3: Analyze Results

For each detected hook:
1. **Identify the hooking module** — which DLL owns the memory region the hook JMPs to?
2. **Classify the hook type** — inline, IAT, EAT, or syscall stub?
3. **Assess the hook quality** — inline + syscall stub = strong interception; IAT-only = bypassable
4. **Map to ATT&CK** — what technique does monitoring this API help detect?

### Step 4: Coverage Assessment

Group hooked APIs by ATT&CK technique:
- **T1055 (Process Injection)**: NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThread, NtQueueApcThread, NtMapViewOfSection
- **T1059 (Command Execution)**: CreateProcess, ShellExecute, WinExec
- **T1547 (Boot/Logon Persistence)**: RegSetValueEx, NtSetValueKey for Run keys
- **T1003 (Credential Dumping)**: NtReadVirtualMemory on lsass.exe, MiniDumpWriteDump

Identify unhooked APIs within each technique cluster — these are the blind spots.

## Key APIs Reference

### Process Operations
| API | DLL | ATT&CK | Notes |
|-----|-----|--------|-------|
| NtCreateProcess | ntdll | T1055 | Process creation |
| NtCreateProcessEx | ntdll | T1055 | Extended process creation |
| NtCreateUserProcess | ntdll | T1055 | Modern process creation (Vista+) |
| NtCreateThread | ntdll | T1055 | Remote thread creation |
| NtCreateThreadEx | ntdll | T1055 | Extended thread creation |
| NtResumeThread | ntdll | T1055 | Resume suspended thread |

### Memory Operations
| API | DLL | ATT&CK | Notes |
|-----|-----|--------|-------|
| NtAllocateVirtualMemory | ntdll | T1055 | Allocate RWX memory |
| NtWriteVirtualMemory | ntdll | T1055 | Write to remote process |
| NtProtectVirtualMemory | ntdll | T1055 | Change memory protection |
| NtMapViewOfSection | ntdll | T1055.012 | Map shared section |
| NtReadVirtualMemory | ntdll | T1003 | Read remote process memory |

### Registry Operations
| API | DLL | ATT&CK | Notes |
|-----|-----|--------|-------|
| NtCreateKey | ntdll | T1547 | Create registry key |
| NtSetValueKey | ntdll | T1547 | Set registry value |
| NtDeleteKey | ntdll | T1112 | Delete registry key |

## Output Format

```json
{
  "product": "Product Name",
  "scan_timestamp": "2026-01-01T00:00:00Z",
  "baseline": "ntdll_clean.json",
  "hooks": [
    {
      "api_name": "NtCreateThreadEx",
      "module": "ntdll.dll",
      "hook_type": "inline",
      "hooking_module": "edr_agent.dll",
      "original_bytes": "4C 8B D1 B8 C7 00 00 00",
      "patched_bytes": "E9 AB CD EF 01 00 00 00",
      "confidence": 0.95,
      "attack_techniques": ["T1055", "T1055.003"]
    }
  ],
  "unhooked_critical": ["NtMapViewOfSection", "NtQueueApcThread"]
}
```

## Tools

- `revav.tools.hook_scanner` — primary tool for this skill
