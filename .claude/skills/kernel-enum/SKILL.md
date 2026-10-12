---
name: kernel-enum
description: Kernel callback enumeration methodology
---

# Kernel Callback Enumeration

## Callback Types

1. **Process Callbacks** — PsSetCreateProcessNotifyRoutineEx
2. **Thread Callbacks** — PsSetCreateThreadNotifyRoutineEx
3. **Image Load Callbacks** — PsSetLoadImageNotifyRoutineEx
4. **Registry Callbacks** — CmRegisterCallbackEx
5. **Object Callbacks** — ObRegisterCallbacks
6. **Minifilter Callbacks** — FltRegisterFilter (file system operations)
7. **WFP Callouts** — FwpsCalloutRegister (network filtering)
8. **ETW ThreatIntel** — EtwThreatIntProvRegister

## Approach

- Enumerate callback arrays from kernel structures
- Resolve owning driver per callback
- Map minifilter altitudes for priority ordering
- Cross-reference with known driver signatures

## Confidence

Kernel callbacks provide the highest confidence detection coverage. Missing callbacks for a category indicate coverage gaps.

## Tool Integration

Use `revav scan --agents callback` for kernel callback extraction.
