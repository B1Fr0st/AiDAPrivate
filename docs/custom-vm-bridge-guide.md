# AiDA Custom VM Bridge Guide

This guide covers running malware or suspicious binaries in a separate Windows VM while keeping AiDAStandalone.exe on the host. It works with VMware, VirtualBox, QEMU, Hyper-V, and custom VM stacks as long as the host and guest can share one private folder.

AiDA's built-in `Run in VM` path uses Windows Sandbox. The Custom VM Bridge path is for analysts who want a persistent lab VM, a provider-specific VM, or a manually built Windows guest.

## Security Model

AiDA stays on the host. The guest receives only:

- The staged sample, if you selected one in the Run dialog
- `AiDAGuestAgent.exe`
- `launch_config.json`
- The bridge folders: `requests`, `responses`, and `artifacts`

Do not copy AiDAStandalone.exe into the guest. Do not expose AiDA's localhost MCP server to the VM network. The bridge is file-backed so guest actions are limited to explicit JSON requests written by AiDA.

## Recommended Lab Layout

Use one bridge folder per investigation:

```text
C:\AiDA-VM-Bridge\case-001
```

Share that folder into the VM with a guest path such as:

```text
Z:\AiDA-VM-Bridge\case-001
```

The exact guest path depends on your hypervisor. VMware shared folders may appear as a drive letter or under `\\vmware-host\Shared Folders\...`. VirtualBox shared folders often use a drive letter or `\\VBOXSVR\...`. QEMU can use virtio-fs, 9p, or a private Samba share.

Keep the bridge private to one analysis VM. Do not reuse a bridge folder across unrelated samples.

## UI Workflow

1. Open AiDA on the host.
2. Press `Run`.
3. Select `Custom VM`.
4. Optional: choose a host-side sample path. AiDA will copy it into `samples` under the bridge.
5. Choose the host bridge folder.
6. Enter the guest-visible path to that same shared folder.
7. Optional: enter the guest sample path. If you selected a host sample, AiDA auto-fills it as:

```text
<guest bridge>\samples\<sample filename>
```

8. Click `Activate`.
9. Click `Copy command`.
10. Paste and run that command inside the guest VM.

The command has this shape:

```powershell
"Z:\AiDA-VM-Bridge\case-001\agent\AiDAGuestAgent.exe" --bridge "Z:\AiDA-VM-Bridge\case-001"
```

The guest agent reads `launch_config.json`, starts the sample when a guest sample path is present, then services AiDA bridge requests.

## MCP Workflow

Agents and scripts can activate the same workflow through `vm_bridge_manage`.

Activate a bridge:

```json
{
  "action": "activate",
  "bridge_dir": "C:\\AiDA-VM-Bridge\\case-001",
  "guest_bridge_dir": "Z:\\AiDA-VM-Bridge\\case-001",
  "host_sample": "C:\\samples\\sample.exe",
  "guest_sample": "Z:\\AiDA-VM-Bridge\\case-001\\samples\\sample.exe",
  "args": ""
}
```

`host_sample` is optional. When it is present, AiDA copies it into `bridge\samples`. If `guest_bridge_dir` is present and `guest_sample` is omitted, AiDA auto-fills the guest sample path. `stage_agent` defaults to `true` and copies `AiDAGuestAgent.exe` into `bridge\agent`.

Check host-side and guest-side status:

```json
{ "action": "status" }
```

```json
{ "action": "ping", "timeout_ms": 5000 }
```

List guest processes:

```json
{ "action": "list_processes", "filter": "sample", "timeout_ms": 5000 }
```

Attach to a guest process:

```json
{ "action": "attach", "pid": 4321, "timeout_ms": 5000 }
```

Read memory from the attached guest process:

```json
{
  "action": "read_memory",
  "pid": 4321,
  "address": "0x140001000",
  "size": 256,
  "timeout_ms": 5000
}
```

After the bridge is active, normal tools such as `list_processes`, `read_memory`, `read_string`, and `query_memory` default to the guest unless you pass `target: "host"`.

## Supported Guest Operations

`AiDAGuestAgent.exe` currently supports:

- status
- process listing
- attach and detach
- module enumeration
- thread enumeration
- memory map
- memory query
- memory read
- string read
- region dump
- memory byte-pattern search

Region dumps are written under the bridge `artifacts` folder so they are visible to AiDA on the host.

## Hypervisor Notes

VMware:

- Use a shared folder that is writable from both host and guest.
- If the shared folder is exposed through `\\vmware-host\Shared Folders`, you can use that UNC path as the guest bridge path.
- A mapped drive letter is easier to paste into the Run dialog.

VirtualBox:

- Use a shared folder with automount or manually map it to a drive letter.
- Confirm the guest user can create files under `requests`, `responses`, and `artifacts`.

QEMU:

- Use any private host/guest file-sharing method that preserves normal file create, rename, and delete semantics.
- virtio-fs, 9p, or a private host-only Samba share can work.
- Prefer a host-only/private network if you use SMB.

Custom VM stacks:

- AiDA only requires a guest Windows process running `AiDAGuestAgent.exe` and a shared directory visible from both sides.
- The guest path and host path do not need to match.
- The bridge does not require the guest to connect to AiDA's localhost MCP server.

## Operational Checklist

Before running a sample:

- Snapshot or checkpoint the VM.
- Disable shared clipboard and drag-and-drop unless needed for your lab process.
- Use a dedicated bridge folder for the case.
- Keep the bridge folder outside sensitive host directories.
- Confirm the bridge folder is not shared with other machines.
- Confirm AiDAStandalone.exe is only on the host.

After running a sample:

- Export required artifacts from the bridge folder.
- Shut down the guest agent or revert the VM snapshot.
- Deactivate the bridge from AiDA or call `vm_bridge_manage` with `action=deactivate`.
- Archive or delete the case bridge folder according to your evidence-handling process.

## Troubleshooting

If AiDA says the guest timed out:

- Confirm `AiDAGuestAgent.exe` is running inside the guest.
- Confirm the guest command uses the guest-visible bridge path.
- Confirm the host bridge folder contains `requests`, `responses`, and `artifacts`.
- Confirm files created by the host appear inside the guest and files created by the guest appear on the host.
- Check `status.json` in the bridge root.

If the sample does not start:

- Confirm `launch_config.json` contains the guest-visible sample path.
- Confirm the sample exists at that exact path inside the guest.
- Start the guest agent from an elevated prompt if the sample requires elevated inspection permissions.

If host tools inspect the host instead of the guest:

- Make sure the bridge is active.
- Pass `target: "guest"` explicitly to guest-aware tools.
- Pass `target: "host"` explicitly when you intentionally want host memory or host processes.
