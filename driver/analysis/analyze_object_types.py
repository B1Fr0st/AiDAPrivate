import idaapi
import idc
import ida_bytes
import ida_name
import struct

object_types = {
    'ExEventObjectType': 0x140cfc4c0,
    'ExSemaphoreObjectType': 0x140cfb258,
    'ExTimerObjectType': 0x140cfc680,
    'IoCompletionObjectType': 0x140cfc5d8,
    'MmSectionObjectType': 0x140cfc520,
    'CmKeyObjectType': 0x140cfc430,
    'PsPartitionType': 0x140cfc7e0,
    'ExMutantObjectType': 0x140cfb250,
    'SeTokenObjectType': 0x140d2d028,
    'TmTransactionObjectType': 0x140cfc790,
    'TmTransactionManagerObjectType': 0x140cfcb18,
    'TmResourceManagerObjectType': 0x140cfcb20,
    'TmEnlistmentObjectType': 0x140cfcc60,
    'ExpKeyedEventObjectType': 0x140cfb248,
    'ExpWorkerFactoryObjectType': 0x140cfb168,
    'ExCallbackObjectType': 0x140cfc950,
    'ExProfileObjectType': 0x140cfb2d0,
    'AlpcPortObjectType': 0x140cfc548,
    'IoFileObjectType': 0x140cfc448,
    'IoDeviceObjectType': 0x140cfc810,
    'IoDriverObjectType': 0x140cfc5a8,
    'IoAdapterObjectType': 0x140cfcc58,
    'IoControllerObjectType': 0x140cfcb08,
    'DbgkDebugObjectType': 0x140cfb0f0,
    'PopPowerRequestObjectType': 0x140cfb300,
    'MmSessionObjectType': 0x140cfc6c8,
    'ExpIRTimerObjectType': 0x140cfc7a8,
    'IopWaitCompletionPacketObjectType': 0x140cfc9b0,
    'PspActivityReferenceObjectType': 0x140cfcaa0,
    'EtwpRegistrationObjectType': 0x140cfc638,
    'WmipGuidObjectType': 0x140cfc670,
    'LpcPortObjectType': 0x140cfb260,
    'LpcWaitablePortObjectType': 0x140cfb398,
    'ExCrossVmEventObjectType': 0x140c16168,
    'ExCrossVmMutantObjectType': 0x140c16170,
    'TtmpTerminalObjectType': 0x140d2e8e0,
    'TtmpQueueObjectType': 0x140d2ea40,
    'ObpDirectoryObjectType': 0x140c25bc0,
    'ObpSymbolicLinkObjectType': 0x140c25bc8,
    'ObpTypeObjectType': 0x140c25bd8,
    'EtwpSessionDemuxObjectType': 0x140cfc958,
    'HalpDmaAdapterObjectType': 0x140cfc650,
}

def get_name(addr):
    n = ida_name.get_name(addr)
    if not n:
        return hex(addr)
    return n

results = []
for name, addr in sorted(object_types.items(), key=lambda x: x[1]):
    data = ida_bytes.get_bytes(addr, 0x100)
    if data is None:
        results.append(f"{name}: FAILED TO READ at {hex(addr)}")
        continue

    # Name UNICODE_STRING at offset 0x10
    name_len = struct.unpack_from('<H', data, 0x10)[0]
    name_buf = struct.unpack_from('<Q', data, 0x18)[0]
    obj_name = ""
    if name_buf != 0 and name_len > 0:
        nb = ida_bytes.get_bytes(name_buf, min(name_len, 128))
        if nb:
            obj_name = nb.decode('utf-16-le', errors='replace')

    # Index at 0x28
    index = data[0x28]

    # TypeInfo at 0x40
    ti_len = struct.unpack_from('<H', data, 0x40)[0]
    ti_flags = data[0x42]
    ti_flags2 = data[0x43]
    valid_access = struct.unpack_from('<I', data, 0x44)[0]
    retain_access = struct.unpack_from('<I', data, 0x48)[0]

    # GENERIC_MAPPING at 0x4C (16 bytes)
    gen_read = struct.unpack_from('<I', data, 0x4C)[0]
    gen_write = struct.unpack_from('<I', data, 0x50)[0]
    gen_exec = struct.unpack_from('<I', data, 0x54)[0]
    gen_all = struct.unpack_from('<I', data, 0x58)[0]

    # PoolType at 0x5C
    pool_type = struct.unpack_from('<I', data, 0x5C)[0]
    # DefaultPagedPoolCharge at 0x60
    paged_charge = struct.unpack_from('<I', data, 0x60)[0]
    # DefaultNonPagedPoolCharge at 0x64
    nonpaged_charge = struct.unpack_from('<I', data, 0x64)[0]

    # Now scan for procedure pointers after 0x68
    # OpenProcedure, CloseProcedure, DeleteProcedure, ParseProcedure, SecurityProcedure, QueryNameProcedure, OkayToCloseProcedure
    # Each is 8 bytes. Let's scan 0x68 to 0xC0 for non-zero pointers
    procs = {}
    proc_names = ['OpenProc', 'CloseProc', 'DeleteProc', 'ParseProc', 'SecurityProc', 'QueryNameProc', 'OkayToCloseProc']
    for i, pn in enumerate(proc_names):
        off = 0x68 + i * 8
        if off + 8 <= len(data):
            val = struct.unpack_from('<Q', data, off)[0]
            if val != 0:
                procs[pn] = get_name(val)
            else:
                procs[pn] = "NULL"

    body_size = nonpaged_charge if pool_type == 0 else paged_charge
    pool_str = "NonPagedPool" if pool_type == 0 else f"PagedPool({pool_type})"

    line = f"{name} | obj_name={obj_name} | index={index} | pool={pool_str} | body_size={body_size} (paged={paged_charge} nonpaged={nonpaged_charge}) | ti_len={ti_len} | flags=0x{ti_flags:02x},{ti_flags2:02x} | valid_access=0x{valid_access:08x} | retain=0x{retain_access:08x}"
    line += f" | Close={procs.get('CloseProc','?')} | Delete={procs.get('DeleteProc','?')} | Open={procs.get('OpenProc','?')} | Parse={procs.get('ParseProc','?')} | Security={procs.get('SecurityProc','?')} | QueryName={procs.get('QueryNameProc','?')} | OkayToClose={procs.get('OkayToCloseProc','?')}"
    results.append(line)

print("\n".join(results))
