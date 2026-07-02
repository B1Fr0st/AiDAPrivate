import idautils
import idc
import ida_hexrays
import re

# Segment heap LFH bucket sizes (Windows 10 19041+ / Windows 11)
lfh_buckets_seg = [16,32,48,64,80,96,112,128,144,160,176,192,208,224,240,256,
                   272,288,304,320,352,384,416,448,480,512,576,640,704,768,832,896,
                   960,1024,1088,1152,1280,1360,1440,1520,1600,1760,1920,2080,2240,
                   2400,2560,2720,2880,3040,3200]

def get_bucket(size):
    for b in lfh_buckets_seg:
        if size <= b:
            return b
    return -1

# Complete object type data
objects = [
    # name, body_size, type_global, pool_type, close_proc, delete_proc, init_proc, user_creatable, fully_zeroed, uninit_ranges
    ("Event", 24, "ExEventObjectType", "NonPaged", "NULL", "NULL", "KeInitializeEvent", True, True, []),
    ("Semaphore", 32, "ExSemaphoreObjectType", "NonPaged", "NULL", "NULL", "KeInitializeSemaphore", True, True, []),
    ("Timer", 328, "ExTimerObjectType", "NonPaged", "NULL", "ExpDeleteTimer", "KeInitializeTimerEx+KeInitializeDpc", True, False, [(48,159),(192,327)]),
    ("IRTimer", 168, "ExpIRTimerObjectType", "NonPaged", "NULL", "ExpDeleteTimer2", "KeInitializeIRTimer", True, False, []),
    ("IoCompletion", 80, "IoCompletionObjectType", "NonPaged", "IopCloseIoCompletion", "IopDeleteIoCompletion", "KeInitializeQueue", True, False, []),
    ("Mutant", 56, "ExMutantObjectType", "NonPaged", "NULL", "ExpDeleteMutant", "KeInitializeMutantEx", True, True, []),
    ("KeyedEvent", 1536, "ExpKeyedEventObjectType", "Paged", "NULL", "NULL", "N/A", True, True, []),
    ("WorkerFactory", 576, "ExpWorkerFactoryObjectType", "NonPaged", "ExpCloseWorkerFactory", "ExpDeleteWorkerFactory", "partial", True, False, [(0,71),(72,103),(280,327),(376,463),(576,575)]),
    ("DebugObject", 104, "DbgkDebugObjectType", "NonPaged", "DbgkCloseDebugObject?", "DbgkDeleteDebugObject?", "partial", True, False, [(40,47)]),
    ("JobObject", 1600, "PsJobType", "NonPaged", "?", "?", "memset+list_init", True, True, []),
    ("RegistryTransaction", 32, "CmRegistryTransaction", "Paged", "?", "?", "?", True, True, []),
    ("WaitCompletionPacket", 112, "IopWaitCompletionPacketObjectType", "NonPaged", "IopCloseWaitCompletionPacket", "NULL", "?", True, False, []),
    ("Section", 64, "MmSectionObjectType", "NonPaged", "MiSectionClose?", "MiSectionDelete?", "?", True, False, []),
    ("Partition", 128, "PsPartitionType", "NonPaged", "?", "?", "?", True, False, []),
    ("ALPCPort", 472, "AlpcPortObjectType", "NonPaged", "AlpcpClosePort", "AlpcpDeletePort", "memset+AlpcpInitializePort", True, True, []),
    ("PrivateNamespace", "variable", "ObpDirectoryObjectType", "NonPaged", "?", "?", "memset", True, True, []),
    ("Directory", 344, "ObpDirectoryObjectType", "NonPaged", "?", "?", "?", True, False, []),
    ("SymbolicLink", 40, "ObpSymbolicLinkObjectType", "NonPaged", "?", "?", "?", True, False, []),
    ("Profile", 160, "ExProfileObjectType", "NonPaged", "?", "?", "?", False, False, []),
    ("Callback", 56, "ExCallbackObjectType", "NonPaged", "?", "?", "?", False, False, []),
]

print("=" * 130)
print(f"{'Name':25s} {'Body':>6s} {'Pool':10s} {'Named+OH':>9s} {'Bucket':>7s} {'Unnamed+OH':>10s} {'Bucket':>7s} {'Close':30s} {'Delete':30s}")
print("=" * 130)

for obj in objects:
    name, body, type_g, pool, close, delete, init, user, zeroed, uninit = obj
    if pool != "NonPaged" or not user:
        continue
    if isinstance(body, str):
        print(f"{name:25s} {'variable':>6s} {pool:10s} {'variable':>9s} {'?':>7s} {'variable':>10s} {'?':>7s} {close:30s} {delete:30s}")
        continue
    
    # With security flag (ALPC has it)
    has_sec = (name == "ALPCPort")
    oh_named = 112 + (16 if has_sec else 0)
    oh_unnamed = 80 + (16 if has_sec else 0)
    
    named_total = body + oh_named
    unnamed_total = body + oh_unnamed
    named_bucket = get_bucket(named_total)
    unnamed_bucket = get_bucket(unnamed_total)
    
    m640 = " <==640" if (577 <= named_total <= 640 or 577 <= unnamed_total <= 640) else ""
    m1024 = " <==1024" if (961 <= named_total <= 1024 or 961 <= unnamed_total <= 1024) else ""
    
    print(f"{name:25s} {body:6d} {pool:10s} {named_total:9d} {named_bucket:7d} {unnamed_total:10d} {unnamed_bucket:7d} {close:30s} {delete:30s}{m640}{m1024}")

print("\n\n=== Types with uninitialized fields ===")
for obj in objects:
    name, body, type_g, pool, close, delete, init, user, zeroed, uninit = obj
    if pool != "NonPaged" or not user or zeroed or not uninit:
        continue
    if isinstance(body, str):
        continue
    print(f"\n{name} (body={body}):")
    print(f"  Close: {close}, Delete: {delete}")
    print(f"  Init: {init}")
    print(f"  Fully zeroed: {zeroed}")
    for start, end in uninit:
        print(f"  UNINITIALIZED: offsets {start}-{end} ({end-start+1} bytes)")

print("\n\n=== Key target bucket analysis ===")
print("Bucket 640 (577-640 total):")
for obj in objects:
    name, body, type_g, pool, close, delete, init, user, zeroed, uninit = obj
    if pool != "NonPaged" or not user or isinstance(body, str):
        continue
    has_sec = (name == "ALPCPort")
    oh_named = 112 + (16 if has_sec else 0)
    oh_unnamed = 80 + (16 if has_sec else 0)
    for oh_name, oh in [("named", oh_named), ("unnamed", oh_unnamed)]:
        total = body + oh
        if 577 <= total <= 640:
            print(f"  {name}: body={body}, {oh_name} overhead={oh}, total={total}, zeroed={zeroed}, delete={delete}")

print("\nBucket 1024 (961-1024 total):")
for obj in objects:
    name, body, type_g, pool, close, delete, init, user, zeroed, uninit = obj
    if pool != "NonPaged" or not user or isinstance(body, str):
        continue
    has_sec = (name == "ALPCPort")
    oh_named = 112 + (16 if has_sec else 0)
    oh_unnamed = 80 + (16 if has_sec else 0)
    for oh_name, oh in [("named", oh_named), ("unnamed", oh_unnamed)]:
        total = body + oh
        if 961 <= total <= 1024:
            print(f"  {name}: body={body}, {oh_name} overhead={oh}, total={total}, zeroed={zeroed}, delete={delete}")
