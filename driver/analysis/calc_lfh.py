import json

OBJECT_HEADER_BASE = 48
NAME_INFO = 32
QUOTA_INFO = 32
SECURITY_INFO = 16

lfh_buckets = [16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
               272, 288, 304, 320, 352, 384, 416, 448, 480, 512, 560, 608, 640, 672, 704,
               736, 768, 800, 832, 864, 896, 928, 960, 992, 1024, 1088, 1152, 1216, 1280,
               1360, 1440, 1520, 1600, 1680, 1760, 1840, 1920, 2000, 2080, 2160, 2240,
               2320, 2400, 2480, 2560, 2720, 2880, 3040, 3200, 3360, 3520, 3680, 3840,
               4000, 4160, 4320, 4480, 4640, 4800, 4960, 5120]

def get_lfh_bucket(size):
    for b in lfh_buckets:
        if size <= b:
            return b
    return -1

objects = [
    {"name": "Event", "body": 24, "type": "ExEventObjectType", "close": "NULL", "delete": "NULL", "pool": "NonPaged"},
    {"name": "Semaphore", "body": 32, "type": "ExSemaphoreObjectType", "close": "NULL", "delete": "NULL", "pool": "NonPaged"},
    {"name": "Timer", "body": 328, "type": "ExTimerObjectType", "close": "NULL", "delete": "ExpDeleteTimer", "pool": "NonPaged"},
    {"name": "IRTimer", "body": 168, "type": "ExpIRTimerObjectType", "close": "NULL", "delete": "ExpDeleteTimer2", "pool": "NonPaged"},
    {"name": "IoCompletion", "body": 80, "type": "IoCompletionObjectType", "close": "IopCloseIoCompletion", "delete": "IopDeleteIoCompletion", "pool": "NonPaged"},
    {"name": "Mutant", "body": 56, "type": "ExMutantObjectType", "close": "NULL", "delete": "ExpDeleteMutant", "pool": "NonPaged"},
    {"name": "KeyedEvent", "body": 64, "type": "ExpKeyedEventObjectType", "close": "NULL", "delete": "NULL", "pool": "NonPaged"},
    {"name": "WorkerFactory", "body": 520, "type": "ExpWorkerFactoryObjectType", "close": "?", "delete": "?", "pool": "NonPaged"},
    {"name": "DebugObject", "body": 104, "type": "DbgkDebugObjectType", "close": "?", "delete": "?", "pool": "NonPaged"},
    {"name": "JobObject", "body": 432, "type": "JobObject", "close": "?", "delete": "?", "pool": "NonPaged"},
    {"name": "RegistryTransaction", "body": 32, "type": "CmRegistryTransaction", "close": "?", "delete": "?", "pool": "Paged"},
    {"name": "WaitCompletionPacket", "body": 112, "type": "IopWaitCompletionPacketObjectType", "close": "IopCloseWaitCompletionPacket", "delete": "NULL", "pool": "NonPaged"},
]

results = []
for obj in objects:
    if obj["pool"] != "NonPaged":
        continue
    for scenario, overhead in [("unnamed", 80), ("named", 112), ("named+sec", 128)]:
        total = overhead + obj["body"]
        bucket = get_lfh_bucket(total)
        in_1024 = 993 <= total <= 1024
        in_640 = 609 <= total <= 640
        results.append((obj["name"], obj["body"], overhead, scenario, total, bucket, obj["close"], obj["delete"], in_1024, in_640))

print("=" * 100)
print(f"{'Name':25s} {'Body':>5s} {'OH':>4s} {'Scenario':10s} {'Total':>6s} {'Bucket':>6s} {'Close':30s} {'Delete':30s} {'1024':5s} {'640':5s}")
print("=" * 100)
for r in results:
    m1024 = "***" if r[8] else ""
    m640 = "***" if r[9] else ""
    print(f"{r[0]:25s} {r[1]:5d} {r[2]:4d} {r[3]:10s} {r[4]:6d} {r[5]:6d} {r[6]:30s} {r[7]:30s} {m1024:5s} {m640:5s}")

print("\n=== Target bucket 1024 (993-1024 total) ===")
for r in results:
    if r[8]:
        print(f"  {r[0]}: body={r[1]}, overhead={r[2]} ({r[3]}), total={r[4]}, delete={r[7]}")

print("\n=== Target bucket 640 (609-640 total) ===")
for r in results:
    if r[9]:
        print(f"  {r[0]}: body={r[1]}, overhead={r[2]} ({r[3]}), total={r[4]}, delete={r[7]}")

print("\n=== All NonPaged types sorted by body size ===")
seen = set()
for r in sorted(results, key=lambda x: x[1]):
    key = (r[0], r[1])
    if key not in seen:
        seen.add(key)
        print(f"  {r[0]:25s} body={r[1]:4d}  named_total={r[1]+112:4d} bucket={get_lfh_bucket(r[1]+112):5d}  unnamed_total={r[1]+80:4d} bucket={get_lfh_bucket(r[1]+80):5d}")
