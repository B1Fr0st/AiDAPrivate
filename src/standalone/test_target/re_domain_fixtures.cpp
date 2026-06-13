#define AIDA_TEST_TARGET_FIXTURE_API __declspec(dllexport)
#include "re_domain_fixtures.h"
#include "test_log.h"

#include <cstdio>
#include <cstring>
#include <new>
#include <typeinfo>

namespace test_target {
namespace re_fixtures {

namespace {

constexpr std::uint32_t kMagic = 0x41494452u;
constexpr std::uint16_t kVersion = 1;
constexpr std::uint32_t kMatrixCount = 64;
constexpr std::uint32_t kMatrixStride = 64;
constexpr std::uint32_t kStructCount = 16;
constexpr std::uint32_t kMaxHeapBlocks = 128;
constexpr std::uint32_t kDxStaticSlotCount = 5;
constexpr std::uint32_t kDxStaticFixtureKind = 1;

struct matrix4x4_t {
    float v[16];
};

struct fixture_struct_t {
    std::uint32_t id;
    std::uint32_t flags;
    std::uint64_t owner;
    float position[3];
    float velocity[3];
    std::uint32_t health;
    std::uint32_t armor;
    char name[32];
    std::uint64_t link;
};

struct resource_like_object_t {
    void* vtable;
    void* backing;
    std::uint64_t magic;
    std::uint32_t size;
    std::uint32_t stride;
    void* secondary;
    float bounds[4];
    char label[32];
    void* aliases[8];
};

class fixture_rtti_base {
public:
    virtual ~fixture_rtti_base() = default;
    virtual std::uint32_t kind() const noexcept { return 0xB001u; }
    virtual std::uint64_t value() const noexcept { return 0xA1DA000000000001ull; }
};

class fixture_rtti_entity final : public fixture_rtti_base {
public:
    __declspec(noinline) fixture_rtti_entity() noexcept;
    __declspec(noinline) explicit fixture_rtti_entity(std::uint32_t seed) noexcept;
    std::uint32_t id;
    std::uint32_t flags;
    std::uint64_t payload;
    std::uint32_t kind() const noexcept override { return 0xBEEF7001u; }
    std::uint64_t value() const noexcept override { return payload ^ id; }
};

fixture_rtti_entity::fixture_rtti_entity() noexcept
    : fixture_rtti_entity(0x7001u)
{
}

fixture_rtti_entity::fixture_rtti_entity(std::uint32_t seed) noexcept
    : id(0x70010000u ^ seed),
      flags(0x41u | (seed & 0xFFu)),
      payload(0xA1DA700100000002ull ^ (static_cast<std::uint64_t>(seed) << 17u))
{
}

std::atomic<bool>* g_running = nullptr;
config_t g_cfg{};
matrix4x4_t* g_matrix_buffer = nullptr;
fixture_struct_t* g_struct_array = nullptr;
fixture_struct_t g_struct_base{};
resource_like_object_t g_resource{};
fixture_rtti_entity g_rtti_entity{};
alignas(fixture_rtti_entity) unsigned char g_rtti_factory_storage[sizeof(fixture_rtti_entity)] = {};
fixture_rtti_entity* g_rtti_factory_entity = nullptr;
HMODULE g_d3d11 = nullptr;
HMODULE g_dxgi = nullptr;
HANDLE g_window_thread = nullptr;
DWORD g_window_thread_id = 0;
HWND g_hwnd = nullptr;
std::uint64_t g_frame_counter = 0;
void* g_heap_blocks[kMaxHeapBlocks] = {};
std::uint32_t g_heap_count = 0;
std::uint32_t g_heap_stride = 0;
CRITICAL_SECTION g_heap_lock;
bool g_heap_lock_ready = false;
std::atomic<bool> g_local_running{false};
std::uint64_t g_dx_static_slot_accumulator = 0;
volatile std::uint64_t g_analysis_sink = 0;

const char* g_dx_static_slot_names[kDxStaticSlotCount] = {
    "VSSetConstantBuffers",
    "DrawIndexed",
    "DrawIndexedInstanced",
    "PSSetShaderResources",
    "IASetVertexBuffers"
};

const char g_dx_static_fixture_label[] = "static_dummy_d3d11_context_vtable";
void* g_dx_static_vtable[64] = {};
void* g_dx_static_slot_addresses[kDxStaticSlotCount] = {};

extern "C" __declspec(noinline) std::uint64_t aida_re_resource_slot_zero() noexcept
{
    return reinterpret_cast<std::uint64_t>(&g_resource);
}

extern "C" __declspec(noinline) std::uint64_t aida_re_resource_slot_one() noexcept
{
    return reinterpret_cast<std::uint64_t>(g_matrix_buffer);
}

void* g_resource_vtable[] = {
    reinterpret_cast<void*>(&aida_re_resource_slot_zero),
    reinterpret_cast<void*>(&aida_re_resource_slot_one)
};

void initialize_dx_static_vtable()
{
    std::memset(g_dx_static_vtable, 0, sizeof(g_dx_static_vtable));
    g_dx_static_vtable[7] = reinterpret_cast<void*>(&aida_test_re_dx_static_vs_set_constant_buffers);
    g_dx_static_vtable[12] = reinterpret_cast<void*>(&aida_test_re_dx_static_draw_indexed);
    g_dx_static_vtable[14] = reinterpret_cast<void*>(&aida_test_re_dx_static_draw_indexed_instanced);
    g_dx_static_vtable[25] = reinterpret_cast<void*>(&aida_test_re_dx_static_ps_set_shader_resources);
    g_dx_static_vtable[54] = reinterpret_cast<void*>(&aida_test_re_dx_static_ia_set_vertex_buffers);
    g_dx_static_slot_addresses[0] = g_dx_static_vtable[7];
    g_dx_static_slot_addresses[1] = g_dx_static_vtable[12];
    g_dx_static_slot_addresses[2] = g_dx_static_vtable[14];
    g_dx_static_slot_addresses[3] = g_dx_static_vtable[25];
    g_dx_static_slot_addresses[4] = g_dx_static_vtable[54];
}

std::uint64_t min_nonzero_va(std::uint64_t a, std::uint64_t b)
{
    if (a == 0)
        return b;
    if (b == 0)
        return a;
    return a < b ? a : b;
}

std::uint64_t max_va(std::uint64_t a, std::uint64_t b)
{
    return a > b ? a : b;
}

std::uint64_t probe_u64(const void* ptr)
{
    std::uint64_t value = 0;
    __try {
        std::memcpy(&value, ptr, sizeof(value));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
    }
    return value;
}

std::uint64_t resolve_type_descriptor_from_col(std::uint64_t col_va)
{
    struct col_t {
        std::uint32_t signature;
        std::uint32_t offset;
        std::uint32_t cd_offset;
        std::uint32_t type_descriptor_rva;
        std::uint32_t class_descriptor_rva;
        std::uint32_t self_rva;
    };
    if (!col_va)
        return 0;
    col_t col{};
    __try {
        std::memcpy(&col, reinterpret_cast<const void*>(col_va), sizeof(col));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    if (col.signature == 1u && col.self_rva != 0)
        return (col_va - col.self_rva) + col.type_descriptor_rva;
    return static_cast<std::uint64_t>(col.type_descriptor_rva);
}

void update_analysis_range_fields()
{
    const std::uint64_t branch = reinterpret_cast<std::uint64_t>(&aida_test_re_analysis_branch);
    const std::uint64_t callgraph = reinterpret_cast<std::uint64_t>(&aida_test_re_analysis_callgraph);
    const std::uint64_t dispatch = reinterpret_cast<std::uint64_t>(&aida_test_re_analysis_dispatch);
    std::uint64_t lo = min_nonzero_va(branch, callgraph);
    lo = min_nonzero_va(lo, dispatch);
    std::uint64_t hi = max_va(branch, callgraph);
    hi = max_va(hi, dispatch);
    aida_test_re_descriptor.analysis_range_va = lo;
    aida_test_re_descriptor.analysis_range_size = hi >= lo ? static_cast<std::uint32_t>((hi - lo) + 512u) : 0u;
}

bool running_now()
{
    return g_local_running.load(std::memory_order_acquire) && g_running && g_running->load(std::memory_order_acquire);
}

void fill_matrix(std::uint32_t index, std::uint64_t frame)
{
    if (!g_matrix_buffer || index >= kMatrixCount)
        return;
    matrix4x4_t& m = g_matrix_buffer[index];
    std::memset(&m, 0, sizeof(m));
    const float scale = 1.0f;
    m.v[0] = scale;
    m.v[5] = scale;
    m.v[10] = scale;
    m.v[15] = 1.0f;
    m.v[12] = static_cast<float>(index * 7u) + static_cast<float>(frame & 0x0F);
    m.v[13] = static_cast<float>(index * 3u);
    m.v[14] = static_cast<float>((index % 9u) * 11u);
}

void refresh_matrices(std::uint64_t frame)
{
    for (std::uint32_t i = 0; i < kMatrixCount; ++i)
        fill_matrix(i, frame);
}

void fill_structs()
{
    std::memset(&g_struct_base, 0, sizeof(g_struct_base));
    g_struct_base.id = 0xA1DA1000u;
    g_struct_base.flags = 0x100u;
    g_struct_base.owner = reinterpret_cast<std::uint64_t>(g_rtti_factory_entity ? g_rtti_factory_entity : &g_rtti_entity);
    g_struct_base.position[0] = 10.0f;
    g_struct_base.position[1] = 20.0f;
    g_struct_base.position[2] = 30.0f;
    g_struct_base.velocity[0] = 1.0f;
    g_struct_base.velocity[1] = 2.0f;
    g_struct_base.velocity[2] = 3.0f;
    g_struct_base.health = 100u;
    g_struct_base.armor = 75u;
    sprintf_s(g_struct_base.name, sizeof(g_struct_base.name), "AiDA_RE_Struct_Base");

    if (!g_struct_array)
        return;

    for (std::uint32_t i = 0; i < kStructCount; ++i) {
        fixture_struct_t& s = g_struct_array[i];
        s = g_struct_base;
        s.id = 0xA1DA2000u + i;
        s.flags = 0x200u | i;
        s.position[0] = static_cast<float>(i * 11u);
        s.position[1] = static_cast<float>(i * 13u);
        s.position[2] = static_cast<float>(i * 17u);
        s.velocity[0] = static_cast<float>(i + 1u);
        s.velocity[1] = static_cast<float>(i + 2u);
        s.velocity[2] = static_cast<float>(i + 3u);
        s.health = 100u + i;
        s.armor = 50u + i;
        sprintf_s(s.name, sizeof(s.name), "AiDA_RE_Struct_%02u", i);
        s.link = reinterpret_cast<std::uint64_t>(&g_struct_base);
    }
}

void fill_resource()
{
    std::memset(&g_resource, 0, sizeof(g_resource));
    g_resource.vtable = g_resource_vtable;
    g_resource.backing = g_matrix_buffer;
    g_resource.magic = 0xA1DAF11E00000001ull;
    g_resource.size = kMatrixCount * kMatrixStride;
    g_resource.stride = kMatrixStride;
    g_resource.secondary = g_struct_array;
    g_resource.bounds[0] = -1000.0f;
    g_resource.bounds[1] = -1000.0f;
    g_resource.bounds[2] = 1000.0f;
    g_resource.bounds[3] = 1000.0f;
    sprintf_s(g_resource.label, sizeof(g_resource.label), "AiDA_RE_Resource_Object");
    g_resource.aliases[0] = g_matrix_buffer;
    g_resource.aliases[1] = g_struct_array;
    g_resource.aliases[2] = &g_struct_base;
    g_resource.aliases[3] = &g_rtti_entity;
    g_resource.aliases[4] = g_rtti_factory_entity;
}

void* construct_rtti_entity_impl(void* storage, std::uint32_t seed) noexcept
{
    void* target = storage ? storage : static_cast<void*>(g_rtti_factory_storage);
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(target, &mbi, sizeof(mbi)) != sizeof(mbi) ||
        (mbi.State & MEM_COMMIT) == 0 ||
        (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0 ||
        (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) == 0)
        return nullptr;
    if (target == static_cast<void*>(g_rtti_factory_storage) && g_rtti_factory_entity)
        g_rtti_factory_entity->~fixture_rtti_entity();
    fixture_rtti_entity* entity = new(target) fixture_rtti_entity(seed);
    if (target == static_cast<void*>(g_rtti_factory_storage))
        g_rtti_factory_entity = entity;
    return entity;
}

void* factory_rtti_entity_impl(std::uint32_t seed) noexcept
{
    return construct_rtti_entity_impl(static_cast<void*>(g_rtti_factory_storage), seed);
}

void free_heap_blocks_locked()
{
    HANDLE heap = GetProcessHeap();
    for (std::uint32_t i = 0; i < g_heap_count && i < kMaxHeapBlocks; ++i) {
        if (g_heap_blocks[i]) {
            HeapFree(heap, 0, g_heap_blocks[i]);
            g_heap_blocks[i] = nullptr;
        }
    }
    g_heap_count = 0;
    g_heap_stride = 0;
    aida_test_re_descriptor.heap_burst_first_va = 0;
    aida_test_re_descriptor.heap_burst_count = 0;
    aida_test_re_descriptor.heap_burst_stride = 0;
}

LRESULT CALLBACK fixture_window_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_CLOSE) {
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    }
    if (msg == WM_DESTROY) {
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

DWORD WINAPI frame_window_thread(LPVOID)
{
    const wchar_t* cls = L"AiDA_RE_Fixture_Window";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = fixture_window_proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = cls;
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(0, cls, L"AiDA RE Fixture", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 320, 240,
                             nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (g_hwnd) {
        aida_test_re_descriptor.window_hwnd = reinterpret_cast<std::uint64_t>(g_hwnd);
        ShowWindow(g_hwnd, SW_SHOWNA);
        UpdateWindow(g_hwnd);
    }

    MSG msg{};
    while (running_now()) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        aida_test_re_frame_tick(static_cast<std::uint32_t>(g_frame_counter + 1u));
        Sleep(16);
    }

    if (g_hwnd) {
        DestroyWindow(g_hwnd);
        g_hwnd = nullptr;
        aida_test_re_descriptor.window_hwnd = 0;
    }
    UnregisterClassW(cls, GetModuleHandleW(nullptr));
    return 0;
}

void update_descriptor()
{
    aida_test_re_descriptor.magic = kMagic;
    aida_test_re_descriptor.version = kVersion;
    aida_test_re_descriptor.size = sizeof(aida_test_re_descriptor);
    aida_test_re_descriptor.module_base_va = reinterpret_cast<std::uint64_t>(GetModuleHandleW(nullptr));
    aida_test_re_descriptor.descriptor_va = reinterpret_cast<std::uint64_t>(&aida_test_re_descriptor);
    aida_test_re_descriptor.matrix_buffer_va = reinterpret_cast<std::uint64_t>(g_matrix_buffer);
    aida_test_re_descriptor.matrix_count = kMatrixCount;
    aida_test_re_descriptor.matrix_stride = kMatrixStride;
    aida_test_re_descriptor.resource_object_va = reinterpret_cast<std::uint64_t>(&g_resource);
    aida_test_re_descriptor.resource_backing_va = reinterpret_cast<std::uint64_t>(g_matrix_buffer);
    aida_test_re_descriptor.resource_size = kMatrixCount * kMatrixStride;
    aida_test_re_descriptor.resource_stride = kMatrixStride;
    aida_test_re_descriptor.struct_base_va = reinterpret_cast<std::uint64_t>(&g_struct_base);
    aida_test_re_descriptor.struct_array_va = reinterpret_cast<std::uint64_t>(g_struct_array);
    aida_test_re_descriptor.struct_count = kStructCount;
    aida_test_re_descriptor.struct_size = sizeof(fixture_struct_t);
    std::uint64_t rtti_vtable = 0;
    const char* rtti_name = typeid(g_rtti_entity).name();
    (void)rtti_name;
    const void* rtti_instance_bytes = static_cast<const void*>(&g_rtti_entity);
    std::memcpy(&rtti_vtable, rtti_instance_bytes, sizeof(rtti_vtable));
    const std::uint64_t col_va = rtti_vtable ? probe_u64(reinterpret_cast<const void*>(rtti_vtable - sizeof(std::uint64_t))) : 0;
    aida_test_re_descriptor.rtti_instance_va = reinterpret_cast<std::uint64_t>(&g_rtti_entity);
    aida_test_re_descriptor.rtti_vtable_va = rtti_vtable;
    aida_test_re_descriptor.heap_burst_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_re_heap_burst);
    aida_test_re_descriptor.mutate_struct_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_re_mutate_struct);
    aida_test_re_descriptor.frame_tick_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_re_frame_tick);
    aida_test_re_descriptor.frame_counter_va = reinterpret_cast<std::uint64_t>(&g_frame_counter);
    aida_test_re_descriptor.d3d11_module_va = reinterpret_cast<std::uint64_t>(g_d3d11);
    aida_test_re_descriptor.dxgi_module_va = reinterpret_cast<std::uint64_t>(g_dxgi);
    aida_test_re_descriptor.dx_static_vtable_va = reinterpret_cast<std::uint64_t>(g_dx_static_vtable);
    aida_test_re_descriptor.dx_static_slot_names_va = reinterpret_cast<std::uint64_t>(g_dx_static_slot_names);
    aida_test_re_descriptor.dx_static_slot_addresses_va = reinterpret_cast<std::uint64_t>(g_dx_static_slot_addresses);
    aida_test_re_descriptor.dx_static_slot_count = kDxStaticSlotCount;
    aida_test_re_descriptor.dx_static_fixture_kind = kDxStaticFixtureKind;
    aida_test_re_descriptor.dx_static_fixture_label_va = reinterpret_cast<std::uint64_t>(g_dx_static_fixture_label);
    aida_test_re_descriptor.rtti_factory_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_re_factory_rtti_entity);
    aida_test_re_descriptor.rtti_constructor_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_re_construct_rtti_entity);
    aida_test_re_descriptor.rtti_factory_instance_va = reinterpret_cast<std::uint64_t>(g_rtti_factory_entity);
    aida_test_re_descriptor.rtti_complete_object_locator_va = col_va;
    aida_test_re_descriptor.rtti_type_descriptor_va = resolve_type_descriptor_from_col(col_va);
    aida_test_re_descriptor.analysis_branch_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_re_analysis_branch);
    aida_test_re_descriptor.analysis_callgraph_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_re_analysis_callgraph);
    aida_test_re_descriptor.analysis_dispatch_fn_va = reinterpret_cast<std::uint64_t>(&aida_test_re_analysis_dispatch);
    aida_test_re_descriptor.analysis_export_count = 3;
    update_analysis_range_fields();
}

}

void init(const config_t& cfg, std::atomic<bool>& running)
{
    g_cfg = cfg;
    g_running = &running;
    g_local_running.store(true, std::memory_order_release);
    if (!g_heap_lock_ready) {
        InitializeCriticalSection(&g_heap_lock);
        g_heap_lock_ready = true;
    }

    if (!g_matrix_buffer) {
        g_matrix_buffer = static_cast<matrix4x4_t*>(VirtualAlloc(nullptr, kMatrixCount * sizeof(matrix4x4_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    }
    if (!g_struct_array) {
        g_struct_array = static_cast<fixture_struct_t*>(VirtualAlloc(nullptr, kStructCount * sizeof(fixture_struct_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    }

    refresh_matrices(0);
    initialize_dx_static_vtable();
    factory_rtti_entity_impl(0x7101u);
    fill_structs();
    fill_resource();

    if (!g_d3d11)
        g_d3d11 = LoadLibraryA("d3d11.dll");
    if (!g_dxgi)
        g_dxgi = LoadLibraryA("dxgi.dll");

    update_descriptor();

    if (cfg.enable_window && !g_window_thread) {
        g_window_thread = CreateThread(nullptr, 0, frame_window_thread, nullptr, 0, &g_window_thread_id);
    }

    if (cfg.verbose) {
        printf("[re-fixture] descriptor=%p matrix=%p resource=%p struct_array=%p rtti=%p d3d11=%p dxgi=%p window=%d\n",
               &aida_test_re_descriptor,
               g_matrix_buffer,
               &g_resource,
               g_struct_array,
               &g_rtti_entity,
               g_d3d11,
               g_dxgi,
               cfg.enable_window ? 1 : 0);
        printf("[re-fixture] dx_static_vtable=%p slots=%u rtti_factory=%p rtti_ctor=%p col=0x%llX type=0x%llX analysis_branch=%p analysis_callgraph=%p analysis_dispatch=%p\n",
               g_dx_static_vtable,
               aida_test_re_descriptor.dx_static_slot_count,
               reinterpret_cast<void*>(aida_test_re_descriptor.rtti_factory_fn_va),
               reinterpret_cast<void*>(aida_test_re_descriptor.rtti_constructor_fn_va),
               static_cast<unsigned long long>(aida_test_re_descriptor.rtti_complete_object_locator_va),
               static_cast<unsigned long long>(aida_test_re_descriptor.rtti_type_descriptor_va),
               reinterpret_cast<void*>(aida_test_re_descriptor.analysis_branch_fn_va),
               reinterpret_cast<void*>(aida_test_re_descriptor.analysis_callgraph_fn_va),
               reinterpret_cast<void*>(aida_test_re_descriptor.analysis_dispatch_fn_va));
        fflush(stdout);
    }
}

void shutdown_all()
{
    g_local_running.store(false, std::memory_order_release);

    if (g_window_thread) {
        WaitForSingleObject(g_window_thread, 1500);
        CloseHandle(g_window_thread);
        g_window_thread = nullptr;
        g_window_thread_id = 0;
    }

    if (g_heap_lock_ready) {
        EnterCriticalSection(&g_heap_lock);
        free_heap_blocks_locked();
        LeaveCriticalSection(&g_heap_lock);
    }

    if (g_struct_array) {
        VirtualFree(g_struct_array, 0, MEM_RELEASE);
        g_struct_array = nullptr;
    }
    if (g_matrix_buffer) {
        VirtualFree(g_matrix_buffer, 0, MEM_RELEASE);
        g_matrix_buffer = nullptr;
    }

    if (g_d3d11) {
        FreeLibrary(g_d3d11);
        g_d3d11 = nullptr;
    }
    if (g_dxgi) {
        FreeLibrary(g_dxgi);
        g_dxgi = nullptr;
    }
    if (g_rtti_factory_entity) {
        g_rtti_factory_entity->~fixture_rtti_entity();
        g_rtti_factory_entity = nullptr;
    }

    update_descriptor();
}

std::uint64_t heap_burst_impl(std::uint32_t count, std::uint32_t payload_size) noexcept
{
    if (!g_heap_lock_ready)
        return 0;

    if (count == 0)
        count = 1;
    if (count > kMaxHeapBlocks)
        count = kMaxHeapBlocks;
    if (payload_size < 64)
        payload_size = 64;
    if (payload_size > 4096)
        payload_size = 4096;

    EnterCriticalSection(&g_heap_lock);
    free_heap_blocks_locked();

    HANDLE heap = GetProcessHeap();
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint8_t* p = static_cast<std::uint8_t*>(HeapAlloc(heap, HEAP_ZERO_MEMORY, payload_size));
        if (!p)
            break;
        const std::uint64_t magic = 0xA1DAA11000000000ull | i;
        std::memcpy(p, &magic, sizeof(magic));
        std::memcpy(p + 8, &payload_size, sizeof(payload_size));
        std::memcpy(p + 16, &i, sizeof(i));
        for (std::uint32_t j = 24; j < payload_size; ++j)
            p[j] = static_cast<std::uint8_t>((i * 37u + j * 17u + 0x5Au) & 0xFFu);
        g_heap_blocks[i] = p;
        g_heap_count = i + 1u;
    }

    g_heap_stride = payload_size;
    aida_test_re_descriptor.heap_burst_first_va = g_heap_count ? reinterpret_cast<std::uint64_t>(g_heap_blocks[0]) : 0;
    aida_test_re_descriptor.heap_burst_count = g_heap_count;
    aida_test_re_descriptor.heap_burst_stride = g_heap_stride;
    const std::uint64_t result = aida_test_re_descriptor.heap_burst_first_va;
    LeaveCriticalSection(&g_heap_lock);
    return result;
}

std::uint64_t mutate_struct_impl(std::uint32_t index, std::uint32_t delta) noexcept
{
    if (!g_struct_array || index >= kStructCount)
        return 0;

    fixture_struct_t& s = g_struct_array[index];
    s.health += delta;
    s.armor ^= (delta << 1u) | 1u;
    s.position[0] += static_cast<float>(delta);
    s.position[1] += static_cast<float>(delta % 17u);
    s.position[2] += static_cast<float>(delta % 23u);
    s.link = reinterpret_cast<std::uint64_t>(&g_struct_array[(index + 1u) % kStructCount]);
    return reinterpret_cast<std::uint64_t>(&s);
}

std::uint64_t frame_tick_impl(std::uint32_t frame_index) noexcept
{
    g_frame_counter = frame_index;
    refresh_matrices(g_frame_counter);
    if (g_struct_array) {
        const std::uint32_t index = frame_index % kStructCount;
        mutate_struct_impl(index, (frame_index & 0x1Fu) + 1u);
    }
    return g_frame_counter;
}

}
}

extern "C" __declspec(dllexport) test_target::re_fixtures::descriptor_t aida_test_re_descriptor = {
    0x41494452u,
    1,
    sizeof(test_target::re_fixtures::descriptor_t)
};

extern "C" __declspec(dllexport) __declspec(noinline) const test_target::re_fixtures::descriptor_t* aida_test_re_get_descriptor() noexcept
{
    return &aida_test_re_descriptor;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t aida_test_re_heap_burst(std::uint32_t count, std::uint32_t payload_size) noexcept
{
    return test_target::re_fixtures::heap_burst_impl(count, payload_size);
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t aida_test_re_mutate_struct(std::uint32_t index, std::uint32_t delta) noexcept
{
    return test_target::re_fixtures::mutate_struct_impl(index, delta);
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t aida_test_re_frame_tick(std::uint32_t frame_index) noexcept
{
    return test_target::re_fixtures::frame_tick_impl(frame_index);
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t aida_test_re_dx_static_vs_set_constant_buffers(std::uint32_t start_slot, std::uint64_t buffer_va, std::uint32_t count) noexcept
{
    const std::uint64_t result = (static_cast<std::uint64_t>(start_slot) << 48u) ^ (static_cast<std::uint64_t>(count) << 32u) ^ buffer_va ^ 0xA1DAD31100000007ull;
    test_target::re_fixtures::g_dx_static_slot_accumulator ^= result;
    return test_target::re_fixtures::g_dx_static_slot_accumulator;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t aida_test_re_dx_static_draw_indexed(std::uint32_t index_count, std::uint32_t start_index, std::int32_t base_vertex) noexcept
{
    const std::uint64_t result = (static_cast<std::uint64_t>(index_count) * 1315423911ull) ^ (static_cast<std::uint64_t>(start_index) << 17u) ^ static_cast<std::uint32_t>(base_vertex) ^ 0xA1DAD3110000000Cull;
    test_target::re_fixtures::g_dx_static_slot_accumulator += result;
    return result;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t aida_test_re_dx_static_draw_indexed_instanced(std::uint32_t index_count, std::uint32_t instance_count, std::uint32_t start_index) noexcept
{
    const std::uint64_t result = (static_cast<std::uint64_t>(index_count) << 32u) | (static_cast<std::uint64_t>(instance_count) << 16u) | start_index;
    test_target::re_fixtures::g_dx_static_slot_accumulator ^= (result + 0xA1DAD3110000000Eull);
    return test_target::re_fixtures::g_dx_static_slot_accumulator;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t aida_test_re_dx_static_ps_set_shader_resources(std::uint32_t start_slot, std::uint64_t resource_va, std::uint32_t count) noexcept
{
    const std::uint64_t result = resource_va + static_cast<std::uint64_t>(start_slot * 257u + count * 4099u) + 0xA1DAD31100000019ull;
    test_target::re_fixtures::g_dx_static_slot_accumulator = (test_target::re_fixtures::g_dx_static_slot_accumulator << 3u) ^ result;
    return result;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t aida_test_re_dx_static_ia_set_vertex_buffers(std::uint32_t start_slot, std::uint64_t buffer_va, std::uint32_t stride) noexcept
{
    const std::uint64_t result = buffer_va ^ (static_cast<std::uint64_t>(stride) << 24u) ^ start_slot ^ 0xA1DAD31100000036ull;
    test_target::re_fixtures::g_dx_static_slot_accumulator += (result | 1ull);
    return test_target::re_fixtures::g_dx_static_slot_accumulator;
}

extern "C" __declspec(dllexport) __declspec(noinline) void* aida_test_re_construct_rtti_entity(void* storage, std::uint32_t seed) noexcept
{
    return test_target::re_fixtures::construct_rtti_entity_impl(storage, seed);
}

extern "C" __declspec(dllexport) __declspec(noinline) void* aida_test_re_factory_rtti_entity(std::uint32_t seed) noexcept
{
    return test_target::re_fixtures::factory_rtti_entity_impl(seed);
}

#pragma optimize("", off)
extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_re_analysis_branch(std::uint32_t x, std::uint32_t y) noexcept
{
    std::uint32_t acc = 0xA1DA3001u ^ x;
    if ((x & 1u) != 0)
        acc += y * 3u;
    else
        acc ^= y + 0x13572468u;
    if (x > y)
        acc = (acc << 5u) | (acc >> 27u);
    else if (x == y)
        acc += 0x11111111u;
    else
        acc = (acc >> 3u) | (acc << 29u);
    for (std::uint32_t i = 0; i < 6u; ++i) {
        acc ^= (x + i) * 33u;
        if ((acc & 0x80u) != 0)
            acc += y ^ i;
    }
    test_target::re_fixtures::g_analysis_sink ^= acc;
    return acc;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_re_analysis_callgraph(std::uint32_t seed) noexcept
{
    std::uint32_t total = 0;
    for (std::uint32_t i = 0; i < 4u; ++i)
        total += aida_test_re_analysis_branch(seed + i, seed ^ (i * 17u));
    total ^= aida_test_re_analysis_dispatch(seed & 7u, total);
    test_target::re_fixtures::g_analysis_sink += total;
    return total;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint32_t aida_test_re_analysis_dispatch(std::uint32_t opcode, std::uint32_t value) noexcept
{
    std::uint32_t out = value;
    switch (opcode & 7u) {
    case 0u:
        out += 0x101u;
        break;
    case 1u:
        out ^= 0xA5A5A5A5u;
        break;
    case 2u:
        out = (out << 7u) | (out >> 25u);
        break;
    case 3u:
        out *= 33u;
        break;
    case 4u:
        out = aida_test_re_analysis_branch(value & 0xFFu, opcode + 9u);
        break;
    case 5u:
        out -= 0x51515151u;
        break;
    case 6u:
        out ^= (out >> 11u);
        break;
    default:
        out += aida_test_re_analysis_branch(opcode, value);
        break;
    }
    test_target::re_fixtures::g_analysis_sink ^= out;
    return out;
}
#pragma optimize("", on)
