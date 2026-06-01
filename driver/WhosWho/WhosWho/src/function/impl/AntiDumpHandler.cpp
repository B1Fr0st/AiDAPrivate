#include "../Functions.h"
#include "../../imports/Defs.h"
#include "../Struct.h"
#include "../AntiDebug.h"
#include "../Dispatcher.h"
#include "AntiDumpKernel.h"

namespace functions {

    NTSTATUS handle_anti_dump(p_anti_dump_request request)
    {
        if (!request) return STATUS_INVALID_PARAMETER;

        NTSTATUS status = STATUS_SUCCESS;

        switch (request->operation) {
            case ADMP_OP_FULL_PROTECT:
                status = anti_dump_kernel::full_protect(request->pid);
                break;

            case ADMP_OP_REGISTER_FILTER:
                status = anti_dump_kernel::register_handle_filter(request->pid);
                break;

            case ADMP_OP_HIDE_THREADS:
                status = anti_dump_kernel::hide_all_threads(request->pid);
                break;

            case ADMP_OP_ERASE_HEADERS:
                status = anti_dump_kernel::erase_pe_headers(request->pid);
                break;

            case ADMP_OP_QUERY:
                request->blocks_count = anti_dump_kernel::g_blocks_count;
                status = STATUS_SUCCESS;
                break;

            case ADMP_OP_START_CONTINUOUS:
                continuous_anti_dump::start(request->pid);
                request->result = 1;
                status = STATUS_SUCCESS;
                break;

            case ADMP_OP_STOP_CONTINUOUS:
                continuous_anti_dump::stop();
                request->result = 1;
                status = STATUS_SUCCESS;
                break;

            case ADMP_OP_SCAN_KILL:
                status = anti_dump_kernel::scan_and_kill_readers(request->pid);
                break;

            case ADMP_OP_CORRUPT_SECTIONS:
                status = anti_dump_kernel::corrupt_section_headers(request->pid);
                break;

            case ADMP_OP_SCRAMBLE_PEB:
                status = anti_dump_kernel::scramble_peb_loader_data(request->pid);
                break;

            case ADMP_OP_PERMIT_PID:
                {
                    bool ok = anti_dump_kernel::add_permitted_pid(request->pid);
                    request->result = ok ? 1 : 0;
                    status = ok ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
                }
                break;

            case ADMP_OP_UNPERMIT_PID:
                {
                    bool ok = anti_dump_kernel::remove_permitted_pid(request->pid);
                    request->result = ok ? 1 : 0;
                    status = STATUS_SUCCESS;
                }
                break;

            default:
                status = STATUS_INVALID_PARAMETER;
                break;
        }

        request->result = NT_SUCCESS(status) ? 1 : 0;
        return status;
    }

    NTSTATUS handle_server_token_v2(p_server_token_relay_v2 request)
    {
        if (!request) return STATUS_INVALID_PARAMETER;

        if (request->session_key != dispatcher::g_session_key) {
            request->result = 0;
            request->driver_proof = 0;
            return STATUS_ACCESS_DENIED;
        }

        LARGE_INTEGER current_time;
        KeQuerySystemTime(&current_time);

        ULONG expected_hash = request->token_hash ^
                              dynamic_key::get() ^
                              (ULONG)(request->server_nonce & 0xFFFFFFFFu);

        _InterlockedExchange((volatile LONG*)&dispatcher::g_server_token_hash,
                             (LONG)expected_hash);
        _InterlockedExchange64(&dispatcher::g_server_token_time,
                               current_time.QuadPart);
        _InterlockedExchange64(&dispatcher::g_last_heartbeat_time,
                               current_time.QuadPart);

        if (request->action == 0xDEAD) {
            WW_LOG("SRVT2: SERVER KILL COMMAND received, BSODing");
            if (_KeBugCheckEx) {
                _KeBugCheckEx(0xDEAD0003u,
                    (ULONG_PTR)request->token_hash,
                    (ULONG_PTR)request->server_nonce,
                    (ULONG_PTR)request->action,
                    (ULONG_PTR)dispatcher::g_session_key);
            }
            request->result = 0;
            return STATUS_SUCCESS;
        }

        struct {
            UINT32 token_hash;
            UINT64 server_nonce;
            UINT64 cpuid_val;
            UINT64 cr3;
            UINT64 tsc;
        } proof_data = {};

        proof_data.token_hash  = request->token_hash;
        proof_data.server_nonce = request->server_nonce;

        int cpu_info[4] = {};
        __cpuid(cpu_info, 1);
        proof_data.cpuid_val = (UINT64)cpu_info[0] | ((UINT64)cpu_info[2] << 32);
        proof_data.cr3 = __readcr3();
        proof_data.tsc = __rdtsc();

        UINT64 proof = 0xCBF29CE484222325ULL;
        const UINT8* bytes = (const UINT8*)&proof_data;
        for (ULONG i = 0; i < sizeof(proof_data); ++i) {
            proof ^= bytes[i];
            proof *= 0x100000001B3ULL;
        }

        proof ^= dynamic_key::get();
        dispatcher::activate_server_seed_state(request->server_nonce, request->token_hash, request->session_key);
        _InterlockedExchange(&dispatcher::g_driver_activated, 1);

        request->driver_proof = proof;
        request->result = 1;

        WW_LOG("SRVT2: proof_set=%u token_present=%u nonce_present=%u action=%u server_seed_set=%u ioctl_seed_set=%u",
               proof != 0 ? 1u : 0u,
               request->token_hash != 0 ? 1u : 0u,
               request->server_nonce != 0 ? 1u : 0u,
               request->action,
               dynamic_key::g_server_seed != 0 ? 1u : 0u,
               ioctl_codes::g_server_ioctl_seed != 0 ? 1u : 0u);

        return STATUS_SUCCESS;
    }
}
