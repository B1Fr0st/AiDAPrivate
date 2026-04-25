#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace debugger_engine {


enum class bp_type_t : int {
	software = 0,
	hardware_execute,
	hardware_write,
	hardware_read,
	memory_access,
	COUNT
};

enum class bp_state_t : int {
	disabled = 0,
	enabled,
	one_shot,
};

struct breakpoint_t {
	uint64_t    address = 0;
	bp_type_t   type = bp_type_t::software;
	bp_state_t  state = bp_state_t::enabled;
	int         hw_slot = -1;
	int         size = 1;
	std::string name;
	std::string condition;
	std::string log_text;
	int         hit_count = 0;
	uint8_t     original_byte = 0;
	bool        is_internal = false;
};


struct register_set_t {
	uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
	uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
	uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
	uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
	uint64_t rip = 0, rflags = 0;
	uint64_t cs = 0, ds = 0, es = 0, fs = 0, gs = 0, ss = 0;
	uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr6 = 0, dr7 = 0;
};


struct stack_frame_t {
	uint64_t    address = 0;
	uint64_t    return_addr = 0;
	std::string module_name;
	std::string function_name;
	uint64_t    module_offset = 0;
};


struct memory_region_t {
	uint64_t    base = 0;
	uint64_t    size = 0;
	uint32_t    protect = 0;
	uint32_t    state = 0;
	uint32_t    type = 0;
	std::string module_name;
	std::string info;
};


struct watch_entry_t {
	std::string expression;
	std::string value;
	std::string type;
	bool        valid = false;
};


struct trace_record_t {
	uint64_t       address = 0;
	register_set_t regs;
	std::string    disasm_text;
	int            index = 0;
};


struct annotation_t {
	std::string text;
	uint64_t    address = 0;
};


struct handle_info_t {
	uint64_t    handle = 0;
	uint32_t    type_index = 0;
	std::string type_name;
	std::string name;
	uint32_t    access = 0;
};


struct string_ref_t {
	uint64_t    address = 0;
	std::string value;
	std::string module_name;
	uint64_t    module_offset = 0;
	bool        is_unicode = false;
};


enum class dbg_status_t : int {
	idle = 0,
	running,
	paused,
	stepping,
	terminated,
};

struct state_t {

	std::atomic<dbg_status_t>  status{dbg_status_t::idle};
	uint32_t                   target_pid = 0;
	uint32_t                   active_tid = 0;


	std::mutex                 bp_mutex;
	std::vector<breakpoint_t>  breakpoints;
	int                        next_bp_id = 1;


	std::mutex                 reg_mutex;
	register_set_t             registers;


	std::mutex                 stack_mutex;
	std::vector<stack_frame_t> call_stack;


	std::mutex                       memmap_mutex;
	std::vector<memory_region_t>     memory_map;


	std::mutex                 watch_mutex;
	std::vector<watch_entry_t> watches;


	std::mutex                     trace_mutex;
	std::vector<trace_record_t>    trace_log;
	std::atomic<bool>              tracing{false};
	int                            trace_max_depth = 50000;


	std::mutex                          anno_mutex;
	std::map<uint64_t, annotation_t>    comments;
	std::map<uint64_t, annotation_t>    labels;
	std::vector<uint64_t>               bookmarks;


	std::mutex                   handle_mutex;
	std::vector<handle_info_t>   handles;


	std::mutex                   strings_mutex;
	std::vector<string_ref_t>    strings;


	std::thread                  worker_thread;
	std::atomic<bool>            worker_active{false};
};

inline state_t g_state;


void initialize();
void shutdown();


int  add_breakpoint(uint64_t address, bp_type_t type = bp_type_t::software,
					const std::string& name = "", const std::string& condition = "");
bool remove_breakpoint(int index);
bool toggle_breakpoint(int index);
void clear_all_breakpoints();


bool run_target();
bool pause_target();
bool step_into();
bool step_over();
bool step_out();
bool run_to_address(uint64_t address);


register_set_t get_registers();
bool set_register(const std::string& name, uint64_t value);


std::vector<stack_frame_t> get_call_stack();


std::vector<memory_region_t> get_memory_map();


int  add_watch(const std::string& expression);
bool remove_watch(int index);
void refresh_watches();


bool start_trace(int max_records = 50000);
bool stop_trace();


void set_comment(uint64_t address, const std::string& text);
void set_label(uint64_t address, const std::string& text);
void toggle_bookmark(uint64_t address);
std::string get_comment(uint64_t address);
std::string get_label(uint64_t address);


void enumerate_handles();
void find_strings(size_t min_length = 4);


std::string format_flags(uint64_t rflags);
std::string format_protect(uint32_t protect);

}
