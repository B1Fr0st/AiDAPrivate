#pragma once

#include <cstdarg>
#include <cstdio>

void aida_target_log_set_file(const char* path);
void aida_target_log_close();
int aida_target_printf(const char* fmt, ...);
int aida_target_vprintf(const char* fmt, va_list ap);

#ifndef AIDA_TARGET_LOG_NO_MACROS
#define printf aida_target_printf
#define vprintf aida_target_vprintf
#endif
