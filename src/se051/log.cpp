#include "se051/log/log.hpp"

#include <cstdarg>
#include <cstdio>

#include <string>

namespace se051::log {
namespace {

Sink* g_sink = nullptr;
Level g_level = Level::Debug;

} // namespace

void SetSink(Sink* sink) { g_sink = sink; }

void SetLevel(Level level) { g_level = level; }

Level GetLevel() { return g_level; }

void Logf(Level level, const char* fmt, ...) {
    if (g_sink == nullptr) return;
    if (static_cast<int>(level) > static_cast<int>(g_level)) return;

    // Format into a fixed stack buffer; over-long lines are truncated rather
    // than allocating. vsnprintf always null-terminates.
    char buf[SE051_LOG_LINE_CAPACITY];

    va_list args;
    va_start(args, fmt);
    const int n = std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (n < 0) return;  // encoding error

    size_t len = (static_cast<size_t>(n) < sizeof(buf)) ? static_cast<size_t>(n)
                                                        : sizeof(buf) - 1;
    g_sink->Write(level, std::string_view{buf, len});
}

} // namespace se051::log
