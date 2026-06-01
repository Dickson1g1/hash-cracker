#include "progress.hpp"
#include <cstdio>
#include <chrono>
#include <thread>
#include <atomic>
#include <cmath>

// ANSI escape codes for terminal control
// \r        — carriage return (move cursor to line start without newline)
// \033[K    — erase to end of line (clears leftover characters)
// \033[1m   — bold
// \033[32m  — green
// \033[33m  — yellow
// \033[0m   — reset all attributes

static std::string fmt_rate(double hps) {
    if (hps >= 1e9) return std::to_string((int)(hps/1e9)) + " GH/s";
    if (hps >= 1e6) return std::to_string((int)(hps/1e6)) + " MH/s";
    if (hps >= 1e3) return std::to_string((int)(hps/1e3)) + " KH/s";
    return std::to_string((int)hps) + " H/s";
}

static std::string fmt_time(double seconds) {
    if (seconds < 0 || std::isinf(seconds)) return "?";
    int s = (int)seconds % 60;
    int m = ((int)seconds / 60) % 60;
    int h = (int)seconds / 3600;
    char buf[32];
    if (h > 0) snprintf(buf, sizeof(buf), "%dh%02dm%02ds", h, m, s);
    else if (m > 0) snprintf(buf, sizeof(buf), "%dm%02ds", m, s);
    else snprintf(buf, sizeof(buf), "%ds", s);
    return buf;
}

void run_progress(
    const std::atomic<uint64_t>& attempts,
    const std::atomic<bool>& done,
    uint64_t total_known,          // 0 if unknown (brute force)
    const std::string& mode_label)
{
    using namespace std::chrono;
    auto start = steady_clock::now();
    uint64_t last_count = 0;
    auto last_time = start;

    // Print progress on a loop until 'done' is set
    while (!done.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(milliseconds(250));

        auto now   = steady_clock::now();
        uint64_t n = attempts.load(std::memory_order_relaxed);

        // Instantaneous rate over the last 250ms window
        double dt  = duration<double>(now - last_time).count();
        double rate = (n - last_count) / dt;
        last_count = n;
        last_time  = now;

        // Total elapsed time
        double elapsed = duration<double>(now - start).count();

        // ETA calculation (only meaningful if total is known)
        std::string eta_str = "?";
        int bar_filled = 0;
        if (total_known > 0) {
            double progress = std::min(1.0, (double)n / total_known);
            bar_filled = (int)(progress * 40);
            if (rate > 0)
                eta_str = fmt_time((total_known - n) / rate);
        }

        // Build the progress bar: [========>          ]
        std::string bar = "[";
        for (int i = 0; i < 40; ++i)
            bar += (i < bar_filled) ? '=' : (i == bar_filled ? '>' : ' ');
        bar += "]";

        // \r moves cursor to line start; subsequent print overwrites old text.
        // This creates the "live updating" effect without scrolling.
        fprintf(stderr,
            "\r\033[K"           // carriage return + clear line
            "\033[1m%s\033[0m "  // bold mode label
            "%s "                // progress bar (if known total)
            "\033[32m%s\033[0m " // green rate
            "| %s elapsed"       // elapsed time
            " | ETA: %s"         // ETA
            " | \033[33m%llu\033[0m attempts", // yellow attempt count
            mode_label.c_str(),
            total_known > 0 ? bar.c_str() : "",
            fmt_rate(rate).c_str(),
            fmt_time(elapsed).c_str(),
            eta_str.c_str(),
            (unsigned long long)n
        );
        fflush(stderr);
    }
    // Print newline so next output starts on a fresh line
    fprintf(stderr, "\n");
}
