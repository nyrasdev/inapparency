// inapparency-display-preview: draws the OLED screens on a laptop, as text
// or as PBM images, so layouts can be checked without a display.
//
//   inapparency-display-preview            # all screens as text
//   inapparency-display-preview --pbm DIR  # also write DIR/<screen>.pbm

#include <cstdio>
#include <cstring>
#include <string>

#include "inapparency/display/screens.hpp"
#include "inapparency/version.hpp"

namespace {

using namespace inapparency;
using namespace inapparency::display;

void print_text(const char* name, const Framebuffer& fb) {
    std::printf("%s\n+", name);
    for (int x = 0; x < Framebuffer::kWidth; ++x) {
        std::printf("-");
    }
    std::printf("+\n");
    // Two pixel rows per text line using half blocks keeps the aspect ratio.
    for (int y = 0; y < Framebuffer::kHeight; y += 2) {
        std::printf("|");
        for (int x = 0; x < Framebuffer::kWidth; ++x) {
            bool top = fb.get(x, y);
            bool bottom = fb.get(x, y + 1);
            std::printf("%s", top && bottom ? "█" : top ? "▀" : bottom ? "▄" : " ");
        }
        std::printf("|\n");
    }
    std::printf("+");
    for (int x = 0; x < Framebuffer::kWidth; ++x) {
        std::printf("-");
    }
    std::printf("+\n\n");
}

bool write_pbm(const std::string& path, const Framebuffer& fb) {
    std::FILE* f = std::fopen(path.c_str(), "w");
    if (f == nullptr) {
        return false;
    }
    std::fprintf(f, "P1\n%d %d\n", Framebuffer::kWidth, Framebuffer::kHeight);
    for (int y = 0; y < Framebuffer::kHeight; ++y) {
        for (int x = 0; x < Framebuffer::kWidth; ++x) {
            std::fputc(fb.get(x, y) ? '1' : '0', f);
        }
        std::fputc('\n', f);
    }
    return std::fclose(f) == 0;
}

} // namespace

int main(int argc, char** argv) {
    const char* pbm_dir = nullptr;
    if (argc == 3 && std::strcmp(argv[1], "--pbm") == 0) {
        pbm_dir = argv[2];
    } else if (argc != 1) {
        std::fprintf(stderr, "usage: inapparency-display-preview [--pbm DIR]\n");
        return 2;
    }

    struct Screen {
        const char* name;
        Framebuffer fb;
    };
    Screen screens[5] = {
        {"splash", {}}, {"splash-name", {}}, {"status", {}}, {"alert", {}}, {"later", {}}};

    render_splash_logo(screens[0].fb);
    render_splash_name(screens[1].fb, kVersion);

    StatusView idle;
    idle.uptime_ms = 754'000;
    idle.frames = 48'213;
    idle.channel = 6;
    idle.hopping = true;
    idle.storage_enabled = true;
    idle.storage_ok = true;
    render_status(screens[2].fb, idle);

    StatusView alert = idle;
    alert.uptime_ms = 3'723'000;
    alert.frames = 1'204'551;
    alert.alerts = 3;
    alert.suppressed = 12;
    LastAlert a;
    a.severity = Severity::Critical;
    a.rule = "attack-chain";
    a.confidence = 95;
    a.bssid = MacAddress{{0x02, 0xee, 0xee, 0xee, 0xee, 0x01}};
    a.at_ms = 3'720'000;
    alert.last_alert = a;
    render_status(screens[3].fb, alert);

    StatusView later = alert;
    later.uptime_ms = 3'900'000;
    later.storage_ok = false;
    render_status(screens[4].fb, later);

    for (const auto& s : screens) {
        print_text(s.name, s.fb);
        if (pbm_dir != nullptr) {
            std::string path = std::string(pbm_dir) + "/" + s.name + ".pbm";
            if (!write_pbm(path, s.fb)) {
                std::fprintf(stderr, "error: can't write %s\n", path.c_str());
                return 1;
            }
        }
    }
    return 0;
}
