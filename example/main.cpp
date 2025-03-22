#include <knot/dnssd.h>

int main() {
    std::unordered_map<std::string, std::string> txt;
    txt["foo"] = "bar";
    knot::registerService("test_service", "_flowdrop._tcp", "local.", 123, txt, []() {
        return false;
    });
}
