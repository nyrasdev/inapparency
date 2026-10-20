#pragma once

#include <cstdint>

#include "inapparency/context.hpp"
#include "inapparency/event.hpp"
#include "inapparency/observation.hpp"
#include "inapparency/parser.hpp"

namespace inapparency {

struct RuleInfo {
    std::uint32_t id;
    const char* name;
    Severity severity;
    const char* description;
};

// Where rules send their events. Output modules implement this.
class EventSink {
public:
    virtual ~EventSink() = default;
    virtual void emit(const DetectionEvent& event) = 0;
};

class Rule {
public:
    virtual ~Rule() = default;

    virtual const RuleInfo& info() const = 0;

    // Called for every observation, parsed or not. Must not block, must not
    // allocate, and must keep its state bounded.
    virtual void evaluate(const Observation& observation, const ParseResult& result,
                          const DetectionContext& context, EventSink& sink) = 0;
};

} // namespace inapparency
