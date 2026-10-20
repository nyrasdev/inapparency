# Generates the demo capture, replays it and checks the expected alerts show
# up (and nothing else). Run through ctest.
execute_process(COMMAND ${PYTHON} ${SOURCE_DIR}/tools/make_demo_pcap.py ${WORK_DIR}/demo.pcap
                RESULT_VARIABLE gen_result OUTPUT_QUIET)
if(NOT gen_result EQUAL 0)
    message(FATAL_ERROR "make_demo_pcap.py failed")
endif()

execute_process(COMMAND ${REPLAY} ${WORK_DIR}/demo.pcap
                RESULT_VARIABLE replay_result OUTPUT_VARIABLE out ERROR_VARIABLE err)
message("${out}${err}")
if(NOT replay_result EQUAL 0)
    message(FATAL_ERROR "replay exited with ${replay_result}")
endif()

foreach(expected "HIGH deauth-burst confidence=75" "bssid=02:10:10:10:10:10"
                 "requires PMF" "LOW malformed-frames" "events=2")
    string(FIND "${out}" "${expected}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "expected \"${expected}\" in replay output")
    endif()
endforeach()
