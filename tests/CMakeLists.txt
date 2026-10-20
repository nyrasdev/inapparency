add_executable(inapparency_tests
    support/main.cpp
    unit/test_frame.cpp
    unit/test_parser.cpp
    unit/test_robustness.cpp
    unit/test_window.cpp
    unit/test_capture.cpp
    unit/test_serial_format.cpp
    unit/test_pcap.cpp
    unit/test_parser_more.cpp
    unit/test_event_gate.cpp
    unit/test_coverage.cpp
    unit/test_ap_change.cpp
    unit/test_evil_twin.cpp
    unit/test_auth_flood.cpp
    unit/test_correlator.cpp
    unit/test_deauth_burst.cpp
    unit/test_malformed_frames.cpp
    unit/test_display.cpp
    unit/test_storage.cpp
    integration/test_pipeline.cpp
    integration/test_soak.cpp
)
target_include_directories(inapparency_tests PRIVATE support)
find_package(Threads REQUIRED)
target_link_libraries(inapparency_tests PRIVATE inapparency::core inapparency::serial inapparency::host inapparency::display inapparency::storage inapparency_warnings Threads::Threads)

add_test(NAME inapparency_tests COMMAND inapparency_tests)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND AND TARGET inapparency-replay)
    add_test(NAME replay_demo
        COMMAND ${CMAKE_COMMAND}
            -DPYTHON=${Python3_EXECUTABLE}
            -DREPLAY=$<TARGET_FILE:inapparency-replay>
            -DSOURCE_DIR=${PROJECT_SOURCE_DIR}
            -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/replay_demo.cmake)
endif()
