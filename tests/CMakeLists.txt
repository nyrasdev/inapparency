add_executable(inapparency_tests
    support/main.cpp
    unit/test_frame.cpp
    unit/test_parser.cpp
    unit/test_robustness.cpp
    unit/test_window.cpp
    unit/test_deauth_burst.cpp
    unit/test_malformed_frames.cpp
    integration/test_pipeline.cpp
)
target_include_directories(inapparency_tests PRIVATE support)
target_link_libraries(inapparency_tests PRIVATE inapparency::core inapparency_warnings)

add_test(NAME inapparency_tests COMMAND inapparency_tests)
