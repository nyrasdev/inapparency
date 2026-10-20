add_executable(inapparency-replay main.cpp)
target_link_libraries(inapparency-replay PRIVATE
    inapparency::core inapparency::serial inapparency::host inapparency_warnings)
