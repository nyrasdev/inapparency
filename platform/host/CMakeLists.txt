# Host adapter: reads monitor-mode captures (.pcap) on a laptop so the same
# detection code can run without a board.
add_library(inapparency_host STATIC src/pcap.cpp)
add_library(inapparency::host ALIAS inapparency_host)
target_include_directories(inapparency_host PUBLIC include)
target_link_libraries(inapparency_host PUBLIC inapparency::core PRIVATE inapparency_warnings)
