# Quickstart: a guided tour of the se051 API via the single <se051/se051.hpp>
# header. Links the one library target.
add_executable(example_se_quickstart se_quickstart/main.cpp)
target_link_libraries(example_se_quickstart PRIVATE se051::se051)
