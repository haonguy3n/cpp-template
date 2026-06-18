# Per-module example programs. Each is a tiny main() that builds on host and
# under qemu-aarch64. Helper keeps the boilerplate to one line per example.
function(etlx_add_example name)
  add_executable(example_${name} ${name}/main.cpp)
  target_include_directories(example_${name} PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(example_${name}
    PRIVATE etlx::etlx etlx::host etlx_embedded_flags)
endfunction()

etlx_add_example(result_error)
etlx_add_example(cli_minimal)
etlx_add_example(log_uart)
etlx_add_example(io_copy)
etlx_add_example(kv_persist)
etlx_add_example(json_config)
etlx_add_example(sha256_stream)
etlx_add_example(http_get)
etlx_add_example(update_fsm)
etlx_add_example(event_loop)

# Live HTTP over the selected TCP transport (POSIX or Asio).
# etlx::host provides the log sink (not transitive via the asio transport).
add_executable(example_tcp_http_get tcp_http_get/main.cpp)
target_include_directories(example_tcp_http_get PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(example_tcp_http_get
  PRIVATE etlx::transport etlx::host etlx_embedded_flags)

# The mTLS example: TLS over the selected transport.
if(ETLX_WITH_TLS)
  add_executable(example_mtls_client mtls_client/main.cpp)
  target_include_directories(example_mtls_client PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(example_mtls_client
    PRIVATE etlx::tls etlx::transport etlx::host etlx_embedded_flags)
endif()

# SE-backed mTLS: private key operations in the SE05x, TLS handshake via TlsSocket.
if(ETLX_WITH_SE05X)
  add_executable(example_se_mtls_client se_mtls_client/main.cpp)
  target_include_directories(example_se_mtls_client PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(example_se_mtls_client
    PRIVATE etlx::se05x etlx::tls etlx::transport etlx::host etlx_embedded_flags)

  # Quickstart tour of the SE support API via the single <etlx/se.hpp> header.
  add_executable(example_se_quickstart se_quickstart/main.cpp)
  target_include_directories(example_se_quickstart PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(example_se_quickstart
    PRIVATE etlx::se05x etlx::host etlx_embedded_flags)
endif()
