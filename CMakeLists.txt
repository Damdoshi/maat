cmake_minimum_required(VERSION 3.16)
project(maat VERSION 0.20.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_library(maat-monitor STATIC src/monitor_protocol.cpp src/replay_store.cpp src/receiver.cpp)
target_include_directories(maat-monitor PUBLIC src)
target_link_libraries(maat-monitor PUBLIC sqlite3)
target_compile_options(maat-monitor PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_executable(maat-monitor-receiver src/main.cpp)
target_link_libraries(maat-monitor-receiver PRIVATE maat-monitor)
include(CTest)
if(BUILD_TESTING)
  add_test(NAME maat-php-abi-probe-tests
           COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/php_abi_probe_test.sh)
  add_executable(maat-monitor-tests tests/test.cpp)
  target_link_libraries(maat-monitor-tests PRIVATE maat-monitor pthread)
  target_compile_options(maat-monitor-tests PRIVATE -Wall -Wextra -Werror)
  add_test(NAME maat-monitor-tests COMMAND maat-monitor-tests)
endif()
install(TARGETS maat-monitor-receiver RUNTIME DESTINATION sbin)
add_executable(maat-monitor-benchmark tests/bench.cpp)
target_link_libraries(maat-monitor-benchmark PRIVATE maat-monitor)

add_library(maat-http-domain STATIC src/http/http_domain.cpp src/http/identity_broker.cpp src/http/uid_range_config.cpp src/http/connection_proof.cpp src/http/http_stream.cpp)
target_include_directories(maat-http-domain PUBLIC src src/http)
target_compile_options(maat-http-domain PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(maat-http-domain PUBLIC sqlite3)
add_executable(maat-check-config src/http/check_config_main.cpp)
target_link_libraries(maat-check-config PRIVATE maat-http-domain)
add_executable(maat-http-broker src/http/broker_main.cpp)
target_compile_options(maat-http-broker PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(maat-http-broker PRIVATE maat-http-domain)
add_executable(maat-http-bridge src/http/http_bridge.cpp)
target_link_libraries(maat-http-bridge PRIVATE maat-http-domain)
if(BUILD_TESTING)
 add_test(NAME maat-bridge-persistence-smoke
          COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/bridge_persistence_smoke.py
                  $<TARGET_FILE:maat-http-bridge>)
 set_tests_properties(maat-bridge-persistence-smoke PROPERTIES
   SKIP_RETURN_CODE 77 RESOURCE_LOCK maat-http-loopback-port)
endif()
install(TARGETS maat-http-broker maat-http-bridge maat-check-config RUNTIME DESTINATION sbin)
if(BUILD_TESTING)
 add_executable(maat-uid-guard-tests tests/uid_guard_test.cpp)
 target_link_libraries(maat-uid-guard-tests PRIVATE maat-http-domain)
 target_compile_options(maat-uid-guard-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
 add_test(NAME maat-uid-guard-tests COMMAND maat-uid-guard-tests)
 add_executable(maat-session-budget-tests tests/session_budget_test.cpp)
 target_include_directories(maat-session-budget-tests PRIVATE src)
 target_compile_options(maat-session-budget-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
 add_test(NAME maat-session-budget-tests COMMAND maat-session-budget-tests)
 add_executable(maat-http-stream-tests tests/http_stream_test.cpp)
 target_link_libraries(maat-http-stream-tests PRIVATE maat-http-domain pthread)
 target_compile_options(maat-http-stream-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
 add_test(NAME maat-http-stream-tests COMMAND maat-http-stream-tests)
 add_executable(maat-http-tests tests/http_test.cpp)
 target_link_libraries(maat-http-tests PRIVATE maat-http-domain maat-monitor)
 add_test(NAME maat-http-tests COMMAND maat-http-tests)
 add_executable(maat-connection-tests tests/connection_proof_test.cpp)
 target_link_libraries(maat-connection-tests PRIVATE maat-http-domain maat-monitor)
 add_test(NAME maat-connection-tests COMMAND maat-connection-tests)
 add_executable(maat-bind-tests tests/binder_test.cpp)
 target_link_libraries(maat-bind-tests PRIVATE maat-http-domain maat-monitor)
 add_test(NAME maat-bind-tests COMMAND maat-bind-tests)
 set_tests_properties(maat-bind-tests PROPERTIES SKIP_RETURN_CODE 77)
endif()

# Linux-only same-UID process isolation regression test, requiring a
# disposable root container. Not part of ordinary unprivileged CTest.
add_executable(maat-isolation-tests tests/isolation_test.cpp)
target_compile_options(maat-isolation-tests PRIVATE -Wall -Wextra -Werror)

# This pure-C policy is testable even without Apache development headers.
# The Apache DSO itself is opt-in via tools/build-mod-maat.sh.
add_library(maat-ingress-policy STATIC modules/mod_maat/ingress_policy.c modules/mod_maat/maat_broker_client.c)
target_include_directories(maat-ingress-policy PUBLIC modules/mod_maat)
target_compile_options(maat-ingress-policy PRIVATE -Wall -Wextra -Wpedantic -Werror)
if(BUILD_TESTING)
  add_executable(maat-ingress-policy-tests tests/ingress_policy_test.c)
  target_link_libraries(maat-ingress-policy-tests PRIVATE maat-ingress-policy)
  target_compile_options(maat-ingress-policy-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-ingress-policy-tests COMMAND maat-ingress-policy-tests)
  add_executable(maat-apache-hook-stub-tests tests/apache_module_stub_test.c
      modules/mod_maat/ingress_policy.c)
  target_include_directories(maat-apache-hook-stub-tests PRIVATE
      tests/apache-stub modules/mod_maat)
  target_compile_options(maat-apache-hook-stub-tests PRIVATE
      -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-apache-hook-stub-tests COMMAND maat-apache-hook-stub-tests)
  add_executable(maat-descriptor-e2e-tests tests/connection_c_api_test.cpp)
  target_link_libraries(maat-descriptor-e2e-tests PRIVATE maat-http-domain maat-monitor maat-ingress-policy pthread)
  add_test(NAME maat-descriptor-e2e-tests COMMAND maat-descriptor-e2e-tests)
  add_executable(maat-apache-broker-tests tests/apache_broker_test.c)
  target_link_libraries(maat-apache-broker-tests PRIVATE maat-ingress-policy pthread)
  target_compile_options(maat-apache-broker-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-apache-broker-tests COMMAND maat-apache-broker-tests)
endif()

# Administrative-only citizen registry and scope-free issuer preparation (alpha4). No SSH
# trust, civil authority verification, or zero-knowledge anonymity enabled.
add_library(maat-citizen-registry STATIC src/identity/citizen_registry.cpp src/identity/authority_commands.cpp src/identity/scoped_credentials.cpp src/identity/privacy_bootstrap.cpp)
target_include_directories(maat-citizen-registry PUBLIC src)
target_compile_options(maat-citizen-registry PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(maat-citizen-registry PUBLIC sqlite3 crypto)
if(BUILD_TESTING)
  add_executable(maat-citizen-registry-tests tests/citizen_registry_test.cpp)
  target_link_libraries(maat-citizen-registry-tests PRIVATE maat-citizen-registry crypto pthread)
  target_compile_options(maat-citizen-registry-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-citizen-registry-tests COMMAND maat-citizen-registry-tests)

  add_executable(maat-scoped-credentials-tests tests/scoped_credentials_test.cpp)
  target_link_libraries(maat-scoped-credentials-tests PRIVATE maat-citizen-registry crypto pthread)
  target_compile_options(maat-scoped-credentials-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-scoped-credentials-tests COMMAND maat-scoped-credentials-tests)
endif()

# Scope-free issuer preparation: no BBS/ZKP verifier yet, fail-closed by type.
if(BUILD_TESTING)
  add_executable(maat-privacy-bootstrap-tests tests/privacy_bootstrap_test.cpp)
  target_link_libraries(maat-privacy-bootstrap-tests PRIVATE maat-citizen-registry crypto pthread)
  target_compile_options(maat-privacy-bootstrap-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-privacy-bootstrap-tests COMMAND maat-privacy-bootstrap-tests)
endif()

# Experimental BBS proof verifier. Disabled by default. This does NOT set
# identity_verified, integrate SSH, or establish a civic identity authority.
option(MAAT_BUILD_BBS_BRIDGE "Build optional offline Rust BBS proof verifier" OFF)
add_library(maat-bbs-presentation STATIC src/identity/bbs_presentation_gate.cpp)
target_include_directories(maat-bbs-presentation PUBLIC src)
target_compile_options(maat-bbs-presentation PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(maat-bbs-presentation PUBLIC crypto)
if(MAAT_BUILD_BBS_BRIDGE)
  find_program(MAAT_CARGO cargo REQUIRED)
  set(MAAT_BBS_CRATE "${CMAKE_CURRENT_SOURCE_DIR}/libs/maat-bbs")
  if(NOT EXISTS "${MAAT_BBS_CRATE}/Cargo.lock")
    message(FATAL_ERROR "BBS Cargo.lock missing. See docs/IDENTITY-0.20-ALPHA5.md")
  endif()
  set(MAAT_BBS_LIB "${MAAT_BBS_CRATE}/target/release/libmaat_bbs_bridge.a")
  # Only the library is built in non-test configurations. The fixture is
  # deliberately TEST-ONLY: it contains a public hard-coded BBS test issuer key.
  set(MAAT_BBS_FIXTURE "${MAAT_BBS_CRATE}/target/release/maat_bbs_fixture")
  set(MAAT_BBS_ARTIFACTS "${MAAT_BBS_LIB}")
  set(MAAT_BBS_CARGO_TARGETS --lib)
  if(BUILD_TESTING)
    list(APPEND MAAT_BBS_ARTIFACTS "${MAAT_BBS_FIXTURE}")
    list(APPEND MAAT_BBS_CARGO_TARGETS --bin maat_bbs_fixture)
  endif()
  add_custom_command(OUTPUT ${MAAT_BBS_ARTIFACTS}
    COMMAND "${MAAT_CARGO}" build --manifest-path "${MAAT_BBS_CRATE}/Cargo.toml"
            --release --locked --offline ${MAAT_BBS_CARGO_TARGETS}
    WORKING_DIRECTORY "${MAAT_BBS_CRATE}"
    DEPENDS "${MAAT_BBS_CRATE}/src/lib.rs"
            "${MAAT_BBS_CRATE}/src/bin/maat_bbs_fixture.rs"
            "${MAAT_BBS_CRATE}/Cargo.toml" "${MAAT_BBS_CRATE}/Cargo.lock"
    COMMENT "Building offline BBS Rust static library (test fixture only if testing)"
    VERBATIM)
  add_custom_target(maat-bbs-rust-build DEPENDS "${MAAT_BBS_LIB}")
  add_library(maat-bbs-rust STATIC IMPORTED)
  set_target_properties(maat-bbs-rust PROPERTIES IMPORTED_LOCATION "${MAAT_BBS_LIB}")
  add_dependencies(maat-bbs-rust maat-bbs-rust-build)
  target_compile_definitions(maat-bbs-presentation PRIVATE MAAT_ENABLE_BBS=1)
  target_link_libraries(maat-bbs-presentation PUBLIC maat-bbs-rust pthread dl m)
  if(BUILD_TESTING)
    add_executable(maat-bbs-real-proof-tests tests/bbs_real_proof_test.cpp)
    target_link_libraries(maat-bbs-real-proof-tests PRIVATE maat-bbs-presentation)
    target_compile_options(maat-bbs-real-proof-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_compile_definitions(maat-bbs-real-proof-tests PRIVATE
      MAAT_BBS_TEST_FIXTURE_PATH=\"${MAAT_BBS_FIXTURE}\")
    add_dependencies(maat-bbs-real-proof-tests maat-bbs-rust-build)
    add_test(NAME maat-bbs-real-proof-tests COMMAND maat-bbs-real-proof-tests)
  endif()
endif()
if(BUILD_TESTING)
  add_executable(maat-bbs-presentation-gate-tests tests/bbs_presentation_gate_test.cpp)
  target_link_libraries(maat-bbs-presentation-gate-tests PRIVATE maat-bbs-presentation)
  target_compile_options(maat-bbs-presentation-gate-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-bbs-presentation-gate-tests COMMAND maat-bbs-presentation-gate-tests)
endif()

# Alpha6: optional PRIVATE registry-bound blind issuer. Never compiled in the
# default non-Rust build; not installed or called by SSH, broker, or PHP.
if(MAAT_BUILD_BBS_BRIDGE)
  add_library(maat-bbs-bound-issuer STATIC src/identity/bbs_bound_issuer.cpp)
  target_include_directories(maat-bbs-bound-issuer PUBLIC src)
  target_compile_options(maat-bbs-bound-issuer PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_link_libraries(maat-bbs-bound-issuer PUBLIC maat-citizen-registry maat-bbs-rust crypto sqlite3 pthread)
  if(BUILD_TESTING)
    add_executable(maat-bbs-bound-issuer-tests tests/bbs_bound_issuer_test.cpp)
    target_compile_options(maat-bbs-bound-issuer-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    target_link_libraries(maat-bbs-bound-issuer-tests PRIVATE maat-bbs-bound-issuer)
    add_test(NAME maat-bbs-bound-issuer-tests COMMAND maat-bbs-bound-issuer-tests)
  endif()
endif()

# Alpha7: signed incremental public-key trust replication. Independent of Rust;
# no online authority contact on read. Requires an authenticated local root pin.
add_library(maat-replicated-trust STATIC src/identity/replicated_trust.cpp)
target_include_directories(maat-replicated-trust PUBLIC src)
target_compile_options(maat-replicated-trust PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(maat-replicated-trust PUBLIC sqlite3 crypto)
if(BUILD_TESTING)
  add_executable(maat-replicated-trust-tests tests/replicated_trust_test.cpp)
  target_link_libraries(maat-replicated-trust-tests PRIVATE maat-replicated-trust)
  target_compile_options(maat-replicated-trust-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-replicated-trust-tests COMMAND maat-replicated-trust-tests)
endif()

# Alpha8: versioned bounded replication messages; remote SSH peers only
# transport signed events, never decide the local trust root or key state.
add_library(maat-trust-sync STATIC src/identity/trust_sync.cpp)
target_include_directories(maat-trust-sync PUBLIC src)
target_compile_options(maat-trust-sync PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(maat-trust-sync PUBLIC maat-replicated-trust)
add_executable(maat-trust-sync-cli src/identity/trust_sync_main.cpp src/identity/trust_peers.cpp)
set_target_properties(maat-trust-sync-cli PROPERTIES OUTPUT_NAME maat-trust-sync)
target_compile_options(maat-trust-sync-cli PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(maat-trust-sync-cli PRIVATE maat-trust-sync)
if(BUILD_TESTING)
  add_executable(maat-trust-sync-tests tests/trust_sync_test.cpp)
  target_link_libraries(maat-trust-sync-tests PRIVATE maat-trust-sync)
  target_compile_options(maat-trust-sync-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-trust-sync-tests COMMAND maat-trust-sync-tests)
  add_executable(maat-trust-peers-tests tests/trust_peers_test.cpp src/identity/trust_peers.cpp)
  target_include_directories(maat-trust-peers-tests PRIVATE src)
  target_compile_options(maat-trust-peers-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-trust-peers-tests COMMAND maat-trust-peers-tests)
  add_executable(maat-trust-cli-tests tests/trust_sync_cli_test.cpp)
  target_include_directories(maat-trust-cli-tests PRIVATE src)
  target_link_libraries(maat-trust-cli-tests PRIVATE maat-trust-sync)
  target_compile_options(maat-trust-cli-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME maat-trust-cli-tests COMMAND maat-trust-cli-tests $<TARGET_FILE:maat-trust-sync-cli>)
endif()

# Optional BBS gate: check actual issuer against the signed LOCAL replica,
# not an online oracle. This is issuer-wide revocation, NOT anonymous
# individual holder revocation. Never authorize SSH / PHP from this alone.
add_library(maat-bbs-replicated-gate STATIC src/identity/bbs_replicated_gate.cpp)
target_include_directories(maat-bbs-replicated-gate PUBLIC src)
target_compile_options(maat-bbs-replicated-gate PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(maat-bbs-replicated-gate PUBLIC maat-bbs-presentation maat-replicated-trust)

if(MAAT_BUILD_BBS_BRIDGE AND BUILD_TESTING)
  target_link_libraries(maat-bbs-real-proof-tests PRIVATE maat-bbs-replicated-gate)
endif()

# Disposable alpha13 QEMU verifier, deliberately not installed or used by PHP.
if(MAAT_BUILD_BBS_BRIDGE AND BUILD_TESTING)
  add_executable(maat-bbs-p2p-gate tests/qemu/bbs_p2p_gate.cpp)
  target_link_libraries(maat-bbs-p2p-gate PRIVATE maat-bbs-replicated-gate)
  target_compile_options(maat-bbs-p2p-gate PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Alpha14: non-privileged website scaffold checks (never configures live Apache).
if(BUILD_TESTING)
  add_test(NAME maat-site-scaffold-tests
           COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/maat_site_test.py)
endif()
