cmake_minimum_required(VERSION 3.19.4)

project(hlsocket)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

include_directories(
    include
    ext/mbedtls/include
    ext/mbedtls/library)

set(mbedtls ${mbedtls}
    ext/mbedtls/library/aes.c
    ext/mbedtls/library/aesni.c
    ext/mbedtls/library/aria.c
    ext/mbedtls/library/asn1parse.c
    ext/mbedtls/library/asn1write.c
    ext/mbedtls/library/base64.c
    ext/mbedtls/library/bignum.c
    ext/mbedtls/library/bignum_core.c
    ext/mbedtls/library/camellia.c
    ext/mbedtls/library/ccm.c
    ext/mbedtls/library/chacha20.c
    ext/mbedtls/library/chachapoly.c
    ext/mbedtls/library/cipher.c
    ext/mbedtls/library/cipher_wrap.c
    ext/mbedtls/library/constant_time.c
    ext/mbedtls/library/cmac.c
    ext/mbedtls/library/ctr_drbg.c
    ext/mbedtls/library/des.c
    ext/mbedtls/library/dhm.c
    ext/mbedtls/library/ecdh.c
    ext/mbedtls/library/ecdsa.c
    ext/mbedtls/library/ecjpake.c
    ext/mbedtls/library/ecp.c
    ext/mbedtls/library/ecp_curves.c
    ext/mbedtls/library/entropy.c
    ext/mbedtls/library/entropy_poll.c
    ext/mbedtls/library/error.c
    ext/mbedtls/library/gcm.c
    ext/mbedtls/library/hash_info.c
    ext/mbedtls/library/hkdf.c
    ext/mbedtls/library/hmac_drbg.c
    ext/mbedtls/library/md.c
    ext/mbedtls/library/md5.c
    ext/mbedtls/library/memory_buffer_alloc.c
    ext/mbedtls/library/mps_reader.c
    ext/mbedtls/library/mps_trace.c
    ext/mbedtls/library/nist_kw.c
    ext/mbedtls/library/oid.c
    ext/mbedtls/library/padlock.c
    ext/mbedtls/library/pem.c
    ext/mbedtls/library/pk.c
    ext/mbedtls/library/pk_wrap.c
    ext/mbedtls/library/pkcs12.c
    ext/mbedtls/library/pkcs5.c
    ext/mbedtls/library/pkparse.c
    ext/mbedtls/library/pkwrite.c
    ext/mbedtls/library/platform.c
    ext/mbedtls/library/platform_util.c
    ext/mbedtls/library/poly1305.c
    ext/mbedtls/library/psa_crypto.c
    ext/mbedtls/library/psa_crypto_aead.c
    ext/mbedtls/library/psa_crypto_cipher.c
    ext/mbedtls/library/psa_crypto_client.c
    ext/mbedtls/library/psa_crypto_driver_wrappers.c
    ext/mbedtls/library/psa_crypto_ecp.c
    ext/mbedtls/library/psa_crypto_hash.c
    ext/mbedtls/library/psa_crypto_mac.c
    ext/mbedtls/library/psa_crypto_pake.c
    ext/mbedtls/library/psa_crypto_rsa.c
    ext/mbedtls/library/psa_crypto_se.c
    ext/mbedtls/library/psa_crypto_slot_management.c
    ext/mbedtls/library/psa_crypto_storage.c
    ext/mbedtls/library/psa_its_file.c
    ext/mbedtls/library/psa_util.c
    ext/mbedtls/library/ripemd160.c
    ext/mbedtls/library/rsa.c
    ext/mbedtls/library/rsa_alt_helpers.c
    ext/mbedtls/library/sha1.c
    ext/mbedtls/library/sha256.c
    ext/mbedtls/library/sha512.c
    ext/mbedtls/library/ssl_debug_helpers_generated.c
    ext/mbedtls/library/threading.c
    ext/mbedtls/library/timing.c
    ext/mbedtls/library/version.c
    ext/mbedtls/library/version_features.c
    ext/mbedtls/library/x509.c
    ext/mbedtls/library/x509_create.c
    ext/mbedtls/library/x509_crl.c
    ext/mbedtls/library/x509_crt.c
    ext/mbedtls/library/x509_csr.c
    ext/mbedtls/library/x509write_crt.c
    ext/mbedtls/library/x509write_csr.c
    ext/mbedtls/library/debug.c
    ext/mbedtls/library/net_sockets.c
    ext/mbedtls/library/ssl_cache.c
    ext/mbedtls/library/ssl_ciphersuites.c
    ext/mbedtls/library/ssl_client.c
    ext/mbedtls/library/ssl_cookie.c
    ext/mbedtls/library/ssl_msg.c
    ext/mbedtls/library/ssl_ticket.c
    ext/mbedtls/library/ssl_tls.c
    ext/mbedtls/library/ssl_tls12_client.c
    ext/mbedtls/library/ssl_tls12_server.c
    ext/mbedtls/library/ssl_tls13_keys.c
    ext/mbedtls/library/ssl_tls13_server.c
    ext/mbedtls/library/ssl_tls13_client.c
    ext/mbedtls/library/ssl_tls13_generic.c)

set(sources ${sources}
    include/hlsocket.h
    include/hlsocket_platform.h
    include/hlsocket_selector.h
    include/url.h
    src/common.hpp
    src/hlsocket.cpp
    src/hlsocket_ssl.inl
    src/hlsocket_ws.inl
    src/hlsocket_selector.inl
    src/hlsocket_selector_darwin.cpp
    src/hlsocket_selector_emcc.cpp
    src/hlsocket_selector_posix.cpp
    src/hlsocket_selector_win.cpp
    src/url.cpp)

add_library(hlsocket STATIC ${sources} ${mbedtls})

add_executable(test_hlsocket ${sources} ${mbedtls} examples/test.c)

install(TARGETS
        hlsocket
    EXPORT hlsocketConfig
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

export(TARGETS
        hlsocket
    NAMESPACE hlsocket::
    FILE "${CMAKE_CURRENT_BINARY_DIR}/hlsocketConfig.cmake"
)

install(EXPORT
        hlsocketConfig
    DESTINATION "${CMAKE_INSTALL_DATADIR}/hlsocket/cmake"
    NAMESPACE hlsocket::
)
