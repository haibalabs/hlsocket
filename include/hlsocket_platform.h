/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Platform.
#define HL_WINDOWS 0
#define HL_ANDROID 0
#define HL_IOS 0
#define HL_IOS_SIM 0
#define HL_TVOS 0
#define HL_OSX 0
#define HL_EMSCRIPTEN 0
#define HL_LINUX 0
#define HL_DARWIN (HL_IOS || HL_IOS_SIM || HL_TVOS || HL_OSX)
#define HL_POSIX (HL_ANDROID || HL_EMSCRIPTEN || HL_LINUX)
#define HL_MOBILE (HL_ANDROID || HL_IOS || HL_TVOS)
#define HL_DESKTOP (HL_WINDOWS || HL_OSX || HL_LINUX)

#ifndef HL_EMSCRIPTEN_WORKER
#define HL_EMSCRIPTEN_WORKER 0
#endif // HL_EMSCRIPTEN_WORKER

#define HL_EMSCRIPTEN_MAIN (HL_EMSCRIPTEN && !HL_EMSCRIPTEN_WORKER)

// Target CPU.
#define HL_ASMJS 0
#define HL_ARM32 0
#define HL_ARM64 0
#define HL_I386 0
#define HL_X86_64 0

// Pointer size.
#define HL_PTR_SIZE 0

// Size of a cache line.
#if HL_EMSCRIPTEN
#define HL_CACHE_LINE_SIZE 8
#else
#define HL_CACHE_LINE_SIZE 64
#endif

// Target CPU extensions.
#define HL_NEON 0
#define HL_SSE 0

// Compiler.
#define HL_EMCC 0
#define HL_EMCC_VER 0 // EMCC version as integer value: MMmmpp
#define HL_CLANG 0
#define HL_CLANG_VER 0 // Clang version as integer value: MMmmpp
#define HL_GCC 0
#define HL_GCC_VER 0 // GCC version as integer value: MMmmpp
#define HL_MSVC 0
#define HL_MSVC_VER 0 // Set to _MSC_VER


#if defined(__EMSCRIPTEN__)
#undef HL_EMSCRIPTEN
#define HL_EMSCRIPTEN 1
#elif defined(_WIN32) || defined(_WIN64) || defined(_WINDOWS)
#undef HL_WINDOWS
#define HL_WINDOWS 1
#elif defined(ANDROID) || defined(__ANDROID__)
#undef HL_ANDROID
#define HL_ANDROID 1
#elif defined(__APPLE__)
#include "TargetConditionals.h"
#if TARGET_OS_TV
#undef HL_TVOS
#define HL_TVOS 1
#elif TARGET_IPHONE_SIMULATOR
#undef HL_IOS
#define HL_IOS 1
#undef HL_IOS_SIM
#define HL_IOS_SIM 1
#elif TARGET_OS_IPHONE
#undef HL_IOS
#define HL_IOS 1
#elif TARGET_OS_MAC
#undef HL_OSX
#define HL_OSX 1
#else
#error Unrecognized platform!
#endif
#elif defined(__linux__)
#undef HL_LINUX
#define HL_LINUX 1
#else
#error Unrecognized platform!
#endif

#if defined(__EMSCRIPTEN__)
#if defined(__asmjs__)
#undef HL_ASMJS
#define HL_ASMJS 1
#endif
#undef HL_PTR_SIZE
#define HL_PTR_SIZE 4
#elif defined(__x86_64__) || defined(_M_X64)
#undef HL_X86_64
#define HL_X86_64 1
#undef HL_PTR_SIZE
#define HL_PTR_SIZE 8
#elif defined(__i386__) || defined(_M_IX86)
#undef HL_I386
#define HL_I386 1
#undef HL_PTR_SIZE
#define HL_PTR_SIZE 4
#elif defined(__aarch64__)
#undef HL_ARM64
#define HL_ARM64 1
#undef HL_PTR_SIZE
#define HL_PTR_SIZE 8
#elif defined(__arm__)
#undef HL_ARM32
#define HL_ARM32 1
#undef HL_PTR_SIZE
#define HL_PTR_SIZE 4
#else
#error Unrecognized target CPU!
#endif

#if defined(__ARM_NEON__)
#undef HL_NEON
#define HL_NEON 1
#elif defined(__SSE__) || (defined(_M_IX86_FP) && (_M_IX86_FP == 1 || _M_IX86_FP == 2))
#undef HL_SSE
#define HL_SSE 1
#endif // __ARM_NEON__

#if defined(__EMSCRIPTEN__)
#undef HL_EMCC
#define HL_EMCC 1
#undef HL_EMCC_VER
#define HL_EMCC_VER (__EMSCRIPTEN_major__ * 10000 + __EMSCRIPTEN_minor__ * 100 + __EMSCRIPTEN_tiny__)
#endif // __EMSCRIPTEN__

#if defined(__clang__)
#undef HL_CLANG
#define HL_CLANG 1
#undef HL_CLANG_VER
#define HL_CLANG_VER (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#endif // __clang__

#if defined(_MSC_VER)
#undef HL_MSVC
#define HL_MSVC 1
#undef HL_MSVC_VER
#define HL_MSVC_VER _MSC_VER
#endif // _MSC_VER

#if defined(__GNUC__)
#undef HL_GCC
#define HL_GCC 1
#undef HL_GCC_VER
#define HL_GCC_VER (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif // __GNUC__

#ifndef __cplusplus
#define nullptr ((void*)0)
#endif
