/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

/*
 * \file net_sockets.h
 *
 * \brief Network communication functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/* Copyright (c) 2014 Malte Hildingsson, malte (at) afterwi.se
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * base64.c - by Joe DF (joedf@ahkscript.org)
 * Released under the MIT License
 *
 * See "base64.h", for more information.
 *
 * Thank you for inspiration:
 * http://www.codeproject.com/Tips/813146/Fast-base-functions-for-encode-decode
 */

#include "common.hpp"

struct HLSocketSSL;

#if HLSOCKET_ENABLE_SSL
#ifndef MBEDTLS_CONFIG_FILE
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif // MBEDTLS_CONFIG_FILE

#ifdef MBEDTLS_PLATFORM_C
#include "mbedtls/platform.h"
#else
#define mbedtls_time       time
#define MbedtlsTime     time_t
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif // MBEDTLS_PLATFORM_C

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#ifdef MBEDTLS_SSL_CACHE_C
#include "mbedtls/ssl_cache.h"
#endif // MBEDTLS_SSL_CACHE_C
#endif // HLSOCKET_ENABLE_SSL

static const char* gSSLCertFilename = nullptr;
static const char* gSSLPrivKeyFilename = nullptr;
static std::atomic<int> gSSLInitialized(0);
static bool gSSLCertChain = false;

static bool sslInit() {
#if HLSOCKET_ENABLE_SSL
	if (1 == gSSLInitialized.exchange(1, std::memory_order_relaxed)) {
		return true;
	}

#if HL_EMSCRIPTEN
		EM_ASM({
			Module['websocket'] = Module['websocket'] || {};
			Module['websocket'].url = 'wss://';
			Module['websocket'].subprotocol = 'binary';
		});
#endif // HL_EMSCRIPTEN

		HL_LOG("Initialized SSL\n");
#endif // HLSOCKET_ENABLE_SSL
		return true;
}

#include "hlsocket_ws.inl"
#if HLSOCKET_ENABLE_SSL
#include "hlsocket_ssl.inl"
#endif // HLSOCKET_ENABLE_SSL

static thread_local char gPeerIP[INET6_ADDRSTRLEN];
static thread_local uint8_t gTmpBuf1[16], gTmpBuf2[16], gTmpBuf3[1024];

#if HL_WINDOWS

// Some MS functions want int and MSVC warns if we pass size_t,
// but the standard fucntions use socklen_t, so cast only for MSVC
#if HL_MSVC
#define MSVC_INT_CAST (int)
#else
#define MSVC_INT_CAST
#endif // HL_MSVC

#undef read
#define read(fd, buf, len) recv(fd, (char*)buf, (int)len, 0)
#undef write
#define write(fd, buf, len) send(fd, (char*)buf, (int)len, 0)
#undef close
#define close(fd) closesocket(fd)

static int wsa_init_done = 0;
#else
#define MSVC_INT_CAST

#if HL_DARWIN
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif // MSG_NOSIGNAL
#endif // HL_DARWIN

#undef write
#define write(fd, buf, len) send(fd, (char*)buf, (int)len, MSG_NOSIGNAL)

#endif // HL_WINDOWS

static void resetErrno() {
#if HL_WINDOWS
	WSASetLastError(0);
#else
	errno = 0;
#endif // HL_WINDOWS
}

static int getErrno() {
#if HL_WINDOWS
	int err = WSAGetLastError();
	switch (err) {
	case 0:               return 0;
	case WSAEINPROGRESS:  return EINPROGRESS;
	case WSAEWOULDBLOCK:  return EWOULDBLOCK;
	case WSAEISCONN:      return EISCONN;
	case WSAECONNABORTED: return ECONNABORTED;
	case WSAECONNRESET:   return ECONNRESET;
	case WSAEINTR:        return EINTR;
	default:
		HL_LOG("Unexpected WSA error: %d\n", err);
		return EFAULT;
	}
#else
	return errno;
#endif // HL_WINDOWS
}

static void _logSSL(HLSocket s, int ret) {
#if HLSOCKET_ENABLE_SSL
#ifdef MBEDTLS_ERROR_C
	char errmsg[128];
	mbedtls_strerror(ret, errmsg, 128);
	HL_LOG("    => %d \"%s\" (%p/%x)\n", ret, errmsg, s, hlsocketGetNativeHandle(s));
#endif // MBEDTLS_ERROR_C
#endif // HLSOCKET_ENABLE_SSL
}

// Prepare for using the sockets interface
static int _netPrepare(void) {
#if HL_WINDOWS
	if (wsa_init_done == 0) {
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
			return kSocketOpenFailed;
		wsa_init_done = 1;
	}
#elif !HL_EMSCRIPTEN
	signal(SIGPIPE, SIG_IGN);
#endif // HL_WINDOWS
	return 0;
}

// Check if the requested operation would be blocking on a non-blocking socket
// and thus 'failed' with a negative return value.
// Note: on a blocking socket this function always returns 0!
static int _netWouldBlock(HLSocket s) {
#if HL_WINDOWS
	return WSAGetLastError() == WSAEWOULDBLOCK;
#else
	// Never return 'WOULD BLOCK' on a non-blocking socket
	if ((::fcntl(s->s, F_GETFL) & O_NONBLOCK) != O_NONBLOCK)
		return 0;

	switch (getErrno()) {
#if defined EAGAIN
	case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
	case EWOULDBLOCK:
#endif
#if HL_EMSCRIPTEN
	case 0:
#endif // HL_EMSCRIPTEN
		return 1;
	}
	return 0;
#endif // HL_WINDOWS
}

static void _closeSocket(HLSocket s) {
#if HL_WINDOWS
	closesocket(s->s);
#else
	::close(s->s);
#endif
}

static void _resetError() {
#if HL_WINDOWS
	WSASetLastError(0);
#endif
}

static void _shutdownSocket(HLSocket s) {
#if !HL_EMSCRIPTEN
	shutdown(s->s, 2);
#endif // !HL_EMSCRIPTEN
}

static int32_t _getRecvErrorCode(HLSocket s) {
	if (_netWouldBlock(s) != 0)
		return kSocketRecvWouldBlock;

	int err = getErrno();

	if (err == EPIPE || err == ECONNRESET)
		return kSocketConnReset;

	if (err == EINTR)
		return kSocketRecvWouldBlock;

	return kSocketRecvFailed;
}

static int32_t _getSendErrorCode(HLSocket s) {
	if (_netWouldBlock(s) != 0)
		return kSocketSendWouldBlock;

	int err = getErrno();

	if (err == EPIPE || err == ECONNRESET)
		return kSocketConnReset;

	if (err == EINTR)
		return kSocketSendWouldBlock;

	return kSocketSendFailed;
}

static int32_t _handleRead(HLSocket s, void* buf, size_t len) {
#if HLSOCKET_ENABLE_SSL
	if (s->flags & HLSocketData::kSSL) {
		HL_ASSERT(s->sslCtx);

#if HLSOCKET_VERBOSE_LOGS
		HL_LOG("mbedtls_ssl_read(%p, %p, %zu)\n", &s->sslCtx->ssl, buf, len);
#endif // HLSOCKET_VERBOSE_LOGS

		int32_t rc = (int)mbedtls_ssl_read(&s->sslCtx->ssl, (unsigned char*)buf, (int)len);

		if (rc > 0) {
			return rc;
		}
		else if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
			return kSocketRecvWouldBlock;
		}
		else if (rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
			return kSocketSendWouldBlock;
		}
		else {
			int32_t err = _getRecvErrorCode(s);
			if (err == kSocketRecvWouldBlock) {
				return kSocketRecvWouldBlock;
			}
			if (err == kSocketSendWouldBlock) {
				return kSocketSendWouldBlock;
			}

#if HLSOCKET_VERBOSE_LOGS
			HL_LOG("Error in mbedtls_ssl_read(ssl %p, buf %p, num %zu): read %d, errno %d, code %d, hlsocketGetError %d\n",
				&s->sslCtx->ssl, buf, len, rc, getErrno(), err, hlsocketGetError(s));
#endif // HLSOCKET_VERBOSE_LOGS
			_logSSL(s, rc);

			return kSocketRecvFailed;
		}
	}
	else {
		int32_t rc = (int)::read((int)s->s, buf, len);
#if HLSOCKET_VERBOSE_LOGS
		int32_t err = _getRecvErrorCode(s);
		if (rc < 0 && kSocketSendWouldBlock != err && kSocketRecvWouldBlock != err) {
			HL_LOG("Error in socket read(%d, %p, %zu): %d, %d, %d, %d\n", s->s, buf, len,
				rc, getErrno(), err, hlsocketGetError(s));
		}
#endif // HLSOCKET_VERBOSE_LOGS

		return rc;
	}
#else
	int32_t rc = (int)::read((int)s->s, buf, len);
#if HLSOCKET_VERBOSE_LOGS
	int32_t err = _getRecvErrorCode(s);
	if (rc < 0 && kSocketSendWouldBlock != err && kSocketRecvWouldBlock != err) {
		HL_LOG("Error in socket read(%d, %p, %zu): %d, %d, %d, %d\n", s->s, buf, len, rc, getErrno(), err, hlsocketGetError(s));
	}
#endif // HLSOCKET_VERBOSE_LOGS
	return rc;
#endif // HLSOCKET_ENABLE_SSL
}

static int32_t _handleWrite(HLSocket s, const void* buf, size_t len) {
#if HLSOCKET_ENABLE_SSL
	if (s->flags & HLSocketData::kSSL) {
		HL_ASSERT(s->sslCtx);

#if HLSOCKET_VERBOSE_LOGS
		HL_LOG("mbedtls_ssl_write(%p, %p, %zu)\n", &s->sslCtx->ssl, buf, len);
#endif // HLSOCKET_VERBOSE_LOGS

		int32_t rc = (int)mbedtls_ssl_write(&s->sslCtx->ssl, (const unsigned char*)buf, (int)len);

		if (rc > 0) {
			return rc;
		}
		else if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
			return kSocketRecvWouldBlock;
		}
		else if (rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
			return kSocketSendWouldBlock;
		}
		else {
			int32_t err = _getSendErrorCode(s);
			if (err == kSocketRecvWouldBlock) {
				return kSocketRecvWouldBlock;
			}
			if (err == kSocketSendWouldBlock) {
				return kSocketSendWouldBlock;
			}

#if HLSOCKET_VERBOSE_LOGS
			HL_LOG("Error in mbedtls_ssl_write(ssl %p, buf %p, num %zu): write %d, errno %d, code %d, hlsocketGetError %d\n",
				&s->sslCtx->ssl, buf, len, rc, getErrno(), err, hlsocketGetError(s));
#endif // HLSOCKET_VERBOSE_LOGS
			_logSSL(s, rc);

			return kSocketSendFailed;
		}
	}
	else {
		int32_t rc = (int)::write((int)s->s, buf, len);
#if HLSOCKET_VERBOSE_LOGS
		int32_t err = _getSendErrorCode(s);
		if (rc < 0 && kSocketSendWouldBlock != err && kSocketRecvWouldBlock != err) {
			HL_LOG("Error in socket send(%d, %p, %zu): %d, %d, %d, %d\n", s->s, buf, len, rc, getErrno(), err, hlsocketGetError(s));
		}
#endif // HLSOCKET_VERBOSE_LOGS
		return rc;
	}
#else
	int32_t rc = (int)::write((int)s->s, buf, len);
#if HLSOCKET_VERBOSE_LOGS
	int32_t err = _getSendErrorCode(s);
	if (rc < 0 && kSocketSendWouldBlock != err && kSocketRecvWouldBlock != err) {
		HL_LOG("Error in socket send(%d, %p, %zu): %d, %d, %d, %d\n", s->s, buf, len, rc, getErrno(), err, hlsocketGetError(s));
	}
#endif // HLSOCKET_VERBOSE_LOGS
	return rc;
#endif // HLSOCKET_ENABLE_SSL
}

bool hlsocketInitializeSSL(const char* cert, const char* privkey, bool chain) {
	if (gSSLCertFilename != cert ||
		gSSLPrivKeyFilename != privkey ||
		gSSLCertChain != chain) {
	}

	if (sslInit()) {
		gSSLCertFilename = cert;
		gSSLPrivKeyFilename = privkey;
		gSSLCertChain = chain;
		return true;
	}
	else {
		return false;
	}
}

HLSocket hlsocketCreate(bool ssl, bool listen) {
	if (ssl) {
		sslInit();

		if (!gSSLInitialized) {
			return nullptr;
		}
	}

	HLSocketData* s = new HLSocketData;
	s->initialize();

#if HLSOCKET_ENABLE_SSL
	if (ssl) {
		if (!hlsocketSSLInit(s, listen)) {
			delete s;
			return nullptr;
		}
	}
#endif // HLSOCKET_ENABLE_SSL

	return (HLSocket)s;
}

void hlsocketDestroy(HLSocket* s) {
	if (!s || !(*s)) {
		return;
	}

	if ((*s)->s) {
#if HLSOCKET_ENABLE_SSL
		hlsocketSSLFini(*s);
#endif // HLSOCKET_ENABLE_SSL

#if !HL_EMSCRIPTEN
		shutdown((*s)->s, 2);
#endif // !HL_EMSCRIPTEN
		_closeSocket(*s);
		(*s)->s = 0;
	}

	delete* s;
	*s = nullptr;
}

bool hlsocketIsSSL(HLSocket s) {
	return !!(s->flags & HLSocketData::kSSL);
}

int32_t hlsocketConnect(HLSocket* s, const char* host, const char* port, HLSocketProto proto, float timeoutMillis) {
	int ret;
	struct addrinfo hints, * addr_list, * cur;

	resetErrno();

	if ((ret = _netPrepare()) != 0) {
		return ret;
	}

	// Do name resolution with both IPv6 and IPv4
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = proto == kUDP ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = proto == kUDP ? IPPROTO_UDP : IPPROTO_TCP;

	if (0 == strcmp(host, "localhost")) {
		host = "127.0.0.1";
	}

	if (::getaddrinfo(host, port, &hints, &addr_list) != 0) {
		return kSocketUnknownHost;
	}

	// Try the sockaddrs until a connection succeeds
	ret = kSocketUnknownHost;

	for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
		(*s)->s = ::socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
		if ((signed)(*s)->s < 0) {
			ret = kSocketOpenFailed;
			continue;
		}

		if (timeoutMillis != 0.f) {
			hlsocketSetNonBlock(*s);
		}

		int result = ::connect((*s)->s, cur->ai_addr, MSVC_INT_CAST cur->ai_addrlen);
		int err = getErrno();

		if (result == 0 || err == EINPROGRESS || err == EWOULDBLOCK || err == EISCONN) {
			// Block on the connection
			bool timedout = false;

			if (timeoutMillis != 0.f) {
				fd_set fdset;
				struct timeval tv;
				FD_ZERO(&fdset);
				FD_SET((*s)->s, &fdset);
				tv.tv_sec = (long int)(timeoutMillis / 1000.f);
				tv.tv_usec = (int)((timeoutMillis - (float)(1000.f * tv.tv_sec)) * 1000.f);

				if ((int)select((int)((*s)->s + 1), nullptr, &fdset, nullptr, &tv) == 0) {
					ret = kSocketTimeout;
					timedout = true;
				}

				hlsocketSetBlock(*s);
			}

			// Success
			if (!timedout) {
				resetErrno();

				ret = 0;

				(*s)->flags |= HLSocketData::kFirstRecv;

#if HLSOCKET_ENABLE_SSL
				if ((*s)->flags & HLSocketData::kSSL) {
					if (!hlsocketSSLConnect(*s, host)) {
						ret = kSocketConnectFailed;
						_shutdownSocket(*s);
						(*s)->s = 0;
						break;
					}
				}
#endif // HLSOCKET_ENABLE_SSL
			}
			break;
		}
		else if (timeoutMillis != 0.f) {
			hlsocketSetBlock(*s);
		}

		// Error
		ret = kSocketConnectFailed;
		_shutdownSocket(*s);
		(*s)->s = 0;
		break;
	}

	::freeaddrinfo(addr_list);

	return ret;
}

int32_t hlsocketBind(HLSocket* s, const char* bindIP, const char* port, HLSocketProto proto) {
	int             n, ret;
	struct addrinfo hints, * addr_list, * cur;

	if ((ret = _netPrepare()) != 0)
		return ret;

	// Bind to IPv6 and/or IPv4, but only in the desired protocol
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = proto == kUDP ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = proto == kUDP ? IPPROTO_UDP : IPPROTO_TCP;
	if (bindIP == NULL)
		hints.ai_flags = AI_PASSIVE;

	if (::getaddrinfo(bindIP, port, &hints, &addr_list) != 0)
		return kSocketUnknownHost;

	// Try the sockaddrs until a binding succeeds
	ret = kSocketUnknownHost;
	for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
		(*s)->s = ::socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
		if ((signed)(*s)->s < 0) {
			ret = kSocketOpenFailed;
			continue;
		}

		n = 1;
		if (::setsockopt((*s)->s, SOL_SOCKET, SO_REUSEADDR, (const char*)&n, sizeof(n)) != 0) {
			_closeSocket(*s);
			ret = kSocketOpenFailed;
			continue;
		}

		if (::bind((*s)->s, cur->ai_addr, MSVC_INT_CAST cur->ai_addrlen) != 0) {
			_closeSocket(*s);
			ret = kSocketBindFailed;
			continue;
		}

		// Listen only makes sense for TCP
		if (proto == kTCP) {
			if (::listen((*s)->s, kSocketListenBacklog) != 0) {
				_closeSocket(*s);
				ret = kSocketListenFailed;
				continue;
			}
		}

#if HLSOCKET_ENABLE_SSL
		if (!hlsocketSSLBind(*s)) {
			_closeSocket(*s);
			ret = kSocketBindFailed;
			continue;
		}
#endif // HLSOCKET_ENABLE_SSL

		// I we ever get there, it's a success
		ret = 0;
		break;
	}

	::freeaddrinfo(addr_list);

	return ret;
}

int32_t hlsocketAccept(HLSocket* bindCtx, HLSocket* clientCtx, void* clientIP, size_t bufSize, size_t* IPLen) {
	int ret;
	int type;

	struct sockaddr_storage client_addr;

#if HL_ANDROID || defined(__socklen_t_defined) || defined(_SOCKLEN_T) || defined(_SOCKLEN_T_DECLARED) || \
        defined(__DEFINED_socklen_t)
	socklen_t n = (socklen_t)sizeof(client_addr);
	socklen_t type_len = (socklen_t)sizeof(type);
#else
	int n = (int)sizeof(client_addr);
	int type_len = (int)sizeof(type);
#endif

	// Is this a TCP or UDP socket?
	if (::getsockopt((*bindCtx)->s, SOL_SOCKET, SO_TYPE, (char*)&type, &type_len) != 0 ||
		(type != SOCK_STREAM && type != SOCK_DGRAM)) {
		return kSocketAcceptFailed;
	}

	if (type == SOCK_STREAM) {
		// TCP: actual accept()
		*clientCtx = hlsocketCreate(false, false);

#if HLSOCKET_ENABLE_SSL
		if (!hlsocketSSLPreAccept(*bindCtx)) {
			hlsocketDestroy(clientCtx);
			return kSocketAcceptFailed;
		}
#endif // HLSOCKET_ENABLE_SSL

		(*clientCtx)->s = ::accept((*bindCtx)->s, (struct sockaddr*)&client_addr, &n);

		ret = (int)(*clientCtx)->s;

		if ((*clientCtx)->s <= 0) {
			hlsocketDestroy(clientCtx);
			return kSocketAcceptFailed;
		}
		else {
#if HLSOCKET_ENABLE_SSL
			if (!hlsocketSSLAccept(*bindCtx, *clientCtx)) {
				hlsocketDestroy(clientCtx);
				return kSocketAcceptFailed;
			}
#endif // HLSOCKET_ENABLE_SSL
		}
	}
	else {
		// UDP: wait for a message, but keep it in the queue
		char buf[1] = {};

		ret = (int)::recvfrom((*bindCtx)->s, buf, sizeof(buf), MSG_PEEK, (struct sockaddr*)&client_addr, &n);

#if HL_WINDOWS
		if (ret == SOCKET_ERROR && WSAGetLastError() == WSAEMSGSIZE) {
			// We know buf is too small, thanks, just peeking here
			ret = 0;
		}
#endif
	}

	if (ret < 0) {
		if (_netWouldBlock(*bindCtx) != 0)
			return kSocketRecvWouldBlock;

		return kSocketAcceptFailed;
	}

	// UDP: hijack the listening socket to communicate with the client,
	// then bind a new socket to accept new connections
	if (type != SOCK_STREAM) {
		struct sockaddr_storage local_addr;
		int                     one = 1;

		if (::connect((*bindCtx)->s, (struct sockaddr*)&client_addr, n) != 0)
			return kSocketAcceptFailed;

		(*clientCtx)->s = (*bindCtx)->s;

		n = sizeof(struct sockaddr_storage);
		if (::getsockname((*clientCtx)->s, (struct sockaddr*)&local_addr, &n) != 0 ||
			(signed)((*bindCtx)->s = (int)socket(local_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP)) < 0 ||
			::setsockopt((*bindCtx)->s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one)) != 0) {
			return kSocketOpenFailed;
		}

		if (::bind((*bindCtx)->s, (struct sockaddr*)&local_addr, n) != 0) {
			return kSocketBindFailed;
		}
	}

	if (clientIP != NULL) {
		if (client_addr.ss_family == AF_INET) {
			struct sockaddr_in* addr4 = (struct sockaddr_in*)&client_addr;
			*IPLen = sizeof(addr4->sin_addr.s_addr);

			if (bufSize < *IPLen)
				return kSocketBufferTooSmall;

			memcpy(clientIP, &addr4->sin_addr.s_addr, *IPLen);
		}
		else {
			struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&client_addr;
			*IPLen = sizeof(addr6->sin6_addr.s6_addr);

			if (bufSize < *IPLen)
				return kSocketBufferTooSmall;

			memcpy(clientIP, &addr6->sin6_addr.s6_addr, *IPLen);
		}
	}

	(*clientCtx)->flags |= HLSocketData::kFirstRecv;

	return 0;
}

int32_t hlsocketSetBlock(HLSocket s) {
#if HL_WINDOWS
	u_long n = 0;
	return ::ioctlsocket(s->s, FIONBIO, &n);
#else
	return ::fcntl(s->s, F_SETFL, fcntl(s->s, F_GETFL) & ~O_NONBLOCK);
#endif
}

int32_t hlsocketSetNonBlock(HLSocket s) {
#if HL_WINDOWS
	u_long n = 1;
	return ::ioctlsocket(s->s, FIONBIO, &n);
#else
	return ::fcntl(s->s, F_SETFL, fcntl(s->s, F_GETFL) | O_NONBLOCK);
#endif
}

void hlsocketSetBufferSize(HLSocket s, int32_t* sendBufSz, int32_t* recvBufSz) {
	::setsockopt(s->s, SOL_SOCKET, SO_SNDBUF, (const char*)sendBufSz, sizeof(int32_t));
	::setsockopt(s->s, SOL_SOCKET, SO_RCVBUF, (const char*)recvBufSz, sizeof(int32_t));

	socklen_t len = sizeof(int32_t);
	::getsockopt(s->s, SOL_SOCKET, SO_SNDBUF, (char*)sendBufSz, &len);
	len = sizeof(int32_t);
	::getsockopt(s->s, SOL_SOCKET, SO_RCVBUF, (char*)recvBufSz, &len);
}

void hlsocketGetBufferSize(HLSocket s, int32_t* sendBufSz, int32_t* recvBufSz) {
	socklen_t len = sizeof(int32_t);
	::getsockopt(s->s, SOL_SOCKET, SO_SNDBUF, (char*)sendBufSz, &len);
	len = sizeof(int32_t);
	::getsockopt(s->s, SOL_SOCKET, SO_RCVBUF, (char*)recvBufSz, &len);
}

int32_t hlsocketRecv(HLSocket s, void* buf, size_t len) {
	int ret = kSocketSuccess;
	int fd = (int)s->s;

	resetErrno();

	if ((s->flags & HLSocketData::kError) == HLSocketData::kError) {
		return kSocketRecvFailed;
	}

	if (fd < 0)
		return kSocketInvalidContext;

	if (len == 0)
		return 0;

	// Detect if we are connected to a websocket
	if (s->flags & HLSocketData::kFirstRecv) {
		bool fallThru = false;

		HL_ASSERT(len >= 4);

		// Read the first 4 bytes off of the socket
		uint8_t* tok = gTmpBuf3;
		_resetError();

		ret = (int)_handleRead(s, tok, 4);
		if (ret < 0) {
			return _getRecvErrorCode(s);
		}

		s->flags &= ~HLSocketData::kFirstRecv;

		// See if it contains a websocket header
		int32_t hdrSize = 0;
		if (isWSConn(tok, ret)) {
			_resetError();

			int ret2 = (int)_handleRead(s, tok + 4, sizeof(gTmpBuf3) - 4);
			if (ret2 < 0) {
				return _getRecvErrorCode(s);
			}
			ret += ret2;

			Hdr hdr;
			if (parseHdr(tok, ret, hdr, &hdrSize)) {
				// This is a websocket
				s->flags |= HLSocketData::kWebSocket;

				// Send the response header
				_resetError();
				int sendRet = (int)_handleWrite(s, hdr.rsp, strlen(hdr.rsp));
				if (sendRet < 0) {
					return _getSendErrorCode(s);
				}

				// Eat the header data
				ret -= hdrSize;
				if (ret == 0) {
					fallThru = true;
				}
			}
		}

		if (!fallThru) {
			memcpy(buf, tok + hdrSize, ret);
			return ret;
		}
	}

	// If this is a web client, we need to limit the amount of data received
	// to avoid buffering two frame headers
	if (s->flags & HLSocketData::kWebSocket) {
		if (s->rsize == 0) {
			ret = 0;

			// Receive just the next frame header
			while (!recvHdr(s, (uint8_t*)gTmpBuf1, ret)) {
				_resetError();

				ret = (int32_t)_handleRead(s, gTmpBuf1, 1);
				if (ret == 0) {
					return kSocketConnReset;
				}
				else if (ret < 0) {
					return _getRecvErrorCode(s);
				}
			}

			Frame frame;
			if (parseFrameHdr(s->hdr, s->hdrLen, frame)) {
				if (frame.length > UINT32_MAX) {
					return kSocketRecvFailed;
				}
				if (frame.mask) {
					s->flags |= HLSocketData::kMasked;
				}
				s->rsize = (uint32_t)frame.length;
				s->key = (uint32_t)frame.key;
				s->flags &= HLSocketData::kFlagMask;

				s->hdrLen = 0;
			}
			else {
				s->flags |= HLSocketData::kError;
				return kSocketRecvFailed;
			}
		}

		if (s->rsize > 0) {
			// Receive at most the remainder of the payload
			if (len > s->rsize) {
				len = s->rsize;
			}
		}
	}

	_resetError();

	ret = (int)_handleRead(s, buf, len);
	if (ret <= 0) {
		return _getRecvErrorCode(s);
	}

	if ((s->flags & HLSocketData::kWebSocket) && (s->flags & HLSocketData::kMasked)) {
		s->rsize -= ret;

		int8_t   ofs = s->flags & HLSocketData::kOfsMask;
		uint8_t* p = (uint8_t*)buf;
		uint8_t* key = (uint8_t*)&s->key;

		for (int i = 0; i < ret; ++i, ofs = (ofs + 1) & 0x3, p++) {
			*p ^= key[ofs];
		}

		s->flags = (s->flags & HLSocketData::kFlagMask) | ofs;
	}

	return ret;
}

int32_t hlsocketSend(HLSocket s, const void* buf, size_t len) {
	int ret;
	int fd = (int)s->s;

	resetErrno();

	if (fd < 0)
		return kSocketInvalidContext;

	if (len == 0)
		return 0;

	// If this is a websocket, prefix a frame header
	if (s->flags & HLSocketData::kWebSocket) {
		if (s->wsize == 0) {
			int32_t hdrSz = makeFrameHdr(gTmpBuf2, sizeof(gTmpBuf2), len);

			_resetError();
			ret = (int)_handleWrite(s, gTmpBuf2, hdrSz);
			if (ret < 0) {
				return _getSendErrorCode(s);
			}

			s->wsize = len;
		}
		else if (len > s->wsize) {
			len = s->wsize;
		}
	}

	_resetError();
	ret = (int)_handleWrite(s, buf, len);
	if (ret < 0) {
		return _getSendErrorCode(s);
	}

	if (s->flags & HLSocketData::kWebSocket) {
		s->wsize -= ret;
	}

	return ret;
}

int32_t hlsocketRecvTimeout(HLSocket s, void* buf, size_t len, uint32_t timeoutMillis) {
	int            ret;
	struct timeval tv;
	fd_set         read_fds;
	int            fd = (int)s->s;

	if (fd < 0)
		return kSocketInvalidContext;

	if (len == 0)
		return 0;

	FD_ZERO(&read_fds);
	FD_SET(fd, &read_fds);

	tv.tv_sec = timeoutMillis / 1000;
	tv.tv_usec = (timeoutMillis % 1000) * 1000;

	ret = ::select(fd + 1, &read_fds, NULL, NULL, timeoutMillis == 0 ? NULL : &tv);

	// Zero fds ready means we timed out
	if (ret == 0)
		return kSocketTimeout;

	if (ret < 0) {
		if (getErrno() == EINTR)
			return kSocketConnReset;

		return kSocketRecvFailed;
	}

	// This call will not block
	return hlsocketRecv(s, buf, len);
}

int32_t hlsocketRecvAllTimeout(HLSocket s, void* buf, size_t len, uint32_t timeoutMillis) {
	if (len > INT32_MAX)
		return kSocketBufferTooSmall;

	size_t remaining = len;
	while (remaining > 0) {
		int32_t rc = hlsocketRecvTimeout(s, buf, remaining, timeoutMillis);
		if (rc < 0) {
			return rc;
		}

		buf = (uint8_t*)buf + rc;
		remaining -= (size_t)rc;
	}

	return (int32_t)len;
}

const char* hlsocketGetPeerName(HLSocket s) {
	static char emptyStr[1] = {};

	if (!s) {
		return emptyStr;
	}

	sockaddr_storage addr;
	socklen_t        addrLen = sizeof(addr);

	if (0 != ::getpeername(s->s, (sockaddr*)&addr, &addrLen)) {
		return emptyStr;
	}

	if (0 != ::getnameinfo((sockaddr*)&addr, addrLen, gPeerIP, sizeof(gPeerIP), 0, 0, NI_NUMERICHOST)) {
		return emptyStr;
	}

	return gPeerIP;
}

int32_t hlsocketGetError(HLSocket s) {
	int err;

#if HL_ANDROID || defined(__socklen_t_defined) || defined(_SOCKLEN_T) || defined(_SOCKLEN_T_DECLARED) || \
        defined(__DEFINED_socklen_t)
	socklen_t err_len = (socklen_t)sizeof(err);
#else
	int err_len = (int)sizeof(err);
#endif

	int rc = ::getsockopt(s->s, SOL_SOCKET, SO_ERROR, (char*)&err, &err_len);
	if (rc != 0 || err != 0) {
		return kSocketConnectFailed;
	}

	return 0;
}

size_t hlsocketGetRecvPending(HLSocket s) {
#if HL_WINDOWS
	u_long avail = 0;
	int rc = ioctlsocket(s->s, FIONREAD, &avail);
	if (rc == SOCKET_ERROR) {
		HL_LOG("Error return from ioctl: %d, errno %d\n", rc, WSAGetLastError());
	}
	return (size_t)avail;
#else
	int avail = 0;
	int rc = ioctl(s->s, FIONREAD, &avail);
	if (rc < 0) {
		HL_LOG("Error return from ioctl: %d, errno %d\n", rc, errno);
	}
	return (size_t)avail;
#endif
}

const int32_t hlsocketGetNativeHandle(HLSocket s) {
	// From OpenSSL's docs:
	// "Even though sizeof(SOCKET) is 8, it's safe to cast it to int, because
	//  the value constitutes an index in per-process table of limited size
	//  and not a real pointer."

	return (int32_t)(s ? s->s : 0);
}

void hlsocketCalcSHA1(const void* src, size_t srcSize, SHA1Digest* digest) {
	/* Copyright (c) 2014 Malte Hildingsson, malte (at) afterwi.se
	 * Permission is hereby granted, free of charge, to any person obtaining a copy
	 * of this software and associated documentation files (the "Software"), to deal
	 * in the Software without restriction, including without limitation the rights
	 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	 * copies of the Software, and to permit persons to whom the Software is
	 * furnished to do so, subject to the following conditions:
	 * The above copyright notice and this permission notice shall be included in
	 * all copies or substantial portions of the Software.
	 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	 * THE SOFTWARE.
	 */

	auto sha1mix = [](unsigned* r, unsigned* w) {
		unsigned a = r[0];
		unsigned b = r[1];
		unsigned c = r[2];
		unsigned d = r[3];
		unsigned e = r[4];
		unsigned t, i = 0;

		#define rol(x, s) ((x) << (s) | (unsigned)(x) >> (32 - (s)))
		#define mix(f, v)                                   \
			do {                                            \
				t = (f) + (v) + rol(a, 5) + e + w[i & 0xf]; \
				e = d;                                      \
				d = c;                                      \
				c = rol(b, 30);                             \
				b = a;                                      \
				a = t;                                      \
			} while (0)

			for (; i < 16; ++i)
				mix(d ^ (b & (c ^ d)), 0x5a827999);

			for (; i < 20; ++i) {
				w[i & 0xf] = rol(w[i + 13 & 0xf] ^ w[i + 8 & 0xf] ^ w[i + 2 & 0xf] ^ w[i & 0xf], 1);
				mix(d ^ (b & (c ^ d)), 0x5a827999);
			}

			for (; i < 40; ++i) {
				w[i & 0xf] = rol(w[i + 13 & 0xf] ^ w[i + 8 & 0xf] ^ w[i + 2 & 0xf] ^ w[i & 0xf], 1);
				mix(b ^ c ^ d, 0x6ed9eba1);
			}

			for (; i < 60; ++i) {
				w[i & 0xf] = rol(w[i + 13 & 0xf] ^ w[i + 8 & 0xf] ^ w[i + 2 & 0xf] ^ w[i & 0xf], 1);
				mix((b & c) | (d & (b | c)), 0x8f1bbcdc);
			}

			for (; i < 80; ++i) {
				w[i & 0xf] = rol(w[i + 13 & 0xf] ^ w[i + 8 & 0xf] ^ w[i + 2 & 0xf] ^ w[i & 0xf], 1);
				mix(b ^ c ^ d, 0xca62c1d6);
			}

		#undef mix
		#undef rol

		r[0] += a;
		r[1] += b;
		r[2] += c;
		r[3] += d;
		r[4] += e;
	};

	size_t i = 0;
	unsigned w[16], r[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

	for (; i < (srcSize & ~0x3f);) {
		do {
			w[i >> 2 & 0xf] = ((const uint8_t*)src)[i + 3] << 0x00 | ((const uint8_t*)src)[i + 2] << 0x08 |
			        ((const uint8_t*)src)[i + 1] << 0x10 | ((const uint8_t*)src)[i + 0] << 0x18;
		} while ((i += 4) & 0x3f);

		sha1mix(r, w);
	}

	memset(w, 0, sizeof(w));

	for (; i < srcSize; ++i) {
		w[i >> 2 & 0xf] |= ((const uint8_t*)src)[i] << ((3 ^ (i & 3)) << 3);
	}

	w[i >> 2 & 0xf] |= 0x80 << ((3 ^ (i & 3)) << 3);

	if ((srcSize & 0x3f) > 56) {
		sha1mix(r, w);
		memset(w, 0, sizeof(w));
	}

	w[15] = (unsigned)(srcSize << 3);
	sha1mix(r, w);

	uint8_t* h = (uint8_t*)digest->buffer;
	for (i = 0; i < 5; ++i) {
		h[(i << 2) + 0] = (uint8_t)(r[i] >> 0x18);
		h[(i << 2) + 1] = (uint8_t)(r[i] >> 0x10);
		h[(i << 2) + 2] = (uint8_t)(r[i] >> 0x08);
		h[(i << 2) + 3] = (uint8_t)(r[i] >> 0x00);
	}
}

size_t hlsocketBase64(const uint8_t* src, size_t srcSize, char* dst, size_t dstSize) {
	/*
	 * base64.c - by Joe DF (joedf@ahkscript.org)
	 * Released under the MIT License
	 *
	 * See "base64.h", for more information.
	 *
	 * Thank you for inspiration:
	 * http://www.codeproject.com/Tips/813146/Fast-base-functions-for-encode-decode
	 */

	auto base64EncodeTriple = [](const unsigned char triple[3], char result[4]) {
		int tripleValue;
		tripleValue = triple[0];
		tripleValue *= 256;
		tripleValue += triple[1];
		tripleValue *= 256;
		tripleValue += triple[2];

		const char* BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		for (int i = 0; i < 4; ++i) {
			result[3 - i] = BASE64_CHARS[tripleValue % 64];
			tripleValue /= 64;
		}
	};

	HL_ASSERT(src);
	HL_ASSERT(srcSize > 0);
	size_t reqDstSize = ((srcSize + 2) / 3 * 4) + 1;
	if (!dst || dstSize < reqDstSize)
		return reqDstSize;

	// encode all full triples
	while (srcSize >= 3) {
		base64EncodeTriple(src, dst);
		srcSize -= 3;
		src += 3;
		dst += 4;
	}

	// encode the last one or two characters
	if (srcSize > 0) {
		unsigned char temp[3] = {};
		memcpy(temp, src, srcSize);
		base64EncodeTriple(temp, dst);
		dst[3] = '=';
		if (srcSize == 1)
			dst[2] = '=';
		dst += 4;
	}

	// terminate the string
	dst[0] = 0;

	return 0;
}
