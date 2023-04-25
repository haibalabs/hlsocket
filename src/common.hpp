#pragma once

#include "hlsocket.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <atomic>

#if HL_WINDOWS
#undef INET6_ADDRSTRLEN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#endif // HP_WINDOWS

struct HLSocketSSL;

struct HLSocketData {
	static const uint8_t kFirstRecv = 0x04;
	static const uint8_t kWebSocket = 0x08;
	static const uint8_t kMasked    = 0x10;
	static const uint8_t kSSL       = 0x20;
	static const uint8_t kSSLParent = 0x40;
	static const uint8_t kError     = 0x80;
	static const uint8_t kFlagMask  = 0xfc;
	static const uint8_t kOfsMask   = 0x03;

	HLSocketSSL*  sslCtx;
	size_t        wsize;
#if HL_WINDOWS
	uintptr_t     s;
#else
	int           s;
#endif
	uint32_t      rsize;
	uint32_t      key;
	uint8_t       flags;
	uint8_t       hdrLen;
	uint8_t       hdr[14];

	void initialize() {
		sslCtx = nullptr;
		wsize  = 0;
		s      = 0;
		rsize  = 0;
		key    = 0;
		flags  = 0;
		hdrLen = 0;
	}
};
