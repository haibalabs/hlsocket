/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

struct Hdr {
	char key[128];
	char proto[128];
	char rsp[256];
	int32_t ver = 0;
};

struct Frame {
	uint64_t length;
	uint32_t key;
	bool fin;
	bool mask;
	int8_t opcode;
};

static bool isWSConn(void* buf, int32_t len) {
	return (len >= 4) && (0 == ::memcmp(buf, "GET ", 4));
}

static bool parseHdr(void* buf, int32_t len, Hdr& hdr, int32_t* headerLen = nullptr) {
	const char kMagic[]    = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	const char kKeyStr[]   = "Sec-WebSocket-Key:";
	const char kVerStr[]   = "Sec-WebSocket-Version:";
	const char kProtoStr[] = "Sec-WebSocket-Protocol:";
	const char kRspFmt[]   =
		"HTTP/1.1 101 Switching Protocols\r\n" \
		"Upgrade: websocket\r\n"               \
		"Connection: Upgrade\r\n"              \
		"%s%s%s"                               \
		"Sec-WebSocket-Accept: %s\r\n\r\n";

	const int32_t kMaxLines = 32;
	char* lines[kMaxLines] = { 0 };
	int32_t nLines = 1;
	char* p = (char*)buf;

	// Terminate all of the lines in the handshake
	lines[0] = (char*)buf;

	while (len-- >= 4) {
		if (*p == '\r' && *(p + 1) == '\n') {
			// Terminate this line
			if (nLines == kMaxLines) {
				return false;
			}

			*p = '\0';
			lines[nLines++] = p + 2;

			if (*(p + 2) == '\r' && *(p + 3) == '\n') {
				// The end of this line is also the end of the header
				if (headerLen) {
					*headerLen = (int32_t)(p - (char*)buf + 4);
					break;
				}
			}
		}

		p++;
	}

	// Update repsonse string
	auto writeRsp = [&]() {
		// Append the WS magic string to the client key per the spec
		char accept[256] = {0};
		snprintf(accept, sizeof(accept), "%s%s", hdr.key, kMagic);

		// Generate the accept key
		SHA1Digest digest;
		hlsocketCalcSHA1(accept, strlen(accept), &digest);

		size_t sz = hlsocketBase64((uint8_t*)&digest, sizeof(digest), nullptr, 0);
		if (!sz || sz >= sizeof(accept)) {
			return false;
		}

		if (0 != hlsocketBase64((uint8_t*)&digest, sizeof(digest), accept, sz)) {
			return false;
		}

		// Format the response
		if (hdr.proto[0] == '\0') {
			snprintf(hdr.rsp, sizeof(hdr.rsp), kRspFmt, "", "", "", accept);
		}
		else {
			snprintf(hdr.rsp, sizeof(hdr.rsp), kRspFmt, "Sec-WebSocket-Protocol: ", hdr.proto, "\r\n", accept);
		}

		return true;
	};

	// Parse fields
	for (int32_t i = 0; i < nLines; ++i) {
		char* l = lines[i];

		if (strstr(l, kKeyStr)) {
			hdr.key[sizeof(hdr.key) - 1] = 0;
			strncpy(hdr.key, l + sizeof(kKeyStr), sizeof(hdr.key) - 1);

			if (!writeRsp()) {
				return false;
			}
		}
		else if (strstr(l, kProtoStr)) {
			hdr.proto[sizeof(hdr.proto) - 1] = 0;
			strncpy(hdr.proto, l + sizeof(kProtoStr), sizeof(hdr.proto) - 1);

			if (!writeRsp()) {
				return false;
			}
		}
		else if (strstr(l, kVerStr)) {
			int32_t count = sscanf(l + sizeof(kVerStr), "%d", &hdr.ver);
			if (count <= 0) {
				return false;
			}
		}
	}

	return true;
}

static int32_t getFrameHdrSize(uint8_t buf[2]) {
	bool      mask   = !!(buf[1] & 0x80);
	uint8_t   length =    buf[1] & 0x7F;
	return 2 + (mask ? 4 : 0) + (length == 126 ? 2 : (length == 127 ? 8 : 0));
}

static bool parseFrameHdr(uint8_t* buf, int32_t len, Frame& frame) {
	HL_ASSERT(len >= 2 && len >= getFrameHdrSize(buf));

	frame.fin    = !!(buf[0] & 0x80);
	frame.opcode =    buf[0] & 0x0F;
	frame.mask   = !!(buf[1] & 0x80);
	frame.length =    buf[1] & 0x7F;

	if (frame.length == 126) {
		frame.length = ((uint64_t)buf[2] << 8) | buf[3];
		frame.key = !frame.mask ? 0 :
			((uint32_t)buf[4] << 0 ) |
			((uint32_t)buf[5] << 8 ) |
			((uint32_t)buf[6] << 16) |
			((uint32_t)buf[7] << 24);
	}
	else if (frame.length == 127) {
		frame.length =
			((uint64_t)buf[2] << 56) |
			((uint64_t)buf[3] << 48) |
			((uint64_t)buf[4] << 40) |
			((uint64_t)buf[5] << 32) |
			((uint64_t)buf[6] << 24) |
			((uint64_t)buf[7] << 16) |
			((uint64_t)buf[8] << 8 ) |
			((uint64_t)buf[9] << 0 );
		frame.key = !frame.mask ? 0 :
			((uint32_t)buf[10] << 0 ) |
			((uint32_t)buf[11] << 8 ) |
			((uint32_t)buf[12] << 16) |
			((uint32_t)buf[13] << 24);
	}
	else {
		frame.key = !frame.mask ? 0 :
			((uint32_t)buf[2] << 0 ) |
			((uint32_t)buf[3] << 8 ) |
			((uint32_t)buf[4] << 16) |
			((uint32_t)buf[5] << 24);
	}

	return true;
}

int32_t makeFrameHdr(uint8_t* buf, int32_t len, uint64_t payloadLength) {
	HL_ASSERT(len >= 10);

	buf[0] = 0x82;

	if (payloadLength < 126) {
		buf[1] = (uint8_t)(payloadLength & 0x7F);
		return 2;
	}
	else if (payloadLength <= UINT16_MAX) {
		buf[1] = 126;
		buf[2] = (uint8_t)((payloadLength  >> 8) & 0xff);
		buf[3] = (uint8_t)((payloadLength  >> 0) & 0xff);
		return 4;
	}
	else {
		buf[1] = 127;
		buf[2] = (uint8_t)((payloadLength  >> 56) & 0xff);
		buf[3] = (uint8_t)((payloadLength  >> 48) & 0xff);
		buf[4] = (uint8_t)((payloadLength  >> 40) & 0xff);
		buf[5] = (uint8_t)((payloadLength  >> 32) & 0xff);
		buf[6] = (uint8_t)((payloadLength  >> 24) & 0xff);
		buf[7] = (uint8_t)((payloadLength  >> 16) & 0xff);
		buf[8] = (uint8_t)((payloadLength  >>  8) & 0xff);
		buf[9] = (uint8_t)((payloadLength  >>  0) & 0xff);
		return 10;
	}
}

bool recvHdr(HLSocket s, uint8_t* buf, int32_t len) {
	// Append first nibble needed to compute the header size
	while (len > 0 && s->hdrLen < 2) {
		s->hdr[s->hdrLen++] = *buf++;
		len--;
	}
	if (s->hdrLen < 2) {
		return false;
	}

	// Push the rest of the header data
	int32_t sz = getFrameHdrSize(s->hdr);
	while (len > 0 && s->hdrLen < sz) {
		s->hdr[s->hdrLen++] = *buf++;
		len--;
	}

	return (s->hdrLen == sz);
}
