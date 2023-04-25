/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#include "hlsocket.h"

#ifdef WIN32
#include <io.h>
#define F_OK 0
#define access _access
#else
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#define CERT_PATH "server.pem"

static bool checkReturnCode(int32_t rc, const char* op) {
	if (rc >= 0)
		return true;
	fprintf(stderr, "Failed to %s with socket error -0x%X\n", op, - rc);
	return false;
}

int main(int argc, const char * argv[]) {
	if (access(CERT_PATH, F_OK) != 0) {
		fprintf(stderr, "Missing certificate; make sure the test is being run from the examples folder\n");
		return -1;
	}

	bool sslEnabled = hlsocketInitializeSSL("server.pem", "server.pem", true);
	HL_ASSERT(sslEnabled);

	HLSocket s = hlsocketCreate(true, false);
	HL_ASSERT(s);

	sslEnabled = hlsocketIsSSL(s);
	HL_ASSERT(sslEnabled);

	int32_t rc = hlsocketConnect(&s, "1.1.1.1", "443", kTCP, 500);
	if (!checkReturnCode(rc, "connect"))
		return -1;

	rc = hlsocketSetBlock(s);
	if (!checkReturnCode(rc, "set blocking"))
		return -1;

	rc = hlsocketSend(s, "%", 1); // trigger a response 400 from cloudflare
	if (!checkReturnCode(rc, "send"))
		return -1;

	char buf[1024] = {0};
	hlsocketRecvAllTimeout(s, buf, sizeof(buf), 1000);

	printf("- - - - - - - - - - - - - - - - begin response - - - - - - - - - - - - - - - -\n");
	printf("%s\n", buf);
	printf("- - - - - - - - - - - - - - - -  end response  - - - - - - - - - - - - - - - -\n");

	hlsocketDestroy(&s);

	return 0;
}
