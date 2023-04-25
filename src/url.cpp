/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#include "url.h"
#include <string.h>

bool urlParse(const char* full_, URLPieces* parsed) {
	char* full = (char*)full_;
	
	if (!full || !parsed) {
		return false;
	}

	size_t len = strlen(full);
	if (len == 0) {
		return false;
	}

	// http://en.wikipedia.org:80/w/index.php?title=Burrito#Breakfast_burrito
	const char* end       = full + len;
	const char* scheme[2] = {0};
	const char* domain[2] = {0};
	const char* port[2]   = {0};
	const char* path[2]   = {0};
	const char* query[2]  = {0};
	const char* anchor[2] = {0};

	// scheme
	scheme[0] = full;
	scheme[1] = strstr(scheme[0], "://");
	if (scheme[1]) {
		scheme[1] += 3;
	}
	else {
		scheme[1] = scheme[0];
	}

	// domain
	domain[0] = scheme[1];
	domain[1] = strpbrk(domain[0], ":/");
	if (!domain[1]) {
		domain[1] = end;
	}

	// port
	port[0] = domain[1];
	port[1] = strchr(port[0], (*domain[1] == ':') ? '/' : ':');
	if (!port[1]) {
		port[1] = port[0];
	}

	// path
	path[0] = port[1];
	path[1] = strchr(path[0], '?');
	if (!path[1]) {
		path[1] = end;
	}

	// query
	query[0] = path[1];
	query[1] = strchr(query[0], '#');
	if (!query[1]) {
		query[1] = end;
	}

	// anchor
	anchor[0] = query[1];
	anchor[1] = end;

	// done
	memset(parsed, 0, sizeof(URLPieces));

	parsed->full.data     = full;
	parsed->full.length   = len;
	parsed->scheme.data   = (char*)scheme[0];
	parsed->scheme.length = scheme[1] - scheme[0];
	parsed->domain.data   = (char*)domain[0];
	parsed->domain.length = domain[1] - domain[0];
	parsed->port.data     = (char*)port[0];
	parsed->port.length   = port[1] - port[0];
	parsed->path.data     = (char*)path[0];
	parsed->path.length   = path[1] - path[0];
	parsed->query.data    = (char*)query[0];
	parsed->query.length  = query[1] - query[0];
	parsed->anchor.data   = (char*)anchor[0];
	parsed->anchor.length = anchor[1] - anchor[0];

	parsed->hasScheme     = !!parsed->scheme.length;
	parsed->hasDomain     = !!parsed->domain.length;
	parsed->hasPort       = !!parsed->port.length;
	parsed->hasPath       = !!parsed->path.length;
	parsed->hasQuery      = !!parsed->query.length;
	parsed->hasAnchor     = !!parsed->anchor.length;
	parsed->isSSL         = parsed->hasScheme && strncmp(parsed->scheme.data, "https://", parsed->scheme.length);

	return parsed->hasDomain; // require at least a domain substring
}
