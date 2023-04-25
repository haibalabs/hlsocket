/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#pragma once

#include "hlsocket.h"
#include <stdint.h>

struct URLPieces {
	struct String {
		char* data;
		size_t length;
	};

	// the full original URL
	String full; 

	// components
	String scheme;
	String domain;
	String port;
	String path;
	String query;
	String anchor;

	bool hasScheme;
	bool hasDomain;
	bool hasPort;
	bool hasPath;
	bool hasQuery;
	bool hasAnchor;
	bool isSSL;
};

// ================================================================================================
/// Parse a URL into component pieces.
/// \param[in]    full   The full URL.
/// \param[inout] parsed The URL parsed into parts.
/// \return The value true if parsing succeeded, else false.
// ================================================================================================
HL_API bool urlParse(const char* full, URLPieces* parsed);
