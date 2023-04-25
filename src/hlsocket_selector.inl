/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

struct HLSocketSelectorPimpl {
#if HL_WINDOWS
	WSAEVENT* socketEvents;
#elif HL_DARWIN
	int32_t   kq;
	int32_t   writefd;
	uint32_t* socketEvents;
#elif HL_POSIX
	int32_t   poll;
	int32_t*  socketEvents;
#else
#error Unrecognized platform!
#endif

	HLSocket* sockets;
	uint32_t  socketCount;
	uint32_t  maxSocketCount;
	bool      destroyOnFinalize;
	bool      initialized;

	HLSocketSelectorPimpl()
	        : destroyOnFinalize(false), initialized(false) {}

	uint32_t findSocket(HLSocket s) {
		uint32_t index = 1;
		for (; index < socketCount; ++index) {
			if (sockets[index] == s) {
				break;
			}
		}
		return (index == socketCount) ? 0 : index;
	}
};

HLSocketSelector::HLSocketSelector() {
	impl = new HLSocketSelectorPimpl();
}

HLSocketSelector::~HLSocketSelector() {
	delete impl;
}

HLSocket HLSocketSelector::get(uint32_t index) {
	HL_ASSERT(index > 0 && index < impl->socketCount);
	return impl->sockets[index];
}
