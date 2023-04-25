/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#include "hlsocket_selector.h"

#include "common.hpp"

#if HL_WINDOWS

#undef INET6_ADDRSTRLEN
#include <winsock2.h>
#include <ws2tcpip.h>

#include "hlsocket_selector.inl"

// ------------------------------------------------------------------------------------------------
static long convertToWSAEvents(uint32_t events) {
	long result = 0;
	if (events & HLSocketSelector::kWantAccept) {
		result |= FD_ACCEPT;
	}
	if (events & HLSocketSelector::kWantRead) {
		result |= FD_READ;
	}
	if (events & HLSocketSelector::kWantWrite) {
		result |= FD_WRITE;
	}
	if (events & HLSocketSelector::kWantClose) {
		result |= FD_CLOSE;
	}
	return result;
}

// ------------------------------------------------------------------------------------------------
static uint32_t convertToSSEvents(long events) {
	long result = 0;
	if (events & FD_ACCEPT) {
		result |= HLSocketSelector::kWantAccept;
	}
	if (events & FD_READ) {
		result |= HLSocketSelector::kWantRead;
	}
	if (events & FD_WRITE) {
		result |= HLSocketSelector::kWantWrite;
	}
	if (events & FD_CLOSE) {
		result |= HLSocketSelector::kWantClose;
	}
	return result;
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::initialize(void* buffer, uint32_t bufferSize, uint32_t maxSocketCount,
		bool destroyOnFinalize) {
	if (impl->initialized) {
		finalize();
	}

	HL_ASSERT(buffer);
	HL_ASSERT(bufferSize >= HLSocketSelector::bufferSize(maxSocketCount));
	HL_ASSERT(maxSocketCount + 1 <= WSA_MAXIMUM_WAIT_EVENTS);

	uint32_t socketsSize = (maxSocketCount + 1) * sizeof(HLSocket);
	impl->socketEvents = (WSAEVENT*)((uint8_t*)buffer + socketsSize);
	impl->sockets = (HLSocket*)buffer;

	impl->socketEvents[0] = WSACreateEvent();
	impl->sockets[0] = 0;
	impl->socketCount = 1;
	impl->maxSocketCount = maxSocketCount;
	impl->destroyOnFinalize = destroyOnFinalize;
	impl->initialized = true;
	HL_ASSERT(impl->socketEvents[0] != WSA_INVALID_EVENT);
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::finalize() {
	if (!impl->initialized) {
		return;
	}

	uint32_t count = impl->socketCount - 1;
	while (count-- > 0) {
		removeAtIndex(1, impl->destroyOnFinalize);
	}

	BOOL success = WSACloseEvent(impl->socketEvents[0]);
	HL_ASSERT(success);

	impl->initialized = false;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::add(HLSocket s, uint32_t events) {
	HL_ASSERT(impl->initialized);
	HL_ASSERT(s);
	if (s == 0) {
		return false;
	}

	if (impl->socketCount >= (impl->maxSocketCount + 1)) {
		return false;
	}

	long wsaEvents = convertToWSAEvents(events);
	HL_ASSERT(wsaEvents != 0);
	if (wsaEvents == 0) {
		return false;
	}

	uint32_t index = impl->socketCount++;

	impl->socketEvents[index] = WSACreateEvent();
	impl->sockets[index] = s;
	HL_ASSERT(impl->socketEvents[index] != WSA_INVALID_EVENT);

	int result = WSAEventSelect(s->s, impl->socketEvents[index], wsaEvents);
	HL_ASSERT(result == 0);

	return true;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::setEvents(HLSocket s, uint32_t events) {
	HL_ASSERT(impl->initialized);
	HL_ASSERT(s);
	if (s == 0) {
		return false;
	}

	uint32_t index = impl->findSocket(s);
	return (index != 0) ? setEventsAtIndex(index, events) : false;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::setEventsAtIndex(uint32_t index, uint32_t events) {
	HL_ASSERT(impl->initialized);
	HL_ASSERT(index > 0);
	HL_ASSERT(index < impl->socketCount);
	if (index == 0 || index >= impl->socketCount) {
		return false;
	}

	long wsaEvents = convertToWSAEvents(events);
	HL_ASSERT(wsaEvents != 0);

	int result = WSAEventSelect(impl->sockets[index]->s, impl->socketEvents[index], wsaEvents);
	HL_ASSERT(result == 0);

	return true;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::remove(HLSocket s, bool destroySocket) {
	HL_ASSERT(impl->initialized);
	HL_ASSERT(s);
	if (s == 0) {
		return false;
	}

	uint32_t index = impl->findSocket(s);
	return (index != 0) ? removeAtIndex(index, destroySocket) : false;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::removeAtIndex(uint32_t index, bool destroySocket) {
	HL_ASSERT(impl->initialized);
	HL_ASSERT(index > 0);
	HL_ASSERT(index < impl->socketCount);
	if (index == 0 || index >= impl->socketCount) {
		return false;
	}

	int result = WSAEventSelect(impl->sockets[index]->s, nullptr, 0);
	HL_ASSERT(result == 0);

	BOOL success = WSACloseEvent(impl->socketEvents[index]);
	HL_ASSERT(success);

	if (destroySocket) {
		hlsocketDestroy(&impl->sockets[index]);
	}

	if (--impl->socketCount > index) {
		impl->sockets[index] = impl->sockets[impl->socketCount];
		impl->socketEvents[index] = impl->socketEvents[impl->socketCount];
	}

	return true;
}

// ------------------------------------------------------------------------------------------------
uint32_t HLSocketSelector::tryWait(uint32_t millis, uint32_t* events) {
	HL_ASSERT(impl->initialized);

	DWORD status = WSAWaitForMultipleEvents((DWORD)impl->socketCount, (const WSAEVENT*)impl->socketEvents,
		false, (DWORD)millis, false);
	HL_ASSERT(status < WSA_WAIT_EVENT_0 + impl->socketCount);

	if (status > WSA_WAIT_EVENT_0 && status < WSA_WAIT_EVENT_0 + impl->socketCount) {
		status -= WSA_WAIT_EVENT_0;

		WSANETWORKEVENTS wsaEvents;
		int result = WSAEnumNetworkEvents(impl->sockets[status]->s, impl->socketEvents[status], &wsaEvents);
		HL_ASSERT(result == 0);

		if (events) {
			*events = convertToSSEvents(wsaEvents.lNetworkEvents);
		}

		return status;
	}
	else {
		return 0;
	}
}

// ------------------------------------------------------------------------------------------------
uint32_t HLSocketSelector::wait(uint32_t* events) {
	HL_ASSERT(impl->initialized);
	return tryWait(INFINITE, events);
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::interrupt() {
	HL_ASSERT(impl->initialized);
	BOOL success = SetEvent(impl->socketEvents[0]);
	HL_ASSERT(success);
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::reset() {
	HL_ASSERT(impl->initialized);
	BOOL success = ResetEvent(impl->socketEvents[0]);
	HL_ASSERT(success);
}

#endif // HL_WINDOWS
