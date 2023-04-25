/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#include "hlsocket_selector.h"

#include "common.hpp"

#if HL_EMSCRIPTEN

#include "hlsocket_selector.inl"

// ------------------------------------------------------------------------------------------------
static int32_t convertToEPollEvents(uint32_t events) {
	int32_t result = 0;
	if (events & HLSocketSelector::kWantAccept || events & HLSocketSelector::kWantRead) {
		result |= EPOLLIN;
	}
	if (events & HLSocketSelector::kWantWrite) {
		result |= EPOLLOUT;
	}
	if (events & HLSocketSelector::kWantClose) {
		result |= EPOLLRDHUP;
	}
	return result;
}

// ------------------------------------------------------------------------------------------------
static uint32_t convertToSSEvents(uint32_t events) {
	uint32_t result = 0;
	if (events & EPOLLIN) {
		result |= HLSocketSelector::kWantAccept | HLSocketSelector::kWantRead;
	}
	if (events & EPOLLOUT) {
		result |= HLSocketSelector::kWantWrite;
	}
	if (events & EPOLLRDHUP) {
		result |= HLSocketSelector::kWantClose;
	}
	return result;
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::initialize(void* buffer, uint32_t bufferSize, uint32_t maxSocketCount,
		bool destroyOnFinalize) {
	if (impl->initialized) {
		finalize();
		HL_ASSERT(!impl->initialized);
	}

	HL_ASSERT(buffer);
	HL_ASSERT(bufferSize >= HLSocketSelector::bufferSize(maxSocketCount));

	HL_UNUSED(bufferSize);

	uint32_t socketsSize    = (maxSocketCount + 1) * sizeof(HLSocket);
	impl->socketEvents       = (int32_t*)buffer + (socketsSize / sizeof(int32_t));
	impl->sockets            = (HLSocket*)buffer;

	impl->socketCount       = 1;
	impl->maxSocketCount    = maxSocketCount;
	impl->destroyOnFinalize = destroyOnFinalize;
	impl->initialized       = true;
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::finalize() {
	if (!impl->initialized) {
		return;
	}

	uint32_t count = impl->socketCount - 1;
	while (count-- > 0) {
		remove(impl->sockets[1], impl->destroyOnFinalize);
	}

//	result = close(impl->sockets[0]);
//	HL_ASSERT(result == 0);

	impl->initialized = false;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::add(HLSocket s, uint32_t events) {
	HL_UNUSED(events);

	HL_ASSERT(impl->initialized);
	HL_ASSERT(s);
	if (s == 0) {
		return false;
	}

	if (impl->socketCount >= (impl->maxSocketCount + 1)) {
		return false;
	}

	uint32_t index = impl->socketCount++;
	impl->sockets[index] = s;

	return true;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::setEvents(HLSocket s, uint32_t events) {
	HL_UNUSED(events);

	HL_ASSERT(impl->initialized);
	HL_ASSERT(s);
	if (s == 0) {
		return false;
	}

	return true;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::setEventsAtIndex(uint32_t index, uint32_t events) {
	HL_UNUSED(events);

	HL_ASSERT(impl->initialized);
	HL_ASSERT(index > 0);
	HL_ASSERT(index < impl->socketCount);
	if (index == 0 || index >= impl->socketCount) {
		return false;
	}

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
	HL_ASSERT(index > 0);
	HL_ASSERT(index < impl->socketCount);

	if (destroySocket) {
		hlsocketDestroy(&impl->sockets[index]);
	}

	if (--impl->socketCount > index) {
		impl->sockets[index]      = impl->sockets[impl->socketCount];
	}

	return true;
}

// ------------------------------------------------------------------------------------------------
uint32_t HLSocketSelector::tryWait(uint32_t millis, uint32_t* events) {
	HL_UNUSED_2(millis, events);

	HL_ASSERT(impl->initialized);

	// TODO: select()!
	return (uint32_t)1;
}

// ------------------------------------------------------------------------------------------------
uint32_t HLSocketSelector::wait(uint32_t* events) {
	HL_ASSERT(impl->initialized);
	return tryWait((uint32_t)-1, events);
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::interrupt() {
	HL_ASSERT(impl->initialized);
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::reset() {
	HL_ASSERT(impl->initialized);
}

#endif // HL_EMSCRIPTEN
