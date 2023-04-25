/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#include "hlsocket_selector.h"

#include "common.hpp"

#if HL_POSIX && !HL_EMSCRIPTEN

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

	uint32_t socketsSize = (maxSocketCount + 1) * sizeof(HLSocket);
	impl->socketEvents    = (int32_t*)buffer + (socketsSize / sizeof(int32_t));
	impl->sockets         = (HLSocket*)buffer;

	impl->poll = epoll_create1(EPOLL_CLOEXEC);
	HL_ASSERT(impl->poll != -1);

	impl->sockets[0] = hlsocketCreate(true, false);
	HL_ASSERT(impl->sockets[0]);

	impl->sockets[0]->s = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	HL_ASSERT(impl->sockets[0]->s != -1);

	epoll_event event;
	event.events  = EPOLLIN;
	event.data.fd = 0;
	int result    = epoll_ctl(impl->poll, EPOLL_CTL_ADD, impl->sockets[0]->s, &event);
	HL_ASSERT(result == 0);

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

	epoll_event event;

	int result = epoll_ctl(impl->poll, EPOLL_CTL_DEL, impl->sockets[0]->s, &event);
	HL_ASSERT(result == 0);

	result = close(impl->sockets[0]->s);
	HL_ASSERT(result == 0);
	impl->sockets[0]->s = 0;
	hlsocketDestroy(&impl->sockets[0]);

	result = close(impl->poll);
	HL_ASSERT(result == 0);

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

	int32_t epollEvents = convertToEPollEvents(events);
	HL_ASSERT(epollEvents != 0);
	if (epollEvents == 0) {
		return false;
	}

	uint32_t index = impl->socketCount++;

	impl->sockets[index]      = s;
	impl->socketEvents[index] = epollEvents;

	epoll_event event;
	event.events  = (uint32_t)epollEvents;
	event.data.fd = (int)index;
	int result    = epoll_ctl(impl->poll, EPOLL_CTL_ADD, s->s, &event);
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

	int32_t epollEvents = convertToEPollEvents(events);
	HL_ASSERT(epollEvents != 0);
	if (epollEvents == 0) {
		return false;
	}

	impl->socketEvents[index] = epollEvents;

	epoll_event event;
	event.events  = (uint32_t)epollEvents;
	event.data.fd = (int)index;
	int result    = epoll_ctl(impl->poll, EPOLL_CTL_MOD, impl->sockets[index]->s, &event);
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
	HL_ASSERT(index > 0);
	HL_ASSERT(index < impl->socketCount);

	epoll_event event  = {0};
	int         result = epoll_ctl(impl->poll, EPOLL_CTL_DEL, impl->sockets[index]->s, &event);
	HL_ASSERT(result == 0);

	if (destroySocket) {
		hlsocketDestroy(&impl->sockets[index]);
	}

	if (--impl->socketCount > index) {
		impl->sockets[index]      = impl->sockets[impl->socketCount];
		impl->socketEvents[index] = impl->socketEvents[impl->socketCount];
		event.events             = (uint32_t)impl->socketEvents[index];
		event.data.fd            = (int)index;
		result                   = epoll_ctl(impl->poll, EPOLL_CTL_MOD, impl->sockets[index]->s, &event);
		HL_ASSERT(result == 0);
	}

	return true;
}

// ------------------------------------------------------------------------------------------------
uint32_t HLSocketSelector::tryWait(uint32_t millis, uint32_t* events) {
	HL_ASSERT(impl->initialized);

	epoll_event event;
	int         result = epoll_wait(impl->poll, &event, 1, (int)millis);
	if (result <= 0) {
		return 0;
	}

	int32_t i = event.data.fd;
	HL_ASSERT(i >= 0 && i < (int32_t)impl->socketCount);

	if (events) {
		*events = convertToSSEvents(event.events);
	}

	return (uint32_t)i;
}

// ------------------------------------------------------------------------------------------------
uint32_t HLSocketSelector::wait(uint32_t* events) {
	HL_ASSERT(impl->initialized);
	return tryWait((uint32_t)-1, events);
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::interrupt() {
	HL_ASSERT(impl->initialized);

	eventfd_t value  = 1;
	int       result = eventfd_write(impl->sockets[0]->s, value);
	HL_ASSERT(result == 0);
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::reset() {
	HL_ASSERT(impl->initialized);

	eventfd_t value  = 0;
	int       result = eventfd_read(impl->sockets[0]->s, &value);
}

#endif // HL_POSIX && !HL_EMSCRIPTEN
