/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#include "hlsocket_selector.h"

#include "common.hpp"

#if HL_DARWIN

#include "hlsocket_selector.inl"

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
	HL_ASSERT(0 == (socketsSize % sizeof(int32_t)));
	impl->socketEvents    = (uint32_t*)buffer + (socketsSize >> 2);
	impl->sockets         = (HLSocket*)buffer;

	impl->kq = kqueue();
	HL_ASSERT(impl->kq != -1);

	int pipefd[2];
	int result = pipe(pipefd);
	HL_ASSERT(result != -1);

	result = fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
	HL_ASSERT(result != -1);

	impl->sockets[0] = hlsocketCreate(true, false);
	HL_ASSERT(impl->sockets[0]);

	impl->sockets[0]->s = pipefd[0];
	impl->writefd       = pipefd[1];

	struct kevent changes;
	EV_SET(&changes, impl->sockets[0]->s, EVFILT_READ, EV_ADD, 0, 0, nullptr);
	result = kevent(impl->kq, &changes, 1, 0, 0, 0);
	HL_ASSERT(result != -1);

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

	int result = close(impl->kq);
	HL_ASSERT(result == 0);

	result = close(impl->sockets[0]->s);
	HL_ASSERT(result == 0);
	impl->sockets[0]->s = 0;
	hlsocketDestroy(&impl->sockets[0]);

	result = close(impl->writefd);
	HL_ASSERT(result == 0);

	impl->initialized = false;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::add(HLSocket s, uint32_t events) {
	HL_ASSERT(impl->initialized);
	if (!s || (0 == (events & (kWantAccept | kWantRead | kWantWrite | kWantClose)))) {
		HL_ASSERT(false);
		return false;
	}

	if (impl->socketCount >= (impl->maxSocketCount + 1)) {
		return false;
	}

	uint32_t index = impl->socketCount++;

	impl->sockets[index]      = s;
	impl->socketEvents[index] = events;

	struct kevent changes;

	if (events & (HLSocketSelector::kWantAccept | HLSocketSelector::kWantRead)) {
		EV_SET(&changes, s->s, EVFILT_READ, EV_ADD, 0, 0, (void*)(uintptr)index);
		int result = kevent(impl->kq, &changes, 1, 0, 0, 0);
		HL_ASSERT(result != -1);
	}

	if (events & HLSocketSelector::kWantWrite) {
		EV_SET(&changes, s->s, EVFILT_WRITE, EV_ADD, 0, 0, (void*)(uintptr)index);
		int result = kevent(impl->kq, &changes, 1, 0, 0, 0);
		HL_ASSERT(result != -1);
	}

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

	uint32_t oldEvents = impl->socketEvents[index];
	if (oldEvents == events) {
		return true;
	}
	impl->socketEvents[index] = events;

	HLSocket s = impl->sockets[index];
	bool oldRd = oldEvents & (HLSocketSelector::kWantAccept | HLSocketSelector::kWantRead);
	bool newRd =    events & (HLSocketSelector::kWantAccept | HLSocketSelector::kWantRead);
	bool oldWr = oldEvents & (HLSocketSelector::kWantWrite);
	bool newWr =    events & (HLSocketSelector::kWantWrite);

	if (oldRd != newRd) {
		struct kevent changes;
		EV_SET(&changes, s->s, EVFILT_READ, newRd ? EV_ADD : EV_DELETE, 0, 0, (void*)(uintptr)index);
		int result = kevent(impl->kq, &changes, 1, 0, 0, 0);
		HL_ASSERT(result != -1);
	}
	if (oldWr != newWr) {
		struct kevent changes;
		EV_SET(&changes, s->s, EVFILT_WRITE, newWr ? EV_ADD : EV_DELETE, 0, 0, (void*)(uintptr)index);
		int result = kevent(impl->kq, &changes, 1, 0, 0, 0);
		HL_ASSERT(result != -1);
	}

	return true;
}

// ------------------------------------------------------------------------------------------------
bool HLSocketSelector::remove(HLSocket s, bool destroySocket) {
	HL_ASSERT(impl->initialized);
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

	if (!HLSocketSelector::setEventsAtIndex(index, 0)) {
		return false;
	}
	if (destroySocket) {
		hlsocketDestroy(&impl->sockets[index]);
	}
	impl->sockets[index] = nullptr;

	if ((impl->socketCount > 0) && (impl->socketCount - 1) >= index) {
		uint32_t last = impl->socketCount - 1;
		impl->sockets[index]      = impl->sockets[last];
		impl->socketEvents[index] = 0;

		uint32_t events = impl->socketEvents[last];
		(void)HLSocketSelector::setEventsAtIndex(last, 0);
		(void)HLSocketSelector::setEventsAtIndex(index, events);

		--impl->socketCount;
	}

	return true;
}

// ------------------------------------------------------------------------------------------------
uint32_t HLSocketSelector::tryWait(uint32_t millis, uint32_t* events) {
	HL_ASSERT(impl->initialized);

	timespec  tspec;
	timespec* timeout = nullptr;
	if (millis != (uint32_t)-1) {
		tspec.tv_sec  = (time_t)(millis / 1000);
		tspec.tv_nsec = (long)(millis % 1000) * 1000000L;
		while (tspec.tv_nsec >= 1000000000L) {
			++tspec.tv_sec;
			tspec.tv_nsec -= 1000000000L;
		}
		timeout = &tspec;
	}

	struct kevent event;
	int           result = kevent(impl->kq, nullptr, 0, &event, 1, timeout);
	if (result < 0 && timeout) {
		struct timespec ts;
		ts.tv_sec  = millis / 1000;
		ts.tv_nsec = (long)(millis % 1000) * 1000000L;
		nanosleep(&ts, 0);
		return 0;
	}
	else if (result <= 0) {
		return 0;
	}

	int32_t i = (int32_t)(uintptr)event.udata;
	HL_ASSERT(i >= 0 && i < (int32_t)impl->socketCount);

	if (events) {
		if (event.filter == EVFILT_READ) {
			*events |= HLSocketSelector::kWantAccept | HLSocketSelector::kWantRead;
		}
		else if (event.filter == EVFILT_WRITE) {
			*events |= HLSocketSelector::kWantWrite;
		}
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

	char data = 0;
	ssize_t result = (ssize_t)write(impl->writefd, &data, 1);
	HL_ASSERT(result != -1);
}

// ------------------------------------------------------------------------------------------------
void HLSocketSelector::reset() {
	HL_ASSERT(impl->initialized);

	ssize_t result;
	char data[16];
	errno = 0;
	while ((result = (ssize_t)read(impl->sockets[0]->s, data, sizeof(data))) > 0) {}
	HL_ASSERT(errno == EAGAIN || result != -1);
}

#endif // HL_DARWIN
