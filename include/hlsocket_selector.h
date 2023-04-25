/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#pragma once

#include "hlsocket.h"

struct HLSocketSelectorPimpl;

// ================================================================================================
/// A socket I/O event notification object.
///
/// As sockets are added to the selector, they are assigned indices that start with 1. If a call to
/// tryWait or wait returns an index value of 1 or greater, the 'events' parameter will be set to a
/// value that indicates one or more of the following occurred:
///   - a connection is ready to be accepted by the listening socket at that index
///   - data is available to be read from the socket at that index
///   - data is able to be written to the socket at that index
///
/// All conditions are "level-triggered", meaning if tryWait or wait is called again before having
/// accepted the connection or consumed all data on the socket, the calls will return immediately.
///
/// A return of 0 from wait or tryWait means interrupt has been called. All future calls to tryWait
/// and wait will return immediately until reset is called.
///
/// Note that a HLSocketSelector isn't thread-safe: the caller must synchronize its usage from
/// multiple threads.
// ================================================================================================
struct HL_API HLSocketSelector {
	HLSocketSelector();
	~HLSocketSelector();
	HLSocketSelector(const HLSocketSelector&) = delete;
	void operator=(const HLSocketSelector&) = delete;

	static const uint32_t kWantAccept = 0x01; ///< socketAccept will succeed without blocking.
	static const uint32_t kWantRead   = 0x02; ///< socketRead will succeed without blocking.
	static const uint32_t kWantWrite  = 0x04; ///< socketWrite will succeed without blocking.
	static const uint32_t kWantClose  = 0x08; ///< Other party wants to shut down the connection.

	/// Calculate the size of the buffer required to store a maximum number of sockets.
	/// \param[in] maxSocketCount Maximum sockets that may be stored in the selector.
	/// \return                   Size in bytes of the buffer required to store the given sockets.
	static constexpr uint32_t bufferSize(uint32_t maxSocketCount) {
		// uint32_t socketsSize  = (maxSocketCount + 1) * sizeof(HLSocket)
#if HL_WINDOWS
		// uint32_t socketEventsSize  = (maxSocketCount + 1) * sizeof(DWORD)
		return (maxSocketCount + 1) * sizeof(HLSocket) + (maxSocketCount + 1) * sizeof(unsigned long);
#else
		// uint32_t socketEventsSize  = (maxSocketCount + 1) * sizeof(int32_t)
		return (maxSocketCount + 1) * sizeof(HLSocket) + (maxSocketCount + 1) * sizeof(int32_t);
#endif // HP_WINDOWS
	}

	/// Constructs the selector.
	/// \param[in] buffer            Pointer to a memory buffer in which to store the selector.
	/// \param[in] bufferSize        Size in bytes of the buffer pointed to by buffer.
	/// \param[in] maxSocketCount    Maximum sockets that may be stored in the selector.
	/// \param[in] destroyOnFinalize If true, finalize() will call hlsocketDestroy for all sockets.
	void initialize(void* buffer, uint32_t bufferSize, uint32_t maxSocketCount, bool destroyOnFinalize);

	/// Destructs the selector.
	void finalize();

	/// Adds a socket to the selector.
	/// \param[in] s      A socket.
	/// \param[in] events A bitfield of events the caller is interested in.
	/// \return           True if the socket was added, false if the selector is full.
	bool add(HLSocket s, uint32_t events = kWantAccept | kWantRead);

	/// Sets which socket events should unblock a call to tryWait and wait.
	/// \param[in] s      A socket.
	/// \param[in] events A bitfield of events the caller is interested in.
	/// \return           True if successful, false if the socket wasn't found in the selector.
	bool setEvents(HLSocket s, uint32_t events);

	/// Sets which socket events should unblock a call to tryWait and wait.
	/// Note that the socket corresponding to an index may change upon any call to remove.
	/// \param[in] index  The non-zero index of a socket.
	/// \param[in] events A bitfield of events the caller is interested in.
	/// \return           True if successful, false if the index is out of bounds.
	bool setEventsAtIndex(uint32_t index, uint32_t events);

	/// Removes a socket from the selector.
	/// \param[in] s             A socket.
	/// \param[in] destroySocket If true, hlsocketDestroy will be called for the removed socket.
	/// \return                  True if the socket was removed from the selector, false if the
	///                          socket could not be found.
	bool remove(HLSocket s, bool destroySocket);

	/// Removes a socket from the selector.
	/// Note that the socket corresponding to an index may change upon any call to remove.
	/// \param[in] index         The non-zero index of a socket.
	/// \param[in] destroySocket If true, hlsocketDestroy will be called for the removed socket.
	/// \return                  True if the socket was removed from the selector.
	bool removeAtIndex(uint32_t index, bool destroySocket);

	/// Gets a socket stored in the selector.
	/// Note that the socket corresponding to an index may change upon any call to remove.
	/// \param[in] index The non-zero index of the socket to get from the selector.
	/// \return          A socket.
	HLSocket get(uint32_t index);

	/// Waits on the selector for the given amount of time, or until one of its sockets is signaled.
	/// Note that the socket corresponding to an index may change upon any call to remove.
	/// \param[in]  millis Number of milliseconds to wait before timing out.
	/// \param[out] events If non-null, will be set to a bitfield of which events occurred.
	/// \return            The index of the signaled socket, or 0 upon a timeout or interruption.
	uint32_t tryWait(uint32_t millis, uint32_t* events);

	/// Waits on the selector until one of its sockets is signaled.
	/// Note that the socket corresponding to an index may change upon any call to remove.
	/// \param[out] events If non-null, will be set to a bitfield of which events occurred.
	/// \return            The index of the signaled socket, or 0 upon a timeout or interruption.
	uint32_t wait(uint32_t* events);

	/// Interrupts any ongoing and future calls to tryWait and wait.
	void interrupt();

	/// Resets the selector after a call to interrupt.
	void reset();

protected:
	HLSocketSelectorPimpl* impl = nullptr;
};

// ================================================================================================
/// A HLSocketSelector with an inline buffer.
// ================================================================================================
template <uint32_t kMaxSocketCount>
struct HLSocketSelectorInl : public HLSocketSelector {
	/// Constructs the HLSocketSelectorInl.
	/// \param[in] destroyOnFinalize If true, finalize() will call hlsocketDestroy for all sockets.
	void initialize(bool destroyOnFinalize) {
		((HLSocketSelector*)this)->initialize((void*)buffer, sizeof(buffer), kMaxSocketCount, destroyOnFinalize);
	}

protected:
	uint8_t buffer[HLSocketSelector::bufferSize(kMaxSocketCount)];
};
