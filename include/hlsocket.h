/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

#ifndef HLAB_SOCKET_H
#define HLAB_SOCKET_H

#include "hlsocket_platform.h"

#define HLSOCKET_VERSION             "1.0 WIP"
#define HLSOCKET_VERSION_NUM         1

#define HLSOCKET_ENABLE_SSL          1
#define HLSOCKET_VERBOSE_LOGS        1
#define HLSOCKET_ENABLE_SSL_DBG_LOGS 1

#ifndef HL_API
#define HL_API
#endif

#ifndef HL_ASSERT
#include <assert.h>
#define HL_ASSERT(x) assert(x)
#endif

#define HL_UNUSED(x) x = x

#ifndef HL_MALLOC
#define HL_MALLOC(sz)       malloc(sz)
#define HL_REALLOC(p,newsz) realloc(p,newsz)
#define HL_FREE(p)          free(p)
#endif

#ifndef HL_LOG
#define HL_LOG printf
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ssl_st SSL;
typedef struct bio_st BIO;
typedef struct HLSocketData* HLSocket;

/// HLSocket error codes
typedef enum {
	kSocketSuccess        = 0,       ///< No error.
	kSocketOpenFailed     = -0x0042, ///< Failed to open a socket.
	kSocketBufferTooSmall = -0x0043, ///< Buffer is too small to hold the data.
	kSocketConnectFailed  = -0x0044, ///< The connection to the given server / port failed.
	kSocketInvalidContext = -0x0045, ///< The context is invalid, eg because it was free()ed.
	kSocketBindFailed     = -0x0046, ///< Binding of the socket failed.
	kSocketListenFailed   = -0x0048, ///< Could not listen on the socket.
	kSocketAcceptFailed   = -0x004A, ///< Could not accept the incoming connection.
	kSocketRecvFailed     = -0x004C, ///< Reading information from the socket failed.
	kSocketSendFailed     = -0x004E, ///< Sending information through the socket failed.
	kSocketConnReset      = -0x0050, ///< Connection was reset by peer.
	kSocketUnknownHost    = -0x0052, ///< Failed to get an IP address for the given hostname.
	kSocketTimeout        = -0x6800, ///< The operation timed out.
	kSocketSendWouldBlock = -0x6880, ///< A non-blocking write operation would normally block (send buffer full).
	kSocketRecvWouldBlock = -0x6900  ///< A non-blocking read operation would normally block (no data available).
} HLSocketError;

/// Transport
typedef enum { kTCP = 0, kUDP = 1 } HLSocketProto;

/// SHA1 digest
typedef struct SHA1Digest_ {
	uint32_t buffer[20 >> 2];
} SHA1Digest;

/// SSL read and write buffer sizes
static const int32_t kSocketSSLBufSize = 16 * 1024;

/// The backlog that listen() should use
static const int32_t kSocketListenBacklog = 10;

// ================================================================================================
/// Initialize the SSL layer.
/// \param[in] cert    Path to the PEM file containing the certificate or certificate chain.
/// \param[in] privkey Path to the PEM file containing the private key.
/// \param[in] chain   Pass true if cert is a certificate chain.
/// \return            true if successful
// ================================================================================================
HL_API bool hlsocketInitializeSSL(const char* cert, const char* privkey, bool chain);

// ================================================================================================
/// Initialize a socket.
/// \param[in] ssl    Enable SSL for the socket.
/// \param[in] listen Pass true if socket will be used in a listen mode, false if client/connect mode.
/// \return A new socket.
// ================================================================================================
HL_API HLSocket hlsocketCreate(bool ssl, bool listen);

// ================================================================================================
/// Gracefully shutdown the connection and free associated data.
/// \param[in,out] s HLSocket to destroy
// ================================================================================================
HL_API void hlsocketDestroy(HLSocket* s);

// ================================================================================================
/// Determine if SSL is enabled for the socket.
/// \return true if SSL is enabled
// ================================================================================================
HL_API bool hlsocketIsSSL(HLSocket s);

// ================================================================================================
/// Initiate a connection with host:port in the given protocol.
/// \param[in,out] s             HLSocket to use
/// \param[in]     host          Host to connect to
/// \param[in]     port          Port number or service name to connect to
/// \param[in]     proto         Protocol: kTCP or kUDP
/// \param[in]     timeoutMillis Connection timeout, in seconds
/// \return 0 if successful, or one of:
///     kSocketOpenFailed,
///     kSocketUnknownHost,
///     kSocketConnectFailed
/// \note Sets the socket in connected mode even with UDP.
// ================================================================================================
HL_API int32_t hlsocketConnect(HLSocket* s, const char* host, const char* port,
	HLSocketProto proto, float timeoutMillis);

// ================================================================================================
/// Create a receiving socket on bindIP:port in the chosen protocol. If bindIP == NULL, all
/// interfaces are bound.
/// \param[in,out] s      HLSocket to use
/// \param[in]     bindIP IP to bind to, can be NULL
/// \param[in]     port   Port number or service name to use
/// \param[in]     proto  Protocol: kTCP or kUDP
/// \return 0 if successful, or one of:
///     kSocketOpenFailed,
///     kSocketBindFailed,
///     kSocketListenFailed
/// \note Regardless of the protocol, opens the sockets and binds it.
///       In addition, make the socket listening if protocol is TCP.
// ================================================================================================
HL_API int32_t hlsocketBind(HLSocket* s, const char* bindIP, const char* port,
	HLSocketProto proto);

// ================================================================================================
/// Accept a connection from a remote client.
/// \param[in,out] bindCtx   Relevant socket
/// \param[out]    clientCtx Will contain the new connected client socket
/// \param[out]    clientIP  Will contain the new client's IP address
/// \param[in]     bufSize   Size of the clientIP buffer
/// \param[in]     IPLen     Will receive the size of the client IP written
/// \return 0 if successful, or
///     kSocketAcceptFailed, or
///     kSocketBufferTooSmall if bufSize is too small,
///     kSocketRecvWouldBlock if bind_fd was set to non-blocking and accept() would block.
// ================================================================================================
HL_API int32_t hlsocketAccept(HLSocket* bindCtx, HLSocket* clientCtx, void* clientIP, size_t bufSize, size_t* IPLen);

// ================================================================================================
/// Set the socket blocking.
/// \param[in] s HLSocket to set
/// \return 0 if successful, or a non-zero error code
// ================================================================================================
HL_API int32_t hlsocketSetBlock(HLSocket s);

// ================================================================================================
/// Set the socket non-blocking.
/// \param[in] s HLSocket to set
/// \return 0 if successful, or a non-zero error code
// ================================================================================================
HL_API int32_t hlsocketSetNonBlock(HLSocket s);

// ================================================================================================
/// Set the socket send and receive buffer sizes.
/// \param[in] s            HLSocket to set
/// \param[inout] sendBufSz Size in bytes of the send buffer; returns the accepted size
/// \param[inout] recvBufSz Size in bytes of the receive buffer; returns the accepted size
// ================================================================================================
HL_API void hlsocketSetBufferSize(HLSocket s, int32_t* sendBufSz, int32_t* recvBufSz);

// ================================================================================================
/// Get the socket send and receive buffer sizes.
/// \param[in] s          HLSocket to get
/// \param[out] sendBufSz Returns the size in bytes of the send buffer
/// \param[out] recvBufSz Returns the size in bytes of the send buffer
// ================================================================================================
HL_API void hlsocketGetBufferSize(HLSocket s, int32_t* sendBufSz, int32_t* recvBufSz);

// ================================================================================================
/// Read at most 'len' characters. If no error occurs, the actual amount read is returned.
/// \param[in] s   HLSocket
/// \param[in] buf The buffer to write to
/// \param[in] len Maximum length of the buffer
/// \return the number of bytes received, or a non-zero error code; with a non-blocking socket,
///     kSocketRecvWouldBlock indicates read() would block.
// ================================================================================================
HL_API int32_t hlsocketRecv(HLSocket s, void* buf, size_t len);

// ================================================================================================
/// Write at most 'len' characters. If no error occurs, the actual amount read is returned.
/// \param[in] s   HLSocket
/// \param[in] buf The buffer to read from
/// \param[in] len The length of the buffer
/// \return the number of bytes sent, or a non-zero error code; with a non-blocking socket,
///     kSocketSendWouldBlock indicates write() would block.
// ================================================================================================
HL_API int32_t hlsocketSend(HLSocket s, const void* buf, size_t len);

// ================================================================================================
/// Read at most 'len' characters, blocking for at most 'timeout' seconds. If no error occurs, the
/// actual amount read is returned.
/// \param[in] s             HLSocket
/// \param[in] buf           The buffer to write to
/// \param[in] len           Maximum length of the buffer
/// \param[in] timeoutMillis Maximum number of milliseconds to wait for data.
///     0 means no timeout (wait forever).
/// \return the number of bytes received, or a non-zero error code:
///     kSocketTimeout if the operation timed out,
///     kSocketRecvWouldBlock if interrupted by a signal.
/// \note This function will block (until data becomes available or timeout is reached) even if
///     the socket is set to non-blocking. Handling timeouts with non-blocking reads requires
///     a different strategy.
// ================================================================================================
HL_API int32_t hlsocketRecvTimeout(HLSocket s, void* buf, size_t len, uint32_t timeoutMillis);

// ================================================================================================
/// Read 'len' characters, blocking for at most 'timeout' seconds per read operation.
/// \param[in] s             HLSocket
/// \param[in] buf           The buffer to write to
/// \param[in] len           Number of bytes to receive.
/// \param[in] timeoutMillis Maximum number of milliseconds to wait for data.
///     0 means no timeout (wait forever).
/// \return the number of bytes received, or a non-zero error code:
///     kSocketTimeout if the operation timed out,
///     kSocketRecvWouldBlock if interrupted by a signal.
/// \note This function will block (until data becomes available or timeout is reached) even if
///     the socket is set to non-blocking. Handling timeouts with non-blocking reads requires
///     a different strategy.
// ================================================================================================
HL_API int32_t hlsocketRecvAllTimeout(HLSocket s, void* buf, size_t len, uint32_t timeoutMillis);

// ================================================================================================
/// Obtain a null-terminated string representation of the peer's IP address.
/// \param[in] s HLSocket
/// \return If successful, a string containing the peer's IP, or the empty string upon an error.
// ================================================================================================
HL_API const char* hlsocketGetPeerName(HLSocket s);

// ================================================================================================
/// Obtain the SO_ERROR option for the socket.
/// \param[in] s HLSocket
/// \return A socket error code.
// ================================================================================================
HL_API int32_t hlsocketGetError(HLSocket s);

// ================================================================================================
/// Get the number of bytes available to be read on the socket.
/// \param[in] s HLSocket
/// \return Bytes of pending data.
// ================================================================================================
HL_API size_t hlsocketGetRecvPending(HLSocket s);

// ================================================================================================
/// Get the native socket handle.
/// \param[in] s HLSocket
/// \return Native socket handle (SOCKET on Windows, int everywhere else)
// ================================================================================================
HL_API const int32_t hlsocketGetNativeHandle(HLSocket s);

// ================================================================================================
/// Compute the SHA1 digest of a buffer.
/// \param[in] src     Pointer to memory to be hashed.
/// \param[in] srcSize Size in bytes of the buffer at src.
/// \param[in] digest  Stores the SHA1 digest upon return.
// ================================================================================================
HL_API void hlsocketCalcSHA1(const void* src, size_t srcSize, SHA1Digest* digest);

// ================================================================================================
/// Encode data using Base64 (RFC3548).
/// \param[in] src     Pointer to memory to be encoded.
/// \param[in] srcSize Size in bytes of the buffer at src.
/// \param[in] dst     Pointer to memory to hold the encoded data as a null-terminated string.
/// \param[in] dstSize Size in bytes of the buffer at dst.
/// \return            0 if successful, otherwise the size in bytes of the buffer at dst needed to
///                    store the encoded result
/// \note If nullptr is passed for dst, or if dstSize is too small, then the required size of the
///       buffer at dst will be returned.
// ================================================================================================
HL_API size_t hlsocketBase64(const uint8_t* src, size_t srcSize, char* dst, size_t dstSize);

#ifdef __cplusplus
}
#endif

#endif // HLAB_SOCKET_H
