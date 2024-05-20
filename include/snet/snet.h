/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package github.com/lschulz/snet/go */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h>

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */


#line 17 "snet_wrapper.go"

 #include "snet/snet_cdefs.h"
 #include <stdlib.h>
 #include <string.h>

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef size_t GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
#ifdef _MSC_VER
#include <complex.h>
typedef _Fcomplex GoComplex64;
typedef _Dcomplex GoComplex128;
#else
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;
#endif

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif

extern ScStatus ScParseLocalUDPAddr(cchar* str, struct ScLocalUDPAddr* addr);
extern ScStatus ScParseLocalUDPAddrN(cchar* str, int length, struct ScLocalUDPAddr* addr);
extern ScStatus ScFormatLocalUDPAddr(ConstPtrScLocalUDPAddr addr, char* str, ScSize* cap);
extern ScStatus ScParseUDPAddr(cchar* str, struct ScUDPAddr* udp);
extern ScStatus ScParseUDPAddrN(cchar* str, int length, struct ScUDPAddr* udp);
extern ScStatus ScFormatUDPAddr(ConstPtrScUDPAddr udp, char* str, ScSize* length);

/**
\brief Cancel an asynchronous operation.
*/
extern void ScCancelAsyncOp(struct ScAsyncOp* op);

/**
\brief Initialize the host context.
*/
extern ScStatus ScHostInit(ScHostCtx* hostCtx, ConstPtrScConfig config, ScSCMPHandler scmpCallback, uintptr_t scmpUserData, GoInt32 timeout);

/**
\brief Initialize the host context.
*/
extern void ScHostInitAsync(ScHostCtx* hostCtx, ConstPtrScConfig config, ScSCMPHandler scmpCallback, uintptr_t scmpUserData, struct ScAsyncOp* op);

/**
\brief Destroy the host context. Make sure there are no sockets using ths context anymore before
destroying it.
*/
extern void ScHostDestroy(ScHostCtx hostCtx);

/**
\brief Allocate memory through the callback passed during host context initialization.
*/
extern void* ScHostAllocMem(ScHostCtx hostCtx, GoInt size);

/**
\brief Deallocate memory allocated with ScHostAllocMem().
*/
extern void ScHostFreeMem(ScHostCtx hostCtx, void* ptr);

/**
\brief Return the local AS address.
*/
extern ScIA ScHostLocalIA(ScHostCtx hostCtx);

/**
\brief Query paths from the SCION daemon.
*/
extern ScStatus ScQueryPaths(ScHostCtx hostCtx, ScIA dst, struct ScPath*** paths, uint32_t* count, GoUint64 flags, GoInt32 timeout);

/**
\brief Query paths from the SCION daemon.
*/
extern void ScQueryPathsAsync(ScHostCtx hostCtx, ScIA dst, struct ScPath*** paths, uint32_t* count, GoUint64 flags, struct ScAsyncOp* op);

/**
\brief Open a socket.
*/
extern ScStatus ScOpenSocket(ScHostCtx hostCtx, ConstPtrScLocalUDPAddr local, ScSocket* sock, GoInt32 timeout);

/**
\brief Open a socket.
*/
extern void ScOpenSocketAsync(ScHostCtx hostCtx, ConstPtrScLocalUDPAddr local, ScSocket* sock, struct ScAsyncOp* op);

/**
\brief Close a socket.
*/
extern void ScCloseSocket(ScSocket conn);

/**
\brief Set a deadline for all current and future sent operations. Setting this to a value in
the past cancels all send operations immediately. Setting the deadline to a negative value
disables a previously set send deadline.
\param[in] conn An open socket
\param[in] deadline Deadline as Unix timestamp in milliseconds. A negative value
           disables a previously set deadline.
*/
extern ScStatus ScSocketSetSendDeadline(ScSocket sock, GoInt64 deadline);

/**
\brief Set a deadline for all current and future receive operations. Setting this to a value
in the past cancels all receive operations immediately. Setting the deadline to a negative
value disables a previously set receive deadline.
\param[in] conn An open socket
\param[in] deadline Deadline as Unix timestamp in milliseconds. A negative value
           disables a previously set deadline.
*/
extern ScStatus ScSocketSetRecvDeadline(ScSocket sock, GoInt64 deadline);

/**
\brief Send a UDP packet.
*/
extern ScStatus ScSendPacket(ScSocket sock, struct ScUDPPacket* pkt);

/**
\brief Send a UDP packet.
\details Calling cancel() on the async object has no effect. The only way to cancel a pending
operation is by closing the socket or setting a send deadline.
*/
extern void ScSendPacketAsync(ScSocket conn, struct ScUDPPacket* pkt, struct ScAsyncOp* op);

/**
\brief Receive a UDP packet.
*/
extern ScStatus ScRecvPacket(ScSocket sock, struct ScUDPPacket* pkt);

/**
\brief Receive a UDP packet.
\details Calling cancel() on the async object has no effect. The only way to cancel a pending
operation is by closing the socket or setting a receive deadline.
*/
extern void ScRecvPacketAsync(ScSocket sock, struct ScUDPPacket* pkt, struct ScAsyncOp* op);

#ifdef __cplusplus
}
#endif
