// Copyright 2024 Lars-Christian Schulz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SNET_INCLUDE_GUARD
#define SNET_INCLUDE_GUARD

#include <stdint.h>
#include <stddef.h>

#if _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <Windows.h>
    #undef min
    #undef max
#else
    #include <pthread.h>
#endif

#define SC_IP_ZONE_ID_MAX_LEN 16

#define SC_FLAG_PATH_REFRESH (1ull << 0)
#define SC_FLAG_PATH_HIDDEN (1ull << 1)
#define SC_FLAG_PATH_GET_IFACES (1ull << 32)
#define SC_FLAG_PATH_GET_META (1ull << 33)

typedef const char cchar;
typedef ptrdiff_t ScSize;
typedef unsigned char ScByte;

typedef uintptr_t ScHostCtx;
typedef uintptr_t ScSocket;

typedef uint64_t ScIA;
typedef uint16_t ScPort;
typedef uint64_t ScIfId;

typedef enum ScStatus
{
    // Codes indicating success are >= 0
    /// \brief Operation successful
    SC_SUCCESS = 0,
    /// \brief Operation completed successfully, but response is empty
    SC_EMPTY_RESPONSE = 1,
    /// \brief Operation timed out.
    SC_TIMEOUT = 1,
    /// \brief Asynchronous operation is still io progress.
    SC_NOT_READY = 2,
    /// \brief Asynchronous operation was canceld.
    SC_CANCELED = 3,

    // Codes indicating failure are < 0
    /// \brief Operation failed without additional information.
    SC_ERROR_FAILED = -1,
    /// \brief Caller passed in valid arguments.
    SC_ERROR_INVALID_ARG = -2,
    /// \brief Operation failed because caller provided insufficent buffer space.
    /// Retry with a larger buffer.
    SC_ERROR_BUFFER_INSUFFICIENT = -3,
    /// \brief Operation failed because of an issue with communicating with the
    /// SCION daemon.
    SC_ERROR_DAEMON = -4,
} ScStatus;

typedef enum ScAddrType
{
    SC_ADDR_TYPE_INVALID = 0,
    SC_ADDR_TYPE_IPV4 = 1,
    SC_ADDR_TYPE_IPV6 = 2,
} ScAddrType;

typedef enum ScSCMPType
{
    SC_SCMP_TYPE_DESTINATION_UNREACHABLE = 1,
    SC_SCMP_TYPE_PACKET_TOO_BIG = 2,
    SC_SCMP_TYPE_PARAMETER_PROBLEM = 4,
    SC_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN = 5,
    SC_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN = 6,
} ScSCMPType;

typedef enum ScPathLinkType {
    SC_PATH_LINK_TYPE_UNSET = 0,
    SC_PATH_LINK_TYPE_DIRECT,
    SC_PATH_LINK_TYPE_MULTIHOP,
    SC_PATH_LINK_TYPE_OPENNET,
} ScPathLinkType;

struct ScSCMPMessage
{
    ScSCMPType type;
};

struct ScSCMPDestinationUnreachable
{
    ScSCMPType type;
    uint8_t code;
};

struct ScSCMPPacketTooBig
{
    ScSCMPType type;
    uint8_t code;
    uint16_t mtu;
};

struct ScSCMPParameterProblem
{
    ScSCMPType type;
    uint8_t code;
    uint16_t pointer;
};

struct ScSCMPExternalInterfaceDown
{
    ScSCMPType type;
    uint8_t code;
    ScIA originator;
    ScIfId interface;
};

struct ScSCMPInternalConnectivityDown
{
    ScSCMPType type;
    uint8_t code;
    ScIA originator;
    ScIfId ingressIf;
    ScIfId egressIf;
};

typedef void* (*ScMalloc)(size_t n);
typedef void (*ScFree)(void*);
typedef void (*ScSCMPHandler)(const struct ScSCMPMessage* msg, uintptr_t userdata);
typedef void (*ScCompletionHandler)(ScStatus result, void* userdata);

struct ScAsyncOp
{
    ScCompletionHandler callback;
    void* userdata;
    ScStatus result;
    uintptr_t handle; // opaque handle used by Go
#if _WIN32
    CRITICAL_SECTION crit;
#else
    pthread_mutex_t mutex;
#endif
};

struct ScHostAddr
{
    ScAddrType type;
    ScByte ip[16];
    char zone[SC_IP_ZONE_ID_MAX_LEN]; // always null terminated
};

struct ScLocalUDPAddr
{
    struct ScHostAddr host;
    ScPort port;
};

struct ScUDPAddr
{
    ScIA ia;
    struct ScLocalUDPAddr local;
};

/// \brief Host context configuration parameters.
struct ScConfig
{
    /// \brief Socket address of the SCION daemon. If NULL, the default address is used.
    const char* sciondAddr;
    /// \brief Optional callback for allocating memory returned throught the C API.
    ScMalloc malloc;
    /// \brief Optional callback for releasing memory allocated with the `malloc` callback. If
    /// `malloc` is not NULL, so must be `free`.
    ScFree free;
};

struct ScHopIface
{
    ScIA ia;
    ScIfId ifid;
};

struct ScGeoCoords
{
    float latitude;
    float longitude;
};

/// \brief Path metadata
struct ScPathMetadata
{
    uint16_t latencyLen;
    uint16_t bandwidthLen;
    uint16_t geoLen;
    uint16_t linkTypeLen;
    uint16_t internalHopsLen;
    /// Array of N-1 latency values in nanoseconds for N interfaces.
    uint64_t* latency;
    /// Array of N-1 bandwidth values in kbit/s for N interfaces.
    uint64_t* bandwidth;
    /// Array of N geographical coordinates for each interface.
    struct ScGeoCoords* geo;
    /// Array of N/2 link types of the inter-domain links between N interfaces.
    ScPathLinkType* linkType;
    /// Array of internal hop count between interfaces. The first and last
    /// (source and destination) AS do not have an entry. Consequentially, the
    /// array has a length of N/2 - 1 entries for N interfaces.
    uint32_t* internalHops;
};

struct ScPath
{
    ScIA src; ///< Source AS
    ScIA dst; ///< Destination AS

    uint32_t expiry; ///< Path expiration date as Unix timestmap in seconds
    uint16_t mtu;    ///< Path MTU in bytes
    uint16_t ifaces; ///< The number of AS interfaces on the path

    ScByte* dp;    ///< Encoded path for use in the data plane
    ScSize  dpLen; ///< Length of the buffer pointed to by `dp`
    struct ScLocalUDPAddr nextHop; ///< Next hop router

    // Optional interface metadata. If not NULL, an array of length `ifaces`.
    struct ScHopIface* ifaceMeta;
    // Optional additional path metadata. If not NULL, a single ScPathMetadata struct.
    struct ScPathMetadata* meta;
};

/// \brief SCION UDP packet header and payload data.
struct ScUDPPacket
{
    // Addresses
    struct ScUDPAddr remote;      ///< Address of the remote source/destination host
    struct ScLocalUDPAddr router; ///< Border router the packet is sent to or was received from

    // Path
    ScByte* dpPath;   ///< Encoded path from SCION header
    ScSize dpPathLen; ///< Valid length of the buffer pointed to by `dpPath`
    ScSize dpPathCap; ///< Maximum capacity of the buffer pointed to by `dpPath`

    // Payload
    ScByte* payload;   ///< UDP payload
    ScSize payloadLen; ///< Valid length of the buffer pointed to by `payload`
    ScSize payloadCap; ///< Maximum capacity of the buffer pointed to by `payload`
};

#ifdef __cplusplus
extern "C" {
#endif

/**
\brief Compare two AS-local UDP addresses.
\return Negative value if lhs is considered to be ordered before rhs. Positive value if lhs is
ordered after rhs. Zero if lhs and rhs are equal.
**/
int ScCompLocalUDPAddr(const struct ScLocalUDPAddr* lhs, const struct ScLocalUDPAddr* rhs);

/**
\brief Compare two global UDP addresses.
\return Negative value if lhs is considered to be ordered before rhs. Positive value if lhs is
ordered after rhs. Zero if lhs and rhs are equal.
*/
int ScCompUDPAddr(const struct ScUDPAddr* lhs, const struct ScUDPAddr* rhs);

/**
\brief In-place reverse a SCION path in its raw dataplane format.
*/
ScStatus ScReversePath(ScByte* path, ScSize* len, ScSize cap);

#ifdef __cplusplus
}
#endif

inline void* call_malloc(ScMalloc cb, size_t n)
{
    return cb(n);
}

inline void call_free(ScFree cb, void *ptr)
{
    cb(ptr);
}

inline void call_scmp_handler(ScSCMPHandler handler, const struct ScSCMPMessage *msg, uintptr_t user)
{
    handler(msg, user);
}

inline void call_completion_handler(ScCompletionHandler handler, ScStatus result, void* userdata)
{
    handler(result, userdata);
}

typedef const struct ScConfig* ConstPtrScConfig;
typedef const struct ScUDPAddr* ConstPtrScUDPAddr;
typedef const struct ScLocalUDPAddr* ConstPtrScLocalUDPAddr;

#endif // SNET_INCLUDE_GUARD
