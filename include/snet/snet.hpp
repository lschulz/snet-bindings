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

#pragma once

#include "snet/snet.h"

#if _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <Windows.h>
    #undef min
    #undef max
#else
    #include <pthread.h>
#endif

#include <array>
#include <chrono>
#include <cassert>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <ostream>
#include <ranges>
#include <span>
#include <string_view>
#include <vector>


namespace scion {

class Path;
using Byte = std::byte;
using PathVec = std::vector<std::unique_ptr<Path>>;

////////////////////
// Error Handling //
////////////////////

enum class Status
{
    // Codes indicating success are >= 0
    Success = 0,
    EmptyResponse = 1,
    Timeout = 2,
    NotReady = 3,
    Cancelled = 4,

    // Codes indicating failure are < 0
    Failed = -1,
    InvalidArg = -2,
    BufferInsufficient = -3,
    DaemonError = -4,
    NotInitialized = -100,
    SocketClosed = -101,
};

std::ostream& operator<<(std::ostream& stream, Status status);

class Exception : public virtual std::exception
{
public:
    Exception(std::string message)
        : msg(std::move(message))
    { }

    const char* what() const noexcept { return msg.c_str(); }
    virtual Status toStatus() const noexcept { return Status::Failed; };

private:
    std::string msg;
};

class AbnormalStatus : public virtual Exception
{
public:
    using Exception::Exception;
};

class EmptyResponse : public AbnormalStatus
{
public:
    using AbnormalStatus::AbnormalStatus;
    Status toStatus() const noexcept override { return Status::EmptyResponse; }
};

class Timeout : public AbnormalStatus
{
public:
    using AbnormalStatus::AbnormalStatus;
    Status toStatus() const noexcept override { return Status::Timeout; }
};

class NotReady : public AbnormalStatus
{
public:
    using AbnormalStatus::AbnormalStatus;
    Status toStatus() const noexcept override { return Status::NotReady; }
};

class Cancelled : public AbnormalStatus
{
public:
    using AbnormalStatus::AbnormalStatus;
    Status toStatus() const noexcept override { return Status::Cancelled; }
};

class Error : public virtual Exception
{
public:
    using Exception::Exception;
    Status toStatus() const noexcept override { return Status::Failed; }
};

class InvalidArg : public Error
{
public:
    using Error::Error;
    Status toStatus() const noexcept override { return Status::InvalidArg; }
};

class BufferInsufficient : public Error
{
public:
    using Error::Error;
    Status toStatus() const noexcept override { return Status::BufferInsufficient; }
};

class DaemonError : public Error
{
public:
    using Error::Error;
    Status toStatus() const noexcept override { return Status::DaemonError; }
};

class NotInitialized : public Error
{
public:
    using Error::Error;
    Status toStatus() const noexcept override { return Status::NotInitialized; }
};

class SocketClosed : public Error
{
public:
    using Error::Error;
    Status toStatus() const noexcept override { return Status::SocketClosed; }
};

/// \brief Throws an appropriate exception if the status indicates an error.
Status throwOnError(Status status);

/// \brief Throws an exception if status is not success.
Status throwOnAbnormal(Status status);

////////////
// Slices //
////////////

/// \brief Encapsulates a pointer to a buffer, the capacity of the buffer, and
/// the length of the valid data in the buffer similar to a Go slice.
class Slice
{
public:
    Slice()
        : m_ptr(nullptr), m_size(0), m_capacity(0)
    {}

    Slice(Byte* ptr, std::size_t size)
        : m_ptr(ptr), m_size(size), m_capacity(size)
    {}

    Slice(Byte* ptr, std::size_t size, std::size_t capacity)
        : m_ptr(ptr), m_size(size), m_capacity(capacity)
    {
        assert(size <= capacity);
    }

    Slice(std::span<Byte> span)
        : m_ptr(span.data()), m_size(span.size()), m_capacity(span.size())
    {}

    Slice(std::vector<Byte>& v)
        : m_ptr(v.data()), m_size(v.size()), m_capacity(v.size())
    {}

    static Slice Uninitialized(std::span<Byte> span) { return Slice(span.data(), 0, span.size()); }
    static Slice Uninitialized(std::vector<Byte>& v) { return Slice(v.data(), 0, v.size()); }

    std::span<Byte> toSpan() { return std::span(m_ptr, m_size); }
    std::span<const Byte> toSpan() const { return std::span(m_ptr, m_size); }

    std::span<Byte> toSpanFull() { return std::span(m_ptr, m_capacity); }
    std::span<const Byte> toSpanFull() const { return std::span(m_ptr, m_capacity); }

    Byte* ptr() { return m_ptr; }
    const Byte* ptr() const { return m_ptr; }
    std::size_t size() const { return m_size; }
    std::size_t capacity() const { return m_capacity; }

    void setSize(std::size_t size)
    {
        if (size > static_cast<std::size_t>(m_capacity)) {
            throw InvalidArg("tried to increase slice size beyond capacity");
        }
        m_size = size;
    }

    friend class Socket;

private:
    Byte* m_ptr;
    GoInt m_size;
    GoInt m_capacity;
};

///////////////////////////////
// Asynchronous Notification //
///////////////////////////////

/// \brief AsyncOps are instantiated with a completion handler. Completion handlers are notified
/// when an asynchronous operation completes or has been cancelled.
class CompletionHandler
{
public:
    virtual ~CompletionHandler() = default;

    friend class HostCtx;
    friend class Socket;
    friend class AsyncOp;

private:
    virtual void setContext(ScAsyncOp* op) {}
    virtual void execute(Status status) = 0;
};

/// \brief Specifies a function to be called on completion.
/// \note The callback function is called from a Go thread and should return quickly.
class CompletionCallback : public CompletionHandler
{
public:
    CompletionCallback(std::function<void(Status)> callback)
        : callback(std::move(callback))
    {}

private:
    void execute(Status status) override
    {
        callback(status);
    }

private:
    std::function<void(Status)> callback;
};

#ifndef _WIN32
/// \brief CompletionCV encapsulates a condition variable that can be waited on.
class CompletionCV : public CompletionHandler
{
public:
    CompletionCV();
    CompletionCV(CompletionCV&) = delete;
    CompletionCV(CompletionCV&&) = delete;
    CompletionCV& operator=(CompletionCV&) = delete;
    CompletionCV& operator=(CompletionCV&&) = delete;
    ~CompletionCV() override;

    /// \brief Wait for the conditiona variable to become signaled.
    /// \return Status of the asynchronous operation.
    /// \exception std::system_error if wait fails.
    Status wait();

    /// \brief Wait for the conditiona variable to become signaled or until `timeout` milliseconds
    /// have elapsed.
    /// \return Status of the asynchronous operation or Status::Timeout.
    /// \exception std::system_error if wait fails.
    Status wait(int timeout);

private:
    void setContext(ScAsyncOp* op) override { this->op = op; }
    void execute(Status status) override;

private:
    ScAsyncOp *op;
    pthread_cond_t cond;
};
#endif // _WIN32

#ifndef _WIN32
/// \brief CompletionPipe waits on a POSIX pipe.
class CompletionPipe : public CompletionHandler
{
public:
    CompletionPipe();
    CompletionPipe(CompletionPipe&) = delete;
    CompletionPipe(CompletionPipe&&) = delete;
    CompletionPipe& operator=(CompletionPipe&) = delete;
    CompletionPipe& operator=(CompletionPipe&&) = delete;
    ~CompletionPipe() override;

    /// \brief Wait until the operation is completed.
    /// \return Status of the asynchronous operation.
    Status wait();

    /// \brief Return the read end of the pipe for use in poll(), epoll() and similar functions.
    int getHandle() const { return pipe[0]; }

private:
    void execute(Status status) override;

private:
    std::array<int, 2> pipe = {-1, -1};
};
#endif // _WIN32

#if __linux__
/// \brief CompletionEventFD uses a Linux event file descriptor as waitable object.
/// \note Only available on Linux.
class CompletionEventFD : public CompletionHandler
{
public:
    CompletionEventFD();
    CompletionEventFD(CompletionEventFD&) = delete;
    CompletionEventFD(CompletionEventFD&&) = delete;
    CompletionEventFD& operator=(CompletionEventFD&) = delete;
    CompletionEventFD& operator=(CompletionEventFD&&) = delete;
    ~CompletionEventFD() override;

    /// \brief Wait until the event is set. The event is automatically reset by this call.
    /// \return Status of the asynchronous operation.
    Status wait();

    /// \brief Return the file descriptor for use in poll(), epoll() and similar functions.
    /// \note poll() and similar will not auto-reset the event. To reset the event when it has
    /// become signaled, call wait().
    int getHandle() const { return event; }

private:
    void execute(Status status) override;

private:
    int event = -1;
};
#endif // __linux__

#if _WIN32
/// \brief CompletionEvent uses a Win32 event as waitable object.
/// \note Only available on Windows.
class CompletionEvent : public CompletionHandler
{
public:
    CompletionEvent();
    CompletionEvent(CompletionEvent&) = delete;
    CompletionEvent(CompletionEvent&&) = delete;
    CompletionEvent& operator=(CompletionEvent&) = delete;
    CompletionEvent& operator=(CompletionEvent&&) = delete;
    ~CompletionEvent() override;

    /// \brief Wait until the event is set. The event is automatically reset.
    /// \exception std::system_error if wait fails.
    void wait();

    /// \brief Return the file descriptor for use in WaitForSingleObject(), WaitMultipleObject() and
    /// similar functions.
    /// \note This is an auto-reset event.
    HANDLE getHandle() const { return event; }

private:
    void execute(Status status) override;

private:
    HANDLE event = INVALID_HANDLE_VALUE;
};
#endif // _WIN32

/// \brief Passed to functions initiating asynchronous operations.
class AsyncOp
{
public:
    AsyncOp(std::unique_ptr<CompletionHandler> handler);
    AsyncOp(AsyncOp&& other) = default;
    AsyncOp& operator=(AsyncOp&& other) = default;
    ~AsyncOp();

    CompletionHandler* getHandler() { return handler.get(); }
    const CompletionHandler* getHandler() const { return handler.get(); }

    /// \brief Returns result of the operation if it has completed or was cancelled. If the
    /// operation is still ongoing Status::NotReady is returned instead.
    Status getStatus();

    /// \brief Attempt to cancel the operation. The completion hander is still
    /// invoked for cancelled operations with Status::Cancelled.
    void cancel();

    friend class HostCtx;
    friend class Socket;

private:
    std::unique_ptr<ScAsyncOp> go = {};
    std::unique_ptr<CompletionHandler> handler;
};

///////////////
// Addresses //
///////////////

enum class HostAddrType
{
    Unspec = 0,
    IPv4 = 1,
    IPv6 = 2,
};

/// \brief SCION AS identifier (ISD + ASN)
class IA
{
public:
    IA() = default;
    explicit IA(std::uint64_t ia) : ia(ia) {}
    operator std::uint64_t() const { return ia; }

    friend std::ostream& operator<<(std::ostream &stream, IA ia);

private:
    std::uint64_t ia = 0;
};

/// \brief AS interface ID
class IFID
{
public:
    IFID() = default;
    explicit IFID(std::uint64_t ifid) : ifid(ifid) {}
    operator std::uint64_t() const { return ifid; }

    friend std::ostream& operator<<(std::ostream &stream, IFID ifid);

private:
    std::uint64_t ifid = 0;
};

/// \brief AS local UDP address
class LocalUDPAddr
{
public:
    LocalUDPAddr() = default;
    explicit LocalUDPAddr(const ScLocalUDPAddr& addr) : addr(addr) {}
    explicit operator ScLocalUDPAddr() const { return addr; }

    LocalUDPAddr(std::array<Byte, 4> ip, std::uint16_t port);
    LocalUDPAddr(std::array<Byte, 16> ip, std::uint16_t port, std::string_view zone = std::string_view());

    static std::optional<LocalUDPAddr> fromString(const char* str);
    static std::optional<LocalUDPAddr> fromString(std::string_view str);

    HostAddrType getType() const { return static_cast<HostAddrType>(addr.host.type); };

    std::array<Byte, 4> getIPv4() const
    {
        assert(addr.host.type == SC_ADDR_TYPE_IPV4);
        std::array<Byte, 4> array;
        std::copy(
            reinterpret_cast<const Byte*>(addr.host.ip),
            reinterpret_cast<const Byte*>(addr.host.ip)+4,
            array.begin());
        return array;
    }

    void setIPv4(std::array<Byte, 4> ip)
    {
        addr.host.type = SC_ADDR_TYPE_IPV4;
        std::copy(ip.cbegin(), ip.cend(), reinterpret_cast<Byte*>(addr.host.ip));
        std::fill_n(addr.host.zone, SC_IP_ZONE_ID_MAX_LEN, 0);
    }

    std::array<Byte, 16> getIPv6() const
    {
        assert(addr.host.type == SC_ADDR_TYPE_IPV6);
        std::array<Byte, 16> array;
        std::copy(
            reinterpret_cast<const Byte*>(addr.host.ip),
            reinterpret_cast<const Byte*>(addr.host.ip)+16,
            array.begin());
        return array;
    }

    void setIPv6(std::array<Byte, 16> ip)
    {
        addr.host.type = SC_ADDR_TYPE_IPV6;
        std::copy(ip.cbegin(), ip.cend(), reinterpret_cast<Byte*>(addr.host.ip));
        std::fill_n(addr.host.zone, SC_IP_ZONE_ID_MAX_LEN, 0);
    }

    std::string_view getZone() const { return std::string_view(addr.host.zone); };
    void setZone(std::string_view zone);

    std::uint16_t getPort() const { return addr.port; }
    void setPort(std::uint16_t port) { addr.port = port; }

    friend std::ostream& operator<<(std::ostream& stream, const LocalUDPAddr& addr);
    friend class UDPAddr;
    friend class Socket;

private:
    ScLocalUDPAddr addr = {};
};

/// \brief Global SCION UDP address
class UDPAddr
{
public:
    UDPAddr() = default;
    explicit UDPAddr(const ScUDPAddr& addr) : addr(addr) {}
    explicit operator ScUDPAddr() const { return addr; }

    UDPAddr(IA ia, const LocalUDPAddr& local)
        : addr({ia, local.addr})
    {}

    UDPAddr(IA ia, std::array<Byte, 4> ip, std::uint16_t port);
    UDPAddr(IA ia, std::array<Byte, 16> ip, std::uint16_t port, std::string_view zone = std::string_view());

    static std::optional<UDPAddr> fromString(const char* str);
    static std::optional<UDPAddr> fromString(std::string_view str);

    IA getIA() const { return IA(addr.ia); }
    void setIA(IA ia) { addr.ia = ia; }

    HostAddrType getType() const { return static_cast<HostAddrType>(addr.local.host.type); };

    std::array<Byte, 4> getIPv4() const
    {
        assert(addr.local.host.type == SC_ADDR_TYPE_IPV4);
        std::array<Byte, 4> array;
        std::copy(
            reinterpret_cast<const Byte*>(addr.local.host.ip),
            reinterpret_cast<const Byte*>(addr.local.host.ip)+4,
            array.begin());
        return array;
    }

    void setIPv4(std::array<Byte, 4> ip)
    {
        addr.local.host.type = SC_ADDR_TYPE_IPV4;
        std::copy(ip.cbegin(), ip.cend(), reinterpret_cast<Byte*>(addr.local.host.ip));
        std::fill_n(addr.local.host.zone, SC_IP_ZONE_ID_MAX_LEN, 0);
    }

    std::array<Byte, 16> getIPv6() const
    {
        assert(addr.local.host.type == SC_ADDR_TYPE_IPV6);
        std::array<Byte, 16> array;
        std::copy(
            reinterpret_cast<const Byte*>(addr.local.host.ip),
            reinterpret_cast<const Byte*>(addr.local.host.ip)+16,
            array.begin());
        return array;
    }

    void setIPv6(std::array<Byte, 16> ip)
    {
        addr.local.host.type = SC_ADDR_TYPE_IPV6;
        std::copy(ip.cbegin(), ip.cend(), reinterpret_cast<Byte*>(addr.local.host.ip));
        std::fill_n(addr.local.host.zone, SC_IP_ZONE_ID_MAX_LEN, 0);
    }

    std::string_view getZone() const { return std::string_view(addr.local.host.zone); };
    void setZone(std::string_view zone);

    std::uint16_t getPort() const { return addr.local.port; }
    void setPort(std::uint16_t port) { addr.local.port = port; }

    friend std::ostream& operator<<(std::ostream& stream, const UDPAddr& addr);
    friend class Socket;

private:
    ScUDPAddr addr = {};
};

///////////
// Paths //
///////////

/// \brief Reverse a dataplane path.
Status reversePath(Slice& path);

/// \brief Static path metadata from beacons.
class PathMetadata
{
public:
    struct GeoCoords
    {
        explicit GeoCoords(ScGeoCoords c)
            : latitude(c.latitude), longitude(c.longitude)
        {}
        float latitude;
        float longitude;
    };

    enum class LinkType
    {
        Unset = 0,
        Direct,
        MultiHop,
        OpenNet,
    };

    PathMetadata() = default;
    explicit PathMetadata(const ScPathMetadata& meta)
        : latency(meta.latency, meta.latency + meta.latencyLen)
        , bandwidth(meta.bandwidth, meta.bandwidth + meta.bandwidthLen)
        , geo(meta.geo, meta.geo + meta.geoLen)
        , internalHops(meta.internalHops, meta.internalHops + meta.internalHopsLen)
    {
        auto v = std::span(meta.linkType, meta.linkType + meta.linkTypeLen)
            | std::views::transform([](auto x) { return static_cast<LinkType>(x); });
        linkType.assign(v.begin(), v.end());
    }

public:
    std::vector<uint64_t> latency;
    std::vector<uint64_t> bandwidth;
    std::vector<GeoCoords> geo;
    std::vector<LinkType> linkType;
    std::vector<std::uint32_t> internalHops;
};

/// \brief SCION path with associated metadata.
class Path final
{
public:
    Path() = default;
    Path(const ScPath& path);

    friend std::ostream& operator<<(std::ostream& stream, const Path& path);

public:
    IA src;
    IA dst;

    std::uint32_t expiry;
    std::uint16_t mtu;
    std::uint16_t ifaces;

    LocalUDPAddr nextHop;
    std::vector<Byte> dp;

    std::vector<std::pair<IA, IFID>> ifaceMeta;
    std::unique_ptr<PathMetadata> meta;
};

//////////////////
// Host Context //
//////////////////

/// \brief A host context encapsulates the connection to (one of) the SCION end host stack(s)
/// installed on the system.
class HostCtx final
{
public:
    HostCtx() = default;
    HostCtx(const HostCtx& other) = delete;
    HostCtx(HostCtx&& other);

    HostCtx& operator=(const HostCtx& other) = delete;
    HostCtx& operator=(HostCtx&& other);

    ~HostCtx();

    ScHostCtx get() const { return ctx; }

    /// \brief Returns the identifier of the AS this host context belongs to.
    /// \exception NotInitialized
    IA getLocalIA() const;

    /// \brief Initialize the host context. A host context must be initialized before it can be
    /// used.
    /// \param[in] sciond Optional socket address of the SCION daemon to connect to.
    /// \param[in] timeout Timeout for the initialization. Zero disables the timeout.
    /// \exception InvalidArg if the context has already been initialized.
    Status init(const char* sciond, std::chrono::milliseconds timeout);

    /// \copybrief HostCtx::init
    /// \param[in] async Completion token for asynchronous operation.
    /// \exception InvalidArg if the context has already been initialized.
    void initAsync(const char* sciond, AsyncOp& async);

    /// \brief Query paths from the SCION daemon.
    /// \param[in] dst Destination AS.
    /// \param[in] flags
    /// \param[in] timeout Timeout for path request. Zero disables the timeout.
    /// \return Pair of received paths and status code.
    /// \exception NotInitialized
    std::tuple<PathVec, Status> queryPaths(IA dst, uint64_t flags, std::chrono::milliseconds timeout) const;

    /// \copybrief HostCtx::queryPaths
    /// \param[in] async Completion token for asynchronous operation.
    /// \exception NotInitialized
    void queryPathsAsync(PathVec& paths, IA dst, uint64_t flags, AsyncOp& async);

private:
    ScHostCtx ctx = 0;
};

////////////
// Socket //
////////////

/// \brief Interface for SCMP message handlers.
class SCMPHandler
{
public:
    virtual void handle(const ScSCMPMessage* msg) = 0;
};

/// \brief Socket for reading and writing SCION packets.
class Socket
{
public:
    /// \brief Construct a SCION socket with the given handler for SCMP
    /// messages. The socket must be opened using open() or asyncOpen() before
    /// it can be used for communication.
    Socket(SCMPHandler& handler) : handler(&handler) {}
    Socket(const Socket& other) = delete;
    Socket(Socket&& other);

    Socket& operator=(const Socket& other) = delete;
    Socket& operator=(Socket&& other);

    ~Socket() { close(); }

    ScSocket get() const { return sock; };
    bool isOpen() const { return sock != 0; }

    /// \brief Bind the socket to a local IP address. A socket must be bound before it can sent or
    /// receive packets.
    /// \param[in] ctx Host context
    /// \param[in] local Local IP address to bind to. Binding to wildcard addresses is currently not
    ///            supported.
    /// \param[in] timeout Zero disables the timeout.
    /// \exception InvalidArg if the socket is already bound.
    Status open(HostCtx& ctx, const LocalUDPAddr& local, std::chrono::milliseconds timeout);

    /// \copybrief Socket::open
    /// \param[in] async Completion token for asynchronous operation.
    void openAsync(HostCtx& ctx, const LocalUDPAddr& local, AsyncOp& async);

    /// \brief Close the socket.
    void close() noexcept;

    /// \brief Set a deadline for all current and future sent operations. Setting this to a value in
    /// the past cancels all send operations immediately. Setting the deadline to nullopt disables a
    /// previously set send deadline.
    /// \param[in] deadeline Deadline as Unix timestamp with millisecond resolution.
    /// \note The socket must be open in order for this call to succeed.
    void setSendDeadline(std::optional<std::chrono::milliseconds> deadline);

    /// \brief Set a deadline for all current and future receive operations. Setting this to a value
    /// in the past cancels all receive operations immediately. Setting the deadline to nullopt
    /// disables a previously set receive deadline.
    /// \param[in] deadeline Deadline as Unix timestamp with millisecond resolution.
    /// \note The socket must be open in order for this call to succeed.
    void setRecvDeadline(std::optional<std::chrono::milliseconds> deadline);

    /// \brief Send a SCION/UDP packet.
    /// \param[in] remote SCION UDP address of the destination host.
    /// \param[in] router Next hop border router in the local AS.
    /// \param[in] dpPath Raw dataplane path.
    /// \param[in] payload UDP payload.
    Status sendPacket(
        const UDPAddr& remote, const LocalUDPAddr& router,
        const Slice& dpPath, const Slice& payload);

    /// \brief Send a SCION/UDP packet to a host in the same AS.
    Status sendPacketLocal(const UDPAddr& remote, const Slice& payload);

    /// \copybrief Socket::sendPacket
    /// \details remote, router, dpPath, and payload are copied and can be destroyed after this
    /// function returns. The buffers pointed to by the slices must remain valid until the operation
    /// completes.
    /// \param[in] async Completion token for asynchronous operation.
    void sendPacketAsync(
        const UDPAddr& remote, const LocalUDPAddr& router,
        const Slice& dpPath, const Slice& payload, AsyncOp& async);

    /// \copybrief Socket::sendPacketLocal
    /// \details remote and payload are copied and can be
    /// destroyed after this function returns. The buffer pointed to by the slice must remain valid
    /// until the operation completes.
    void sendPacketLocalAsync(const UDPAddr& remote, const Slice& payload, AsyncOp& async);

    /// \brief Receive a SCION/UDP packet.
    /// \param[out] dpPath Raw dataplane path of the received packet.
    /// \param[out] payload UDP payload of the received packet.
    /// \return Tuple of the remote host's SCION address, the address of the
    /// router the packet was received from, and the status code.
    std::tuple<UDPAddr, LocalUDPAddr, Status> recvPacket(Slice& dpPath, Slice& payload);

    /// \copydoc Socket::recvPacket(dpPath,payload)
    std::tuple<UDPAddr, Status> recvPacket(Slice& payload);

    /// \copybrief Socket::recvPacket(dpPath,payload,timeout)
    /// \details from, router, dpPath, and payload must be preallocated before calling this function
    /// and must remain valid until the operation completes.
    /// \param[in] async Completion token for asynchronous operation.
    void recvPacketAsync(UDPAddr& from, LocalUDPAddr& router, Slice& dpPath, Slice& payload, AsyncOp& async);

    /// \copydoc Socket::recvPacketAsync(from,router,dpPath,payload,async)
    void recvPacketAsync(UDPAddr& from, Slice& payload, AsyncOp& async);

private:
    static void handleSCMP(const ScSCMPMessage* msg, uintptr_t userdata);

private:
    ScSocket sock = 0;
    SCMPHandler* handler;
};

} // namespace scion
