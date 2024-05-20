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

#include "snet/snet.hpp"

#if __linux__
    #include <pthread.h>
    #include <sys/eventfd.h>
    #include <fcntl.h>
#elif __unix__
    #include <pthread.h>
#endif

#include <algorithm>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

namespace scion {

////////////////////
// Error Handling //
////////////////////

// Offset to add to a status code guaranteeing all valid values are > 0.
constexpr uint64_t STATUS_CODE_BIAS = 1024;

static constexpr Status castStatus(ScStatus status)
{
    return static_cast<Status>(status);
}

DLLEXPORT
std::ostream& operator<<(std::ostream& stream, Status status)
{
    switch (status)
    {
    case Status::Success:
        stream << "success";
        break;
    case Status::EmptyResponse:
        stream << "empty response";
        break;
    case Status::Timeout:
        stream << "operation timed out";
        break;
    case Status::NotReady:
        stream << "async operation is not ready";
        break;
    case Status::Cancelled:
        stream << "async operation was cancelled";
        break;
    case Status::Failed:
        stream << "operation failed";
        break;
    case Status::InvalidArg:
        stream << "invalid argument";
        break;
    case Status::BufferInsufficient:
        stream << "buffer insufficient";
        break;
    case Status::DaemonError:
        stream << "error in communication with SCION daemon";
        break;
    case Status::NotInitialized:
        stream << "not initialized";
        break;
    case Status::SocketClosed:
        stream << "socket is closed";
        break;
    default:
        stream << "<invalid>";
        break;
    }
    return stream;
}

DLLEXPORT
Status throwOnError(Status status)
{
    switch (status)
    {
    case Status::Failed:
        throw Error("operation failed");
    case Status::InvalidArg:
        throw InvalidArg("invalid argument");
    case Status::BufferInsufficient:
        throw BufferInsufficient("buffer insufficient");
    case Status::DaemonError:
        throw DaemonError("error in communication with SCION daemon");
    case Status::NotInitialized:
        throw NotInitialized("not initialized");
    case Status::SocketClosed:
        throw SocketClosed("socket is closed");
    default:
        return status;
    }
}

DLLEXPORT
Status throwOnAbnormal(Status status)
{
    switch (throwOnError(status))
    {
    case Status::EmptyResponse:
        throw EmptyResponse("empty response");
    case Status::Timeout:
        throw Timeout("operation timed out");
    case Status::NotReady:
        throw NotReady("async operation is not ready");
    case Status::Cancelled:
        throw Cancelled("async operation was cancelled");
    default:
        return status;
    }
}

//////////////////
// CompletionCV //
//////////////////
#ifndef _WIN32

CompletionCV::CompletionCV()
{
    pthread_cond_init(&cond, NULL);
}

CompletionCV::~CompletionCV()
{
    pthread_cond_destroy(&cond);
}

Status CompletionCV::wait()
{
    pthread_mutex_lock(&op->mutex);
    while (op->result == SC_NOT_READY) {
        int err = pthread_cond_wait(&cond, &op->mutex);
        if (err) {
            pthread_mutex_unlock(&op->mutex);
            throw std::system_error(err, std::system_category());
        }
    }
    auto result = castStatus(op->result);
    pthread_mutex_unlock(&op->mutex);
    return result;
}

Status CompletionCV::wait(int timeout)
{
    timespec ts;
    int err = clock_gettime(CLOCK_REALTIME, &ts);
    if (err) {
        throw std::system_error(err, std::system_category());
    }
    ts.tv_sec += timeout / 1000;
    ts.tv_nsec += timeout % 1000;
    if (ts.tv_nsec > 1000000000) {
        ts.tv_nsec = ts.tv_nsec % 1000000000;
        ts.tv_sec += 1;
    }

    pthread_mutex_lock(&op->mutex);
    while (op->result == SC_NOT_READY) {
        err = pthread_cond_timedwait(&cond, &op->mutex, &ts);
        if (err == ETIMEDOUT) {
            pthread_mutex_unlock(&op->mutex);
            return Status::Timeout;
        } else if (err != 0) {
            pthread_mutex_unlock(&op->mutex);
            throw std::system_error(err, std::system_category());
        }
    }
    auto result = castStatus(op->result);
    pthread_mutex_unlock(&op->mutex);
    return result;

}

void CompletionCV::execute(Status status)
{
    pthread_cond_signal(&cond);
}

#endif // _WIN32

////////////////////
// CompletionPipe //
////////////////////
#ifndef _WIN32

CompletionPipe::CompletionPipe()
{
#if __linux__
    if (pipe2(pipe.data(), O_CLOEXEC) != 0) {
        throw std::system_error(errno, std::system_category());
    }
#else
    if (::pipe(pipe.data()) != 0) {
        throw std::system_error(errno, std::system_category());
    }
    fcntl(pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipe[1], F_SETFD, FD_CLOEXEC);
#endif
}

CompletionPipe::~CompletionPipe()
{
    if (pipe[0]) close(pipe[0]);
    if (pipe[1]) close(pipe[1]);
}

Status CompletionPipe::wait()
{
    std::int64_t value = 0;
    read(pipe[0], &value, sizeof(value));
    return static_cast<Status>(value);
}

void CompletionPipe::execute(Status status)
{
    auto value = static_cast<std::int64_t>(status);
    write(pipe[1], &value, sizeof(value));
}

#endif // _WIN32

///////////////////////
// CompletionEventFD //
///////////////////////
#if __linux__

CompletionEventFD::CompletionEventFD()
    : event(eventfd(0, EFD_CLOEXEC))
{
    if (event < 0) {
        throw std::system_error(errno, std::system_category());
    }
}

CompletionEventFD::~CompletionEventFD()
{
    if (event > 0) {
        close(event);
    }
}

Status CompletionEventFD::wait()
{
    std::uint64_t value = 0;
    static_assert(sizeof(value) == 8);
    read(event, &value, sizeof(value));
    return static_cast<Status>(value - STATUS_CODE_BIAS);
}

void CompletionEventFD::execute(Status status)
{
    auto value = static_cast<std::uint64_t>(status) + STATUS_CODE_BIAS;
    static_assert(sizeof(value) == 8);
    write(event, &value, sizeof(value));
}

#endif // __linux__

/////////////////////
// CompletionEvent //
/////////////////////
#ifdef _WIN32

DLLEXPORT
CompletionEvent::CompletionEvent()
    : event(CreateEventA(NULL, FALSE, FALSE, NULL))
{
    if (event == NULL) {
        throw std::system_error(GetLastError(), std::system_category());
    }
}

DLLEXPORT
CompletionEvent::~CompletionEvent()
{
    if (event != NULL && event != INVALID_HANDLE_VALUE) {
        CloseHandle(event);
    }
}

DLLEXPORT
void CompletionEvent::wait()
{
    DWORD result = WaitForSingleObject(event, INFINITE);
    if (result == WAIT_FAILED) {
        throw std::system_error(GetLastError(), std::system_category());
    }
}

void CompletionEvent::execute(Status status)
{
    SetEvent(event);
}

#endif // _WIN32

/////////////
// AsyncOp //
/////////////
#if _WIN32

DLLEXPORT
AsyncOp::AsyncOp(std::unique_ptr<CompletionHandler> compHandler)
    : go(std::make_unique<ScAsyncOp>())
    , handler(std::move(compHandler))
{
    InitializeCriticalSectionAndSpinCount(&go->crit, 1500);
    if (handler) {
        handler->setContext(go.get());
    }
}

DLLEXPORT
AsyncOp::~AsyncOp()
{
    handler.reset();
    if (go) {
        DeleteCriticalSection(&go->crit);
    }
}

DLLEXPORT
Status AsyncOp::getStatus()
{
    Status result;
    EnterCriticalSection(&go->crit);
    result = castStatus(go->result);
    LeaveCriticalSection(&go->crit);
    return result;
}

#else // _WIN32

AsyncOp::AsyncOp(std::unique_ptr<CompletionHandler> compHandler)
    : go(std::make_unique<ScAsyncOp>())
    , handler(std::move(compHandler))
{
    pthread_mutex_init(&go->mutex, NULL);
    if (handler) {
        handler->setContext(go.get());
    }
}

AsyncOp::~AsyncOp()
{
    handler.reset();
    if (go) {
        pthread_mutex_destroy(&go->mutex);
    }
}

Status AsyncOp::getStatus()
{
    Status result;
    pthread_mutex_lock(&go->mutex);
    result = castStatus(go->result);
    pthread_mutex_unlock(&go->mutex);
    return result;
}

#endif // _WIN32

DLLEXPORT
void AsyncOp::cancel()
{
    ScCancelAsyncOp(go.get());
}

////////
// IA //
////////

DLLEXPORT
std::ostream& operator<<(std::ostream &stream, IA ia)
{
    constexpr auto ASN_BITS = 48;
    constexpr auto MAX_BGP_ASN = (1ull << 32) - 1;
    constexpr auto GROUP_BITS = 16ull;
    constexpr auto GROUP_MAX_VALUE = (1ull << GROUP_BITS) - 1;

    auto isd = ia >> ASN_BITS;
    auto asn = ia & ((1ull << ASN_BITS) - 1);

    stream << isd << "-";
    if (asn <= MAX_BGP_ASN) {
        stream << asn;
    } else {
        stream << std::hex
            << ((asn >> 2 * GROUP_BITS) & GROUP_MAX_VALUE) << ':'
            << ((asn >> GROUP_BITS) & GROUP_MAX_VALUE) << ':'
            << ((asn) & GROUP_MAX_VALUE);
    }
    return stream;
}

//////////
// IFID //
//////////

DLLEXPORT
std::ostream& operator<<(std::ostream &stream, IFID ifid)
{
    stream << ifid.ifid;
    return stream;
}

//////////////////
// LocalUDPAddr //
//////////////////

DLLEXPORT
LocalUDPAddr::LocalUDPAddr(std::array<Byte, 4> ip, std::uint16_t port)
{
    addr.host.type = SC_ADDR_TYPE_IPV4;
    addr.port = port;
    std::copy(ip.cbegin(), ip.cend(), reinterpret_cast<Byte*>(addr.host.ip));
}

DLLEXPORT
LocalUDPAddr::LocalUDPAddr(std::array<Byte,16> ip, std::uint16_t port, std::string_view zone)
{
    if (zone.length() > SC_IP_ZONE_ID_MAX_LEN - 1) {
        throw InvalidArg("Zone identifier too long");
    }
    addr.host.type = SC_ADDR_TYPE_IPV6;
    addr.port = port;
    std::copy(ip.cbegin(), ip.cend(), reinterpret_cast<Byte*>(addr.host.ip));
    std::copy(zone.cbegin(), zone.cend(), addr.host.zone);
}

DLLEXPORT
std::optional<LocalUDPAddr> LocalUDPAddr::fromString(const char* str)
{
    LocalUDPAddr addr;
    if (ScParseLocalUDPAddr(str, &addr.addr) != SC_SUCCESS) {
        return std::nullopt;
    }
    return std::make_optional(std::move(addr));
}

DLLEXPORT
std::optional<LocalUDPAddr> LocalUDPAddr::fromString(std::string_view str)
{
    LocalUDPAddr addr;
    if (ScParseLocalUDPAddrN(str.data(), str.length(), &addr.addr) != SC_SUCCESS) {
        return std::nullopt;
    }
    return std::make_optional(std::move(addr));
}

DLLEXPORT
void LocalUDPAddr::setZone(std::string_view zone)
{
    if (zone.length() > SC_IP_ZONE_ID_MAX_LEN - 1) {
        throw InvalidArg("Zone identifier too long");
    }
    std::fill_n(addr.host.zone, SC_IP_ZONE_ID_MAX_LEN, 0);
    std::copy(zone.cbegin(), zone.cend(), addr.host.zone);
}

DLLEXPORT
std::ostream& operator<<(std::ostream& stream, const LocalUDPAddr& addr)
{
    ScSize size = 128;
    auto buffer = std::make_unique<char[]>(size);

    auto err = ScFormatLocalUDPAddr(&addr.addr, buffer.get(), &size);
    if (err == SC_ERROR_BUFFER_INSUFFICIENT) {
        buffer = std::make_unique<char[]>(size);
        err = ScFormatLocalUDPAddr(&addr.addr, buffer.get(), &size);
    }

    if (err == SC_SUCCESS) {
        stream << buffer.get();
    } else {
        stream << "<invalid>";
    }

    return stream;
}

/////////////
// UDPAddr //
/////////////

DLLEXPORT
UDPAddr::UDPAddr(IA ia, std::array<Byte, 4> ip, std::uint16_t port)
{
    addr.ia = ia;
    addr.local.host.type = SC_ADDR_TYPE_IPV4;
    addr.local.port = port;
    std::copy(ip.cbegin(), ip.cend(), reinterpret_cast<Byte*>(addr.local.host.ip));
}

DLLEXPORT
UDPAddr::UDPAddr(IA ia, std::array<Byte, 16> ip, std::uint16_t port, std::string_view zone)
{
    if (zone.length() > SC_IP_ZONE_ID_MAX_LEN - 1) {
        throw InvalidArg("Zone identifier too long");
    }
    addr.ia = ia;
    addr.local.host.type = SC_ADDR_TYPE_IPV6;
    addr.local.port = port;
    std::copy(ip.cbegin(), ip.cend(), reinterpret_cast<Byte*>(addr.local.host.ip));
    std::copy(zone.cbegin(), zone.cend(), addr.local.host.zone);
}

DLLEXPORT
std::optional<UDPAddr> UDPAddr::fromString(const char* str)
{
    UDPAddr addr;
    if (ScParseUDPAddr(str, &addr.addr) != SC_SUCCESS) {
        return std::nullopt;
    }
    return std::make_optional(std::move(addr));
}

DLLEXPORT
std::optional<UDPAddr> UDPAddr::fromString(std::string_view str)
{
    UDPAddr addr;
    if (ScParseUDPAddrN(str.data(), str.length(), &addr.addr) != SC_SUCCESS) {
        return std::nullopt;
    }
    return std::make_optional(std::move(addr));
}

DLLEXPORT
void UDPAddr::setZone(std::string_view zone)
{
    if (zone.length() > SC_IP_ZONE_ID_MAX_LEN - 1) {
        throw InvalidArg("Zone identifier too long");
    }
    std::fill_n(addr.local.host.zone, SC_IP_ZONE_ID_MAX_LEN, 0);
    std::copy(zone.cbegin(), zone.cend(), addr.local.host.zone);
}

DLLEXPORT
std::ostream& operator<<(std::ostream& stream, const UDPAddr& addr)
{
    ScSize size = 128;
    auto buffer = std::make_unique<char[]>(size);

    auto err = ScFormatUDPAddr(&addr.addr, buffer.get(), &size);
    if (err == SC_ERROR_BUFFER_INSUFFICIENT) {
        buffer = std::make_unique<char[]>(size);
        err = ScFormatUDPAddr(&addr.addr, buffer.get(), &size);
    }

    if (err == SC_SUCCESS) {
        stream << buffer.get();
    } else {
        stream << "<invalid>";
    }

    return stream;
}

//////////
// Path //
//////////

DLLEXPORT
Status reversePath(Slice& path)
{
    ScSize size = path.size();
    ScStatus err = ScReversePath(reinterpret_cast<ScByte*>(path.ptr()), &size, path.capacity());
    if (err == SC_SUCCESS) path.setSize(size);
    return castStatus(err);
}

DLLEXPORT
Path::Path(const ScPath& path)
{
    src = IA(path.src);
    dst = IA(path.dst);

    expiry = path.expiry;
    mtu = path.mtu;
    ifaces = path.ifaces;

    nextHop = LocalUDPAddr(path.nextHop);
    dp.assign(reinterpret_cast<Byte*>(path.dp), reinterpret_cast<Byte*>(path.dp) + path.dpLen);

    ifaceMeta.reserve(path.ifaces);
    for (unsigned int i = 0; i < path.ifaces; ++i) {
        ifaceMeta.emplace_back(IA(path.ifaceMeta[i].ia), IFID(path.ifaceMeta[i].ifid));
    }

    if (path.meta) {
        meta = std::make_unique<PathMetadata>(*path.meta);
    }
}

DLLEXPORT
std::ostream& operator<<(std::ostream& stream, const Path& path)
{
    if (path.ifaceMeta.empty()) {
        stream
            << path.src << " > " << path.dst
            << "(MTU: " << path.mtu << " bytes)";
    } else {
        int i = 0;
        for (const auto& iface : path.ifaceMeta) {
            if (i++ % 2 == 0) {
                stream << iface.first << ' ' << iface.second<< '>';
            } else {
                stream << iface.second << ' ';
            }
        }
        stream << path.dst << " (MTU: " << path.mtu << " bytes)";
    }
    return stream;
}

/////////////
// HostCtx //
/////////////

DLLEXPORT
HostCtx::HostCtx(HostCtx&& other)
    : ctx(other.ctx)
    , handler(other.handler)
{
    other.ctx = 0;
    other.handler = nullptr;
}

DLLEXPORT
HostCtx &HostCtx::operator=(HostCtx&& other)
{
    if (this != &other) {
        if (ctx) {
            ScHostDestroy(ctx);
        }
        ctx = other.ctx;
        handler = other.handler;
    }
    return *this;
}

DLLEXPORT
HostCtx::~HostCtx()
{
    if (ctx) {
        ScHostDestroy(ctx);
    }
}

DLLEXPORT
IA HostCtx::getLocalIA() const
{
    if (!ctx) throw NotInitialized("host conntext not initialized");
    return IA(ScHostLocalIA(ctx));
}

DLLEXPORT
Status HostCtx::init(const char* sciond, std::chrono::milliseconds timeout)
{
    if (ctx) throw InvalidArg("host conntext already initialized");
    ScConfig scConfig = {
        .sciondAddr = sciond,
        .malloc = &std::malloc,
        .free = &std::free,
    };
    return castStatus(ScHostInit(&ctx, &scConfig, &handleSCMP,
        reinterpret_cast<uintptr_t>(this), timeout.count()));
}

DLLEXPORT
void HostCtx::initAsync(const char* sciond, AsyncOp& async)
{
    if (ctx) throw InvalidArg("host conntext already initialized");
    struct Calldata {
        CompletionHandler* handler;
        ScConfig config;
    };
    auto calldata = new Calldata{ async.getHandler(), {
        .sciondAddr = sciond,
        .malloc = &std::malloc,
        .free = &std::free,
    }};
    async.go->userdata = calldata;
    async.go->callback = [](ScStatus result, void* userdata) {
        auto data = std::unique_ptr<Calldata>(reinterpret_cast<Calldata*>(userdata));
        if (data->handler) {
            data->handler->execute(castStatus(result));
        }
    };
    ScHostInitAsync(&ctx, &calldata->config, &handleSCMP,
        reinterpret_cast<uintptr_t>(this), async.go.get());
}

DLLEXPORT
std::tuple<PathVec, Status> HostCtx::queryPaths(IA dst, uint64_t flags, std::chrono::milliseconds timeout) const
{
    if (!ctx) throw NotInitialized("host conntext not initialized");
    PathVec vec;
    ScPath** paths = nullptr;
    uint32_t count = 0;

    auto err = ScQueryPaths(ctx, dst, &paths, &count, flags, timeout.count());
    if (err) return std::make_tuple(std::move(vec), castStatus(err));

    vec.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        vec.push_back(std::make_unique<Path>(*paths[i]));
    }
    return std::make_tuple(std::move(vec), Status::Success);
}

DLLEXPORT
void HostCtx::queryPathsAsync(PathVec& vec, IA dst, uint64_t flags, AsyncOp& async)
{
    if (!ctx) throw NotInitialized("host conntext not initialized");
    struct Calldata {
        CompletionHandler* handler;
        PathVec& vec;
        ScPath** paths;
        uint32_t count;
    };
    auto calldata = new Calldata{async.getHandler(), vec, nullptr, 0};
    async.go->userdata = calldata;
    async.go->callback = [](ScStatus result, void* userdata) {
        auto data = std::unique_ptr<Calldata>(reinterpret_cast<Calldata*>(userdata));
        if (result == SC_SUCCESS) {
            data->vec.reserve(data->count);
            data->vec.resize(0);
            for (uint32_t i = 0; i < data->count; ++i) {
                auto path = data->paths[i];
                data->vec.push_back(std::make_unique<Path>(*path));
                if (path->meta) {
                    if (path->meta->internalHops) std::free(path->meta->internalHops);
                    if (path->meta->linkType) std::free(path->meta->linkType);
                    if (path->meta->geo) std::free(path->meta->geo);
                    if (path->meta->bandwidth) std::free(path->meta->bandwidth);
                    if (path->meta->latency) std::free(path->meta->latency);
                    std::free(path->meta);
                }
                if (path->ifaceMeta) std::free(path->ifaceMeta);
                if (path->dp) std::free(path->dp);
                std::free(path);
            }
            if (data->paths) std::free(data->paths);
        }
        if (data->handler) {
            data->handler->execute(castStatus(result));
        }
    };
    ScQueryPathsAsync(ctx, dst, &calldata->paths, &calldata->count, flags, async.go.get());
}

void HostCtx::handleSCMP(const ScSCMPMessage* msg, uintptr_t userdata)
{
    auto self = reinterpret_cast<HostCtx*>(userdata);
    if (self->handler) {
        self->handler->handle(msg);
    }
}


////////////
// Socket //
////////////

DLLEXPORT
Socket::Socket(Socket&& other)
    : sock(other.sock)
{
    other.sock = 0;
}

DLLEXPORT
Socket& Socket::operator=(Socket&& other)
{
    if (this != &other) {
        close();
        sock = other.sock;
    }
    return *this;
}

DLLEXPORT
Status Socket::open(HostCtx& ctx, const LocalUDPAddr& local, std::chrono::milliseconds timeout)
{
    if (sock) throw InvalidArg("socket already open");
    auto err = ScOpenSocket(
        ctx.get(), &local.addr, &sock, timeout.count());
    return castStatus(err);
}

DLLEXPORT
void Socket::openAsync(HostCtx& ctx, const LocalUDPAddr& local, AsyncOp& async)
{
    if (sock) throw InvalidArg("socket already open");
    struct Calldata {
        CompletionHandler* handler;
        const LocalUDPAddr& local;
    };
    auto calldata = new Calldata{async.getHandler(), local};
    async.go->userdata = calldata;
    async.go->callback = [](ScStatus result, void* userdata) {
        auto data = std::unique_ptr<Calldata>(reinterpret_cast<Calldata*>(userdata));
        if (data->handler) {
            data->handler->execute(castStatus(result));
        }
    };
    ScOpenSocketAsync(
        ctx.get(), &(calldata->local.addr), &sock, async.go.get());
}

DLLEXPORT
void Socket::close() noexcept
{
    if (sock) {
        ScCloseSocket(sock);
        sock = 0;
    }
}

DLLEXPORT
void Socket::setSendDeadline(std::optional<std::chrono::milliseconds> deadline)
{
    if (!sock) throw SocketClosed("socket closed");
    if (deadline) {
        ScSocketSetSendDeadline(sock, deadline->count());
    } else {
        ScSocketSetSendDeadline(sock, -1);
    }
}

DLLEXPORT
void Socket::setRecvDeadline(std::optional<std::chrono::milliseconds> deadline)
{
    if (!sock) throw SocketClosed("socket closed");
    if (deadline) {
        ScSocketSetRecvDeadline(sock, deadline->count());
    } else {
        ScSocketSetRecvDeadline(sock, -1);
    }
}

DLLEXPORT
Status Socket::sendPacket(const UDPAddr& remote, const LocalUDPAddr& router, const Slice& dpPath, const Slice& payload)
{
    if (!sock) throw SocketClosed("socket closed");

    ScUDPPacket pkt = {};
    pkt.remote = remote.addr;
    pkt.router = router.addr;
    pkt.dpPath = (ScByte*)(dpPath.ptr());
    pkt.dpPathLen = dpPath.size();
    pkt.dpPathCap = dpPath.capacity();
    pkt.payload = (ScByte*)(payload.ptr());
    pkt.payloadLen = payload.size();
    pkt.payloadCap = payload.capacity();

    return castStatus(ScSendPacket(sock, &pkt));
}

DLLEXPORT
Status Socket::sendPacketLocal(const UDPAddr& remote, const Slice& payload)
{
    if (!sock) throw SocketClosed("socket closed");

    ScUDPPacket pkt = {};
    pkt.remote = remote.addr;
    pkt.payload = (ScByte*)(payload.ptr());
    pkt.payloadLen = payload.size();
    pkt.payloadCap = payload.capacity();

    return castStatus(ScSendPacket(sock, &pkt));
}

DLLEXPORT
void Socket::sendPacketAsync(const UDPAddr& remote, const LocalUDPAddr& router, const Slice& dpPath, const Slice& payload, AsyncOp& async)
{
    if (!sock) throw SocketClosed("socket closed");

    struct Calldata {
        CompletionHandler* handler;
        ScUDPPacket pkt;
    };
    auto calldata = new Calldata{ async.getHandler(), {} };
    calldata->pkt.remote = remote.addr;
    calldata->pkt.router = router.addr;
    calldata->pkt.dpPath = (ScByte*)(dpPath.ptr());
    calldata->pkt.dpPathLen = dpPath.size();
    calldata->pkt.dpPathCap = dpPath.capacity();
    calldata->pkt.payload = (ScByte*)(payload.ptr());
    calldata->pkt.payloadLen = payload.size();
    calldata->pkt.payloadCap = payload.capacity();

    async.go->userdata = calldata;
    async.go->callback = [](ScStatus result, void* userdata) {
        auto data = std::unique_ptr<Calldata>(reinterpret_cast<Calldata*>(userdata));
        if (data->handler) {
            data->handler->execute(castStatus(result));
        }
    };

    ScSendPacketAsync(sock, &calldata->pkt, async.go.get());
}

DLLEXPORT
void Socket::sendPacketLocalAsync(const UDPAddr& remote, const Slice& payload, AsyncOp& async)
{
    if (!sock) throw SocketClosed("socket closed");

    struct Calldata {
        CompletionHandler* handler;
        ScUDPPacket pkt;
    };
    auto calldata = new Calldata{ async.getHandler(), {} };
    calldata->pkt.remote = remote.addr;
    calldata->pkt.payload = (ScByte*)(payload.ptr());
    calldata->pkt.payloadLen = payload.size();
    calldata->pkt.payloadCap = payload.capacity();

    async.go->userdata = calldata;
    async.go->callback = [](ScStatus result, void* userdata) {
        auto data = std::unique_ptr<Calldata>(reinterpret_cast<Calldata*>(userdata));
        if (data->handler) {
            data->handler->execute(castStatus(result));
        }
    };

    ScSendPacketAsync(sock, &calldata->pkt, async.go.get());
}

DLLEXPORT
std::tuple<UDPAddr, LocalUDPAddr, Status> Socket::recvPacket(Slice& dpPath, Slice& payload)
{
    if (!sock) throw SocketClosed("socket closed");

    ScUDPPacket pkt = {};
    pkt.dpPath = reinterpret_cast<ScByte*>(dpPath.ptr());
    pkt.dpPathLen = dpPath.size();
    pkt.dpPathCap = dpPath.capacity();
    pkt.payload = reinterpret_cast<ScByte*>(payload.ptr());
    pkt.payloadLen = payload.size();
    pkt.payloadCap = payload.capacity();

    ScStatus err = ScRecvPacket(sock, &pkt);
    if (err == SC_SUCCESS) {
        dpPath.setSize(pkt.dpPathLen);
        payload.setSize(pkt.payloadLen);
    }

    return std::make_tuple(
        UDPAddr(pkt.remote),
        LocalUDPAddr(pkt.router),
        castStatus(err)
    );
}

DLLEXPORT
std::tuple<UDPAddr, Status> Socket::recvPacket(Slice& payload)
{
    if (!sock) throw SocketClosed("socket closed");

    ScUDPPacket pkt = {};
    pkt.payload = reinterpret_cast<ScByte*>(payload.ptr());
    pkt.payloadLen = payload.size();
    pkt.payloadCap = payload.capacity();

    ScStatus err = ScRecvPacket(sock, &pkt);
    if (err == SC_SUCCESS) {
        payload.setSize(pkt.payloadLen);
    }

    return std::make_tuple(
        UDPAddr(pkt.remote),
        castStatus(err)
    );
}

DLLEXPORT
void Socket::recvPacketAsync(UDPAddr& from, LocalUDPAddr& router, Slice& dpPath, Slice& payload, AsyncOp& async)
{
    if (!sock) throw SocketClosed("socket closed");

    struct Calldata {
        CompletionHandler* handler;
        UDPAddr& from;
        LocalUDPAddr& router;
        Slice& dpPath;
        Slice& payload;
        ScUDPPacket pkt;
    };
    auto calldata = new Calldata{async.getHandler(), from, router, dpPath, payload, {}};
    calldata->pkt.router = router.addr;
    calldata->pkt.dpPath = (ScByte*)(dpPath.ptr());
    calldata->pkt.dpPathLen = dpPath.size();
    calldata->pkt.dpPathCap = dpPath.capacity();
    calldata->pkt.payload = (ScByte*)(payload.ptr());
    calldata->pkt.payloadLen = payload.size();
    calldata->pkt.payloadCap = payload.capacity();

    async.go->userdata = calldata;
    async.go->callback = [](ScStatus result, void* userdata) {
        auto data = std::unique_ptr<Calldata>(reinterpret_cast<Calldata*>(userdata));
        if (result == SC_SUCCESS) {
            data->from = UDPAddr(data->pkt.remote);
            data->router = LocalUDPAddr(data->pkt.router);
            data->dpPath.setSize(data->pkt.dpPathLen);
            data->payload.setSize(data->pkt.payloadLen);
        }
        if (data->handler) {
            data->handler->execute(castStatus(result));
        }
    };
    ScRecvPacketAsync(sock, &calldata->pkt, async.go.get());
}

DLLEXPORT
void Socket::recvPacketAsync(UDPAddr& from, Slice& payload, AsyncOp& async)
{
    if (!sock) throw SocketClosed("socket closed");

    struct Calldata {
        CompletionHandler* handler;
        UDPAddr& from;
        Slice& payload;
        ScUDPPacket pkt;
    };
    auto calldata = new Calldata{async.getHandler(), from, payload, {}};
    calldata->pkt.payload = (ScByte*)(payload.ptr());
    calldata->pkt.payloadLen = payload.size();
    calldata->pkt.payloadCap = payload.capacity();

    async.go->userdata = calldata;
    async.go->callback = [](ScStatus result, void* userdata) {
        auto data = std::unique_ptr<Calldata>(reinterpret_cast<Calldata*>(userdata));
        if (result == SC_SUCCESS) {
            data->from = UDPAddr(data->pkt.remote);
            data->payload.setSize(data->pkt.payloadLen);
        }
        if (data->handler) {
            data->handler->execute(castStatus(result));
        }
    };
    ScRecvPacketAsync(sock, &calldata->pkt, async.go.get());
}

} // namespace scion
