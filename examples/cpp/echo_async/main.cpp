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

#include "common/pch.hpp"
#include "common/message_parser.hpp"

#include <asio.hpp>
#include <getopt.h>

#include <cctype>
#include <cstddef>
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

#if __unix__
namespace posix = asio::posix;
#elif _WIN32
namespace windows = asio::windows;
#endif

struct Arguments
{
    std::string sciond;
    std::string localAddr;
    std::string remoteAddr;
    std::vector<char> message;
};

bool parseArgs(int argc, char* argv[], Arguments& args)
{
    static const option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "sciond", required_argument, NULL, 'd'},
        { "local", required_argument, NULL, 'l' },
        { "remote", required_argument, NULL, 'r' },
        { "msg", required_argument, NULL, 'm' },
        {}
    };

    int opt = -1;
    while ((opt = getopt_long_only(argc, argv, "", longopts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'd':
            args.sciond = optarg;
            break;
        case 'l':
            args.localAddr = optarg;
            break;
        case 'r':
            args.remoteAddr = optarg;
            break;
        case 'm':
        {
            int errorPos = 0;
            std::tie(args.message, errorPos) = parseString(optarg);
            if (errorPos >= 0) {
                std::cout << "Error parsing message at char " << errorPos << '\n';
                return false;
            }
            break;
        }
        case 'h':
        default:
            std::cout
                << "Usage: echo-async -sciond DAEMON -local LOCAL -remote REMOTE -msg MESSAGE\n"
                << "  DAEMON  SCION Daemon address (default \"127.0.0.1:30255\")\n"
                << "  LOCAL   Local IP address and port (required for servers)\n"
                << "  REMOTE  Scion address of the remote server (only for clients)\n"
                << "  MESSAGE The message clients will send to the server\n";
            return false;
        }
    }

    // Check for mandatory options
    if (args.localAddr.empty()) {
        std::cout << "Local address is a mandatory option\n";
        return false;
    }

    return true;
}

class SCMPHandler : public scion::SCMPHandler
{
public:
    void handle(const ScSCMPMessage* msg) override
    {
        switch (msg->type)
        {
        case SC_SCMP_TYPE_DESTINATION_UNREACHABLE:
        {
            auto args = reinterpret_cast<const ScSCMPDestinationUnreachable*>(msg);
            std::cerr << "SCMP: Destination Unreachable (" << args->code << ")\n";
            break;
        }
        case SC_SCMP_TYPE_PACKET_TOO_BIG:
        {
            auto args = reinterpret_cast<const ScSCMPPacketTooBig*>(msg);
            std::cerr << "SCMP: Packet Too Big (MTU is " << args->mtu << ")\n";
            break;
        }
        case SC_SCMP_TYPE_PARAMETER_PROBLEM:
        {
            auto args = reinterpret_cast<const ScSCMPParameterProblem*>(msg);
            std::cerr << "SCMP: Parameter Problem (" << args->code << "at byte " << args->pointer << ")\n";
            break;
        }
        case SC_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN:
        {
            auto args = reinterpret_cast<const ScSCMPExternalInterfaceDown*>(msg);
            std::cerr
                << "SCMP: External Interface Down (" << args->code << ") AS "
                << scion::IA(args->originator) << " Interface " << args->interface << "=\n";
            break;
        }
        case SC_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN:
        {
            auto args = reinterpret_cast<const ScSCMPInternalConnectivityDown*>(msg);
            std::cerr
                << "SCMP: Internal Connectivity Down (" << args->code << ") >"
                << args->ingressIf << ' ' << scion::IA(args->originator) << ' ' << args->egressIf << ">\n";
            break;
        }
        }
    }
} scmpHandler;

class Server
{
public:
    Server()
        : socket(scmpHandler)
#if __linux__
        , asyncOp(std::make_unique<scion::CompletionEventFD>())
#elif _WIN32
        , asyncOp(std::make_unique<scion::CompletionEvent>())
#else
        , asyncOp(std::make_unique<scion::CompletionPipe>())
#endif
        , signals(ioContext, SIGINT, SIGTERM)
        , event(ioContext)
    {
#if __linux__
        completionHandler = dynamic_cast<scion::CompletionEventFD*>(asyncOp.getHandler());
#elif _WIN32
        completionHandler = dynamic_cast<scion::CompletionEvent*>(asyncOp.getHandler());
#else
        completionHandler = dynamic_cast<scion::CompletionPipe*>(asyncOp.getHandler());
#endif
        if (!completionHandler) throw std::bad_cast();
        event.assign(completionHandler->getHandle());
    }

    int listen(Arguments& args)
    {
        using namespace scion;
        using namespace std::placeholders;

        auto loc = LocalUDPAddr::fromString(args.localAddr);
        if (!loc) {
            std::cerr << "Invalid address: " << args.remoteAddr << '\n';
            return EXIT_FAILURE;
        }
        local = *loc;

        hostCtx.initAsync(args.sciond.c_str(), asyncOp);
    #if _WIN32
        event.async_wait(std::bind(&Server::hostInitialized, this, _1));
    #else
        event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Server::hostInitialized, this, _1));
    #endif
        signals.async_wait(std::bind(&Server::cancel, this, _1, _2));

        ioContext.run();
        return EXIT_SUCCESS;
    }

private:
    void hostInitialized(const std::error_code& error)
    {
        using namespace scion;
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

    #if _WIN32
        auto status = asyncOp.getStatus();
    #else
        auto status = completionHandler->wait();
    #endif
        if (status != Status::Success) {
            std::cerr << "Host context initialization failed (" << status << ")\n";
            throwOnAbnormal(status);
        }

        socket.openAsync(hostCtx, local, asyncOp);
    #if _WIN32
        event.async_wait(std::bind(&Server::connected, this, _1));
    #else
        event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Server::connected, this, _1));
    #endif
    }

    void connected(const std::error_code& error)
    {
        using namespace scion;
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

    #if _WIN32
        auto status = asyncOp.getStatus();
    #else
        auto status = completionHandler->wait();
    #endif
        if (status != Status::Success) {
            std::cerr << "Opening connection failed (" << status << ")\n";
            throwOnAbnormal(status);
        }

        std::cout << "Server listening at " << UDPAddr(hostCtx.getLocalIA(), local) << '\n';

        path = Slice::Uninitialized(pathBuf);
        payload = Slice::Uninitialized(payloadBuf);
        socket.recvPacketAsync(remote, router, path, payload, asyncOp);
    #if _WIN32
        event.async_wait(std::bind(&Server::received, this, _1));
    #else
        event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Server::received, this, _1));
    #endif
    }

    void received(const std::error_code& error)
    {
        using namespace scion;
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

    #if _WIN32
        auto status = asyncOp.getStatus();
    #else
        auto status = completionHandler->wait();
    #endif
        if (status != Status::Success) {
            std::cerr << "Reading from socket failed (" << status << ")\n";
            throwOnAbnormal(status);
        }

        std::cerr << "Received " << payload.size() << " bytes from " << remote << ":\n";
        printBuffer(std::cout, payload.ptr(), payload.size()) << "\n";

        status = reversePath(path);
        if (status != Status::Success) {
            std::cerr << "Cannot reverse path (" << status << ")\n";
            throwOnAbnormal(status);
        }

        socket.sendPacketAsync(remote, router, path, payload, asyncOp);
    #if _WIN32
        event.async_wait(std::bind(&Server::sent, this, _1));
    #else
        event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Server::sent, this, _1));
    #endif
    }

    void sent(const std::error_code& error)
    {
        using namespace scion;
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

    #if _WIN32
        auto status = asyncOp.getStatus();
    #else
        auto status = completionHandler->wait();
    #endif
        if (status != Status::Success) {
            std::cerr << "Writing to socket failed (" << status << ")\n";
            throwOnAbnormal(status);
        }

        path = Slice::Uninitialized(pathBuf);
        payload = Slice::Uninitialized(payloadBuf);
        socket.recvPacketAsync(remote, router, path, payload, asyncOp);
    #if _WIN32
        event.async_wait(std::bind(&Server::received, this, _1));
    #else
        event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Server::received, this, _1));
    #endif
    }

    void cancel(const asio::error_code& error, int signal)
    {
        using namespace std::chrono_literals;
        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
        }
        if (error || signal == SIGINT || signal == SIGTERM) {
            std::cerr << "Cancelling..." << std::endl;
            asyncOp.cancel();
            // To my knowledge, there are only two ways to cancel a read or write operation on the
            // underlying Go socket, closing the socket or setting the deadline to a value in the
            // past.
            if (socket.isOpen()) {
                socket.setRecvDeadline(0ms);
                socket.setSendDeadline(0ms);
            }
        }
    }

private:
#if __linux__
    scion::CompletionEventFD* completionHandler;
#elif _WIN32
    scion::CompletionEvent* completionHandler;
#else
    scion::CompletionPipe* completionHandler;
#endif
    scion::LocalUDPAddr local;
    scion::HostCtx hostCtx;
    scion::Socket socket;
    scion::AsyncOp asyncOp;

    asio::io_context ioContext;
    asio::signal_set signals;
#if __unix__
    posix::stream_descriptor event;
#elif _WIN32
    windows::object_handle event;
#endif

    scion::UDPAddr remote;
    scion::LocalUDPAddr router;
    scion::Slice path, payload;
    std::array<std::byte, 512> pathBuf;
    std::array<std::byte, 4096> payloadBuf;
};

class Client
{
public:
    Client()
        : socket(scmpHandler)
#if __linux__
        , asyncOp(std::make_unique<scion::CompletionEventFD>())
#elif _WIN32
        , asyncOp(std::make_unique<scion::CompletionEvent>())
#else
        , asyncOp(std::make_unique<scion::CompletionPipe>())
#endif
        , signals(ioContext, SIGINT, SIGTERM)
        , event(ioContext)
    {
#if __linux__
        completionHandler = dynamic_cast<scion::CompletionEventFD*>(asyncOp.getHandler());
#elif _WIN32
        completionHandler = dynamic_cast<scion::CompletionEvent*>(asyncOp.getHandler());
#else
        completionHandler = dynamic_cast<scion::CompletionPipe*>(asyncOp.getHandler());
#endif
        if (!completionHandler) throw std::bad_cast();
        event.assign(completionHandler->getHandle());
    }

    int connect(Arguments& args)
    {
        using namespace scion;
        using namespace std::placeholders;

        auto src = LocalUDPAddr::fromString(args.localAddr);
        if (!src) {
            std::cerr << "Invalid address: " << args.remoteAddr << '\n';
            return EXIT_FAILURE;
        }
        local = *src;
        auto dst = UDPAddr::fromString(args.remoteAddr);
        if (!dst) {
            std::cerr << "Invalid address: " << args.remoteAddr << '\n';
            return EXIT_FAILURE;
        }
        remote = *dst;

        auto v = std::span(args.message)
            | std::views::transform([](auto x) { return static_cast<std::byte>(x); });
        payloadBuf.assign(v.begin(), v.end());

        hostCtx.initAsync(args.sciond.c_str(), asyncOp);
    #if _WIN32
        event.async_wait(std::bind(&Client::hostInitialized, this, _1));
    #else
        event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Client::hostInitialized, this, _1));
    #endif
        signals.async_wait(std::bind(&Client::cancel, this, _1, _2));

        ioContext.run();
        return EXIT_SUCCESS;
    }

private:
    void hostInitialized(const std::error_code& error)
    {
        using namespace scion;
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

    #if _WIN32
        auto status = asyncOp.getStatus();
    #else
        auto status = completionHandler->wait();
    #endif
        if (status != Status::Success) {
            std::cerr << "Host context initialization failed (" << status << ")\n";
            throwOnAbnormal(status);
        }

        socket.openAsync(hostCtx, local, asyncOp);
    #if _WIN32
        event.async_wait(std::bind(&Client::connected, this, _1));
    #else
        event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Client::connected, this, _1));
    #endif
    }

    void connected(const std::error_code& error)
    {
        using namespace scion;
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

    #if _WIN32
        auto status = asyncOp.getStatus();
    #else
        auto status = completionHandler->wait();
    #endif
        if (status != Status::Success) {
            std::cerr << "Opening connection failed (" << status << ")\n";
            throwOnAbnormal(status);
        }

        if (remote.getIA() == hostCtx.getLocalIA()) {
            sendPacket(nullptr);
        } else {
            uint64_t flags = SC_FLAG_PATH_REFRESH | SC_FLAG_PATH_GET_IFACES | SC_FLAG_PATH_GET_META;
            hostCtx.queryPathsAsync(paths, remote.getIA(), flags, asyncOp);
        #if _WIN32
            event.async_wait(std::bind(&Client::gotPaths, this, _1));
        #else
            event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Client::gotPaths, this, _1));
        #endif
        }
    }

    void gotPaths(const std::error_code& error)
    {
        using namespace scion;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

    #if _WIN32
        auto status = asyncOp.getStatus();
    #else
        auto status = completionHandler->wait();
    #endif
        if (status != Status::Success) {
            std::cerr << "No path to destination (" << status << ")\n";
            throwOnAbnormal(status);
        }

        sendPacket(paths[0].get());
    }

    void sendPacket(scion::Path* path)
    {
        using namespace scion;
        using namespace std::placeholders;

        payload = Slice(payloadBuf);
        if (path) {
            socket.sendPacketAsync(remote, path->nextHop, Slice(path->dp), payload, asyncOp);
        } else {
            socket.sendPacketLocalAsync(remote, payload, asyncOp);
        }
    #if _WIN32
        event.async_wait(std::bind(&Client::sent, this, _1));
    #else
        event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Client::sent, this, _1));
    #endif
    }

    void sent(const std::error_code& error)
    {
        using namespace scion;
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

    #if _WIN32
        auto status = asyncOp.getStatus();
    #else
        auto status = completionHandler->wait();
    #endif
        if (status != Status::Success) {
            std::cerr << "Writing to socket failed(" << status << ")\n";
            throwOnAbnormal(status);
        }

        payloadBuf.resize(4096);
        payload = Slice(payloadBuf);
        socket.recvPacketAsync(remote, payload, asyncOp);
    #if _WIN32
        event.async_wait(std::bind(&Client::received, this, _1));
    #else
        event.async_wait(posix::stream_descriptor::wait_read, std::bind(&Client::received, this, _1));
    #endif
    }

    void received(const std::error_code& error)
    {
        using namespace scion;
        using namespace std::placeholders;

        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
            return;
        }

    #if _WIN32
        auto status = asyncOp.getStatus();
    #else
        auto status = completionHandler->wait();
    #endif
        if (status != Status::Success) {
            std::cerr << "Reading from socket failed (" << status << ")\n";
            throwOnAbnormal(status);
        }

        std::cerr << "Received " << payload.size() << " bytes from " << remote << ":\n";
        printBuffer(std::cout, payload.ptr(), payload.size()) << "\n";
        ioContext.stop();
    }

    void cancel(const asio::error_code& error, int signal)
    {
        using namespace std::chrono_literals;
        if (error) {
            std::cerr << "ASIO error: " << error.message() << std::endl;
        }
        if (error || signal == SIGINT || signal == SIGTERM) {
            std::cerr << "Cancelling..." << std::endl;
            asyncOp.cancel();
            // To my knowledge, there are only two ways to cancel a read or write operation on the
            // underlying Go socket, closing the socket or setting the deadline to a value in the
            // past.
            if (socket.isOpen()) {
                socket.setRecvDeadline(0ms);
                socket.setSendDeadline(0ms);
            }
        }
    }

private:
#if __linux__
    scion::CompletionEventFD* completionHandler;
#elif _WIN32
    scion::CompletionEvent* completionHandler;
#else
    scion::CompletionPipe* completionHandler;
#endif
    scion::LocalUDPAddr local;
    scion::HostCtx hostCtx;
    scion::Socket socket;
    scion::AsyncOp asyncOp;

    asio::io_context ioContext;
    asio::signal_set signals;
#if __unix__
    posix::stream_descriptor event;
#elif _WIN32
    windows::object_handle event;
#endif

    scion::UDPAddr remote;
    scion::PathVec paths;
    scion::Slice payload;
    std::vector<std::byte> payloadBuf;
};

int main(int argc, char* argv[])
{
    Arguments args;
    if (!parseArgs(argc, argv, args)) {
        return EXIT_FAILURE;
    }

    try {
        if (args.remoteAddr.empty()) {
            auto server = std::make_unique<Server>();
            return server->listen(args);
        }
        else {
            if (args.message.empty()) args.message = {'H', 'e', 'l', 'l', 'o', '!'};
            auto client = std::make_unique<Client>();
            return client->connect(args);
        }
    }
    catch (const scion::Exception& e) {
        std::cerr << "SCION error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
