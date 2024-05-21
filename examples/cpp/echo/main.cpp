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
#include "ncurses_helper.hpp"

#include <getopt.h>

#include <cassert>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

#if _WIN32
bool isKeyPressed(HANDLE hConsoleInput, WORD vKey)
{
    DWORD eventCount = 0;
    INPUT_RECORD buffer[8];
    while (true) {
        GetNumberOfConsoleInputEvents(hConsoleInput, &eventCount);
        if (eventCount == 0) break;
        DWORD recordsRead = 0;
        ReadConsoleInput(hConsoleInput, buffer, ARRAYSIZE(buffer), &recordsRead);
        for (DWORD i = 0; i < recordsRead; ++i) {
            if (buffer[i].EventType == KEY_EVENT) {
                const auto &keyEvent = buffer[i].Event.KeyEvent;
                if (keyEvent.bKeyDown && keyEvent.wVirtualKeyCode == vKey)
                    return true;
            }
        }
    }
    return false;
}

#define CON_CURSES(x)
#define CON_WIN32(x) x

#else // _WIN32
#include "ncurses_helper.hpp"

#define CON_CURSES(x) x
#define CON_WIN32(x)

#endif // _WIN32

struct Arguments
{
    std::string sciond;
    std::string localAddr;
    std::string remoteAddr;
    std::vector<char> message;
    int count = 1;
    bool interactive = false;
    bool show_path = false;
    bool quiet = false;
};

static bool parseArgs(int argc, char* argv[], Arguments& args)
{
    static const option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "sciond", required_argument, NULL, 'd'},
        { "local", required_argument, NULL, 'l' },
        { "remote", required_argument, NULL, 'r' },
        { "msg", required_argument, NULL, 'm' },
        { "count", required_argument, NULL, 'c' },
        { "interactive", no_argument, NULL, 'i'},
        { "show-path", no_argument, NULL, 's'},
        { "quiet", no_argument, NULL, 'q'},
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
        case 'c':
        {
            std::stringstream stream(optarg);
            stream >> args.count;
            if (!stream || args.count < 0) {
                std::cout << "Invalid value for COUNT\n";
                return false;
            }
            break;
        }
        case 'i':
            args.interactive = true;
            break;
        case 's':
            args.show_path = true;
            break;
        case 'q':
            args.quiet = true;
            break;
        case 'h':
        default:
            std::cout
                << "Usage: echo -sciond DAEMON -local LOCAL -remote REMOTE -msg MESSAGE -count COUNT\n"
                << "  DAEMON  SCION Daemon address (default \"127.0.0.1:30255\")\n"
                << "  LOCAL   Local IP address and port (required for servers)\n"
                << "  REMOTE  Scion address of the remote server (only for clients)\n"
                << "  MESSAGE The message clients will send to the server\n"
                << "  COUNT   Number of messages to send\n"
                << "Optional Flags:\n"
                << "  -interactive Prompt for path selection (client only)\n"
                << "  -show-path   Print the paths taken by each packet\n"
                << "  -quiet       Only print response from server (client only)\n";
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

std::unique_ptr<scion::Path> selectPath(scion::HostCtx& hostCtx, scion::IA dest, bool interactive)
{
    using namespace scion;
    using namespace std::chrono_literals;

    Status status;
    PathVec paths;
    std::tie(paths, status) = hostCtx.queryPaths(dest, SC_FLAG_PATH_GET_IFACES, 0ms);
    if (status != Status::Success) {
        std::cerr << "No paths to destination (" << status << ")\n";
        return nullptr;
    }
    if (interactive) {
        while (true) {
            unsigned int i = 0;
            for (const auto& path : paths) {
                std::cerr << '[' << i++ << "] " << *path << '\n';
            }
            std::cerr << "Choose path: ";
            unsigned int selection = 0;
            std::cin >> selection;
            if (selection < paths.size()) {
                return std::move(paths[selection]);
            } else {
                std::cerr << "Invalid selection\n";
            }
        }
    } else {
        return std::move(paths.front());
    }
}

int runServer(Arguments& args)
{
    using namespace scion;
    using namespace std::chrono_literals;

    Status status;
    HostCtx hostCtx(scmpHandler);
    Socket socket;
    UDPAddr from;
    LocalUDPAddr lastHop;
    std::vector<std::byte> pathBuf(1024), buffer(2028);

    auto local = LocalUDPAddr::fromString(args.localAddr);
    if (!local) {
        std::cerr << "Invalid address: " << args.localAddr << '\n';
        return EXIT_FAILURE;
    }

    status = hostCtx.init(args.sciond.c_str(), 1s);
    if (status != Status::Success) {
        std::cerr << "Host initialization failed (" << status << ")\n";
        return EXIT_FAILURE;
    }
    status = socket.open(hostCtx, *local, 1s);
    if (status != Status::Success) {
        std::cerr << "Cannot open connection (" << status << ")\n";
        return EXIT_FAILURE;
    }

    CON_WIN32(HANDLE hConsoleInput = GetStdHandle(STD_INPUT_HANDLE));
    CON_CURSES(ncurses::initServer());

    std::stringstream stream;
    hostCtx.getLocalIA();
    stream << "Server listening at " << UDPAddr(hostCtx.getLocalIA(), *local) << '\n';
    stream << "Press q to quit.\n";
    CON_WIN32(std::cout << stream.str());
    CON_CURSES(ncurses::print(stream.str().c_str()));

    CON_WIN32(while (!isKeyPressed(hConsoleInput, TCHAR('Q'))))
    CON_CURSES(while (ncurses::getChar() != 'q'))
    {
        CON_CURSES(ncurses::refreshScreen());

        auto now = std::chrono::seconds(std::time(nullptr));
        socket.setRecvDeadline(std::chrono::milliseconds(now + 100ms));
        Slice path(pathBuf);
        Slice payload(buffer);

        std::tie(from, lastHop, status) = socket.recvPacket(path, payload);
        if (status == Status::Success) {
            stream.str("");
            stream.clear();
            stream << "Received " << payload.size() << " bytes from " << from << ":\n";
            printBuffer(stream, payload.ptr(), payload.size()) << '\n';
            if (args.show_path) {
                stream << "Raw path:\n";
                printBuffer(stream, path.ptr(), path.size()) << '\n';
            }
            CON_WIN32(std::cout << stream.str());
            CON_CURSES(ncurses::print(stream.str().c_str()));

            if (reversePath(path) == Status::Success) {
                socket.sendPacket(from, lastHop, path, payload);
            }
        }
    }
    CON_CURSES(ncurses::endServer());

    return EXIT_SUCCESS;
}

int runClient(Arguments& args)
{
    using namespace scion;
    using namespace std::chrono_literals;

    Status status;
    HostCtx hostCtx(scmpHandler);
    Socket socket;
    UDPAddr from;
    LocalUDPAddr lastHop;
    std::vector<std::byte> pathBuf(1024), buffer(2028);

    auto src = LocalUDPAddr::fromString(args.localAddr);
    if (!src) {
        std::cerr << "Invalid address: " << args.localAddr << '\n';
        return EXIT_FAILURE;
    }
    auto dest = UDPAddr::fromString(args.remoteAddr);
    if (!dest) {
        std::cerr << "Invalid address: " << args.remoteAddr << '\n';
        return EXIT_FAILURE;
    }

    status = hostCtx.init(args.sciond.c_str(), 1s);
    if (status != Status::Success) {
        std::cerr << "Host initialization failed (" << status << ")\n";
        return EXIT_FAILURE;
    }
    std::unique_ptr<Path> path;
    if (dest->getIA() != hostCtx.getLocalIA()) {
        path = selectPath(hostCtx, dest->getIA(), args.interactive);
        if (!path) return EXIT_FAILURE;
    }

    status = socket.open(hostCtx, *src, 1s);
    if (status != Status::Success) {
        std::cerr << "Cannot open connection (" << status << ")\n";
    }

    Slice message(reinterpret_cast<std::byte*>(args.message.data()), args.message.size());
    for (int i = 0; i < args.count; ++i) {
        if (path) {
            socket.sendPacket(*dest, path->nextHop, Slice(path->dp), message);
        } else {
            socket.sendPacketLocal(*dest, message);
        }

        auto now = std::chrono::seconds(std::time(nullptr));
        socket.setRecvDeadline(std::chrono::milliseconds(now + 5s));
        Slice respPath(pathBuf), payload(buffer);
        if (!args.show_path) {
            std::tie(from, status) = socket.recvPacket(payload);
        } else {
            std::tie(from, lastHop, status) = socket.recvPacket(respPath, payload);
        }
        if (status == Status::Success) {
            if (!args.quiet) {
                std::cerr << "Received " << payload.size() << " bytes:\n";
                printBuffer(std::cout, payload.ptr(), payload.size()) << '\n';
                if (args.show_path) {
                    std::cerr << "Raw path:\n";
                    printBuffer(std::cerr, respPath.ptr(), respPath.size());
                }
            } else {
                printEscapedString(std::cout, (char*)payload.ptr(), payload.size()) << '\n';
            }
        }
    }

    return EXIT_SUCCESS;
}

int main(int argc, char* argv[])
{
    Arguments args;
    if (!parseArgs(argc, argv, args)) {
        return EXIT_FAILURE;
    }

    if (args.remoteAddr.empty()) {
        return runServer(args);
    }
    else {
        if (args.message.empty()) args.message = {'H', 'e', 'l', 'l', 'o', '!'};
        return runClient(args);
    }
}
