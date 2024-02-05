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

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "snet/snet.h"
#include "snet/snet.hpp"

#include <array>
#include <cstring>
#include <string_view>
#include <utility>

constexpr std::byte operator ""_b(unsigned long long i)
{
    return std::byte{static_cast<unsigned char>(i)};
}

TEST_CASE("handling of AS-local UDP addresses")
{
    static const std::array<std::pair<const char*, ScLocalUDPAddr>, 3> cases = {
        std::make_pair("127.0.0.1:5000", ScLocalUDPAddr{
            {SC_ADDR_TYPE_IPV4, {127, 0, 0, 1}, {}}, 5000
        }),
        std::make_pair("[::1]:5000", ScLocalUDPAddr{
            {SC_ADDR_TYPE_IPV6, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, {}}, 5000
        }),
        std::make_pair("[fe80::1234:5678:9abc:def0%eth1]:5000", ScLocalUDPAddr{
            {SC_ADDR_TYPE_IPV6,
                {0xfe, 0x80, 0, 0, 0, 0, 0, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
                {'e', 't', 'h', '1'}
            }, 5000
        }),
    };

    for (auto& i : cases) {
        CAPTURE(i.first);
        auto len = std::strlen(i.first);

        ScLocalUDPAddr addr;
        REQUIRE(ScParseLocalUDPAddr(i.first, &addr) == SC_SUCCESS);
        REQUIRE(ScCompLocalUDPAddr(&addr, &i.second) == 0);

        REQUIRE(ScParseLocalUDPAddrN(i.first, len, &addr) == SC_SUCCESS);
        REQUIRE(ScCompLocalUDPAddr(&addr, &i.second) == 0);

        if (i.second.host.zone[0] == 0) { // test fails because zone id is not included in string
            char str[128];
            ScSize cap = 10;
            REQUIRE(ScFormatLocalUDPAddr(&i.second, str, &cap) == SC_ERROR_BUFFER_INSUFFICIENT);
            CHECK(cap == len + 1);
            REQUIRE(cap <= sizeof(str));
            REQUIRE(ScFormatLocalUDPAddr(&i.second, str, &cap) == SC_SUCCESS);
            CHECK(str == std::string_view(i.first));
        }
    }
}

TEST_CASE("handling of global UDP addresses")
{
    static const std::array<std::pair<const char*, ScUDPAddr>, 3> cases = {
        std::make_pair("1-ff00:0:1,127.0.0.1:5000", ScUDPAddr{
            0x1ff0000000001, {{SC_ADDR_TYPE_IPV4, {127, 0, 0, 1}, {}}, 5000}
        }),
        std::make_pair("1-ff00:0:1,[::1]:5000", ScUDPAddr{
            0x1ff0000000001, {{SC_ADDR_TYPE_IPV6, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, {}}, 5000}
        }),
        std::make_pair("1-ff00:0:1,[fe80::1234:5678:9abc:def0%eth1]:5000", ScUDPAddr{
            0x1ff0000000001, {{SC_ADDR_TYPE_IPV6,
                {0xfe, 0x80, 0, 0, 0, 0, 0, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
                {'e', 't', 'h', '1'}
            }, 5000}
        }),
    };

    for (auto& i : cases) {
        CAPTURE(i.first);
        auto len = std::strlen(i.first);

        ScUDPAddr addr;
        REQUIRE(ScParseUDPAddr(i.first, &addr) == SC_SUCCESS);
        REQUIRE(ScCompUDPAddr(&addr, &i.second) == 0);

        REQUIRE(ScParseUDPAddrN(i.first, len, &addr) == SC_SUCCESS);
        REQUIRE(ScCompUDPAddr(&addr, &i.second) == 0);

        char str[128];
        ScSize cap = 10;
        REQUIRE(ScFormatUDPAddr(&i.second, str, &cap) == SC_ERROR_BUFFER_INSUFFICIENT);
        CHECK(cap == len + 1);
        REQUIRE(cap <= sizeof(str));
        REQUIRE(ScFormatUDPAddr(&i.second, str, &cap) == SC_SUCCESS);
        CHECK(str == std::string_view(i.first));
    }
}

TEST_CASE("LocalUDPAddr")
{
    using namespace scion;

    std::array<std::byte, 4> ipv4 = {
        127_b, 0_b, 0_b, 1_b
    };
    LocalUDPAddr addr4(ipv4, 1000);
    CHECK(addr4.getType() == HostAddrType::IPv4);
    CHECK(addr4.getIPv4() == ipv4);
    CHECK(addr4.getPort() == 1000);

    std::array<std::byte, 16> ipv6 = {
        0xfe_b, 0x80_b, 0_b, 0_b, 0_b, 0_b, 0_b, 0x00_b,
        0x12_b, 0x34_b, 0x56_b, 0x78_b, 0x9a_b, 0xbc_b, 0xde_b, 0xf0_b
    };
    LocalUDPAddr addr6(ipv6, 1000, "interface_name_");
    CHECK(addr6.getType() == HostAddrType::IPv6);
    CHECK(addr6.getIPv6() == ipv6);
    CHECK(addr6.getPort() == 1000);
    CHECK(addr6.getZone() == "interface_name_");

    CHECK_THROWS_AS([&ipv6]() {
        LocalUDPAddr addr6(ipv6, 1000, "long_interface_name");
    }(), InvalidArg);
}

TEST_CASE("UDPAddr")
{
    using namespace scion;

    std::array<std::byte, 4> ipv4 = {
        127_b, 0_b, 0_b, 1_b
    };
    UDPAddr addr4(IA{1}, ipv4, 1000);
    CHECK(addr4.getIA() == IA{1});
    CHECK(addr4.getType() == HostAddrType::IPv4);
    CHECK(addr4.getIPv4() == ipv4);
    CHECK(addr4.getPort() == 1000);

    std::array<std::byte, 16> ipv6 = {
        0xfe_b, 0x80_b, 0_b, 0_b, 0_b, 0_b, 0_b, 0x00_b,
        0x12_b, 0x34_b, 0x56_b, 0x78_b, 0x9a_b, 0xbc_b, 0xde_b, 0xf0_b
    };
    UDPAddr addr6(IA{1}, ipv6, 1000, "interface_name_");
    CHECK(addr6.getIA() == IA{1});
    CHECK(addr6.getType() == HostAddrType::IPv6);
    CHECK(addr6.getIPv6() == ipv6);
    CHECK(addr6.getPort() == 1000);
    CHECK(addr6.getZone() == "interface_name_");

    CHECK_THROWS_AS([&ipv6]() {
        UDPAddr addr6(IA{1}, ipv6, 1000, "long_interface_name");
    }(), InvalidArg);
}
