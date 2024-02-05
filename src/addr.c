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

#include "snet/snet.h"

#include <assert.h>
#include <string.h>

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

DLLEXPORT
int ScCompLocalUDPAddr(const struct ScLocalUDPAddr* lhs, const struct ScLocalUDPAddr* rhs)
{
    assert(lhs && rhs);
    if (lhs->host.type != rhs->host.type) {
        return (int)rhs->host.type - (int)lhs->host.type;
    }

    if (lhs->host.type == SC_ADDR_TYPE_INVALID) {
        return 0;
    } else if (lhs->host.type == SC_ADDR_TYPE_IPV4) {
        for (int i = 0; i < 4; ++i) {
            if (lhs->host.ip[i] != rhs->host.ip[i]) {
                return rhs->host.ip[i] - lhs->host.ip[i];
            }
        }
    } else if (lhs->host.type == SC_ADDR_TYPE_IPV6) {
        for (int i = 0; i < 16; ++i) {
            if (lhs->host.ip[i] != rhs->host.ip[i]) {
                return rhs->host.ip[i] - lhs->host.ip[i];
            }
        }
        int diff = strcmp(lhs->host.zone, rhs->host.zone);
        if (diff) return diff;
    }

    return rhs->port - lhs->port;
}

DLLEXPORT
int ScCompUDPAddr(const struct ScUDPAddr* lhs, const struct ScUDPAddr* rhs)
{
    assert(lhs && rhs);
    if (lhs->ia != rhs->ia) {
        return rhs->ia - lhs->ia;
    } else {
        return ScCompLocalUDPAddr(&lhs->local, &rhs->local);
    }
}
