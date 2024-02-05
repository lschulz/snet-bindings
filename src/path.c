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

#include <string.h>

#if __linux__
#include <arpa/inet.h>
#elif _WIN32
#include <winsock2.h>
#endif

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

struct __attribute__((packed)) InfoField_t
{
    uint8_t flags;   // (1 bit) construction direction flag
                     // (1 bit) peering path flag
                     // (6 bit) reserved flags
    uint8_t rsv;     // reserved
    uint16_t seg_id; // SegID
    uint32_t ts;     // timestamp in Unix time
};

struct __attribute__((packed)) HopField_t
{
    uint8_t flags;    // (1 bit) cons egress router alert
                      // (1 bit) cons ingress router alert
                      // (6 bit) reserved flags
    uint8_t exp;      // expiry time
    uint16_t ingress; // ingress interface in construction direction
    uint16_t egress;  // egress interface in construction direction
    uint8_t mac[6];   // message authentication code
};

#define META_SIZE 4
#define INF_SIZE 8
#define HF_SIZE 12

#define swap(a, b) do { typeof(a) t = a; a = b; b = t;} while (0)

// Reverse a SCION path in-place
DLLEXPORT
ScStatus ScReversePath(ScByte* path, ScSize* len, ScSize cap)
{
    if (!path || !len) return SC_ERROR_INVALID_ARG;
    if (*len == 0) return SC_SUCCESS; // empty path
    if (*len < 4) return SC_ERROR_INVALID_ARG;
    uint32_t pathMeta = 0;
    memcpy(&pathMeta, path, META_SIZE);
    pathMeta = ntohl(pathMeta);

    uint32_t seg2 = pathMeta & 0x3f;
    uint32_t seg1 = (pathMeta >> 6) & 0x3f;
    uint32_t seg0 = (pathMeta >> 12) & 0x3f;
    uint32_t res = (pathMeta >> 18) & 0x3f;
    uint32_t currHop = (pathMeta >> 24) & 0x3f;
    uint32_t currInf = (pathMeta >> 30) & 0x03;

    uint32_t numInf = (seg0 > 0) + (seg1 > 0) + (seg2 > 0);
    uint32_t numHop = seg0 + seg1 + seg2;
    if (numInf < 1) return SC_ERROR_INVALID_ARG;
    if (numHop < 2 || numHop > 64) return SC_ERROR_INVALID_ARG;
    if (*len != META_SIZE + numInf * INF_SIZE + numHop * HF_SIZE) {
        return SC_ERROR_INVALID_ARG;
    }

    // Reverse order of info fields
    unsigned char *inf = &path[META_SIZE];
    if (numInf > 1) {
        struct InfoField_t temp;
        memcpy(&temp, inf, INF_SIZE);
        memcpy(inf, &inf[(numInf-1) * INF_SIZE], INF_SIZE);
        memcpy(&inf[(numInf-1) * INF_SIZE], &temp, INF_SIZE);
    }

    // Reverse cons dir flag
    for (size_t i = 0; i < numInf; ++i) {
        inf[i * INF_SIZE] ^= 1;
    }

    // Reverse order of hop fields
    unsigned char *hfs = &path[META_SIZE + numInf * INF_SIZE];
    for (size_t i = 0, j = numHop-1; i < j; ++i, --j) {
        struct HopField_t temp;
        memcpy(&temp, &hfs[i * HF_SIZE], HF_SIZE);
        memcpy(&hfs[i * HF_SIZE], &hfs[j * HF_SIZE], HF_SIZE);
        memcpy(&hfs[j * HF_SIZE], &temp, HF_SIZE);
    }

    // Update path meta header
    currInf = numInf - currInf - 1;
    currHop = numHop - currHop - 1;

    if (numInf == 2) swap(seg0, seg1);
    else if (numInf == 3) swap(seg1, seg0);

    pathMeta = seg2 | (seg1 << 6) | (seg0 << 12) | (res << 18) | (currHop << 24) | (currInf << 30);
    pathMeta = htonl(pathMeta);
    memcpy(path, &pathMeta, META_SIZE);

    return SC_SUCCESS;
}
