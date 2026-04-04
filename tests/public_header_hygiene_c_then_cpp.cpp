// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify.h"
#include "purify.hpp"
#include "purify/bppp.hpp"

int purify_public_header_hygiene_c_then_cpp()
{
    return PURIFY_SECRET_KEY_BYTES == 64u ? 0 : 1;
}
