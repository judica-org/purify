// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/bppp.hpp"
#include "purify.hpp"
#include "purify.h"

int purify_public_header_hygiene_cpp_then_c()
{
    return PURIFY_PUBLIC_KEY_BYTES == 64u ? 0 : 1;
}
