/*
 * Simplified Errors.h for client-simulator standalone build
 */

#ifndef _ACORE_ERRORS_H_
#define _ACORE_ERRORS_H_

#include "Define.h"
#include <cstdlib>
#include <string>
#include <string_view>
#include <iostream>

#define ASSERT(cond, ...) do { if (!(cond)) { \
    std::cerr << "ASSERT failed: " #cond << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
    std::abort(); \
}} while(0)

#define ASSERT_NODEBUGINFO(cond, ...) do { if (!(cond)) { \
    std::cerr << "ASSERT failed: " #cond << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
    std::abort(); \
}} while(0)

#define ABORT(...) do { \
    std::cerr << "ABORT at " << __FILE__ << ":" << __LINE__ << std::endl; \
    std::abort(); \
} while(0)

#define WPAssert(cond, ...) ASSERT(cond)
#define WPAbort(...) ABORT()

#endif
