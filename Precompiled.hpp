#pragma once

#ifndef PRECOMPILED_HPP
#    define PRECOMPILED_HPP

#    include "ProcessAuditing.hrc"
#    include "TargetVer.hpp"

#    define WIN32_NO_STATUS
#    include <Windows.h> // Windows must be first in the list (before other Windows headers)
#    undef WIN32_NO_STATUS

/* ****************************** Third-Party ****************************** */
#    include "include/json.hpp"

// clang-format off
// concurrentqueue must come before blockingconcurrentqueue
#include "include/concurrentqueue.h"
#include "include/blockingconcurrentqueue.h"
// clang-format on

/* **************************** Standard Library **************************** */
#    include <atomic>
#    include <fstream>
#    include <iomanip>
#    include <iostream>
#    include <memory>
#    include <mutex>
#    include <sstream>
#    include <string>
#    include <thread>
#    include <vector>

/* *************************** Windows Libraries *************************** */
#    include <ntstatus.h>
#    include <winerror.h>
#    include <strsafe.h>
#    include <psapi.h>
#    include <bcrypt.h>
#    pragma comment(lib, "bcrypt.lib")

#endif // PRECOMPILED_HPP
