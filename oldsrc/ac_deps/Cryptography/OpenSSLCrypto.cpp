/*
 * This file is part of the AzerothCore Project. See AUTHORS file for Copyright information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "OpenSSLCrypto.h"
#include <openssl/crypto.h>

void OpenSSLCrypto::threadsSetup()
{
    // OpenSSL 1.1: No provider setup needed
    // OpenSSL 3.0: Uncomment below to enable legacy provider
    // OSSL_PROVIDER_load(nullptr, "legacy");
}

void OpenSSLCrypto::threadsCleanup()
{
    // No cleanup needed for OpenSSL 1.1
}
