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

#ifndef AZEROTHCORE_SRP6_H
#define AZEROTHCORE_SRP6_H

#include "AuthDefines.h"
#include "Cryptography/BigNumber.h"
#include "Cryptography/CryptoHash.h"
#include <optional>

namespace Acore::Crypto
{
    class AC_COMMON_API SRP6
    {
    public:
        static constexpr std::size_t SALT_LENGTH = 32;
        using Salt = std::array<uint8, SALT_LENGTH>;

        static constexpr std::size_t VERIFIER_LENGTH = 32;
        using Verifier = std::array<uint8, VERIFIER_LENGTH>;

        static constexpr std::size_t EPHEMERAL_KEY_LENGTH = 32;
        using EphemeralKey = std::array<uint8, EPHEMERAL_KEY_LENGTH>;

        static std::array<uint8, 1> const g;
        static std::array<uint8, 32> const N;

        static EphemeralKey GetNWireFormat();

        static std::pair<Salt, Verifier> MakeRegistrationData(std::string const& username, std::string const& password);

        static bool CheckLogin(std::string const& username, std::string const& password, Salt const& salt, Verifier const& verifier)
        {
            return (verifier == CalculateVerifier(username, password, salt));
        }

        static SHA1::Digest GetSessionVerifier(EphemeralKey const& A, SHA1::Digest const& clientM, SessionKey const& K)
        {
            return SHA1::GetDigestOf(A, clientM, K);
        }

        SRP6(std::string const& username, Salt const& salt, Verifier const& verifier);
        std::optional<SessionKey> VerifyChallengeResponse(EphemeralKey const& A, SHA1::Digest const& clientM);

    private:
        bool _used = false;

        static Verifier CalculateVerifier(std::string const& username, std::string const& password, Salt const& salt);
        static SessionKey SHA1Interleave(EphemeralKey const& S);

        static BigNumber const _g;
        static BigNumber const _N;

        static EphemeralKey _B(BigNumber const& b, BigNumber const& v) { return ((_g.ModExp(b, _N) + (v * 3)) % N).ToByteArray<EPHEMERAL_KEY_LENGTH>(); }

        SHA1::Digest const _I;
        BigNumber const _b;
        BigNumber const _v;

    public:
        Salt const s;
        EphemeralKey const B;
    };
}

#endif