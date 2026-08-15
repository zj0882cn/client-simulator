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

#include "SRP6.h"
#include "Cryptography/CryptoRandom.h"
#include "Utilities/Util.h"
#include <functional>

using SHA1 = Acore::Crypto::SHA1;
using SRP6 = Acore::Crypto::SRP6;

/*static*/ std::array<uint8, 1> const SRP6::g = { 7 };
/*static*/ std::array<uint8, 32> const SRP6::N = HexStrToByteArray<32>("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", true);
/*static*/ BigNumber const SRP6::_g(SRP6::g);
/*static*/ BigNumber const SRP6::_N(HexStrToByteArray<32>("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", true), true);

SRP6::EphemeralKey SRP6::GetNWireFormat()
{
    return _N.ToByteArray<32>();
}

/*static*/ std::pair<SRP6::Salt, SRP6::Verifier> SRP6::MakeRegistrationData(std::string const& username, std::string const& password)
{
    std::pair<SRP6::Salt, SRP6::Verifier> res;
    Crypto::GetRandomBytes(res.first);
    res.second = CalculateVerifier(username, password, res.first);
    return res;
}

/*static*/ SRP6::Verifier SRP6::CalculateVerifier(std::string const& username, std::string const& password, SRP6::Salt const& salt)
{
    return _g.ModExp(
        SHA1::GetDigestOf(
            salt,
            SHA1::GetDigestOf(username, ":", password)
        )
    ,_N).ToByteArray<32>();
}

/*static*/ SessionKey SRP6::SHA1Interleave(SRP6::EphemeralKey const& S)
{
    std::array<uint8, EPHEMERAL_KEY_LENGTH / 2> buf0{}, buf1{};
    for (std::size_t i = 0; i < EPHEMERAL_KEY_LENGTH / 2; ++i)
    {
        buf0[i] = S[2 * i + 0];
        buf1[i] = S[2 * i + 1];
    }

    std::size_t p = 0;
    while (p < EPHEMERAL_KEY_LENGTH && !S[p])
        ++p;

    if (p & 1)
        ++p;

    p /= 2;

    SHA1::Digest const hash0 = SHA1::GetDigestOf(buf0.data() + p, EPHEMERAL_KEY_LENGTH / 2 - p);
    SHA1::Digest const hash1 = SHA1::GetDigestOf(buf1.data() + p, EPHEMERAL_KEY_LENGTH / 2 - p);

    SessionKey K;
    for (std::size_t i = 0; i < SHA1::DIGEST_LENGTH; ++i)
    {
        K[2 * i + 0] = hash0[i];
        K[2 * i + 1] = hash1[i];
    }
    return K;
}

SRP6::SRP6(std::string const& username, Salt const& salt, Verifier const& verifier)
    : _I(SHA1::GetDigestOf(username)), _b(Crypto::GetRandomBytes<32>()), _v(verifier), s(salt), B(_B(_b, _v)) {
    auto hexStr = [](auto const& data) -> std::string {
        std::string result;
        char buf[3];
        for (uint8 b : data) {
            snprintf(buf, sizeof(buf), "%02x", b);
            result += buf;
        }
        return result;
    };
    printf("[SRP6 Init] v: %s\n", hexStr(verifier).c_str());
    printf("[SRP6 Init] B: %s\n", hexStr(B).c_str());
}

std::optional<SessionKey> SRP6::VerifyChallengeResponse(EphemeralKey const& A, SHA1::Digest const& clientM)
{
    ASSERT(!_used, "A single SRP6 object must only ever be used to verify ONCE!");
    _used = true;

    auto hexStr = [](auto const& data) -> std::string {
        std::string result;
        char buf[3];
        for (uint8 b : data) {
            snprintf(buf, sizeof(buf), "%02x", b);
            result += buf;
        }
        return result;
    };

    BigNumber const _A(A);
    if ((_A % _N).IsZero())
        return std::nullopt;

    BigNumber const u(SHA1::GetDigestOf(A, B));
    printf("[SRP6 Server] b: %s\n", hexStr(_b.ToByteArray<32>()).c_str());
    printf("[SRP6 Server] u: %s\n", hexStr(u.ToByteArray<20>()).c_str());
    printf("[SRP6 Server] _v: %s\n", hexStr(_v.ToByteArray<32>()).c_str());
    EphemeralKey const S = (_A * (_v.ModExp(u, _N))).ModExp(_b, N).ToByteArray<32>();

    SessionKey K = SHA1Interleave(S);

    printf("[SRP6 Server] A: %s\n", hexStr(A).c_str());
    printf("[SRP6 Server] B: %s\n", hexStr(B).c_str());
    printf("[SRP6 Server] S: %s\n", hexStr(S).c_str());
    printf("[SRP6 Server] K: %s\n", hexStr(K).c_str());
    printf("[SRP6 Server] u: %s\n", hexStr(u.ToByteArray<20>()).c_str());

    EphemeralKey N_wire = _N.ToByteArray<32>();
    std::array<uint8, 1> g_wire = { g[0] };

    SHA1::Digest const NHash = SHA1::GetDigestOf(N_wire);
    SHA1::Digest const gHash = SHA1::GetDigestOf(g_wire);
    SHA1::Digest NgHash;
    std::transform(NHash.begin(), NHash.end(), gHash.begin(), NgHash.begin(), std::bit_xor<>());

    SHA1::Digest const ourM = SHA1::GetDigestOf(NgHash, _I, s, A, B, K);

    printf("[SRP6 Server] N_wire: %s\n", hexStr(N_wire).c_str());
    printf("[SRP6 Server] NHash: %s\n", hexStr(NHash).c_str());
    printf("[SRP6 Server] gHash: %s\n", hexStr(gHash).c_str());
    printf("[SRP6 Server] NgHash: %s\n", hexStr(NgHash).c_str());
    printf("[SRP6 Server] clientM: %s\n", hexStr(clientM).c_str());
    printf("[SRP6 Server] ourM: %s\n", hexStr(ourM).c_str());
    printf("[SRP6 Server] match: %s\n", ourM == clientM ? "YES" : "NO");

    if (ourM == clientM)
        return K;

    return std::nullopt;
}