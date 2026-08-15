#pragma once

#include "Cryptography/BigNumber.h"
#include "Cryptography/CryptoHash.h"
#include "Cryptography/Authentication/SRP6.h"
#include "Utilities/Util.h"
#include <algorithm>
#include <array>
#include <string>
#include <utility>

namespace ClientSimulator
{
    using SHA1 = Acore::Crypto::SHA1;
    using SRP6 = Acore::Crypto::SRP6;

    inline std::array<uint8, 32> BuildClientEphemeralKey(BigNumber const& a)
    {
        BigNumber const g(SRP6::g);
        BigNumber const N(SRP6::N);
        return g.ModExp(a, N).ToByteArray<32>();
    }

    using SessionKey = std::array<uint8, 40>;

    inline SessionKey ComputeSessionKey(BigNumber const& a,
        std::array<uint8, 32> const& serverB,
        std::string const& username,
        std::string const& password,
        SRP6::Salt const& salt,
        SRP6::Verifier const& verifier)
    {
        BigNumber const N(SRP6::N);
        BigNumber const aValue(a);
        BigNumber const serverBValue(serverB);
        BigNumber const v(verifier);
        BigNumber const x(SHA1::GetDigestOf(salt, SHA1::GetDigestOf(username, ":", password)));
        BigNumber const u(SHA1::GetDigestOf(BuildClientEphemeralKey(aValue), serverB));

        BigNumber const base = ((serverBValue - (v * 3)) % N + N) % N;
        BigNumber const exponent = aValue + (u * x);
        std::array<uint8, 32> const S = base.ModExp(exponent, N).ToByteArray<32>();

        std::array<uint8, 16> buf0{};
        std::array<uint8, 16> buf1{};
        for (std::size_t i = 0; i < 16; ++i)
        {
            buf0[i] = S[2 * i + 0];
            buf1[i] = S[2 * i + 1];
        }

        std::size_t p = 0;
        while (p < S.size() && !S[p])
            ++p;

        if (p & 1)
            ++p;

        p /= 2;

        SHA1::Digest const hash0 = SHA1::GetDigestOf(buf0.data() + p, 16 - p);
        SHA1::Digest const hash1 = SHA1::GetDigestOf(buf1.data() + p, 16 - p);

        SessionKey K{};
        for (std::size_t i = 0; i < SHA1::DIGEST_LENGTH; ++i)
        {
            K[2 * i + 0] = hash0[i];
            K[2 * i + 1] = hash1[i];
        }

        return K;
    }

    inline SHA1::Digest ComputeClientProof(
        std::array<uint8, 32> const& clientA,
        std::array<uint8, 32> const& serverB,
        std::string const& username,
        std::string const& password,
        SRP6::Salt const& salt,
        SessionKey const& sessionKey)
    {
        auto const userHash = SHA1::GetDigestOf(username);
        auto const nHash = SHA1::GetDigestOf(SRP6::N);
        auto const gHash = SHA1::GetDigestOf(SRP6::g);
        std::array<uint8, SHA1::DIGEST_LENGTH> ngHash{};

        std::transform(nHash.begin(), nHash.end(), gHash.begin(), ngHash.begin(), std::bit_xor<>{});
        return SHA1::GetDigestOf(ngHash, userHash, salt, clientA, serverB, sessionKey);
    }

    inline std::string NormalizeLogin(std::string value)
    {
        Utf8ToUpperOnlyLatin(value);
        return value;
    }
}
