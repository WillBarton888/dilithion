// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 2 — CPeerScorer implementation (PR2.1 SCAFFOLD).
//
// This commit lands the CPeerScorer translation unit with stub bodies on
// every method. The class compiles, the binary links, but every method
// asserts on call. PR2.2 fills in the real implementation.
//
// Stubbing rather than committing the full implementation in one go
// matches the Phase 1 PR1.1 → PR1.2 → PR1.3 cadence: scaffold first
// (small, easy review), implement next (algorithm-heavy review), cut
// over last (call-site adaptation review). Each PR independently
// reviewable by Cursor + user.

#include <net/port/peer_scorer.h>

#include <cassert>

namespace dilithion::net::port {

CPeerScorer::CPeerScorer() = default;

CPeerScorer::~CPeerScorer() = default;

bool CPeerScorer::Misbehaving(::dilithion::net::NodeId /*peer*/,
                              ::dilithion::net::MisbehaviorType /*type*/,
                              const std::string& /*reason*/)
{
    assert(false && "CPeerScorer::Misbehaving(enum) — implementation in PR2.2");
    return false;
}

bool CPeerScorer::Misbehaving(::dilithion::net::NodeId /*peer*/,
                              int /*weight*/,
                              const std::string& /*reason*/)
{
    assert(false && "CPeerScorer::Misbehaving(weight) — implementation in PR2.2");
    return false;
}

int CPeerScorer::GetScore(::dilithion::net::NodeId /*peer*/) const
{
    assert(false && "CPeerScorer::GetScore — implementation in PR2.2");
    return 0;
}

void CPeerScorer::ResetScore(::dilithion::net::NodeId /*peer*/)
{
    assert(false && "CPeerScorer::ResetScore — implementation in PR2.2");
}

void CPeerScorer::SetBanThreshold(int /*threshold*/)
{
    assert(false && "CPeerScorer::SetBanThreshold — implementation in PR2.2");
}

int CPeerScorer::GetBanThreshold() const
{
    assert(false && "CPeerScorer::GetBanThreshold — implementation in PR2.2");
    return 0;
}

void CPeerScorer::DecayAll()
{
    assert(false && "CPeerScorer::DecayAll — implementation in PR2.2");
}

size_t CPeerScorer::GetScoreMapSizeForTest() const
{
    assert(false && "CPeerScorer::GetScoreMapSizeForTest — implementation in PR2.2");
    return 0;
}

bool CPeerScorer::AddScoreLocked(::dilithion::net::NodeId /*peer*/,
                                 int /*weight*/,
                                 const std::string& /*reason*/)
{
    assert(false && "CPeerScorer::AddScoreLocked — implementation in PR2.2");
    return false;
}

}  // namespace dilithion::net::port
