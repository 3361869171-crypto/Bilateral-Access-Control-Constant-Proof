// BN254/PFC(128) context, group wrappers, counters, batch pairing primitives.
#include "pfc_global.h"
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace std;

// Process-wide singleton (function-local static ⇒ thread-safe initialization since C++11).
PFCContext& PFCContext::getInstance() {
    static PFCContext instance;
    return instance;
}

// ⚠ BA_SEED determines randomSeed (the master switch for keys/blinds/nonces/generators); if the curve, group order, or trace disagrees with the BN formulas ⇒ throw runtime_error.
void PFCContext::init() {
    if (pfc) return; 
    try {
        pfc = new PFC(128); // 128-bit security parameter ⇒ BN254/k=12
        // Seed the RNG: BA_SEED=<integer> ⇒ bit-for-bit replay with the same seed and inputs; otherwise use the current time.
        const char* seedEnv = getenv("BA_SEED");
        randomSeed = (seedEnv && *seedEnv) ? strtoul(seedEnv, nullptr, 10)
                                           : (unsigned long)time(NULL);
        irand(randomSeed);
        // ---- BN254 (k=12) parameter x: parse explicitly as hexadecimal (no reliance on library side effects) ----
        miracl* mip = get_mip();
        const int oldBase = mip->IOBASE;
        mip->IOBASE = 16;
        char x_param[] = "-4080000000000001";
        Big x = x_param;
        mip->IOBASE = oldBase;
        BN_p = new Big(36*pow(x,4) + 36*pow(x,3) + 24*x*x + 6*x + 1);
        BN_n = new Big(36*pow(x,4) + 36*pow(x,3) + 18*x*x + 6*x + 1);

        // ---- Setup self-check: the parameters used internally to build the group must match the BN formulas (fail immediately on a wrong curve or hex parse rather than silently completing the experiment) ----
        const Big trace_expected = 6*x*x + 1;
        if (!(*pfc->mod    == *BN_p))
            throw std::runtime_error("PFCContext::init: base field p does not match the BN formula (check the radix of x / curve choice)");
        if (!( pfc->order() == *BN_n))
            throw std::runtime_error("PFCContext::init: group order n does not match the BN formula");
        if (!(*pfc->trace  == trace_expected))
            throw std::runtime_error("PFCContext::init: trace does not match the BN formula 6x^2+1");
        P = new G1;
        Q = new G2;
        pfc->random(*P);
        pfc->random(*Q);
    } catch (...) {
        cleanup(); // roll back all allocated resources (cleanup is nullptr-safe)
        throw;
    }
}

// Release in reverse order (Big/G1/G2 before the PFC instance) and null out pointers ⇒ repeatable and safe on exception paths.
void PFCContext::cleanup() {
    if (P)  { delete P;  P = nullptr; }
    if (Q)  { delete Q;  Q = nullptr; }
    if (BN_p) { delete BN_p; BN_p = nullptr; }
    if (BN_n) { delete BN_n; BN_n = nullptr; }
    if (pfc) { delete pfc; pfc = nullptr; }
}

// The library's multi_miller only reads its inputs (copying internally) ⇒ const_cast is safe; this project does not use precomputed tables (ptable).
GT PFCContext::multiPair(const vector<G2>& a, const vector<G1>& b) {
    if (a.size() != b.size()) throw invalid_argument("PFCContext::multiPair: size mismatch");
    if (a.empty()) return GT(1);
    if (!pfc) init();
    ++multiPairCalls;
    pairingCount += (long)a.size();
    const size_t n = a.size();
    vector<G2*> q(n);
    vector<G1*> x(n);
    for (size_t i = 0; i < n; ++i) { q[i] = const_cast<G2*>(&a[i]); x[i] = const_cast<G1*>(&b[i]); }
    return pfc->multi_pairing((int)n, q.data(), x.data());
}

// Count pairEqCalls += 1 (the sound path also goes through multiPair ⇒ multiPairCalls +1 as well; the two counters must not be added).
bool PFCContext::pairEq(const G2& a1, const G1& b1, const G2& a2, const G1& b2) {
    ++pairEqCalls;
    if (a1.g.iszero() || b1.g.iszero() || a2.g.iszero() || b2.g.iszero())
        return pair(a1, b1) == pair(a2, b2);
    const vector<G2> q { a1, a2 };
    const vector<G1> x { b1, -b2 };
    return multiPair(q, x) == GT(1);
}

// Contract: a/e have equal lengths and matching order; mismatches throw invalid_argument; gtPowCount += number of terms; exponents are reduced modulo the group order.
static const size_t kGtBatchMax = 4;

GT PFCContext::powerMulti(const vector<GT>& a, const vector<Big>& e) {
    if (a.size() != e.size()) throw invalid_argument("PFCContext::powerMulti: size mismatch");
    if (a.empty()) return GT(1);
    if (!pfc) init();
    const Big q = pfc->order();
    gtPowCount += (long)a.size();
    GT acc(1);
    const size_t n = a.size();
    for (size_t s = 0; s < n; s += kGtBatchMax) {
        const size_t k = (n - s < kGtBatchMax) ? (n - s) : kGtBatchMax;
        if (k == 1) { acc = acc * pfc->power(a[s], e[s] % q); continue; }
        vector<ZZn12> zx(k);
        vector<Big>   be(k);
        for (size_t i = 0; i < k; ++i) { zx[i] = a[s + i].g; be[i] = e[s + i] % q; }
        GT g;
        g.g = pow((int)k, zx.data(), be.data());
        acc = acc * g;
    }
    return acc;
}

// G2 multi-exponentiation: Σ_i e_i·a_i (the G2-side dual of powerMulti).
G2 PFCContext::g2MultiMult(const vector<G2>& a, const vector<Big>& e) {
    if (a.size() != e.size()) throw invalid_argument("PFCContext::g2MultiMult: size mismatch");
    if (a.empty()) return G2();
    if (!pfc) init();
    const Big q = pfc->order();
    g2MultCount += (long)a.size();
    G2 acc;
    for (size_t i = 0; i < a.size(); ++i) acc = acc + pfc->mult(a[i], e[i] % q);
    return acc;
}
