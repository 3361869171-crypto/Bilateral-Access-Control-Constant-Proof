// BN254/PFC(128) context, group wrappers, counters, batch pairing primitives.
#ifndef PFC_GLOBAL_H
#define PFC_GLOBAL_H

#include <string>
#include <chrono>
#include <vector>
#include "miracl.h"
#include "ecn.h"
#include "ecn2.h"
#include "zzn2.h"
#include "zzn12a.h"
#define MR_PAIRING_BN
#include "pairing_3.h"

// Wall-clock timing (experimental output only; never used in protocol decisions): elapsed_ms() = milliseconds since construction, complementing the group-operation counters.
class Timer {
private:
    std::chrono::high_resolution_clock::time_point start;
public:
    Timer() : start(std::chrono::high_resolution_clock::now()) {}
    double elapsed_ms() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    }
};

class PFCContext {
public:
    static PFCContext& getInstance();
    void init();
    void cleanup();

    // pfc = MIRACL PFC(128) ⇒ BN254/k=12; P/Q = G1/G2 generators (random, controlled by BA_SEED, allocated after init()).
    PFC* pfc = nullptr;
    G1* P = nullptr;
    G2* Q = nullptr;
    Big* BN_p = nullptr;
    Big* BN_n = nullptr;

    long pairingCount = 0;
    long gtPowCount   = 0;
    long g1MultCount  = 0;
    long g2MultCount  = 0;
    long multiPairCalls = 0;
    long pairEqCalls    = 0; // pairEq() call count (the sound path goes through multiPair ⇒ multiPairCalls +1 as well; the degenerate fallback uses pair()×2 ⇒ only this counter increments)
    void resetCounters() { pairingCount = gtPowCount = g1MultCount = g2MultCount = multiPairCalls = pairEqCalls = 0; }

    // BA_SEED=<integer> ⇒ use it (the same seed fully replays an experiment); otherwise use the current time. It is the master switch for keys/blinds/nonces/generators.
    unsigned long randomSeed = 0;

    GT pair(const G2& a, const G1& b)   { ++pairingCount; return pfc->pairing(a, b); }
    GT power(const GT& a, const Big& e) { ++gtPowCount;   return pfc->power(a, e); }
    G1 mult(const G1& a, const Big& e)  { ++g1MultCount;  return pfc->mult(a, e); }
    G2 mult(const G2& a, const Big& e)  { ++g2MultCount;  return pfc->mult(a, e); }

    // One n-term multiPair ⇒ the former +n and the latter +1; they must not be added, and assertions must state the accounting convention and path.
    GT multiPair(const std::vector<G2>& a, const std::vector<G1>& b);
    // Degenerate fallback: if any term contains the identity ⇒ fall back to pointwise comparison, semantically identical to the previous implementation.
    bool pairEq(const G2& a1, const G1& b1, const G2& a2, const G1& b2);
    // See the implementation for the batch cap (kGtBatchMax=4; the library precomputes 2^n tables, so larger n is slower).
    GT powerMulti(const std::vector<GT>& a, const std::vector<Big>& e);
    G2 g2MultiMult(const std::vector<G2>& a, const std::vector<Big>& e);

private:
    PFCContext() {}
    ~PFCContext() { cleanup(); }
    PFCContext(const PFCContext&) = delete;
    PFCContext& operator=(const PFCContext&) = delete;
};

static const size_t BN_FIELD_BYTES = 32;
inline size_t size_of_big_fixed(const Big&) { return BN_FIELD_BYTES; }
inline size_t size_of_g1_fixed(const G1&)    { return 2 * BN_FIELD_BYTES; }
inline size_t size_of_g2_fixed(const G2&)    { return 4 * BN_FIELD_BYTES; }
// Compressed point encoding (1-byte prefix + x): G1 = 1+32, G2 = 1+64

#endif