// TA Setup/KeyGen: public parameters, sparse KZG SRS, secret (x, xprime).
#include "trusted_authority.h"
#include <stdexcept>
#include <vector>

// Auxiliary base h: hash-and-map a label to G1; its discrete log relative to g1 is unknown, which underpins masking/blinding security.
static G1 deriveAuxBase(const char* label) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    G1 h;
    ctx.pfc->hash_and_map(h, (char*)label);
    return h;
}

// Setup: build groups, derive generators/auxiliary base, sample msk = (x, x′), compute X̃ = g2^x, and build the KZG-style SRS (Y/Y_tilde[0..L+1]).
SystemParams TrustedAuthority::initialize(int maxAttrs) {
    if (maxAttrs < 1) throw std::invalid_argument("maxAttrs must be >= 1");
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();

    SystemParams p;
    p.g1 = *ctx.P;
    p.g2 = *ctx.Q;
    p.h  = deriveAuxBase("bilateral_access_aux_v1");
    p.maxAttrs = maxAttrs;

    // msk = (x, x′): x′ is sampled during Setup (the SRS trapdoor); x belongs to KeyGen material and is sampled here on its behalf.
    do { ctx.pfc->random(x_); }     while (x_ == 0);
    do { ctx.pfc->random(xprime_); } while (xprime_ == 0);
    hasSecrets_ = true;

    // g1^x is issuer-private and is never published: doing so reveals signing capability and lets anyone forge credentials for arbitrary attribute sets (N0/v8).
    p.Xtilde1 = ctx.mult(p.g2, x_);

    // Hence the public key (X̃, Ỹ_1..Ỹ_{L+1}) is entirely contained in pp.
    const Big q = ctx.pfc->order();
    const int srsSize = maxAttrs + 3;
    p.Y.resize(srsSize);
    p.Y_tilde.resize(srsSize);
    p.Y[0] = p.g1;
    p.Y_tilde[0] = p.g2;
    Big pow = xprime_;
    for (int i = 1; i < srsSize; ++i) {
        p.Y[i] = ctx.mult(p.g1, pow);
        p.Y_tilde[i] = ctx.mult(p.g2, pow);
        pow = modmult(pow, xprime_, q);
    }
    pp_ = p;
    return p;
}

SystemParams TrustedAuthority::initializeBase(int maxAttrs) {
    if (maxAttrs < 1) throw std::invalid_argument("maxAttrs must be >= 1");
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();

    SystemParams p;
    p.g1 = *ctx.P;
    p.g2 = *ctx.Q;
    p.h  = deriveAuxBase("bilateral_access_aux_v1");
    p.maxAttrs = maxAttrs;

    do { ctx.pfc->random(x_); }     while (x_ == 0);
    do { ctx.pfc->random(xprime_); } while (xprime_ == 0);
    hasSecrets_ = true;
    p.Xtilde1 = ctx.mult(p.g2, x_); // g1^x is not published (issuer-private; N0/v8).
    pp_ = p;
    return p;
}

// Message keys start at x′^1; x′^0 = 1 is never used (a publicly known key would enable linear malleability).
void TrustedAuthority::fillPkView(PSVerifyKey& pk) const {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    pk.Y2.clear();

    if (pp_.Y_tilde.size() >= 2) {
        for (size_t i = 1; i < pp_.Y_tilde.size(); ++i) pk.Y2.push_back(pp_.Y_tilde[i]);
        return;
    }
    const Big q = ctx.pfc->order();
    Big pow = xprime_ % q;
    for (int i = 0; i <= pp_.maxAttrs; ++i) {
        pk.Y2.push_back(ctx.mult(*ctx.Q, pow));
        pow = modmult(pow, xprime_, q);
    }
}

// Guards: reject x ≡ 0, x′ ≡ 0, and x′ ≡ 1 (publicly known message key); throw logic_error if initialize* was not called first.
PSKeyPair TrustedAuthority::keyGen() const {
    if (!hasSecrets_)
        throw std::logic_error("TrustedAuthority::keyGen: call initialize()/initializeBase() first");
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    const Big q = ctx.pfc->order();

    PSKeyPair kp;
    kp.sk.x     = x_ % q;
    kp.sk.xprime = xprime_ % q;
    if (kp.sk.x == 0)     throw std::invalid_argument("KeyGen: x must be non-zero mod q");
    if (kp.sk.xprime == 0) throw std::invalid_argument("KeyGen: xprime must be non-zero mod q");
    if (kp.sk.xprime == 1) throw std::logic_error("KeyGen: xprime == 1 forbidden (message key would be public)");

    kp.pk.X2 = pp_.Xtilde1;
    fillPkView(kp.pk);
    return kp;
}

