// TA Setup/KeyGen: public parameters, sparse KZG SRS, secret (x, xprime).
#ifndef TRUSTED_AUTHORITY_H
#define TRUSTED_AUTHORITY_H

#include <vector>
#include "pfc_global.h"
#include "ps_credential.h"


// Public system parameters: generators g1/g2 (reproducible under the same BA_SEED), auxiliary base h (unknown discrete log), attribute bound, X̃, and the KZG SRS (Y/Y_tilde).
struct SystemParams {
    G1  g1;
    G2  g2;
    G1  h;
    int maxAttrs;

    // The verification side contains G2 elements only; g1^x is deliberately excluded because publishing it reveals signing capability and lets anyone forge credentials (N0/v8).
    G2  Xtilde1;

    // Y2[i] = Ỹ_{i+1} corresponds to coefficient q_i (i ≥ 1), so x′^0 = 1 is never used.
    std::vector<G1> Y;
    std::vector<G2> Y_tilde;
};

class TrustedAuthority {
public:
    // Setup: build groups, derive generators/auxiliary base, sample msk = (x, x′), compute X̃ = g2^x, and build the SRS (L+3 entries).
    SystemParams initialize(int maxAttrs);

    // The resulting pp cannot be used for MoniPoly commitments/set-relation proofs.
    SystemParams initializeBase(int maxAttrs);

    // Guards: reject x ≡ 0, x′ ≡ 0, and x′ ≡ 1; zero group multiplications rely on Setup having pre-sampled x and X̃; the TA hands sk to the issuer while verifiers receive only pp.
    PSKeyPair keyGen() const;

    const SystemParams& params() const { return pp_; }
    const Big& xSecret() const { return x_; }
    const Big& xprimeSecret() const { return xprime_; }
    bool hasSecrets() const { return hasSecrets_; }

private:
    // Public-key view = pp slice: Y2 = (Ỹ_1, ..., Ỹ_{L+1}); if pp has no SRS, compute it on the fly from x′.
    void fillPkView(PSVerifyKey& pk) const;

    SystemParams pp_;
    Big  x_;
    Big  xprime_;
    bool hasSecrets_ = false;
};

#endif
