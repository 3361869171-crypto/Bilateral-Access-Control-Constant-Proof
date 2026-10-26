// Pointcheval-Sanders multi-message credentials: sign, randomize, blind issue, verify.
#ifndef PS_CREDENTIAL_H
#define PS_CREDENTIAL_H

#include <stdexcept>
#include <vector>
#include "pfc_global.h"


struct PSCredential {
    G1 sigma1;
    G1 sigma2;
};

struct PSSignKey {
    Big x;
    Big xprime;
};

struct PSVerifyKey {
    G2 X2;
    std::vector<G2> Y2;
};

struct PSKeyPair {
    PSSignKey   sk;
    PSVerifyKey pk;
};


// Fails if msgs is empty or some message key x′^{i+1} == 1 (forbidden).
PSCredential PSSign(const PSSignKey& sk, const std::vector<Big>& msgs);
PSCredential PSRandomize(const PSCredential& cred);

// Bound check: |coefs| ≤ |pk view| (the Ỹ slice length in pp); otherwise the issued credential cannot be verified.
struct CredentialRequest {
    std::vector<Big> coefs;
};
CredentialRequest ObtainRequest(const std::vector<Big>& attributes);

// ⚠ Security boundary (read carefully): no attribute-validity proof is implemented ⇒ under blind issuance the issuer cannot tell whether these coefficients correspond to genuinely held attributes, so a user may submit any attribute set for signing (bypassing access control).

// ---- User → issuer blind-issuance message (minimal, truly blind) ---- contains only one blinded point; the issuer never sees the unblinded commitment C_{x′}.
struct BlindCredentialRequest {
    G1 Cprime;
};


// User side (2): blind C' = C_{x′}·g1^t (t is kept secret by the user and used for unblinding).
G1 BlindCommitment(const G1& Cqx, const Big& t);

// User side (3): unblind σ2 ← σ2 · σ1^{-t}.
PSCredential UnblindCredential(const PSCredential& blindSig, const Big& t);

// Issuer side: sign the "commitment" without knowing the attributes: σ1 = g1^u, σ2 = σ1^x·(C')^u — g1^x stays private and the attributes remain hidden.
PSCredential PSSignOnCommitment(const PSSignKey& sk, const G1& Cprime);

// Member key: sk_ = (x, x′) is the combined secret key; pk_ is the pp slice view.
class AttributeIssuer {
public:
    AttributeIssuer(const PSSignKey& sk, const PSVerifyKey& pkView) : sk_(sk), pk_(pkView) {}

    PSCredential issue(const std::vector<Big>& coefs) const {
        return PSSign(sk_, coefs);
    }

    PSCredential obtain(const CredentialRequest& req) const {
        if (req.coefs.empty())
            throw std::invalid_argument("Obtain: empty credential request");
        if (req.coefs.size() > pk_.Y2.size())
            throw std::invalid_argument("Obtain: request exceeds published (merged) key view");
        return PSSign(sk_, req.coefs);
    }

    // ⚠ No attribute-validity proof: the caller must ensure that the user genuinely holds these attributes; otherwise the user can make the issuer sign an arbitrary attribute set.
    PSCredential obtainBlind(const BlindCredentialRequest& req) const {
        return PSSignOnCommitment(sk_, req.Cprime);
    }

    // Published view = a slice of pp (the secret key is never distributed).
    const PSVerifyKey& publicKey() const { return pk_; }

private:
    PSSignKey sk_;
    PSVerifyKey pk_;
};

// By default, verification folds the equation into e(Σ_i s_i·Y2_i, σ1) plus 2 U terms (3 multi-pairing terms in total); folding never changes the decision.
struct ZKPsVectorBinding {
    std::vector<Big> sm;
    GT Up;
    Big c;
};

// Commitment: compute Up from the given t (T3 fusion: Up = e(Σ_i t_i·Y2_i, σ1) ⇒ one pairing, zero GT exponentiations).
void SigmaCommitZkPs(const PSCredential& sig, const PSVerifyKey& pk,
                     const std::vector<Big>& msgs, const std::vector<Big>& sharedT,
                     GT& Up);

// Responses: sm_i = t_i + c·m_i.
void zkPsResponses(const std::vector<Big>& msgs, const std::vector<Big>& t,
                   const Big& challenge, std::vector<Big>& sm);

// Verify: ∏B_i^{s_i} = Up·U^c.
bool zkPsVerifyWithChallenge(const PSCredential& sig, const PSVerifyKey& pk,
                             const std::vector<Big>& responses, const GT& Up,
                             const Big& q, const Big& challenge);

#endif
