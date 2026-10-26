// Set commitment and intersection/difference relation proofs over a KZG SRS.
#ifndef MONIPOLY_H
#define MONIPOLY_H


#include <vector>
#include <utility>
#include "pfc_global.h"
#include "trusted_authority.h"
#include "ps_credential.h"
#include "knowledge_signature.h"

// Attribute set → ascending coefficient vector (shared encoding for PS credentials and commitments): returns the coefficients of ∏(x′+a_i) (last entry 1); fails if attributes is empty.
std::vector<Big> AttributeCoefficients(const std::vector<Big>& attributes);

class MoniPoly {
public:
    G1 CommitSet(const std::vector<G1>& Y, const std::vector<Big>& A, const Big& o, const Big& p) const;
    bool OpenIntersection(const std::vector<G1>& Y,
                          const std::vector<Big>& A, const Big& o,
                          const std::vector<Big>& Aprime, int l,
                          std::vector<Big>& I, G1& W, const Big& p) const;
    bool VerifyIntersection(const std::vector<G1>& Y, const std::vector<G2>& Y_tilde,
                            const G1& C, const std::vector<Big>& I,
                            const G1& W, const std::vector<Big>& Aprime,
                            int l, const Big& p) const;
    bool OpenDifference(const std::vector<G1>& Y,
                        const std::vector<Big>& A, const Big& o,
                        const std::vector<Big>& Aprime, int l_bar,
                        std::vector<Big>& D, G1& W, std::vector<Big>& r_coeff, const Big& p) const;
    bool VerifyDifference(const std::vector<G1>& Y, const std::vector<G2>& Y_tilde,
                          const G1& C, const std::vector<Big>& D,
                          const G1& W, const std::vector<Big>& r_coeff,
                          const std::vector<Big>& Aprime, int l_bar, const Big& p) const;

    static std::vector<Big> MPEncode_set(const std::vector<Big>& S, const Big& p);
    static std::vector<Big> MPEncode(const std::vector<Big>& A, const Big& o, const Big& p);
    static std::pair<std::vector<Big>, std::vector<Big>> poly_div(const std::vector<Big>& f, const std::vector<Big>& d, const Big& p);
    static std::vector<Big> poly_gcd(const std::vector<Big>& a, const std::vector<Big>& b, const Big& p);

private:
    static bool isInSet(const Big& m, const std::vector<Big>& S);
    static std::vector<Big> setIntersection(const std::vector<Big>& S1, const std::vector<Big>& S2);
    static std::vector<Big> setDifference(const std::vector<Big>& S1, const std::vector<Big>& S2);
};

enum class MoniClauseType { Intersection, Difference };

struct PolicyClause {
    MoniClauseType type;
    std::vector<Big> set;
    int threshold;

    static PolicyClause Intersection(const std::vector<Big>& cands, int t) {
        PolicyClause c;
        c.type = MoniClauseType::Intersection; c.set = cands; c.threshold = t;
        return c;
    }
    static PolicyClause Intersection(const Big& attr) {
        PolicyClause c;
        c.type = MoniClauseType::Intersection; c.set.assign(1, attr); c.threshold = 1;
        return c;
    }
    static PolicyClause Intersection(const Big& attr, int t) {
        PolicyClause c;
        c.type = MoniClauseType::Intersection; c.set.assign(1, attr); c.threshold = t;
        return c;
    }
    static PolicyClause Difference(const std::vector<Big>& set, int t) {
        PolicyClause c;
        c.type = MoniClauseType::Difference; c.set = set; c.threshold = t;
        return c;
    }
};

// Composition: logical AND only — every clause is required (each with its own witness and pairing equation); static constructors: Single(c) for one clause / And(cs) for several.
struct Policy {
    std::vector<PolicyClause> clauses;

    static Policy Single(const PolicyClause& c) {
        Policy p; p.clauses.push_back(c); return p;
    }
    static Policy And(std::vector<PolicyClause> cs) {
        Policy p; p.clauses = std::move(cs); return p;
    }
};

std::string ClauseDesc(const PolicyClause& c);
std::string PolicyDesc(const Policy& p);

struct ClauseProof {
    int clauseIndex;
    MoniClauseType type;
    int threshold;
    std::vector<Big> publicSet;
    std::vector<Big> revealed;
    G1 witness;
    std::vector<Big> remainderCoeff;
    size_t size() const;
};

// The binding "credential ↔ coefficients ↔ commitment" is not stored here; it is carried by MoniPresentation's anchoring (A2 + responses s + C_{x′}) under the same challenge c.
struct MoniProof {
    G1 commitment;
    Big nonce; // one-time random nonce (absorbed into the unified challenge ⇒ anti-replay / anti-bytewise-linkage)
    std::vector<ClauseProof> proofs;
    // Size (G1=64 B / field element=32 B / GT=384 B): C + nonce + clause count + Σ clauses.
    size_t size() const;
};

MoniProof ProveSetRelation(const SystemParams& sys,
                           const std::vector<Big>& attributes,
                           const Big& opening,
                           const Policy& policy);

bool VerifySetRelation(const MoniProof& proof, const SystemParams& sys);

bool MoniMatchesPolicy(const MoniProof& proof,
                       const Policy& policy,
                       std::string* why = nullptr);

// ---- Main path Prove / Verify ---- shifted commitment C_{x′} = Σ f_k·Y[k+1] and anchoring A2 + c·C_{x′} = Σ s_k·Y[k+1].

// Anchoring proof: A2 = Σ t_k·Y[k+1]; s_k = t_k + c·f_k; c = challenge.
struct MoniAnchorProof {
    G1 A2;
    std::vector<Big> s;
    Big c;
};

// Presentation: shifted commitment + anchoring proof + identity proof (σ'/nonce/Up/c).
struct MoniPresentation {
    G1 Cxprime;
    MoniAnchorProof anchor;
    CoeffKnowledgeSignature ks; // σ'/nonce/Up/c
};

// Commitments: C = Σ f_k·Y[k], C_{x′} = Σ f_k·Y[k+1].
void MoniCommits(const SystemParams& sys, const std::vector<Big>& f,
                 G1& C, G1& Cxprime);

// Public pairing check: e(Ỹ[1],C) == e(Ỹ[0],C_{x′}) ⇔ C_{x′} = C^{x′}.
bool VerifyAnchoring(const SystemParams& sys, const G1& C, const G1& Cxprime);

// ⚠ Caller contract: invoke only inside session initialization (MoniSessionInit) ⇒ the issuer is online once per session and offline afterwards.
PSCredential MoniBlindObtain(const SystemParams& sys, const std::vector<Big>& f,
                             const AttributeIssuer& issuer, G1& C, G1& Cxprime,
                             Big& t, G1& blindOut);

// Precondition: o ≠ 0; o ∉ A ∪ policy sets; f = Encode(A,o).
bool MoniValidateInputs(const SystemParams& sys, const std::vector<Big>& attrs,
                        const Big& o, const std::vector<Big>& f,
                        const Policy& policy, const MoniProof& mp,
                        std::string* why = nullptr);

// Legacy flow: every presentation required a fresh o + online blind issuance ⇒ the issuer had to be online for each presentation.
struct MoniSession {
    Big o;
    std::vector<Big> f;
    PSCredential cred;
    G1 C;
    G1 Cxprime;
    Big t;
    G1 blind;
};

// Fails (throws runtime_error) if A is empty / contains 0 / o = 0 / o ∈ A ∪ policy sets / the SRS is too short (|A| > maxAttrs) / the policy is empty / a clause is unsatisfied.
MoniSession MoniSessionInit(const SystemParams& sys, const std::vector<Big>& attrs,
                            const AttributeIssuer& issuer, const Policy& policy,
                            MoniProof& mp,
                            const std::vector<Big>& extraForbidden = std::vector<Big>());

MoniSession MoniSessionInit(const SystemParams& sys, const std::vector<Big>& attrs,
                            const Big& o, const AttributeIssuer& issuer,
                            const Policy& policy, MoniProof& mp);

// [Presentation] (offline: no issuer contact) — takes the session credential; each call randomizes the credential and draws a fresh nonce/t_k.
MoniPresentation MoniProve(const SystemParams& sys, const MoniSession& session,
                           const PSVerifyKey& issuerPub, const std::string& msg,
                           const MoniProof& mp);

MoniPresentation MoniProve(const SystemParams& sys, const std::vector<Big>& f,
                           const PSCredential& cred, const PSVerifyKey& issuerPub,
                           const std::string& msg, const MoniProof& mp);

// Convenience entry point: encodes (A,o) internally.
MoniPresentation MoniProveFromAttrs(const SystemParams& sys,
                                    const std::vector<Big>& attrs, const Big& o,
                                    const PSCredential& cred,
                                    const PSVerifyKey& issuerPub,
                                    const std::string& msg, MoniProof& mp);

// Six-step verification (identity/anchoring/credential/public pairing/set relation/policy; all required).
bool MoniDecide(const MoniPresentation& pr, const PSVerifyKey& issuerPub,
                const SystemParams& sys, const std::string& msg,
                const MoniProof& mp, const Policy& required,
                std::string* why = nullptr, DecideStats* stats = nullptr);

#endif
