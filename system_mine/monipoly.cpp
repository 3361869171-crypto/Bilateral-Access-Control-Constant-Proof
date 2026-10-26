// Set commitment and intersection/difference relation proofs over a KZG SRS.
#include "monipoly.h"
#include "fs_transcript.h"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace std;

// Invariant: next[0]=p0·m; next[i]=poly[i-1]+poly[i]·m; next[k]=poly[k-1] (monic).

vector<Big> AttributeCoefficients(const vector<Big>& attributes) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    if (attributes.empty()) throw invalid_argument("empty attributes");
    // Ascending coefficients of ∏(x′+a_i), with last entry 1.
    return MoniPoly::MPEncode_set(attributes, ctx.pfc->order());
}

vector<Big> MoniPoly::MPEncode_set(const vector<Big>& S, const Big& p) {
    if (S.empty()) return vector<Big>(1, Big(1));
    vector<Big> poly;
    poly.reserve(S.size() + 1);
    poly.push_back(Big(1));
    for (const Big& m : S) {
        const int k = (int)poly.size();
        poly.push_back(Big(1));
        for (int i = k - 1; i >= 1; --i)
            poly[i] = (modmult(poly[i], m, p) + poly[i - 1]) % p;
        poly[0] = modmult(poly[0], m, p);
    }
    return poly;
}

vector<Big> MoniPoly::MPEncode(const vector<Big>& A, const Big& o, const Big& p) {
    vector<Big> poly = MPEncode_set(A, p);
    const int k = (int)poly.size();
    poly.push_back(Big(1));
    for (int i = k - 1; i >= 1; --i)
        poly[i] = (modmult(poly[i], o, p) + poly[i - 1]) % p;
    poly[0] = modmult(poly[0], o, p);
    return poly;
}

// ⚠ Use inverse() (xgcd) rather than powmod to avoid corrupting the Montgomery state used by ZZn pairings.
pair<vector<Big>, vector<Big>> MoniPoly::poly_div(const vector<Big>& f,
                                                  const vector<Big>& d, const Big& p) {
    auto normalize = [](vector<Big>& v){ while(!v.empty() && v.back()==0) v.pop_back(); };
    vector<Big> d_copy = d;
    normalize(d_copy);
    const int deg_d = (int)d_copy.size()-1;
    if (deg_d < 0) {
        vector<Big> only_f = f;
        normalize(only_f);
        return { vector<Big>(1, Big(0)), move(only_f) };
    }
    vector<Big> r = f;
    normalize(r);
    const int deg_f = (int)r.size()-1;
    if (deg_f < deg_d) return { vector<Big>(1, Big(0)), move(r) };

    vector<Big> q(deg_f-deg_d+1, Big(0));
    // Note: do not invert via pow(lc,p-2,p) (powmod corrupts the Montgomery state used by ZZn pairings).
    Big inv_lc_d = inverse(d_copy[deg_d], p);
    auto modp = [&p](Big v) -> Big { v %= p; if (v < 0) v += p; return v; };

    for (int i = deg_f-deg_d; i >= 0; --i) {
        int target = i + deg_d;
        while (!r.empty() && r.back()==0) r.pop_back();
        if (r.empty() || (int)r.size()-1 != target) continue;
        Big scale = modp(modmult(r[target], inv_lc_d, p));
        q[i] = scale;
        for (int j = 0; j <= deg_d; ++j) {
            if (i+j < (int)r.size()) {
                r[i+j] = modp(r[i+j] - modmult(scale, d_copy[j], p));
            }
        }
        r[target] = 0;
    }
    normalize(q); normalize(r);
    return {q, r};
}

vector<Big> MoniPoly::poly_gcd(const vector<Big>& a, const vector<Big>& b, const Big& p) {
    vector<Big> A = a, B = b;
    auto normalize = [](vector<Big>& v){ while(!v.empty() && v.back()==0) v.pop_back(); };
    normalize(A); normalize(B);
    if (A.empty()) return B;
    if (B.empty()) return A;
    if (A.size() < B.size()) swap(A, B);
    while (!B.empty()) {
        auto div_res = poly_div(A, B, p);
        vector<Big> R = move(div_res.second);
        A.swap(B);
        B = move(R);
        normalize(B);
    }
    if (!A.empty()) {
        Big lc = A.back();
        Big inv_lc = inverse(lc, p);
        for (Big& coeff : A) coeff = modmult(coeff, inv_lc, p);
    }
    return A;
}

bool MoniPoly::isInSet(const Big& m, const vector<Big>& S) {
    for (const Big& x : S) if (m == x) return true;
    return false;
}

vector<Big> MoniPoly::setIntersection(const vector<Big>& S1, const vector<Big>& S2) {
    vector<Big> inter;
    for (const Big& x : S1) if (isInSet(x, S2)) inter.push_back(x);
    return inter;
}

vector<Big> MoniPoly::setDifference(const vector<Big>& S1, const vector<Big>& S2) {
    vector<Big> diff;
    for (const Big& x : S1) if (!isInSet(x, S2)) diff.push_back(x);
    return diff;
}

// Bound: F=(x′+o)·∏(x′+a_i) has |A|+2 coefficients, so Y.size() ≥ |A|+2 is required.
G1 MoniPoly::CommitSet(const vector<G1>& Y, const vector<Big>& A, const Big& o, const Big& p) const {
    vector<Big> coeff = MPEncode(A, o, p);
    if (coeff.size() > Y.size()) {
        throw std::runtime_error("CommitSet: encoded polynomial degree exceeds SRS size (|A| > maxAttrs?)");
    }
    G1 C = PFCContext::getInstance().mult(Y[0], coeff[0]);
    for (int j = 1; j < (int)coeff.size(); ++j)
        C = C + PFCContext::getInstance().mult(Y[j], coeff[j]);
    return C;
}


// W = Σ_j w[j]·Y[j] (commitment to the quotient polynomial).
bool MoniPoly::OpenIntersection(const vector<G1>& Y,
                                const vector<Big>& A, const Big& o,
                                const vector<Big>& Aprime, int l,
                                vector<Big>& I, G1& W, const Big& p) const {
    const vector<Big>& userA = A;
    vector<Big> inter = setIntersection(userA, Aprime);
    if ((int)inter.size() < l) return false;
    I.assign(inter.begin(), inter.begin() + l);
    vector<Big> S = setDifference(userA, I);
    S.push_back(o);
    vector<Big> w = MPEncode_set(S, p);
    if (w.size() > Y.size()) {
    throw std::runtime_error("OpenIntersection: witness polynomial degree exceeds SRS size");
    }
    W = PFCContext::getInstance().mult(Y[0], w[0]);
    for (size_t j = 1; j < w.size(); ++j)
        W = W + PFCContext::getInstance().mult(Y[j], w[j]);
    return true;
}

// Plaintext defenses: I is non-empty, |I| ≥ l, I ⊆ Aprime, I has no duplicates; |i_coeff| ≤ |Y_tilde|.
bool MoniPoly::VerifyIntersection(const vector<G1>& Y, const vector<G2>& Y_tilde,
                                  const G1& C, const vector<Big>& I,
                                  const G1& W, const vector<Big>& Aprime,
                                  int l, const Big& p) const {
    // ⇒ This primitive itself enforces "unsatisfied threshold/policy ⇒ reject", so a direct call cannot bypass the policy.
    if (I.empty() || l < 1 || (int)I.size() < l) return false;
    if (Aprime.empty()) return false;
    for (size_t i = 0; i < I.size(); ++i) {
        if (!isInSet(I[i], Aprime)) return false;
        for (size_t j = i + 1; j < I.size(); ++j)
            if (I[i] == I[j]) return false;
    }
    // [Defense in depth · C1] Degenerate commitments: C or W equal to the identity O ⇒ e1 = e2 = 1_T (always true) ⇒ any revealed set could "prove" a match.
    if (C.g.iszero() || W.g.iszero()) return false;
    vector<Big> i_coeff = MPEncode_set(I, p);
    if (i_coeff.size() > Y_tilde.size()) return false;

    // Formula: Commit(I) = Σ (i_coeff[j] * Y_tilde[j]).
    G2 commit_I = PFCContext::getInstance().mult(Y_tilde[0], i_coeff[0]);
    for (size_t j = 1; j < i_coeff.size(); ++j) {
        commit_I = commit_I + PFCContext::getInstance().mult(Y_tilde[j], i_coeff[j]);
    }

    // [T2 fusion] e(Ỹ[0],C) == e(commit_I,W) ⇔ combine both terms into one multi-pairing == 1_T (still counted as 2 terms; degenerate points fall back to pointwise).
    return PFCContext::getInstance().pairEq(Y_tilde[0], C, commit_I, W);
}

// Invariant: f_A = q·f_D + r; if the user actually holds a value in D ⇒ r = 0 ⇒ verification must reject.
bool MoniPoly::OpenDifference(const vector<G1>& Y,
                              const vector<Big>& A, const Big& o,
                              const vector<Big>& Aprime, int l_bar,
                              vector<Big>& D, G1& W, vector<Big>& r_coeff, const Big& p) const {
    const vector<Big>& userA = A;
    vector<Big> diff = setDifference(Aprime, userA);
    if ((int)diff.size() < l_bar) return false;
    D.assign(diff.begin(), diff.begin() + l_bar);
    vector<Big> f_coeff = MPEncode(userA, o, p);
    vector<Big> d_coeff = MPEncode_set(D, p);
    auto div_res = poly_div(f_coeff, d_coeff, p);
    vector<Big> q_coeff = move(div_res.first);
    r_coeff = move(div_res.second);
    // If the user actually holds an attribute in D (i.e. A∩D ≠ ∅), f_A is divisible by f_D → the remainder is 0,
    r_coeff.resize(l_bar, Big(0));
    if (q_coeff.size() > Y.size()) {
    throw std::runtime_error("OpenDifference: quotient polynomial degree exceeds SRS size");
    }
    W = PFCContext::getInstance().mult(Y[0], q_coeff[0]);
    for (size_t j = 1; j < q_coeff.size(); ++j)
        W = W + PFCContext::getInstance().mult(Y[j], q_coeff[j]);
    return true;
}

// Verify: r ≠ 0; gcd(f_D,r)=1 (coprime ⇒ D∩A=∅); pairing equation e(g2,L) == e(R2,R1).
bool MoniPoly::VerifyDifference(const vector<G1>& Y, const vector<G2>& Y_tilde,
                                const G1& C, const vector<Big>& D,
                                const G1& W, const vector<Big>& r_coeff,
                                const vector<Big>& Aprime, int l_bar, const Big& p) const {
    // Parameter validity (defensive): avoid out-of-bounds reads from empty sets/short remainders, and prevent an overstated threshold when |D| < l_bar.
    if (l_bar < 1 || D.empty() || Aprime.empty()) return false;
    if ((int)D.size() < l_bar) return false;
    if ((int)r_coeff.size() < l_bar) return false;
    // [Defense in depth · C1] Degenerate commitments: C or W equal to the identity O ⇒ the pairing equation e1 == e2 degenerates to 1_T == 1_T (always true).
    if (C.g.iszero() || W.g.iszero()) return false;
    bool is_zero = true;
    for (const Big& r : r_coeff) if (r != 0) { is_zero = false; break; }
    if (is_zero) return false;

    vector<Big> d_coeff = MPEncode_set(D, p);
    vector<Big> r_copy = r_coeff;
    while (!r_copy.empty() && r_copy.back() == 0) r_copy.pop_back();
    if (!r_copy.empty()) {
        vector<Big> g = poly_gcd(d_coeff, r_copy, p);
        if (g.size() > 1) return false;
    }

    vector<Big> m1 = MPEncode_set(Aprime, p);
    vector<Big> Aprime_minus_D = setDifference(Aprime, D);
    vector<Big> m2 = MPEncode_set(Aprime_minus_D, p);
    if (m1.size() > Y.size() || m2.size() > Y.size()) return false;
    if (d_coeff.size() > Y_tilde.size()) return false;

    G1 L = C;
    for (int j = 0; j < l_bar; ++j) {
        Big neg_rj = (r_coeff[j] == 0) ? Big(0) : (p - r_coeff[j]);
        L = L + PFCContext::getInstance().mult(Y[j], neg_rj);
    }
    for (size_t j = 0; j < m1.size(); ++j)
        L = L + PFCContext::getInstance().mult(Y[j], m1[j]);

    G1 R1 = W;
    for (size_t j = 0; j < m2.size(); ++j)
        R1 = R1 + PFCContext::getInstance().mult(Y[j], m2[j]);

    G2 R2 = PFCContext::getInstance().mult(Y_tilde[0], d_coeff[0]);
    for (size_t j = 1; j < d_coeff.size(); ++j)
        R2 = R2 + PFCContext::getInstance().mult(Y_tilde[j], d_coeff[j]);

    // [T2 fusion] e(Ỹ[0],L) == e(R2,R1) ⇔ combine both terms into one multi-pairing == 1_T (still counted as 2 terms; degenerate points fall back to pointwise).
    return PFCContext::getInstance().pairEq(Y_tilde[0], L, R2, R1);
}

string ClauseDesc(const PolicyClause& c) {
    string s = (c.type == MoniClauseType::Intersection) ? "intersection (|A∩set|≥" : "difference (|set\\A|≥";
    s += std::to_string(c.threshold);
    s += ", |set|=" + std::to_string(c.set.size()) + ")";
    return s;
}

string PolicyDesc(const Policy& p) {
    string s = "AND(" + std::to_string(p.clauses.size()) + " clauses):";
    for (size_t i = 0; i < p.clauses.size(); ++i)
        s += " [" + std::to_string(i + 1) + "]" + ClauseDesc(p.clauses[i]);
    return s;
}

// ---------- Size estimates (G1=64 B, Big=32 B) ----------
inline size_t clause_proof_size_calc(const ClauseProof& a) {
    const size_t G1B = size_of_g1_fixed(a.witness);
    const size_t BIGB = BN_FIELD_BYTES;
    size_t total = 2 * G1B;
    total += 1 + 4;
    total += 4;
    total += 4 + a.revealed.size() * BIGB;
    total += 4 + a.remainderCoeff.size() * BIGB;
    total += 4 + a.publicSet.size() * BIGB;
    return total;
}
size_t ClauseProof::size() const { return clause_proof_size_calc(*this); }

inline size_t moni_proof_size_calc(const MoniProof& a) {
    size_t total = size_of_g1_fixed(a.commitment);
    total += BN_FIELD_BYTES;
    total += 4 + a.proofs.size() * 4;
    for (const ClauseProof& c : a.proofs) total += c.size();
    return total;
}
size_t MoniProof::size() const { return moni_proof_size_calc(*this); }

static bool contains(const vector<Big>& v, const Big& x) {
    for (const Big& e : v) if (e == x) return true;
    return false;
}
static bool hasDuplicates(const vector<Big>& v) {
    for (size_t i = 0; i < v.size(); ++i)
        for (size_t j = i + 1; j < v.size(); ++j)
            if (v[i] == v[j]) return true;
    return false;
}

// Early rejection (otherwise proving succeeds but verification can never pass): empty/zero-containing/duplicate set, out-of-range t, |set| > maxAttrs.
static bool proveClause(const SystemParams& sys, const MoniPoly& moni,
                        const vector<Big>& attrs, const Big& opening,
                        const PolicyClause& cl, int idx, ClauseProof& out, string& why) {
    PFCContext& ctx = PFCContext::getInstance();
    const Big q = ctx.pfc->order();

    if (cl.set.empty()) { why = "policy set is empty"; return false; }
    if (cl.threshold < 1 || cl.threshold > (int)cl.set.size()) { why = "invalid threshold (t out of range)"; return false; }
    for (const Big& v : cl.set) if (v == 0) { why = "policy set contains 0 (invalid value)"; return false; }
    // Duplicate elements (early rejection): the verifier's verifyClause runs hasDuplicates on publicSet,
    if (hasDuplicates(cl.set)) { why = "policy set contains duplicate elements (the same value appears more than once)"; return false; }
    // so |set| must be ≤ maxAttrs; otherwise generation succeeds but verification can never pass (silent failure).
    if ((int)cl.set.size() > sys.maxAttrs) {
        why = "policy set size " + std::to_string(cl.set.size()) +
              " exceeds maxAttrs=" + std::to_string(sys.maxAttrs);
        return false;
    }

    out = ClauseProof();
    out.clauseIndex = idx;
    out.type = cl.type;
    out.threshold = cl.threshold;
    out.publicSet = cl.set;

    if (cl.type == MoniClauseType::Intersection) {
        vector<Big> I; G1 W;
        if (!moni.OpenIntersection(sys.Y, attrs, opening, cl.set, cl.threshold, I, W, q)) {
            why = "|A∩set| < t";
            return false;
        }
        out.revealed = I;
        out.witness = W;
        return true;
    }
    vector<Big> D; G1 W; vector<Big> r;
    if (!moni.OpenDifference(sys.Y, attrs, opening, cl.set, cl.threshold, D, W, r, q)) {
        why = "|set\\A| < t";
        return false;
    }
    out.revealed = D;
    out.witness = W;
    out.remainderCoeff = r;
    return true;
}

// Note: all precondition checks still run before commitment ⇒ exception type/order/message match the public entry exactly.
static MoniProof ProveSetRelationCore(const SystemParams& sys,
                                      const vector<Big>& attributes,
                                      const Big& opening,
                                      const Policy& policy,
                                      const G1* preC) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();

    if (attributes.empty()) throw invalid_argument("ProveSetRelation: empty attributes");
    if (hasDuplicates(attributes)) throw invalid_argument("attributes must be a set (no duplicates)");
    for (const Big& a : attributes)
        if (a == 0) throw invalid_argument("attributes must be non-zero");
    if (opening == 0) throw invalid_argument("opening must be non-zero");
    // o must be ∉ A ∪ all policy sets:
    for (const Big& a : attributes)
        if (a == opening)
            throw invalid_argument("opening must not be in attributes (require o not in A)");
    for (const PolicyClause& c : policy.clauses)
        for (const Big& v : c.set)
            if (v == opening)
                throw invalid_argument("opening must not be in policy set (require o not in policy set)");
    if ((int)attributes.size() > sys.maxAttrs)
        throw invalid_argument("attributes exceed system maxAttrs");
    if (sys.Y.empty() || sys.Y.size() != sys.Y_tilde.size())
        throw invalid_argument("SRS not initialized");
    if (policy.clauses.empty()) throw invalid_argument("ProveSetRelation: empty policy");

    const Big q = ctx.pfc->order();
    MoniPoly moni;
    MoniProof proof;
    proof.commitment = preC ? *preC : moni.CommitSet(sys.Y, attributes, opening, q);
    // [Anti-replay / anti-bytewise-linkage] one-time nonce: bound by the SoK challenge c (see hashProof).
    ctx.pfc->random(proof.nonce);

    vector<string> reasons;
    for (size_t i = 0; i < policy.clauses.size(); ++i) {
        ClauseProof cp; string why;
        if (proveClause(sys, moni, attributes, opening,
                        policy.clauses[i], (int)i, cp, why))
            proof.proofs.push_back(cp);
        else
            reasons.push_back("clause " + std::to_string(i + 1) + " " +
                              ClauseDesc(policy.clauses[i]) + " is not satisfied: " + why);
    }

    // Composition: [logical AND] only ⇒ every clause must be proven.
    const int satisfied = (int)proof.proofs.size();
    const int total = (int)policy.clauses.size();
    if (satisfied != total) {
        string msg = "policy not satisfied (" + PolicyDesc(policy) + "): only " +
                     std::to_string(satisfied) + "/" + std::to_string(total) + " clauses were proven";
        for (const string& r : reasons) msg += "\n  " + r;
        throw runtime_error(msg);
    }
    return proof;
}

MoniProof ProveSetRelation(const SystemParams& sys,
                           const vector<Big>& attributes,
                           const Big& opening,
                           const Policy& policy) {
    return ProveSetRelationCore(sys, attributes, opening, policy, nullptr);
}

// ② Plaintext checks: revealed is non-empty, duplicate-free, |revealed| [exactly] = t (minimal disclosure), and revealed ⊆ publicSet.
static bool verifyClause(const SystemParams& sys, const MoniPoly& moni,
                         const G1& C, const ClauseProof& cp) {
    PFCContext& ctx = PFCContext::getInstance();
    const Big q = ctx.pfc->order();

    // ① Self-described field validity (prevents an invalid description from "proving" a trivial clause).
    if (cp.type != MoniClauseType::Intersection &&
        cp.type != MoniClauseType::Difference) return false;
    if (cp.publicSet.empty()) return false;
    if (hasDuplicates(cp.publicSet)) return false;
    for (const Big& v : cp.publicSet) if (v == 0) return false;
    if (cp.threshold < 1 || cp.threshold > (int)cp.publicSet.size()) return false;
    // System bound (consistent with proveClause): |set| ≤ maxAttrs.
    if ((int)cp.publicSet.size() > sys.maxAttrs) return false;

    // ② Plaintext checks: the revealed set is non-empty, duplicate-free, |revealed| == t (minimal disclosure), and revealed ⊆ set.
    if (cp.revealed.empty()) return false;
    if ((int)cp.revealed.size() != cp.threshold) return false; // minimal disclosure: exactly t entries
    if (hasDuplicates(cp.revealed)) return false;
    for (const Big& e : cp.revealed)
        if (!contains(cp.publicSet, e)) return false;

    if (cp.type == MoniClauseType::Intersection)
        return moni.VerifyIntersection(sys.Y, sys.Y_tilde, C, cp.revealed,
                                       cp.witness, cp.publicSet, cp.threshold, q);
    if ((int)cp.remainderCoeff.size() < cp.threshold) return false;
    return moni.VerifyDifference(sys.Y, sys.Y_tilde, C, cp.revealed,
                                 cp.witness, cp.remainderCoeff,
                                 cp.publicSet, cp.threshold, q);
}

bool VerifySetRelation(const MoniProof& proof, const SystemParams& sys) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    if (sys.Y.empty() || sys.Y.size() != sys.Y_tilde.size()) return false;
    if (proof.proofs.empty()) return false;

    MoniPoly moni;
    for (const ClauseProof& cp : proof.proofs) {
        if (cp.clauseIndex < 0) return false;
        if (!verifyClause(sys, moni, proof.commitment, cp)) return false;
    }
    // Indices must be unique (two copies of one clause must not count as two clauses).
    for (size_t i = 0; i < proof.proofs.size(); ++i)
        for (size_t j = i + 1; j < proof.proofs.size(); ++j)
            if (proof.proofs[i].clauseIndex == proof.proofs[j].clauseIndex) return false;
    return true;
}

bool MoniMatchesPolicy(const MoniProof& proof, const Policy& policy, std::string* why) {
    auto fail = [&](const std::string& m) {
        if (why) *why = m;
        return false;
    };

    const int total = (int)policy.clauses.size();
    if (total < 1) return fail("policy is empty");
    if (proof.proofs.empty()) return fail("proof contains no clauses");

    // Every proven clause must exactly match the policy clause at the same index (type/set/threshold).
    for (const ClauseProof& cp : proof.proofs) {
        if (cp.clauseIndex >= total)
            return fail("clause index out of range: " + std::to_string(cp.clauseIndex));
        const PolicyClause& cl = policy.clauses[(size_t)cp.clauseIndex];
        const string tag = "clause " + std::to_string(cp.clauseIndex + 1);
        if (cp.type != cl.type) return fail(tag + " type mismatch");
        if (cp.threshold != cl.threshold) return fail(tag + " threshold mismatch");
        if (cp.publicSet.size() != cl.set.size()) return fail(tag + " set size mismatch");
        for (size_t i = 0; i < cl.set.size(); ++i)
            if (!(cp.publicSet[i] == cl.set[i])) return fail(tag + " set element mismatch");
    }

    // Composition: [logical AND] only ⇒ every policy clause must be proven (full coverage).
    const int satisfied = (int)proof.proofs.size();
    if (satisfied != total)
        return fail("AND: only " + std::to_string(satisfied) + "/" +
                    std::to_string(total) + " clauses were proven");
    return true;
}


// Unified challenge (domain-separation label "SOK-SHIFT-v1").
static Big moniChallenge(const SystemParams& sys, const string& bound, const Big& nonce,
                          const G1& Cxprime, const G1& A2, const PSCredential& sig,
                          const PSVerifyKey& pk, const GT& Up, const MoniProof& mp) {
    PFCContext& ctx = PFCContext::getInstance();
    ctx.pfc->start_hash();
    fsAbsorb(ctx.pfc, string("SOK-SHIFT-v1"));
    fsAbsorb(ctx.pfc, bound);
    fsAbsorb(ctx.pfc, nonce);
    fsAbsorb(ctx.pfc, sys.g1);
    fsAbsorb(ctx.pfc, sys.g2);
    fsAbsorb(ctx.pfc, sys.h);
    fsAbsorb(ctx.pfc, sys.Xtilde1);
    fsAbsorb(ctx.pfc, Big((long)sys.Y.size()));
    fsAbsorb(ctx.pfc, Big((long)sys.Y_tilde.size()));
    fsAbsorb(ctx.pfc, Cxprime);
    fsAbsorb(ctx.pfc, A2);
    fsAbsorb(ctx.pfc, sig.sigma1);
    fsAbsorb(ctx.pfc, sig.sigma2);
    fsAbsorb(ctx.pfc, pk.X2);
    for (const G2& e : pk.Y2) fsAbsorb(ctx.pfc, e);
    fsAbsorb(ctx.pfc, Up);
    hashProof(ctx.pfc, mp);
    return ctx.pfc->finish_hash_to_group() % ctx.pfc->order();
}

void MoniCommits(const SystemParams& sys, const vector<Big>& f, G1& C, G1& Cxprime) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    if (f.empty()) throw invalid_argument("MoniCommits: empty f");
    if (sys.Y.size() < f.size() + 1 || sys.Y_tilde.size() < f.size() + 1)
        throw invalid_argument("MoniCommits: SRS too short (need maxAttrs+3 entries)");
    C = ctx.mult(sys.Y[0], f[0]);
    for (size_t k = 1; k < f.size(); ++k) C = C + ctx.mult(sys.Y[k], f[k]);
    Cxprime = ctx.mult(sys.Y[1], f[0]);
    for (size_t k = 1; k < f.size(); ++k) Cxprime = Cxprime + ctx.mult(sys.Y[k + 1], f[k]);
}

bool VerifyAnchoring(const SystemParams& sys, const G1& C, const G1& Cxprime) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    if (sys.Y_tilde.size() < 2) return false;
    return ctx.pairEq(sys.Y_tilde[1], C, sys.Y_tilde[0], Cxprime);
}

static PSCredential MoniBlindObtainCore(const G1& Cxprime, const AttributeIssuer& issuer,
                                        Big& t, G1& blindOut) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    do { ctx.pfc->random(t); } while (t == 0);
    blindOut = BlindCommitment(Cxprime, t);
    PSCredential bs = issuer.obtainBlind(BlindCredentialRequest{ blindOut });
    return UnblindCredential(bs, t);
}

PSCredential MoniBlindObtain(const SystemParams& sys, const vector<Big>& f,
                              const AttributeIssuer& issuer,
                              G1& C, G1& Cxprime, Big& t, G1& blindOut) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    MoniCommits(sys, f, C, Cxprime);
    return MoniBlindObtainCore(Cxprime, issuer, t, blindOut);
}

// Challenge (moniChallenge); responses s_k = t_k + c·f_k; in MoniProof, C is carried by mp.
static void MoniProvePreconditions(const SystemParams& sys, const vector<Big>& f,
                                   const PSVerifyKey& issuerPub) {
    const size_t n2 = f.size();
    if (n2 < 2) throw invalid_argument("MoniProve: too few coefficients");
    if (issuerPub.Y2.size() < n2) throw invalid_argument("MoniProve: pk view too short (need n+2 messages)");
    if (sys.Y.size() < n2 + 1) throw invalid_argument("MoniProve: SRS too short (need maxAttrs+3)");
}

static MoniPresentation MoniProveCore(const SystemParams& sys, const vector<Big>& f,
                                      const PSCredential& cred, const PSVerifyKey& issuerPub,
                                      const string& msg, const MoniProof& mp,
                                      const G1& C, const G1& Cxprime) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    MoniProvePreconditions(sys, f, issuerPub);
    if (!(mp.commitment == C)) throw invalid_argument("MoniProve: mp.commitment != C (A/o mismatch)");
    const size_t n2 = f.size();

    PSCredential sig = PSRandomize(cred);
    Big nonce;
    do { ctx.pfc->random(nonce); } while (nonce == 0);

    vector<Big> t(n2);
    for (size_t k = 0; k < n2; ++k) ctx.pfc->random(t[k]);
    G1 A2 = ctx.mult(sys.Y[1], t[0]);
    for (size_t k = 1; k < n2; ++k) A2 = A2 + ctx.mult(sys.Y[k + 1], t[k]);

    GT Up;
    SigmaCommitZkPs(sig, issuerPub, f, t, Up);

    const Big c = moniChallenge(sys, msg, nonce, Cxprime, A2, sig, issuerPub, Up, mp);
    MoniPresentation out;
    out.Cxprime = Cxprime;
    out.anchor.A2 = A2;
    out.anchor.c = c;
    zkPsResponses(f, t, c, out.anchor.s);
    out.ks.credential = sig;
    out.ks.nonce = nonce;
    out.ks.bind.Up = Up;
    out.ks.bind.c = c;
    out.ks.bind.sm = out.anchor.s;
    return out;
}

// Public entry: compute (C, C_{x′}) once here (identical term by term to the formula inside MoniProveCore).
MoniPresentation MoniProve(const SystemParams& sys, const vector<Big>& f, const PSCredential& cred,
                             const PSVerifyKey& issuerPub, const string& msg, const MoniProof& mp) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    MoniProvePreconditions(sys, f, issuerPub);
    G1 C, Cxprime;
    MoniCommits(sys, f, C, Cxprime);
    return MoniProveCore(sys, f, cred, issuerPub, msg, mp, C, Cxprime);
}

// zkPsVerifyWithChallenge(credential equation, responses=pr.anchor.s); VerifyAnchoring;
bool MoniDecide(const MoniPresentation& pr, const PSVerifyKey& issuerPub, const SystemParams& sys,
                 const string& msg, const MoniProof& mp, const Policy& required,
                 string* why, DecideStats* stats) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    const Big q = ctx.pfc->order();
    const size_t n2 = pr.anchor.s.size();

    // ===== Steps 1-3: challenge + anchoring + credential equation =====
    long p0 = ctx.pairingCount, g0 = ctx.gtPowCount, m0 = ctx.g1MultCount, n0 = ctx.g2MultCount;
    Timer t1;
    if (n2 < 2) { if (why) *why = "response is too short"; return false; }
    if (issuerPub.Y2.size() < n2) { if (why) *why = "public-key view does not cover n+2 messages"; return false; }
    if (sys.Y.size() < n2 + 1) { if (why) *why = "SRS is too short (requires maxAttrs+3)"; return false; }
    // (Degenerate credentials σ=(O,O) and Up=1_T are uniformly rejected by zkPsVerifyWithChallenge in ps_credential.cpp; clause-level C/W checks are in monipoly.cpp.)
    if (pr.Cxprime.g.iszero() || mp.commitment.g.iszero()) {
        if (why) *why = "degenerate input: commitment is the identity";
        return false;
    }

    const Big c = moniChallenge(sys, msg, pr.ks.nonce, pr.Cxprime, pr.anchor.A2,
                                 pr.ks.credential, issuerPub, pr.ks.bind.Up, mp);
    if (!(c == pr.anchor.c) || !(c == pr.ks.bind.c)) { if (why) *why = "challenge mismatch (transcript was modified)"; return false; }
    {
        G1 rhs = ctx.mult(sys.Y[1], pr.anchor.s[0]);
        for (size_t k = 1; k < n2; ++k) rhs = rhs + ctx.mult(sys.Y[k + 1], pr.anchor.s[k]);
        G1 lhs = pr.anchor.A2 + ctx.mult(pr.Cxprime, c);
        if (!(lhs == rhs)) { if (why) *why = "x′-shift anchoring failed (credential messages != coefficients of C_{x′})"; return false; }
    }
    if (!zkPsVerifyWithChallenge(pr.ks.credential, issuerPub, pr.anchor.s, pr.ks.bind.Up, q, c)) {
        if (why) *why = "credential equation verification failed";
        return false;
    }
    long p1 = ctx.pairingCount, g1c = ctx.gtPowCount, m1c = ctx.g1MultCount, n1c = ctx.g2MultCount;
    if (stats) { stats->sok.ms = t1.elapsed_ms(); stats->sok.pair = p1 - p0;
                 stats->sok.gtpow = g1c - g0; stats->sok.g1 = m1c - m0; stats->sok.g2 = n1c - n0; }

    // ===== Steps 4-5: shifted pairing + set relation =====
    Timer t2;
    if (!VerifyAnchoring(sys, mp.commitment, pr.Cxprime)) {
        if (why) *why = "shift relation C_{x′} = C^x′ verification failed";
        return false;
    }
    if (!VerifySetRelation(mp, sys)) { if (why) *why = "set relation verification failed"; return false; }
    long p2 = ctx.pairingCount, g2c = ctx.gtPowCount, m2c = ctx.g1MultCount, n2c = ctx.g2MultCount;
    if (stats) { stats->rel.ms = t2.elapsed_ms(); stats->rel.pair = p2 - p1;
                 stats->rel.gtpow = g2c - g1c; stats->rel.g1 = m2c - m1c; stats->rel.g2 = n2c - n1c; }

    // ===== Step 6: policy compliance (plaintext only) =====
    Timer t3;
    const bool ok = MoniMatchesPolicy(mp, required, why);
    if (stats) { stats->match.ms = t3.elapsed_ms(); stats->match.pair = ctx.pairingCount - p2;
                 stats->match.gtpow = ctx.gtPowCount - g2c;
                 stats->match.g1 = ctx.g1MultCount - m2c; stats->match.g2 = ctx.g2MultCount - n2c; }
    return ok;
}

static bool MoniCheckContract(const vector<Big>& attrs, const Big& o, const Policy& policy, string* why) {
    auto fail = [&](const string& m) { if (why) *why = m; return false; };
    if (attrs.empty()) return fail("attrs empty");
    if (o == 0) return fail("opening o must be non-zero");
    for (const Big& a : attrs) {
        if (a == 0) return fail("attribute must be non-zero");
        if (a == o) return fail("o must not be in attributes");
    }
    for (const PolicyClause& cl : policy.clauses)
        for (const Big& v : cl.set) if (v == o) return fail("o must not be in policy set");
    return true;
}

// Preconditions (without mp): o ≠ 0; a ≠ 0; o ∉ attrs; o ∉ policy sets; f == MPEncode(attrs,o).
static bool MoniValidateInputsWithoutMp(const SystemParams& sys, const vector<Big>& attrs, const Big& o,
                                        const vector<Big>& f, const Policy& policy, string* why) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    auto fail = [&](const string& m) { if (why) *why = m; return false; };
    if (!MoniCheckContract(attrs, o, policy, why)) return false;
    const vector<Big> expect = MoniPoly::MPEncode(attrs, o, ctx.pfc->order());
    if (expect.size() != f.size()) return fail("f size mismatch vs (attrs,o)");
    for (size_t i = 0; i < f.size(); ++i) if (!(expect[i] == f[i])) return fail("f != MPEncode(attrs,o)");
    return true;
}

bool MoniValidateInputs(const SystemParams& sys, const vector<Big>& attrs, const Big& o,
                         const vector<Big>& f, const Policy& policy, const MoniProof& mp,
                         string* why) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    auto fail = [&](const string& m) { if (why) *why = m; return false; };
    if (!MoniCheckContract(attrs, o, policy, why)) return false;
    const Big q = ctx.pfc->order();
    const vector<Big> expect = MoniPoly::MPEncode(attrs, o, q);
    if (expect.size() != f.size()) return fail("f size mismatch vs (attrs,o)");
    for (size_t i = 0; i < f.size(); ++i) if (!(expect[i] == f[i])) return fail("f != MPEncode(attrs,o)");
    MoniPoly moni;
    const G1 C = moni.CommitSet(sys.Y, attrs, o, q);
    if (!(mp.commitment == C)) return fail("mp.commitment != CommitSet(attrs,o)");
    return true;
}

MoniPresentation MoniProveFromAttrs(const SystemParams& sys, const vector<Big>& attrs, const Big& o,
                                    const PSCredential& cred, const PSVerifyKey& issuerPub,
                                    const string& msg, MoniProof& mp) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    const vector<Big> f = MoniPoly::MPEncode(attrs, o, ctx.pfc->order());
    return MoniProve(sys, f, cred, issuerPub, msg, mp);
}

// The former MoniProveForSession bundled "generate o + online blind issuance" with "presentation" ⇒ every presentation required the issuer to be online.
MoniSession MoniSessionInit(const SystemParams& sys, const vector<Big>& attrs, const Big& o,
                            const AttributeIssuer& issuer, const Policy& policy, MoniProof& mp) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    if (attrs.empty()) throw invalid_argument("MoniSessionInit: empty attributes");
    const Big q = ctx.pfc->order();
    const vector<Big> f = MoniPoly::MPEncode(attrs, o, q);
    {
        std::string bad;
        if (!MoniValidateInputsWithoutMp(sys, attrs, o, f, policy, &bad))
            throw invalid_argument("MoniSessionInit: " + bad);
    }
    // [Deduplicate computation] The flow needs (C, C_{x′}) in three places (blind issuance / attribute-side proof / anchored presentation), and the former implementation computed them separately;
    G1 C, Cxprime;
    MoniCommits(sys, f, C, Cxprime);

    G1 blind;
    Big t;
    // ★ The only online step (once per session): blind C_{x′} → issuer blind signature → unblind ⇒ session credential.
    PSCredential cred = MoniBlindObtainCore(Cxprime, issuer, t, blind);

    mp = ProveSetRelationCore(sys, attrs, o, policy, &C);
    {
        std::string bad;
        if (!MoniCheckContract(attrs, o, policy, &bad))
            throw invalid_argument("MoniSessionInit: " + bad);
        if (!(mp.commitment == C))
            throw invalid_argument("MoniSessionInit: mp.commitment != CommitSet(attrs,o)");
    }
    MoniSession session;
    session.o = o;
    session.f = f;
    session.cred = cred;
    session.C = C;
    session.Cxprime = Cxprime;
    session.t = t;
    session.blind = blind;
    return session;
}

MoniSession MoniSessionInit(const SystemParams& sys, const vector<Big>& attrs,
                            const AttributeIssuer& issuer, const Policy& policy,
                            MoniProof& mp, const vector<Big>& extraForbidden) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    if (attrs.empty()) throw invalid_argument("MoniSessionInit: empty attributes");
    // Forbidden set = A ∪ policy sets ∪ extraForbidden (only tightens sampling; contract validation still uses A ∪ policy sets, see the explicit-o version).
    vector<Big> forbidden = attrs;
    for (const PolicyClause& cl : policy.clauses)
        forbidden.insert(forbidden.end(), cl.set.begin(), cl.set.end());
    forbidden.insert(forbidden.end(), extraForbidden.begin(), extraForbidden.end());
    Big o;
    for (;;) {
        ctx.pfc->random(o);
        if (o == 0) continue;
        bool clash = false;
        for (const Big& v : forbidden) if (v == o) { clash = true; break; }
        if (!clash) break;
    }
    return MoniSessionInit(sys, attrs, o, issuer, policy, mp);
}

// Every call randomizes the session credential and draws fresh nonce/t_k ⇒ responses differ, but C_{x′} is shared (linkable within a session).
MoniPresentation MoniProve(const SystemParams& sys, const MoniSession& session,
                           const PSVerifyKey& issuerPub, const string& msg, const MoniProof& mp) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    return MoniProveCore(sys, session.f, session.cred, issuerPub, msg, mp,
                         session.C, session.Cxprime);
}
