// Pointcheval-Sanders multi-message credentials: sign, randomize, blind issue, verify.
#include "ps_credential.h"
#include "monipoly.h"
#include <stdexcept>
#include <string>
#include <vector>
using namespace std;

// Sample a non-zero random element from Zq* (reject 0 so that u/t/blinds are non-degenerate).
static void randNonzero(Big& v) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    do { ctx.pfc->random(v); } while (v == 0);
}


// Derive y_i = x′^{i+1} on demand and reject pow == 1 at each step (otherwise the message key is public and the credential becomes linearly malleable); g1^x is issuer-private and is never published (N0/v8).
PSCredential PSSign(const PSSignKey& sk, const vector<Big>& msgs) {
    if (msgs.empty()) throw invalid_argument("PSSign: empty message vector");
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();

    const Big q = ctx.pfc->order();
    Big u;
    randNonzero(u);
    PSCredential cred;
    cred.sigma1 = ctx.mult(*ctx.P, u);

    // X = g1^x is issuer-private and is never published (N0/v8: publishing it enables forgery of arbitrary credentials).
    const Big a = sk.xprime % q;
    Big e = sk.x % q;
    Big pow = a;
    for (size_t i = 0; i < msgs.size(); ++i) {
        if (pow == 1) throw logic_error("PSSign: message key == 1 forbidden");
        e = (e + modmult(pow, msgs[i], q)) % q;
        pow = modmult(pow, a, q);
    }
    cred.sigma2 = ctx.mult(cred.sigma1, e);
    return cred;
}

// Randomize: (σ1,σ2) → (σ1^t, σ2^t) with a fresh non-zero random t ⇒ the credential stays valid but its encoding changes every time, preventing linkage.
PSCredential PSRandomize(const PSCredential& cred) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();

    Big t;
    randNonzero(t);
    PSCredential rnd;
    rnd.sigma1 = ctx.mult(cred.sigma1, t);
    rnd.sigma2 = ctx.mult(cred.sigma2, t);
    return rnd;
}

CredentialRequest ObtainRequest(const vector<Big>& attributes) {
    CredentialRequest req;
    req.coefs = AttributeCoefficients(attributes);
    return req;
}

// Blind the commitment: Cprime = C_q + g1^t; a fresh t yields a different Cprime for the same attribute set, so the issuer cannot link it.
G1 BlindCommitment(const G1& Cq, const Big& t) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    return Cq + ctx.mult(*ctx.P, t % ctx.pfc->order());
}

// Unblind: σ2 = σ2_blind - t·σ1, yielding a valid credential on C_q (identical in form to a plaintext issuance).
PSCredential UnblindCredential(const PSCredential& blindSig, const Big& t) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    const Big q = ctx.pfc->order();
    const Big tm = t % q;
    const Big neg = (tm == 0) ? Big(0) : (q - tm);
    PSCredential c;
    c.sigma1 = blindSig.sigma1;
    c.sigma2 = blindSig.sigma2 + ctx.mult(blindSig.sigma1, neg);
    return c;
}

// Sign the blinded commitment: σ1 = g1^u, σ2 = σ1^x · Cprime^u; neither g1^x must be public nor the attributes known.
PSCredential PSSignOnCommitment(const PSSignKey& sk, const G1& Cprime) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    const Big q = ctx.pfc->order();
    Big u;
    randNonzero(u);
    PSCredential s;
    s.sigma1 = ctx.mult(*ctx.P, u);
    s.sigma2 = ctx.mult(s.sigma1, sk.x % q) + ctx.mult(Cprime, u);
    return s;
}


// Bilinear folding: U = e(g2,σ2)·e(X̃,-σ1), reducing two pairings to one (a single final exponentiation).

// SigmaCommitZkPs: commitment phase; bilinear folding reduces n pairings to one (no B_i precomputation and zero GT exponentiations).
void SigmaCommitZkPs(const PSCredential& sig,
                     const PSVerifyKey& pk,
                     const vector<Big>& msgs,
                     const vector<Big>& sharedT,
                     GT& Up) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    const size_t n = msgs.size();
    if (n < 1) throw invalid_argument("SigmaCommitZkPs: empty message vector");
    if (pk.Y2.size() < n || sharedT.size() != n)
        throw invalid_argument("SigmaCommitZkPs: pk view too short / randomness size mismatch");

    // Batch view of the first n Y2 entries (the SRS view may be longer ⇒ slice once with n shallow copies).
    const vector<G2> y2(pk.Y2.begin(), pk.Y2.begin() + (long)n);

#ifndef MONI_SOK_NO_SELFCHECK
    // Self-check (can be disabled at compile time): U == e(Σ_i m_i·Y2_i, σ1), i.e. the credential messages equal the presented coefficients; this only fails early, while soundness is enforced by verification.
    const G2 sMsg = ctx.g2MultiMult(y2, msgs);
    {
        const vector<G2> ua { *ctx.Q, pk.X2 };
        const vector<G1> ub { sig.sigma2, -sig.sigma1 };
        if (!(ctx.multiPair(ua, ub) == ctx.pair(sMsg, sig.sigma1)))
            throw invalid_argument("SigmaCommitZkPs: signature messages != presented coefficients");
    }
#endif

    Up = ctx.pair(ctx.g2MultiMult(y2, sharedT), sig.sigma1);
    return;
}

// Responses (Pedersen reference mode only): s_i = t_i + c·m_i mod q.
void zkPsResponses(const vector<Big>& msgs,
                   const vector<Big>& t,
                   const Big& challenge,
                   vector<Big>& sm) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    if (msgs.empty() || t.size() != msgs.size())
        throw invalid_argument("zkPsResponses: size mismatch");
    const Big q = ctx.pfc->order();
    const Big c = challenge % q;
    sm.resize(msgs.size());
    for (size_t i = 0; i < msgs.size(); ++i)
        sm[i] = (t[i] + modmult(c, msgs[i], q)) % q;
}

// Since v7, the per-index equation g1^{s_i}h^{sr_i} = Cp_i·C_i^{c} and its associated data have been removed.
bool zkPsVerifyWithChallenge(const PSCredential& sig,
                             const PSVerifyKey& pk,
                             const vector<Big>& responses,
                             const GT& Up,
                             const Big& q,
                             const Big& challenge) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    const size_t n = responses.size();
    if (n < 1 || pk.Y2.size() < n) return false;

    // Anti-degeneracy: if σ1 or σ2 is O, every pairing term degenerates to 1_T and the equation holds for any s_i with Up = 1_T (allowing a presentation to be forged for arbitrary attributes).
    if (sig.sigma1.g.iszero() || sig.sigma2.g.iszero()) return false;

    // Anti-degeneracy: Up = 1_T is necessary for that degeneration; an honest prover has Up = ∏B_i^{t_i} ≠ 1_T with probability 1 - 1/q.
    GT one(1);
    if (Up == one) return false;

    // On the right-hand side, fold U^{-c} into the pairing terms e(-c·Q,σ2)·e(-c·X2,-σ1) ⇒ one multi-pairing; zero terms contribute 1_T, matching the previous formulation term by term.
    const Big c = challenge % q;
    vector<G2> qa; vector<G1> xa;
#ifndef MONI_NO_VERIFY_FOLD
    qa.reserve(3); xa.reserve(3);
    {
        const vector<G2> y2(pk.Y2.begin(), pk.Y2.begin() + (long)n);
        vector<Big> sr(n);
        for (size_t i = 0; i < n; ++i) sr[i] = responses[i] % q;
        const G2 sSum = ctx.g2MultiMult(y2, sr);
        if (!sSum.g.iszero()) {
            qa.push_back(sSum); xa.push_back(sig.sigma1);
        }
    }
#else
    qa.reserve(n + 2); xa.reserve(n + 2);
    for (size_t i = 0; i < n; ++i) {
        G1 t = ctx.mult(sig.sigma1, responses[i] % q);
        if (t.g.iszero()) continue;
        qa.push_back(pk.Y2[i]); xa.push_back(t);
    }
#endif
    if (c != 0) {
        const Big negc = q - c;
        qa.push_back(ctx.mult(*ctx.Q, negc)); xa.push_back(sig.sigma2);
        qa.push_back(ctx.mult(pk.X2, negc));  xa.push_back(-sig.sigma1);
    }
    return (ctx.multiPair(qa, xa) == Up);
}
