// SoK, six-step decision, anti-replay, and Pedersen reference path.
#include "knowledge_signature.h"
#include "pedersen.h"
#include "monipoly.h"
#include "fs_transcript.h"
#include <stdexcept>
using namespace std;

static bool hasDuplicates(const vector<Big>& v) {
    for (size_t i = 0; i < v.size(); ++i)
        for (size_t j = i + 1; j < v.size(); ++j)
            if (v[i] == v[j]) return true;
    return false;
}

// ---- Canonical encoding of the Fiat–Shamir challenge c (prevents byte-stream ambiguity from yielding forged statements) ----


// Identity-proof size (C and anchoring moved into MoniProof; see size() in monipoly.cpp): credential σ' + nonce + responses s (non-empty only in reference mode) + Up + challenge c.
size_t CoeffKnowledgeSignature::size() const {
    const size_t G1B  = size_of_g1_fixed(credential.sigma1);
    const size_t BIGB = BN_FIELD_BYTES;
    const size_t GTB  = 12 * BIGB;

    size_t total = 2 * G1B;
    total += BIGB; // non-zero nonce carried by the SoK
    total += 4 + bind.sm.size() * BIGB;
    total += GTB;
    total += BIGB;
    return total;
}

std::string NonceHex(const Big& v) {
    miracl* mip = get_mip();
    int old = mip->IOBASE;
    mip->IOBASE = 16;
    char buf[1200];
    cotstr(v.getbig(), buf);
    mip->IOBASE = old;
    return std::string(buf);
}

const size_t kNonceStateCap = 4096;

// Anti-replay: key = msg.size() + msg + NonceHex(nonce); record in used if fresh; evict the oldest beyond kNonceStateCap.
bool NonceFresh(std::vector<std::string>& used, const Big& nonce,
                const std::string& msg, std::string* why) {
    const std::string key = std::to_string(msg.size()) + msg + NonceHex(nonce);
    for (const std::string& k : used)
        if (k == key) { if (why) *why = "replay: this (nonce, msg) has already been used"; return false; }
    used.push_back(key);
    if (used.size() > kNonceStateCap)
        used.erase(used.begin(), used.begin() + (used.size() - kNonceStateCap));
    return true;
}

// [Anti-replay layer 1] msg must end with an issued, unused sid; on success record it in usedSids (see knowledge_signature.h).
bool SessionBindFresh(const std::vector<std::string>& issued,
                      std::vector<std::string>& usedSids, // list of used sids (anti-replay layer 1)
                      const std::string& msg, std::string* why) {
    if (issued.empty()) return true;
    for (const std::string& sid : issued) {
        if (msg.size() < sid.size()) continue;
        if (msg.compare(msg.size() - sid.size(), sid.size(), sid) != 0) continue;
        for (const std::string& u : usedSids)
            if (u == sid) { if (why) *why = "session identifier has already been used (anti-replay layer 1)"; return false; }
        usedSids.push_back(sid);
        return true;
    }
    if (why) *why = "msg is not bound to a session identifier sid issued by this verifier (anti-replay layer 1 not closed)";
    return false;
}

// Domain-separation label "SOK-LINK-v8|MODE-PED" ⇒ never confused with main-path transcripts.
static Big pedChallenge(const SystemParams& sys,
                        const std::string& bound, // statement-binding string (message m / session identifier)
                        const Big& nonce, // one-time nonce carried by the SoK
                        const PSCredential& sig,
                        const std::vector<PSVerifyKey>& pks,
                        const GT& Up,
                        const PedRelationProof& pr) {
    PFCContext& ctx = PFCContext::getInstance();
    ctx.pfc->start_hash();
    // A different domain-separation label from the main path ⇒ the two modes' transcripts never collide.
    fsAbsorb(ctx.pfc, std::string("SOK-LINK-v8|MODE-PED"));
    fsAbsorb(ctx.pfc, bound); // statement-binding string (message m / session identifier)
    fsAbsorb(ctx.pfc, nonce); // nonce carried by the SoK
    fsAbsorb(ctx.pfc, sys.g1);
    fsAbsorb(ctx.pfc, sys.g2);
    fsAbsorb(ctx.pfc, sys.h);
    fsAbsorb(ctx.pfc, sys.Xtilde1);
    fsAbsorb(ctx.pfc, Big((long)sys.Y.size()));
    fsAbsorb(ctx.pfc, Big((long)sys.Y_tilde.size()));
    // [Public values of the reference-mode relation proof]: nonce + per-attribute commitments + plaintext attributes + blinds
    fsAbsorb(ctx.pfc, pr.nonce);
    fsAbsorb(ctx.pfc, Big((long)pr.com.size()));
    for (const G1& e : pr.com) fsAbsorb(ctx.pfc, e);
    fsAbsorb(ctx.pfc, Big((long)pr.attrs.size()));
    for (const Big& v : pr.attrs) fsAbsorb(ctx.pfc, v);
    fsAbsorb(ctx.pfc, Big((long)pr.blinds.size()));
    for (const Big& b : pr.blinds) fsAbsorb(ctx.pfc, b);
    fsAbsorb(ctx.pfc, sig.sigma1);
    fsAbsorb(ctx.pfc, sig.sigma2);
    fsAbsorb(ctx.pfc, Big((long)pks.size()));
    for (const PSVerifyKey& pk : pks) {
        fsAbsorb(ctx.pfc, pk.X2);
        for (const G2& e : pk.Y2) fsAbsorb(ctx.pfc, e);
    }
    // GT commitment on the identity-proof side (Up = ∏B_i^{t_i}, same as MoniPoly mode)
    fsAbsorb(ctx.pfc, Up);
    return ctx.pfc->finish_hash_to_group() % ctx.pfc->order();
}

CoeffKnowledgeSignature SignOfKnowledgeCoeffPed(const SystemParams& sys,
                                                const PSCredential& credential,
                                                const PSVerifyKey& issuerPub,
                                                const std::string& msg,
                                                const PedRelationProof& pr) {
    // [P0 fix] The credential must cover exactly the plaintext attributes presented in pr: the coefficient vector is derived uniquely from pr.attrs.
    const std::vector<Big>& attributes = pr.attrs;
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();

    const int n = (int)attributes.size();
    if (n < 1) throw std::invalid_argument("no attributes");
    if (n > sys.maxAttrs) throw std::invalid_argument("attributes exceed maxAttrs");
    if (hasDuplicates(attributes)) throw std::invalid_argument("attributes must be a set (no duplicates)");

    // 1) Coefficient vector (the credential still signs it — consistent with MoniPoly mode ⇒ identical credential semantics across modes).
    std::vector<Big> coefs = AttributeCoefficients(attributes);
    const size_t n1 = coefs.size();
    if (issuerPub.Y2.size() < n1)
        throw std::invalid_argument("public key view (pp slice) does not cover the coefficient count");

    // 2) [No anchoring] in this mode ⇒ draw a fresh set of Σ random t, compute Up, and self-check that credential messages == coefficients.
    PSCredential sig = PSRandomize(credential);
    std::vector<Big> t(n1);
    for (size_t j = 0; j < n1; ++j) ctx.pfc->random(t[j]);
    GT Up;
    SigmaCommitZkPs(sig, issuerPub, coefs, t, Up);

    // 3) Unified challenge (Pedersen mode) + one-time nonce carried by the SoK.
    Big nonce;
    do { ctx.pfc->random(nonce); } while (nonce == 0);
    const Big c = pedChallenge(sys, msg, nonce, sig, std::vector<PSVerifyKey>{issuerPub}, Up, pr);

    // 4) Responses sm_i = t_i + c·q_i + assembly ([no anchoring] in this mode: ks carries only the identity proof).
    CoeffKnowledgeSignature ks;
    ks.credential = sig;
    ks.nonce = nonce;
    ks.bind.Up = Up;
    ks.bind.c = c;
    zkPsResponses(coefs, t, c, ks.bind.sm);
    return ks;
}

// [Reference-mode verification] Recompute c = pedChallenge and require it to equal ks.bind.c (defensive), then verify zkPsVerifyWithChallenge(ks.bind.sm, ks.bind.Up).
bool VerifyKnowledgeSignatureCoeffPed(const CoeffKnowledgeSignature& ks,
                                      const PSVerifyKey& issuerPub,
                                      const SystemParams& sys,
                                      const std::string& msg,
                                      const PedRelationProof& pr) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    if (issuerPub.Y2.size() < 1) return false;
    const Big q = ctx.pfc->order();

    const Big c = pedChallenge(sys, msg, ks.nonce, ks.credential,
                               std::vector<PSVerifyKey>{issuerPub}, ks.bind.Up, pr);
    if (!(c == ks.bind.c)) return false; // defensive: the prover-recorded challenge must match the recomputation
    // This mode verifies only the identity proof (credential messages = presented coefficients); relation verification is delegated to VerifyRelationPedersen.
    return zkPsVerifyWithChallenge(ks.credential, issuerPub, ks.bind.sm, ks.bind.Up, q, c);
}

// [Reference-mode single entry] ① VerifyKnowledgeSignatureCoeffPed ∧ ② VerifyRelationPedersen ∧ ③ PolicySatisfiedByPlaintext (plaintext policy), all required; per-step timings go to stats.
bool DecidePresentationPed(const CoeffKnowledgeSignature& ks,
                           const PSVerifyKey& issuerPub,
                           const SystemParams& sys,
                           const std::string& msg,
                           const PedRelationProof& pr,
                           const Policy& required,
                           std::string* why,
                           DecideStats* stats) {
    PFCContext& ctx = PFCContext::getInstance();

    Timer t1;
    long p0 = ctx.pairingCount, g0 = ctx.gtPowCount, m0 = ctx.g1MultCount, n0 = ctx.g2MultCount;
    bool ok1 = VerifyKnowledgeSignatureCoeffPed(ks, issuerPub, sys, msg, pr);
    long p1 = ctx.pairingCount, g1c = ctx.gtPowCount, m1c = ctx.g1MultCount, n1c = ctx.g2MultCount;
    if (stats) { stats->sok.ms = t1.elapsed_ms(); stats->sok.pair = p1 - p0;
                 stats->sok.gtpow = g1c - g0; stats->sok.g1 = m1c - m0; stats->sok.g2 = n1c - n0; }

    Timer t2;
    bool ok2 = VerifyRelationPedersen(pr, sys);
    long p2 = ctx.pairingCount, g2c = ctx.gtPowCount, m2c = ctx.g1MultCount, n2c = ctx.g2MultCount;
    if (stats) { stats->rel.ms = t2.elapsed_ms(); stats->rel.pair = p2 - p1;
                 stats->rel.gtpow = g2c - g1c; stats->rel.g1 = m2c - m1c; stats->rel.g2 = n2c - n1c; }

    Timer t3;
    bool ok3 = PolicySatisfiedByPlaintext(pr.attrs, required, why);
    if (stats) { stats->match.ms = t3.elapsed_ms(); stats->match.pair = ctx.pairingCount - p2;
                 stats->match.gtpow = ctx.gtPowCount - g2c;
                 stats->match.g1 = ctx.g1MultCount - m2c; stats->match.g2 = ctx.g2MultCount - n2c; }

    if (!ok1) { if (why) *why = "identity proof (SoK, Pedersen mode) verification failed"; return false; }
    if (!ok2) { if (why) *why = "relation verification failed (Pedersen commitment ↔ opening mismatch)"; return false; }
    return ok3;
}
