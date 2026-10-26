// Pedersen baseline: per-attribute commitments and plaintext policy decision.
#include "pedersen.h"
#include "monipoly.h"
#include <stdexcept>
#include <string>
using namespace std;

static size_t pedersenCheckSize(size_t values, size_t blinds, const char* who) {
    if (values != blinds)
        throw invalid_argument(string(who) + ": size mismatch (values vs blinds)");
    return values;
}

vector<G1> PedersenCommitAttributes(const SystemParams& sys,
                                    const vector<Big>& attrs,
                                    const vector<Big>& blinds) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    const size_t n = pedersenCheckSize(attrs.size(), blinds.size(), "PedersenCommitAttributes");

    vector<G1> com(n);
    for (size_t i = 0; i < n; ++i)
        com[i] = ctx.mult(sys.g1, attrs[i]) + ctx.mult(sys.h, blinds[i]);
    return com;
}

vector<G1> PedersenCommitVector(const SystemParams& sys,
                                const vector<Big>& values,
                                const vector<Big>& blinds) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();
    const size_t n = pedersenCheckSize(values.size(), blinds.size(), "PedersenCommitVector");

    vector<G1> com(n);
    for (size_t i = 0; i < n; ++i)
        com[i] = ctx.mult(sys.g1, values[i]) + ctx.mult(sys.h, blinds[i]);
    return com;
}

bool PedersenOpenVerify(const SystemParams& sys,
                        const vector<G1>& com,
                        const vector<Big>& values,
                        const vector<Big>& blinds) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();

    // Defensive: reject directly on length mismatch (no out-of-bounds reads).
    if (com.size() != values.size() || values.size() != blinds.size()) return false;

    for (size_t i = 0; i < com.size(); ++i) {
        G1 expect = ctx.mult(sys.g1, values[i]) + ctx.mult(sys.h, blinds[i]);
        G1 got = com[i];
        if (!(got == expect)) return false;
    }
    return true;
}


// Size estimate (same convention: G1 = 64 B).
size_t PedRelationProof::size() const {
    const size_t G1B = size_of_g1_fixed(G1());
    size_t total = BN_FIELD_BYTES;
    total += 4 + com.size() * G1B;
    total += 4 + (attrs.size() + blinds.size()) * BN_FIELD_BYTES;
    return total;
}

PedRelationProof ProveRelationPedersen(const SystemParams& sys, const vector<Big>& attributes) {
    PFCContext& ctx = PFCContext::getInstance();
    if (!ctx.pfc) ctx.init();

    if (attributes.empty()) throw invalid_argument("ProveRelationPedersen: empty attributes");
    for (size_t i = 0; i < attributes.size(); ++i) {
        if (attributes[i] == 0) throw invalid_argument("ProveRelationPedersen: zero attribute");
        for (size_t j = i + 1; j < attributes.size(); ++j)
            if (attributes[i] == attributes[j])
                throw invalid_argument("ProveRelationPedersen: duplicate attribute");
    }
    if ((int)attributes.size() > sys.maxAttrs)
        throw invalid_argument("ProveRelationPedersen: attributes exceed maxAttrs");

    PedRelationProof pr;
    pr.attrs = attributes;
    const size_t n = attributes.size();
    pr.blinds.resize(n);
    for (size_t i = 0; i < n; ++i) {
        do { ctx.pfc->random(pr.blinds[i]); } while (pr.blinds[i] == 0);
    }
    pr.com = PedersenCommitAttributes(sys, attributes, pr.blinds);
    ctx.pfc->random(pr.nonce); // one-time nonce (same as the MoniPoly mode)
    return pr;
}

bool VerifyRelationPedersen(const PedRelationProof& pr, const SystemParams& sys) {
    if (pr.com.empty()) return false;
    if (pr.com.size() != pr.attrs.size()) return false;
    if (pr.attrs.size() != pr.blinds.size()) return false;
    for (const Big& a : pr.attrs) if (a == 0) return false;
    return PedersenOpenVerify(sys, pr.com, pr.attrs, pr.blinds);
}

// · Intersection clause: |A ∩ set| ≥ t ; difference clause: |set \ A| ≥ t
static bool pedContains(const vector<Big>& v, const Big& x) {
    for (const Big& e : v) if (e == x) return true;
    return false;
}

bool PolicySatisfiedByPlaintext(const vector<Big>& attrs, const Policy& policy, string* why) {
    auto fail = [&](const string& m) { if (why) *why = m; return false; };

    if (policy.clauses.empty()) return fail("policy is empty");
    for (size_t ci = 0; ci < policy.clauses.size(); ++ci) {
        const PolicyClause& cl = policy.clauses[ci];
        const string tag = "clause " + to_string(ci + 1);
        int hits = 0;
        if (cl.type == MoniClauseType::Intersection) {
            for (const Big& v : cl.set) if (pedContains(attrs, v)) ++hits;
            if (hits < cl.threshold)
                return fail(tag + " intersection not satisfied: |A∩set|=" + to_string(hits) +
                            " < t=" + to_string(cl.threshold));
        } else {
            for (const Big& v : cl.set) if (!pedContains(attrs, v)) ++hits;
            if (hits < cl.threshold)
                return fail(tag + " difference not satisfied: |set\\A|=" + to_string(hits) +
                            " < t=" + to_string(cl.threshold));
        }
    }
    return true;
}
