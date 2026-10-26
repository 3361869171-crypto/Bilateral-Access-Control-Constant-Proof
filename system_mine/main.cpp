// End-to-end demo and per-stage benchmark driver.
#include "pfc_global.h"
#include "ps_credential.h"
#include "knowledge_signature.h"
#include "trusted_authority.h"
#include "monipoly.h"
#include "pedersen.h"

enum class CommitMode { MoniPoly = 1, Pedersen = 2 };

inline const char* CommitModeName(CommitMode m) {
    if (m == CommitMode::Pedersen) return "Pedersen";
    return "MoniPoly";
}
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <set>
#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <stdexcept>
using namespace std;

// ========== Random attribute sets (duplicate-free) ==========

static mt19937& attrGen() {
    static mt19937 gen = []() -> mt19937 {
        const char* e = getenv("BA_SEED");
        if (e && *e) return mt19937((unsigned)strtoul(e, nullptr, 10));
        return mt19937(random_device{}());
    }();
    return gen;
}

static vector<Big> generate_random_attrs(int count) {
    mt19937& gen = attrGen();
    uniform_int_distribution<unsigned long> dis(1, 1000000);
    vector<Big> attrs;
    set<unsigned long> used;
    while ((int)attrs.size() < count) {
        unsigned long val = dis(gen); 
        if (used.insert(val).second) attrs.push_back(Big(val));
    }
    return attrs;
}

static void printAttrs(const string& who, const vector<Big>& attrs) {
    cout << who << " attributes:";
    for (const Big& a : attrs) cout << " " << a;
    cout << "\n";
}

static int countMatches(const vector<Big>& attrs, const vector<Big>& cands) {
    int c = 0;
    for (const auto& a : attrs)
        for (const auto& v : cands)
            if (a == v) { ++c; break; }
    return c;
}

static int countMissing(const vector<Big>& attrs, const vector<Big>& cands) {
    int c = 0;
    for (const auto& v : cands) {
        bool held = false;
        for (const auto& a : attrs) if (a == v) { held = true; break; }
        if (!held) ++c;
    }
    return c;
}



// Read one clause: type (1 = intersection / peer holds, 2 = difference / peer lacks) + set + threshold.
static PolicyClause readClause(const string& tag, int idx, const vector<Big>& whoAttrs,
                               int maxSetSize) {
    cout << "\n  " << tag << " [Clause " << idx << "]:\n";
    cout << "    Type (1 = intersection / peer holds, 2 = difference / peer lacks): ";
    int ty; cin >> ty;
    if (ty != 2) ty = 1;
    const char* what = (ty == 1) ? "candidate" : "forbidden";
    cout << "    " << what << " attribute count m (policy: the peer's attributes " << (ty == 1 ? "include" : "lack")
         << " at least t " << what << " values): ";
    int m; cin >> m;
    if (m < 1) m = 1;
    if (m > maxSetSize) {
        cout << "    [Info] Policy set size limit = maxAttrs = " << maxSetSize
             << "; using the limit" << endl;
        m = maxSetSize;
    }
    cout << "    Enter " << m << " " << what << " values (suggested: choose from the peer's attribute line above): ";
    vector<Big> setv;
    for (int i = 0; i < m; ++i) {
        int v; cin >> v;
        if (v <= 0) { cout << "    [Warning] Value must be a positive integer; using 1\n"; v = 1; }
        setv.push_back(Big(v));
    }
    cout << "    Threshold t (1.." << m << "): ";
    int t; cin >> t;
    if (t < 1) t = 1;
    if (t > m) t = m;
    cout << "    Selected: {";
    for (size_t i = 0; i < setv.size(); ++i)
        cout << setv[i] << (i + 1 < setv.size() ? "," : "");
    cout << "}  t=" << t;
    if (ty == 1) cout << "  Peer matches=" << countMatches(whoAttrs, setv);
    else         cout << "  Peer missing=" << countMissing(whoAttrs, setv);
    cout << "\n";
    return (ty == 1) ? PolicyClause::Intersection(setv, t)
                     : PolicyClause::Difference(setv, t);
}

// Interactively read a whole policy: n = clause count + readClause per clause + Policy::And(cs).
static Policy readPolicy(const string& label, const vector<Big>& whoAttrs, int maxSetSize) {
    cout << "\n" << label << "\n";
    cout << "  Number of clauses n (1 = single clause; ≥2 can be combined, intersection/difference may be mixed): ";
    int n; cin >> n;
    if (n < 1) n = 1;
    vector<PolicyClause> cs;
    for (int i = 0; i < n; ++i) cs.push_back(readClause(label, i + 1, whoAttrs, maxSetSize));
    Policy p = Policy::And(cs); // composition: logical AND only (all clauses must hold)
    cout << "  Policy: " << PolicyDesc(p) << "\n";
    return p;
}

// Development-time plaintext precheck: per clause countMatches/countMissing ≥ t; on failure set why and skip the round.
static bool precheckPolicy(const Policy& p, const vector<Big>& whoAttrs, string& why) {
    for (size_t i = 0; i < p.clauses.size(); ++i) {
        const PolicyClause& c = p.clauses[i];
        int got = (c.type == MoniClauseType::Intersection)
                    ? countMatches(whoAttrs, c.set)
                    : countMissing(whoAttrs, c.set);
        if (got < c.threshold) {
            why = "clause " + std::to_string(i + 1) + " " + ClauseDesc(c) +
                  ": actual " + std::to_string(got) + " < t=" + std::to_string(c.threshold);
            return false;
        }
    }
    return true;
}
static void printCommitComparison(const SystemParams& sys, const vector<Big>& attrs) {
    PFCContext& ctx = PFCContext::getInstance();
    const Big q = ctx.pfc->order();
    cout << fixed << setprecision(3);
    cout << "\n--- [Demo] Commitment scheme comparison (same attribute set, one call per module) ---\n";

    // MoniPoly: set commitment C = g1^{F(x′)} (with polynomial encoding; requires the SRS).
    Big o;
    do { ctx.pfc->random(o); } while (o == 0);
    ctx.resetCounters();
    Timer t1;
    MoniPoly moni;
    G1 C = moni.CommitSet(sys.Y, attrs, o, q);
    cout << "  [Demo][MoniPoly ] CommitSet -> C : " << t1.elapsed_ms() << " ms  [G1 mul " << ctx.g1MultCount
         << "]  size " << size_of_g1_fixed(C) << " B (1 G1; requires SRS/trusted setup)\n";

    // Pedersen: per-attribute commitment A_i = g1^{a_i}·h^{r_i} (no SRS required).
    vector<Big> blinds(attrs.size());
    for (size_t i = 0; i < blinds.size(); ++i) { do { ctx.pfc->random(blinds[i]); } while (blinds[i] == 0); }
    ctx.resetCounters();
    Timer t2;
    vector<G1> com = PedersenCommitAttributes(sys, attrs, blinds);
    size_t bytes = 0;
    for (const G1& e : com) bytes += size_of_g1_fixed(e);
    cout << "  [Demo][Pedersen ] Per-attribute commitments n=" << com.size() << " : " << t2.elapsed_ms() << " ms  [G1 mul "
         << ctx.g1MultCount << "]  size " << bytes << " B (no SRS/trusted setup required)\n";
}

// Print CLI usage (--commit-compare / --commit=moni|ped|shift / --help).
static void printUsage() {
    cout << "Usage: ./main [options]\n"
            "  (no options)         Normal flow (restart the system on every run + execute one round; the system path uses MoniPoly for set-relation proofs)\n"
            "  --commit-compare,-c  Run the commitment comparison once (MoniPoly polynomial commitment vs Pedersen commitment) and exit\n"
            "  --commit=moni|ped|shift  Select the attribute commitment / set-relation scheme (shift = x′-shift branch: one-time credential + online blind signature)\n"
            "  --bench              Benchmark mode (non-interactive): average over reps per stage + per-side ④/⑤ breakdown + two counting conventions\n"
            "  --attrs N            Number of attributes for --bench (default 10)\n"
            "  --reps N             Repetitions per stage for --bench (default 21, matching the comparison system)\n"
            "  --help,-h            Show this help\n"
            "Interactive: after entering the attribute count, execute one round immediately and exit (the program runs only once); enter 0 to exit; enter a negative number to run only the commitment comparison demo\n";
}

// · Each round = "a fresh system": rebuild the SRS/keys/credentials, then run prove+verify once on each of the two sides; report mean and median over reps per stage.
static int runBench(CommitMode mode, int attrCount, int reps) {
    PFCContext& ctx = PFCContext::getInstance();
    if (reps < 1) reps = 1;
    if (attrCount < 1) attrCount = 1;
    const int n = attrCount;

    struct Cnt { long p, gp, m1, m2, mp, pe; };
    auto snap = [&]() -> Cnt {
        return Cnt{ ctx.pairingCount, ctx.gtPowCount, ctx.g1MultCount, ctx.g2MultCount,
                    ctx.multiPairCalls, ctx.pairEqCalls };
    };
    auto cdiff = [](const Cnt& a, const Cnt& b) -> Cnt {
        return Cnt{ b.p - a.p, b.gp - a.gp, b.m1 - a.m1, b.m2 - a.m2, b.mp - a.mp, b.pe - a.pe };
    };
    auto csum = [](const Cnt& a, const Cnt& b) -> Cnt {
        return Cnt{ a.p + b.p, a.gp + b.gp, a.m1 + b.m1, a.m2 + b.m2, a.mp + b.mp, a.pe + b.pe };
    };
    auto items = [](const Cnt& c) -> string {
        return "pairing terms " + to_string(c.p) + " | GT pow " + to_string(c.gp) +
               " | G1 mul " + to_string(c.m1) + " | G2 mul " + to_string(c.m2);
    };
    auto calls = [](const Cnt& c) -> string {
        return "multiPair calls " + to_string(c.mp) + " | pairEq calls " + to_string(c.pe);
    };
    auto avg = [](const vector<double>& v) -> double {
        double s = 0; for (double x : v) s += x; return v.empty() ? 0.0 : s / (double)v.size();
    };
    auto med = [](vector<double> v) -> double {
        if (v.empty()) return 0.0;
        sort(v.begin(), v.end());
        const size_t m = v.size();
        return (m & 1) ? v[m / 2] : 0.5 * (v[m / 2 - 1] + v[m / 2]);
    };
    auto vsum = [](const vector<double>& a, const vector<double>& b) {
        const size_t k = min(a.size(), b.size());
        vector<double> o(k);
        for (size_t i = 0; i < k; ++i) o[i] = a[i] + b[i];
        return o;
    };

    vector<Big> do_attrs = generate_random_attrs(n);
    vector<Big> du_attrs = generate_random_attrs(n);
    auto buildPolicy = [n](const vector<Big>& other, long f1, long f2) -> Policy {
        vector<PolicyClause> cs;
        vector<Big> first{ other[0] };
        if (n >= 2) first.push_back(other[1]);
        cs.push_back(PolicyClause::Intersection(first, 1));
        cs.push_back(PolicyClause::Difference({ Big(f1), Big(f2) }, 1));
        if (n >= 3) cs.push_back(PolicyClause::Intersection({ other[2] }, 1));
        return Policy::And(cs);
    };
    const Policy P_do = buildPolicy(du_attrs, 2000001L, 2000002L);
    const Policy P_du = buildPolicy(do_attrs, 2000003L, 2000004L);
    {
        string why;
        if (!precheckPolicy(P_do, du_attrs, why) || !precheckPolicy(P_du, do_attrs, why)) {
            cerr << "[bench] Policy unsatisfiable: " << why << "\n";
            return 1;
        }
    }
    // Extra forbidden set for o during session initialization = both parties' attributes ∪ all policy sets (same contract as the interactive path).
    vector<Big> forbidVals;
    forbidVals.insert(forbidVals.end(), do_attrs.begin(), do_attrs.end());
    forbidVals.insert(forbidVals.end(), du_attrs.begin(), du_attrs.end());
    for (const PolicyClause& c : P_do.clauses) forbidVals.insert(forbidVals.end(), c.set.begin(), c.set.end());
    for (const PolicyClause& c : P_du.clauses) forbidVals.insert(forbidVals.end(), c.set.begin(), c.set.end());

    cout << "\n---- bench(commit=" << CommitModeName(mode) << ", n=" << n << ", reps=" << reps
         << ", BA_SEED=" << ctx.randomSeed << ") ----\n";
    cout << "Policy (per side): AND(intersection |set|=2 t=1 ; difference |set|=2 t=1 ; intersection |set|=1 t=1)"
         << " ; PS message count = " << (n + 2) << " (= n+2) ; SRS items = 67 (= maxAttrs+3, maxAttrs=64)\n";
    cout << "Convention: each round = a fresh system (rebuild SRS/keys/credentials) + one prove+verify per side; group construction (PFC(128)+generators) is excluded from all stages\n";

    vector<double> tSetup, tKey, tIss, tP1, tP2, tV1, tV2;
    Cnt cSetup{}, cKey{}, cIss{}, cP1{}, cV1{}, cP2{}, cV2{};
    vector<string> fn_issued, fn_usedSids, fn_used, du_bound, du_usedSids, du_used;
    int done = 0; bool ok1 = false, ok2 = false; string why;
    size_t srsItems = 0;
    for (int r = 0; r < reps; ++r) {
        TrustedAuthority authority;
        Cnt a0 = snap();
        Timer t0;
        SystemParams sys = authority.initialize(64);
        tSetup.push_back(t0.elapsed_ms());
        Cnt a1 = snap();
        Timer t1;
        PSKeyPair kp = authority.keyGen();
        AttributeIssuer issuer(kp.sk, kp.pk);
        tKey.push_back(t1.elapsed_ms());
        Cnt a2 = snap();
        // ③ Obtain/Issue (including session initialization: one online blind issuance per side under MoniPoly).
        MoniProof mp_du, mp_do;
        MoniSession sess_du, sess_do;
        Timer t2;
        CredentialRequest do_req = ObtainRequest(do_attrs);
        CredentialRequest du_req = ObtainRequest(du_attrs);
        PSCredential do_cred = issuer.obtain(do_req);
        PSCredential du_cred = issuer.obtain(du_req);
        if (mode == CommitMode::MoniPoly) {
            sess_du = MoniSessionInit(sys, du_attrs, issuer, P_do, mp_du, forbidVals);
            sess_do = MoniSessionInit(sys, do_attrs, issuer, P_du, mp_do, forbidVals);
        }
        tIss.push_back(t2.elapsed_ms());
        Cnt a3 = snap();
        PSVerifyKey issuer_pub = issuer.publicKey();
        cSetup = cdiff(a0, a1); cKey = cdiff(a1, a2); cIss = cdiff(a2, a3);
        srsItems = sys.Y.size();

        Big sid_r;
        do { ctx.pfc->random(sid_r); } while (sid_r == 0);
        const string sid = NonceHex(sid_r);
        fn_issued.push_back(sid);
        du_bound.push_back(sid);
        const string msg_du = "DU->FN|" + sid;
        const string msg_do = "DO->DU|" + sid;
        string w1, w2;

        if (mode == CommitMode::MoniPoly) {
            // ④-1 Side ①: [presentation] (offline; blind issuance already counted in ③) ⇒ count MoniProve only.
            Cnt b0 = snap();  Timer p1t;
            MoniPresentation sp_du = MoniProve(sys, sess_du, issuer_pub, msg_du, mp_du);
            tP1.push_back(p1t.elapsed_ms());  Cnt b1 = snap();
            Timer v1t;
            ok1 = SessionBindFresh(fn_issued, fn_usedSids, msg_du, &w1) &&
                  NonceFresh(fn_used, sp_du.ks.nonce, msg_du, &w1) &&
                  MoniDecide(sp_du, issuer_pub, sys, msg_du, mp_du, P_do, &w1);
            tV1.push_back(v1t.elapsed_ms());  Cnt b2 = snap();
            Timer p2t;
            MoniPresentation sp_do = MoniProve(sys, sess_do, issuer_pub, msg_do, mp_do);
            tP2.push_back(p2t.elapsed_ms());  Cnt b3 = snap();
            Timer v2t;
            ok2 = SessionBindFresh(du_bound, du_usedSids, msg_do, &w2) &&
                  NonceFresh(du_used, sp_do.ks.nonce, msg_do, &w2) &&
                  MoniDecide(sp_do, issuer_pub, sys, msg_do, mp_do, P_du, &w2);
            tV2.push_back(v2t.elapsed_ms());  Cnt b4 = snap();
            cP1 = cdiff(b0, b1); cV1 = cdiff(b1, b2); cP2 = cdiff(b2, b3); cV2 = cdiff(b3, b4);
        } else {
            Cnt b0 = snap();  Timer p1t;
            PedRelationProof pr_du = ProveRelationPedersen(sys, du_attrs);
            CoeffKnowledgeSignature pf_du = SignOfKnowledgeCoeffPed(sys, du_cred, issuer_pub, msg_du, pr_du);
            tP1.push_back(p1t.elapsed_ms());  Cnt b1 = snap();
            Timer v1t;
            ok1 = SessionBindFresh(fn_issued, fn_usedSids, msg_du, &w1) &&
                  NonceFresh(fn_used, pf_du.nonce, msg_du, &w1) &&
                  DecidePresentationPed(pf_du, issuer_pub, sys, msg_du, pr_du, P_do, &w1);
            tV1.push_back(v1t.elapsed_ms());  Cnt b2 = snap();
            Timer p2t;
            PedRelationProof pr_do = ProveRelationPedersen(sys, do_attrs);
            CoeffKnowledgeSignature pf_do = SignOfKnowledgeCoeffPed(sys, do_cred, issuer_pub, msg_do, pr_do);
            tP2.push_back(p2t.elapsed_ms());  Cnt b3 = snap();
            Timer v2t;
            ok2 = SessionBindFresh(du_bound, du_usedSids, msg_do, &w2) &&
                  NonceFresh(du_used, pf_do.nonce, msg_do, &w2) &&
                  DecidePresentationPed(pf_do, issuer_pub, sys, msg_do, pr_do, P_du, &w2);
            tV2.push_back(v2t.elapsed_ms());  Cnt b4 = snap();
            cP1 = cdiff(b0, b1); cV1 = cdiff(b1, b2); cP2 = cdiff(b2, b3); cV2 = cdiff(b3, b4);
        }
        ++done;
        if (!(ok1 && ok2)) { why = w1 + " | " + w2; break; }
    }

    const vector<double> tP = vsum(tP1, tP2), tV = vsum(tV1, tV2);
    const Cnt cP = csum(cP1, cP2), cV = csum(cV1, cV2);
    const Cnt cTot = csum(csum(cSetup, cKey), csum(cIss, csum(cP, cV)));
    const vector<double>* tail[6] = { &tKey, &tIss, &tP1, &tV1, &tP2, &tV2 };
    vector<double> tAll = tSetup;
    for (int i = 0; i < 6; ++i) tAll = vsum(tAll, *tail[i]);

    cout << fixed << setprecision(3);
    cout << "\n" << left << setw(40) << "Stage" << right << setw(12) << "Last (ms)"
         << setw(12) << "Mean (ms)" << setw(12) << "Median (ms)" << "   [item-count convention · per round] | [call-count convention · per round]\n";
    auto row = [&](const string& nm, const vector<double>& v, const Cnt& c) {
        cout << left << setw(40) << nm << right
             << setw(12) << (v.empty() ? 0.0 : v.back()) << setw(12) << avg(v) << setw(12) << med(v)
             << "   " << items(c) << " | " << calls(c) << "\n";
    };
    row("① Setup (group + SRS)",        tSetup, cSetup);
    row("② KeyGen (deliver sk/pk)",     tKey,   cKey);
    row("③ Obtain/Issue (+ blind signature)",           tIss,   cIss);
    row("④-1 Prove side ① (presentation only)",     tP1,    cP1);
    row("④-2 Prove side ② (presentation only)",     tP2,    cP2);
    row("④   Prove both sides total",       tP,     cP);
    row("⑤-1 Verify side ① (FN, P_do)", tV1,    cV1);
    row("⑤-2 Verify side ② (DU, P_du)", tV2,    cV2);
    row("⑤   Verify both sides total",      tV,     cV);
    row("Total (①..⑤, both sides)",         tAll,   cTot);
    cout << "\nPer-side convention (= both-sides total / 2): ④ Prove " << (avg(tP) / 2.0)
         << " ms/side ; ⑤ Verify " << (avg(tV) / 2.0) << " ms/side ; ④+⑤ "
         << ((avg(tP) + avg(tV)) / 2.0) << " ms/side\n";
    cout << "SRS items (measured) = " << srsItems << " ; result: side ① " << (ok1 ? "pass" : "fail")
         << " | side ② " << (ok2 ? "pass" : "fail") << " | completed rounds " << done << "/" << reps
         << (why.empty() ? "" : ("  [" + why + "]")) << "\n";
    cout << "Note: the Issuer is online once per session — ③ performs one MoniSessionInit per side (generate o and obtain a blind signature from the Issuer),\n"
            "      ④ runs only MoniProve (presentation) and is fully offline; the two sides = two independent sessions\n";
    return (ok1 && ok2 && done == reps) ? 0 : 1;
}

int main(int argc, char** argv) {
    bool cliCompare = false;
    bool modeFromCli = false;
    CommitMode cliMode = CommitMode::MoniPoly;
    bool benchMode = false;
    int  benchReps = 21;
    int  benchAttrs = 10;
    for (int i = 1; i < argc; ++i) {
        const string arg = argv[i];
        if (arg == "--commit-compare" || arg == "-c") {
            cliCompare = true;
        } else if (arg == "--bench") {
            benchMode = true;
        } else if (arg == "--reps" && i + 1 < argc) {
            benchReps = atoi(argv[++i]);
        } else if (arg == "--attrs" && i + 1 < argc) {
            benchAttrs = atoi(argv[++i]);
        } else if (arg.rfind("--commit=", 0) == 0) {
            const string v = arg.substr(9);
            if (v == "moni" || v == "monipoly" || v == "1" || v == "shift" || v == "shifted" || v == "3") {
                cliMode = CommitMode::MoniPoly; modeFromCli = true;
            } else if (v == "ped" || v == "pedersen" || v == "2") {
                cliMode = CommitMode::Pedersen; modeFromCli = true;
            } else {
                cout << "Unknown --commit value: " << v << " (use moni|ped; shift is also accepted)\n";
                return 1;
            }
        } else if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else {
            cout << "Unknown option: " << arg << "\n";
            printUsage();
            return 1;
        }
    }

    PFCContext& ctx = PFCContext::getInstance();
    ctx.init();
    get_mip()->IOBASE = 10;

    // ===== Experiment metrics helpers (statistics only; no protocol logic) =====
    struct Counts { long p, gp, m1, m2, mp, pe; };
    auto snap = [&]() -> Counts {
        return Counts{ ctx.pairingCount, ctx.gtPowCount, ctx.g1MultCount, ctx.g2MultCount,
                       ctx.multiPairCalls, ctx.pairEqCalls };
    };
    auto cntDiff = [](const Counts& from, const Counts& to) -> Counts {
        return Counts{ to.p - from.p, to.gp - from.gp, to.m1 - from.m1, to.m2 - from.m2,
                       to.mp - from.mp, to.pe - from.pe };
    };
    auto cntSum = [](const Counts& a, const Counts& b) -> Counts {
        return Counts{ a.p + b.p, a.gp + b.gp, a.m1 + b.m1, a.m2 + b.m2, a.mp + b.mp, a.pe + b.pe };
    };
    auto cntStr = [](const Counts& c) -> string {
        return "pairing " + to_string(c.p) + " | GT pow " + to_string(c.gp) +
               " | G1 mul " + to_string(c.m1) + " | G2 mul " + to_string(c.m2);
    };
    // Call accounting: one n-term multiPair ⇒ multiPairCalls +1 (and "pairing items" +n); pairEq goes through multiPair ⇒ both increment.
    auto cntStrCall = [](const Counts& c) -> string {
        return "multiPair calls " + to_string(c.mp) + " | pairEq calls " + to_string(c.pe);
    };
    // The two accounting conventions must not be added (see pfc_global.h): print them side by side here.
    auto cntStrBoth = [&cntStr, &cntStrCall](const Counts& c) -> string {
        return "[items] " + cntStr(c) + " | [calls] " + cntStrCall(c);
    };

    cout << "========================================================\n";
    cout << "Bilateral Access Control System (MoniPoly & PS Signature)\n";
    cout << "========================================================\n";
    cout << "Random Seed (BA_SEED) = " << ctx.randomSeed << "\n";
    cout << "For reproducibility, set the BA_SEED environment variable to this value.\n\n";

    cout << "Phase Definition:\n";
    cout << "  [Phase 1] Setup:        Build groups, generate SRS.\n";
    cout << "  [Phase 2] KeyGen:       TA delivers sk/pk to Issuer (0 group ops).\n";
    cout << "  [Phase 3] Issue:        Issue base creds + Online Blind Sign (SessionInit).\n";
    cout << "  [Phase 4] Prove:        Offline NIZK generation (bilateral).\n";
    cout << "  [Phase 5] Verify:       Anti-replay checks + MoniDecide (bilateral).\n\n";

    cout << "Usage: \n";
    cout << "  (no args)               Normal interactive flow.\n";
    cout << "  --commit=moni|ped       Select MoniPoly or Pedersen baseline.\n";
    cout << "  --bench --attrs N --reps R  Run benchmark automatically.\n\n";
    cout << "Enter the number of attributes (0 to exit): ";

    // ④ = sum of "prove" over both sides, ⑤ = sum of "verify" over both sides, with per-side lines -1 (side ①) / -2 (side ②).
    auto lineOut = [](const char* tag, const string& name, double ms, const string& extra) {
        cout << tag << name << ": " << fixed << setprecision(3) << ms << " ms";
        if (!extra.empty()) cout << "  " << extra;
        cout << "\n";
    };
    auto stageLine = [&lineOut](const string& name, double ms, const string& extra = string()) {
        lineOut("[Stage] ", name, ms, extra);
    };
    // Per-side ④/⑤ lines: side ① = DU→FN (policy P_do) / side ② = DO→DU (policy P_du).
    auto sideLine = [&lineOut](const string& name, double ms, const string& extra = string()) {
        lineOut("[Stage] ", name, ms, extra);
    };

    // ⇒ Bypass the interactive path entirely; runBench rebuilds the SRS/keys/credentials per round and times them itself (same reps-mean convention as the comparison system).
    if (benchMode) return runBench(modeFromCli ? cliMode : CommitMode::MoniPoly, benchAttrs, benchReps);

    TrustedAuthority authority;
    Timer t_setup;
    SystemParams sys = authority.initialize(64); // 64-bit security (group order ≈ 256 bits)
    stageLine("① Setup (group + SRS)", t_setup.elapsed_ms());

    // One-shot execution: shared by all exit paths.
    auto finish = []() -> int { cout << "Program exited." << endl; return 0; };

    if (cliCompare) {
        printCommitComparison(sys, generate_random_attrs(4));
        return finish();
    }

    CommitMode commitMode = cliMode;
    if (!modeFromCli) {
        cout << "Select the attribute commitment / set-relation scheme [1 = MoniPoly (shifted commitment + set-relation proof) / "
                "2 = Pedersen (commitment + opening, plaintext matching)]: ";
        int sel = 1;
        if (!(cin >> sel)) sel = 1;
        commitMode = (sel == 2) ? CommitMode::Pedersen : CommitMode::MoniPoly;
    }
    cout << "[Scheme] Using " << CommitModeName(commitMode)
         << (commitMode == CommitMode::Pedersen
                ? " — per-attribute Pedersen commitments + openings + plaintext policy evaluation (the verifier sees the attributes)\n\n"
                : " — shifted commitment (C_{x′} = C^{x′} bound by a public pairing) + set-relation proof via divisibility / coprime remainder; "
                  "the credential signs the full coefficient vector including o (n+2 messages), used once (one online blind signature per session)\n\n");

    { // [One-shot execution] Former while(true) body: execute exactly one round per run (flattened into a single-shot block, no loop)
        int attr_count;
        cout << "Enter the number of attributes (0 to exit): ";
        cin >> attr_count;
        if (attr_count == 0) return finish();
        const bool commitDemoOnly = (attr_count < 0);
        if (commitDemoOnly) attr_count = -attr_count;

        vector<Big> do_attrs = generate_random_attrs(attr_count);
        vector<Big> du_attrs = generate_random_attrs(attr_count);
        cout << "\n[Randomly generated user attributes for this round (decimal; only values matched by the policy appear in a revealed set, all others stay out of the proof)]\n";
        printAttrs("DO", do_attrs);
        printAttrs("DU", du_attrs);
        cout << "[This round] Scheme = " << CommitModeName(commitMode) << "\n";

        if (commitDemoOnly) {
            printCommitComparison(sys, do_attrs);
            return finish(); // one-shot execution: skip issuance/prove/verify and exit directly
        }

        // ---------- ② KeyGen (TA): sk = (x, x′) and pk = pp slice ⇒ zero group multiplications ----------
        Timer t_keygen;
        PSKeyPair kp = authority.keyGen();
        AttributeIssuer issuer(kp.sk, kp.pk);
        stageLine("② KeyGen (deliver sk/pk)", t_keygen.elapsed_ms());
        Policy P_do = readPolicy("Build policy P_do (DO's access policy → requires DU's attributes to satisfy)", du_attrs, sys.maxAttrs);
        string why;
        if (!precheckPolicy(P_do, du_attrs, why)) {
            cout << "\n[Skip this round] DU's attributes cannot satisfy P_do: " << why << "\n\n";
            return finish(); // one-shot execution: this round cannot complete, exit directly
        }
        Policy P_du = readPolicy("Build policy P_du (DU's requirement policy → requires DO's attributes to satisfy)", do_attrs, sys.maxAttrs);
        if (!precheckPolicy(P_du, do_attrs, why)) {
            cout << "\n[Skip this round] DO's attributes cannot satisfy P_du: " << why << "\n\n";
            return finish(); // one-shot execution: this round cannot complete, exit directly
        }

        // Verification = two anti-replay layers first, then MoniDecide / DecidePresentationPed (single entry, no skipped steps).
        vector<string> fn_issued, fn_usedSids, fn_used; // FN: issued sids / used sids / used (nonce,msg) pairs
        vector<string> du_bound, du_usedSids, du_used; // DU: bound sids / used sids / used (nonce,msg) pairs
        // Session-binding check (delegates to SessionBindFresh): if issued is non-empty ⇒ msg must end with an issued, unused sid.
        auto bindCheck = [](const vector<string>& issued, vector<string>& usedSids,
                            const string& msg, string* why) -> bool {
            return SessionBindFresh(issued, usedSids, msg, why); // anti-replay layer 1
        };

        vector<Big> forbidVals;
        forbidVals.insert(forbidVals.end(), do_attrs.begin(), do_attrs.end());
        forbidVals.insert(forbidVals.end(), du_attrs.begin(), du_attrs.end());
        for (const PolicyClause& c : P_do.clauses)
            forbidVals.insert(forbidVals.end(), c.set.begin(), c.set.end());
        for (const PolicyClause& c : P_du.clauses)
            forbidVals.insert(forbidVals.end(), c.set.begin(), c.set.end());

        try {
            // ⚠ Blind issuance belongs to [issuance]: session initialization is timed here; session variables are hoisted to this scope ⇒ ④ counts MoniProve only.
            MoniProof mp_du, mp_do;
            MoniSession sess_du, sess_do;
            Counts sq_pre_issue = snap();
            Timer t_issue;
            CredentialRequest do_req = ObtainRequest(do_attrs);
            CredentialRequest du_req = ObtainRequest(du_attrs);
            PSCredential do_cred = issuer.obtain(do_req);
            PSCredential du_cred = issuer.obtain(du_req);
            if (commitMode == CommitMode::MoniPoly) {
                sess_du = MoniSessionInit(sys, du_attrs, issuer, P_do, mp_du, forbidVals);
                sess_do = MoniSessionInit(sys, do_attrs, issuer, P_du, mp_do, forbidVals);
            }
            stageLine("③ Obtain/Issue (including session initialization / online blind signature)", t_issue.elapsed_ms(),
                      cntStrBoth(cntDiff(sq_pre_issue, snap())));
            PSVerifyKey issuer_pub = issuer.publicKey();
            Counts sq0 = snap();

            // The session identifier is generated and issued by the [verifier (FN)]; the prover binds it into msg (anti-replay layer 1).
            Big sid_r;
            do { ctx.pfc->random(sid_r); } while (sid_r == 0);
            const string sid = NonceHex(sid_r); // generate the session identifier (one-time non-zero random ⇒ hex string)
            fn_issued.push_back(sid); // FN records it as issued ⇒ subsequent binding checks require msg to end with it
            du_bound.push_back(sid); // the second side's verifier (DU) binds the same session identifier (anti-replay layer 1)
            const string msg_du = "DU->FN|" + sid; // bind to this session identifier
            const string msg_do = "DO->DU|" + sid;

            if (commitMode == CommitMode::Pedersen) {
                // ④ = sum of "prove" over both sides, ⑤ = sum of "verify" over both sides (timed per side; no outer Timer wrapping both).
                std::string why_du, why_do;
                Counts pq0 = snap();
                Timer t_p1;
                PedRelationProof pr_du = ProveRelationPedersen(sys, du_attrs);
                CoeffKnowledgeSignature du_proof = SignOfKnowledgeCoeffPed(sys, du_cred, issuer_pub, msg_du, pr_du);
                const double ms_p1 = t_p1.elapsed_ms();
                Counts pq1 = snap();
                Timer t_v1;
                bool fn_valid = bindCheck(fn_issued, fn_usedSids, msg_du, &why_du) &&
                                NonceFresh(fn_used, du_proof.nonce, msg_du, &why_du) &&
                                DecidePresentationPed(du_proof, issuer_pub, sys, msg_du, pr_du, P_do, &why_du);
                const double ms_v1 = t_v1.elapsed_ms();
                Counts pq_v1 = snap();
                Timer t_p2;
                PedRelationProof pr_do = ProveRelationPedersen(sys, do_attrs);
                CoeffKnowledgeSignature do_proof = SignOfKnowledgeCoeffPed(sys, do_cred, issuer_pub, msg_do, pr_do);
                const double ms_p2 = t_p2.elapsed_ms();
                Counts pq_p2 = snap();
                Timer t_v2;
                bool du_valid = bindCheck(du_bound, du_usedSids, msg_do, &why_do) &&
                                NonceFresh(du_used, do_proof.nonce, msg_do, &why_do) &&
                                DecidePresentationPed(do_proof, issuer_pub, sys, msg_do, pr_do, P_du, &why_do);
                const double ms_v2 = t_v2.elapsed_ms();
                Counts pq2 = snap();

                // Segment-wise counts (as in the MoniPoly branch): ④ = segment 1 + segment 3 (prove only) ; ⑤ = segment 2 + segment 4 (verify only).
                const Counts p_c1 = cntDiff(pq0, pq1), p_v1 = cntDiff(pq1, pq_v1);
                const Counts p_c2 = cntDiff(pq_v1, pq_p2), p_v2 = cntDiff(pq_p2, pq2);
                const Counts p_prove = cntSum(p_c1, p_c2), p_verify = cntSum(p_v1, p_v2);

                stageLine("④ DO/DU Prove (side ① + side ②)", ms_p1 + ms_p2, cntStrBoth(p_prove));
                sideLine("④-1 Side ① DU→FN Prove (P_do)", ms_p1, cntStr(p_c1));
                sideLine("④-2 Side ② DO→DU Prove (P_du)", ms_p2, cntStr(p_c2));
                if (fn_valid && du_valid) {
                    stageLine("⑤ FN/DU Verify (side ① + side ②)", ms_v1 + ms_v2, cntStrBoth(p_verify));
                    sideLine("⑤-1 Side ① FN Verify (P_do)", ms_v1, cntStr(p_v1));
                    sideLine("⑤-2 Side ② DU Verify (P_du)", ms_v2, cntStr(p_v2));
                } else {
                    cout << "  ⑤ Verify failed ⇒ timing not reported   [side ① " << why_du << " | side ② " << why_do << "]\n";
                }

                cout << "\n--- Test result (Pedersen baseline, this round's scheme = " << CommitModeName(commitMode) << ") ---\n";
                {
                    int ic_do = 0, dc_do = 0, ic_du = 0, dc_du = 0;
                    for (const PolicyClause& c : P_do.clauses)
                        (c.type == MoniClauseType::Intersection ? ic_do : dc_do)++;
                    for (const PolicyClause& c : P_du.clauses)
                        (c.type == MoniClauseType::Intersection ? ic_du : dc_du)++;
                    cout << "  Policy composition: P_do intersection clauses " << ic_do << " / difference clauses " << dc_do
                         << " ; P_du intersection clauses " << ic_du << " / difference clauses " << dc_du << "\n";
                }
                cout << "  Relation proof (commitment + opening): DU " << pr_du.size() << " B / DO " << pr_do.size()
                     << " B   (contains " << pr_du.com.size() << " commitments + attribute plaintexts + blinding factors)\n";
                cout << "  FN verifies DU (P_do): " << (fn_valid ? "pass" : "fail")
                     << (fn_valid ? string() : ("   [reason: " + why_du + "]")) << "\n";
                cout << "  DU verifies DO (P_du): " << (du_valid ? "pass" : "fail")
                     << (du_valid ? string() : ("   [reason: " + why_do + "]")) << "\n";
                cout << "  Generation (per side) counts: relation " << cntStr(cntDiff(pq0, pq1))
                     << " | SoK " << cntStr(cntDiff(pq1, pq2)) << "\n";
                cout << "  Counts (prove, both sides): " << cntStrBoth(p_prove) << "\n";
                cout << "  Counts (verify, both sides): " << cntStrBoth(p_verify) << "\n";
                cout << "  Counts (both sides, generation + verification): " << cntStrBoth(cntDiff(pq0, pq2)) << "\n";
                cout << "  ⚠ Privacy difference: in this mode the verifier must see the attribute plaintexts to evaluate the policy (this is exactly the gap the ablation exposes)\n";
                cout << "================================\n\n";
                return finish(); // one-shot execution: exit when this round ends
            }

            if (commitMode == CommitMode::MoniPoly) {
                // ④ = sum of "presentation" over both sides (blind issuance already counted in ③), ⑤ = sum of verification over both sides (timed per side).
                std::string why_du, why_do;
                Timer t_p1;
                MoniPresentation sp_du = MoniProve(sys, sess_du, issuer_pub, msg_du, mp_du);
                const double ms_p1 = t_p1.elapsed_ms();
                Counts sq1 = snap();
                Timer t_v1;
                bool fn_valid = bindCheck(fn_issued, fn_usedSids, msg_du, &why_du) &&
                                NonceFresh(fn_used, sp_du.ks.nonce, msg_du, &why_du) &&
                                MoniDecide(sp_du, issuer_pub, sys, msg_du, mp_du, P_do, &why_du);
                const double ms_v1 = t_v1.elapsed_ms();
                Counts sq_v1 = snap();
                Timer t_p2;
                MoniPresentation sp_do = MoniProve(sys, sess_do, issuer_pub, msg_do, mp_do);
                const double ms_p2 = t_p2.elapsed_ms();
                Counts sq_p2 = snap();
                Timer t_v2;
                bool du_valid = bindCheck(du_bound, du_usedSids, msg_do, &why_do) &&
                                NonceFresh(du_used, sp_do.ks.nonce, msg_do, &why_do) &&
                                MoniDecide(sp_do, issuer_pub, sys, msg_do, mp_do, P_du, &why_do);
                const double ms_v2 = t_v2.elapsed_ms();
                Counts sq2 = snap();

                // ④ = segment 1 + segment 3 (prove only, no verification) ; ⑤ = segment 2 + segment 4 (verify only).
                const Counts c_p1 = cntDiff(sq0, sq1), c_v1 = cntDiff(sq1, sq_v1);
                const Counts c_p2 = cntDiff(sq_v1, sq_p2), c_v2 = cntDiff(sq_p2, sq2);
                const Counts c_prove = cntSum(c_p1, c_p2), c_verify = cntSum(c_v1, c_v2);

                stageLine("④ DO/DU Prove (side ① + side ②, presentation only)", ms_p1 + ms_p2, cntStrBoth(c_prove));
                sideLine("④-1 Side ① DU→FN Prove (P_do)", ms_p1, cntStr(c_p1));
                sideLine("④-2 Side ② DO→DU Prove (P_du)", ms_p2, cntStr(c_p2));
                if (fn_valid && du_valid) {
                    stageLine("⑤ FN/DU Verify (side ① + side ②)", ms_v1 + ms_v2, cntStrBoth(c_verify));
                    sideLine("⑤-1 Side ① FN Verify (P_do)", ms_v1, cntStr(c_v1));
                    sideLine("⑤-2 Side ② DU Verify (P_du)", ms_v2, cntStr(c_v2));
                } else {
                    cout << "  ⑤ Verify failed ⇒ timing not reported   [side ① " << why_du << " | side ② " << why_do << "]\n";
                }

                cout << "--- Test result (x′-shift branch: session-level credential, one online blind signature per session initialization) ---\n";
                {
                    int ic_do = 0, dc_do = 0, ic_du = 0, dc_du = 0;
                    for (const PolicyClause& c : P_do.clauses)
                        (c.type == MoniClauseType::Intersection ? ic_do : dc_do)++;
                    for (const PolicyClause& c : P_du.clauses)
                        (c.type == MoniClauseType::Intersection ? ic_du : dc_du)++;
                    cout << "  Policy composition: P_do intersection clauses " << ic_do << " / difference clauses " << dc_do
                         << " ; P_du intersection clauses " << ic_du << " / difference clauses " << dc_du << "\n";
                }
                cout << "  FN verifies DU (P_do): " << (fn_valid ? "pass" : "fail")
                     << (fn_valid ? string() : ("   [reason: " + why_du + "]")) << "\n";
                cout << "  DU verifies DO (P_du): " << (du_valid ? "pass" : "fail")
                     << (du_valid ? string() : ("   [reason: " + why_do + "]")) << "\n";
                cout << "  PS message count: " << (du_attrs.size() + 2) << " (= n+2) ; SRS items: "
                     << sys.Y.size() << " (= maxAttrs+3)\n";
                cout << "  Public check e(Ỹ[1],C) == e(Ỹ[0],C_{x′}): pass ; anchoring: one SRS basis equation (no masking / no s_o)\n";
                cout << "  Counts (presentation, per side): " << cntStrBoth(c_p1) << "\n";
                cout << "  Counts (verification, per side): " << cntStrBoth(c_v1) << "\n";
                cout << "  Counts (presentation, both sides): " << cntStrBoth(c_prove) << "\n";
                cout << "  Counts (verification, both sides): " << cntStrBoth(c_verify) << "\n";
                cout << "  Counts (both sides, presentation + verification): " << cntStrBoth(cntDiff(sq0, sq2)) << "\n";
                cout << "DU per-clause proofs:";
                for (const ClauseProof& c : mp_du.proofs)
                    cout << " [Clause " << c.clauseIndex + 1 << " "
                         << (c.type == MoniClauseType::Intersection ? "intersection" : "difference")
                         << " |revealed|=" << c.revealed.size() << "]";
                cout << "\nDO per-clause proofs:";
                for (const ClauseProof& c : mp_do.proofs)
                    cout << " [Clause " << c.clauseIndex + 1 << " "
                         << (c.type == MoniClauseType::Intersection ? "intersection" : "difference")
                         << " |revealed|=" << c.revealed.size() << "]";
                // ---- Size (one side; same convention as v8: G1=64 B / field element=32 B / GT=384 B) ----
                {
                    auto anchorBytes = [](const MoniPresentation& sp) {
                        return size_of_g1_fixed(sp.Cxprime) + size_of_g1_fixed(sp.anchor.A2)
                             + sp.anchor.s.size() * BN_FIELD_BYTES + BN_FIELD_BYTES;
                    };
                    auto idBytes = [](const MoniPresentation& sp) {
                        return 2 * size_of_g1_fixed(sp.ks.credential.sigma1) + BN_FIELD_BYTES + 12 * BN_FIELD_BYTES;
                    };
                    const size_t b1 = mp_du.size(), b2 = anchorBytes(sp_du), b3 = idBytes(sp_du);
                    cout << "  Size (per side, DU): attribute-side MoniProof (no anchoring) " << b1 << " B ; shifted anchoring (A2 + one s-set + C_{x′} + c) "
                         << b2 << " B ; identity side (σ-randomization + nonce + Up) " << b3 << " B ; total " << (b1 + b2 + b3) << " B" << "\n";
                }
                cout << "\n  Linkability: C/C_{x′} are reused within the same session (intra-session linkable) ; a fresh o across sessions ⇒ unlinkable ; each presentation re-randomizes the credential σ\n";
                cout << "================================\n\n";
                return finish(); // one-shot execution: exit when this round ends
            }

        } catch (const std::exception& e) {
            cerr << "\n[Error in this round] " << e.what()
                 << "\nPossible causes: attributes do not satisfy the policy, or invalid parameters.\n\n";
        }
    }

    cout << "Program exited." << endl;
    return 0;
}
