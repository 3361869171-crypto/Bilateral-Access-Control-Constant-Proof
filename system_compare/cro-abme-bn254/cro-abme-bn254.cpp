// CRO-ABME baseline: BN254/MIRACL port of CRO_ABME.py, Copyright (c) 2024 HUANG QIAN (MIT).
// Upstream: Huang & Si, Certificateless and Revocable Bilateral Access Control for Privacy-Preserving Edge-Cloud Computing, IEEE IoT-J 2024.
// Lagrange x-coordinates are 1..k (not 0..k-1): x=0 makes l_0 numerator zero.
// dec: H(.) domain tag must match the actual pairing value (r2r4 vs r1r3).
// MR_CPP build: define MR_PAIRING_BN; never wrap MIRACL headers in extern C.
//
// Scope: performance measurement only. One invocation runs --reps full pipelines and prints, per stage,
// the mean time, the four group-operation counts and the object sizes. Correctness self-checks, the
// revocation self-check, the upstream anchor comparison and the match combination cap are intentionally
// absent, and every timing window contains the stage call and nothing else.

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
using namespace std;
using namespace std::chrono;

#include "miracl.h"
#include "pairing_3.h"

// Generators must be allocated after PFC (static-init order).
PFC *pfc    = NULL;
G1*  g1_gen = NULL;
G2*  g2_gen = NULL;

struct Cnt { long pairing = 0, gtpow = 0, g1 = 0, g2 = 0; };

static const size_t FIELD_BYTES = 32;
static const size_t SZ_SCALAR   = 32;
static const size_t SZ_G1       = 2 * FIELD_BYTES;
static const size_t SZ_G2       = 4 * FIELD_BYTES;
static const size_t SZ_GT       = 12 * FIELD_BYTES;

struct Ctx {
    PFC* p = nullptr;
    Cnt  cnt;
    void reset() { cnt = Cnt(); }
    void random(Big& b)   { p->random(b); }
    void random(G1& a)    { p->random(a); }
    void random(G2& a)    { p->random(a); }
    void hash_and_map(G1& a, char* s) { p->hash_and_map(a, s); }
    G1 mult(const G1& a, const Big& e) { ++cnt.g1;    return p->mult(a, e); }
    G2 mult(const G2& a, const Big& e) { ++cnt.g2;    return p->mult(a, e); }
    GT power(const GT& a, const Big& e) { ++cnt.gtpow; return p->power(a, e); }
    GT pairing(const G2& a, const G1& b) { ++cnt.pairing; return p->pairing(a, b); }
};
static Ctx ctx;

static steady_clock::time_point t_now() { return steady_clock::now(); }
static double ms_since(steady_clock::time_point t0) {
    return duration_cast<duration<double, milli>>(steady_clock::now() - t0).count();
}
static double mean(const vector<double>& v) {
    if (v.empty()) return 0.0;
    double s = 0.0; for (double x : v) s += x;
    return s / static_cast<double>(v.size());
}

static string hexFixed(const Big& v, size_t bytes) {
    big temp = v.getbig();
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    big_to_bytes((int)bytes, temp, buf, TRUE);
    static const char* HX = "0123456789abcdef";
    string out; out.reserve(bytes * 2);
    for (size_t i = 0; i < bytes; ++i) {
        unsigned char c = (unsigned char)buf[i];
        out.push_back(HX[c >> 4]); out.push_back(HX[c & 15]);
    }
    return out;
}
static string g1Hex(const G1& p) {
    Big x, y; p.g.getxy(x, y);
    return hexFixed(x, FIELD_BYTES) + hexFixed(y, FIELD_BYTES);
}
static string gtHex(const GT& t) {
    ZZn12 v = t.g; ZZn4 u; v.get(u); ZZn2 l, h; u.get(l, h); ZZn a, b, c, d; l.get(a, b); h.get(c, d);
    return hexFixed((Big)a, FIELD_BYTES) + hexFixed((Big)b, FIELD_BYTES) +
           hexFixed((Big)c, FIELD_BYTES) + hexFixed((Big)d, FIELD_BYTES);
}
static G1 hashG1(const string& s) {
    vector<char> buf(s.begin(), s.end()); buf.push_back('\0');
    G1 P; ctx.hash_and_map(P, buf.data()); return P;
}
static void symXor(const Big& theta, vector<unsigned char>& buf) {
    char kb[32]; memset(kb, 0, sizeof(kb));
    big_to_bytes((int)FIELD_BYTES, theta.getbig(), kb, TRUE);
    unsigned char key[32];
    { sha256 sh; shs256_init(&sh);
      for (int i = 0; i < 32; ++i) shs256_process(&sh, (int)(unsigned char)kb[i]);
      shs256_hash(&sh, (char*)key); }
    unsigned char ctr[8]; memset(ctr, 0, 8);
    for (size_t off = 0; off < buf.size(); off += 32) {
        sha256 s2; shs256_init(&s2);
        for (int i = 0; i < 32; ++i) shs256_process(&s2, key[i]);
        for (int i = 0; i < 8; ++i) shs256_process(&s2, ctr[i]);
        unsigned char ks[32]; shs256_hash(&s2, (char*)ks);
        size_t n = min((size_t)32, buf.size() - off);
        for (size_t i = 0; i < n; ++i) buf[off + i] ^= ks[i];
        for (int i = 7; i >= 0; --i) if (++ctr[i]) break;
    }
}

static Big zq(const Big& a, const Big& q) { Big r = a % q; r = (r + q) % q; return r; }
static Big qInv(const Big& a, const Big& q) { return zq(inverse(zq(a, q), q), q); }

// Zq multiplication must use modmult: raw (a*b)%q overflows 384-bit Big at nib=5.
static Big zmul(const Big& a, const Big& b, const Big& q) { return zq(modmult(a, b, q), q); }

static Big polyEval(const vector<Big>& coeff, long x, const Big& q) {
    Big bx((int)x);
    Big share = 0;
    Big xp = 1;
    for (size_t i = 0; i < coeff.size(); ++i) {
        share = zq(share + zmul(coeff[i], xp, q), q);
        xp = zmul(xp, bx, q);
    }
    return share;
}
static vector<Big> genShares(const Big& secret, size_t n, const Big& q) {
    vector<Big> coeff(n);
    for (size_t i = 0; i < n; ++i) { Big r; ctx.random(r); coeff[i] = zq(r, q); }
    coeff[0] = zq(secret, q);
    vector<Big> y(n + 1);
    for (size_t i = 0; i <= n; ++i) y[i] = polyEval(coeff, (long)i, q);
    return y;
}
static vector<Big> recoverCoefficients(long k, const Big& q) {
    vector<Big> coeff(k);
    for (long i = 0; i < k; ++i) {
        Big xi = Big((int)(i + 1));
        Big result = 1;
        for (long j = 1; j <= k; ++j) {
            if (j == i + 1) continue;
            Big num = zq(Big(0) - Big((int)j), q);
            Big den = zq(xi - Big((int)j), q);
            result = zmul(result, zmul(num, qInv(den, q), q), q);
        }
        coeff[i] = result;
    }
    return coeff;
}

struct PP  { G1 g, g_alpha, g_beta; };
struct MSK { Big alpha, beta; };

struct Authority {
    vector<string> attrNames;
    vector<G1>     attribute;
    vector<Big>    attributeSecrets;
    map<string, pair<Big, Big> > ids;
    int idxOf(const string& a) const {
        for (size_t i = 0; i < attrNames.size(); ++i) if (attrNames[i] == a) return (int)i;
        return -1;
    }
};

struct EK { vector<string> pol_S; vector<G1> ek_S; };
struct DK { vector<string> pol_R; vector<G2> dk_R; };
struct PPK { vector<G2> ppk1, ppk2; G2 ppk3; string id; };
struct CT  { string id; vector<unsigned char> c0; vector<G1> c1, c2; GT c3, c4; G1 c5; };
struct CPrime { vector<unsigned char> c0_prime; GT v1, v2, c3, c4; };

static void setup(PP& pp, MSK& msk, Authority& auth, const vector<string>& attributes) {
    const Big q = pfc->order();
    ctx.random(msk.alpha);
    ctx.random(msk.beta);
    G1 g; ctx.random(g);
    pp.g = g;
    pp.g_alpha = ctx.mult(g, msk.alpha);
    pp.g_beta  = ctx.mult(g, msk.beta);

    auth.attrNames = attributes;
    auth.attribute.clear(); auth.attributeSecrets.clear();
    for (size_t i = 0; i < attributes.size(); ++i) {
        Big si; ctx.random(si);
        auth.attributeSecrets.push_back(zq(si, q));
        auth.attribute.push_back(ctx.mult(g, si));
    }
}

static void registerUser(Authority& auth, const string& id, const vector<string>& sigma,
                         vector<G1>& rk, vector<G2>& rk2, Big& theta) {
    const Big q = pfc->order();
    Big w, th;
    ctx.random(w); ctx.random(th);
    auth.ids[id] = make_pair(zq(w, q), zq(th, q));
    theta = zq(th, q);

    rk.clear(); rk2.clear();
    for (size_t i = 0; i < sigma.size(); ++i) {
        int a = auth.idxOf(sigma[i]);
        if (a < 0) { fprintf(stderr, "[cro-abme] register: unregistered attribute %s\n", sigma[i].c_str()); exit(2); }
        rk.push_back(ctx.mult(auth.attribute[a], w));
        rk2.push_back(ctx.mult(*g2_gen, zmul(w, auth.attributeSecrets[a], q)));
    }
}

static void ekGen(const PP& pp, const MSK& msk, Authority& auth,
                  const vector<string>& pol_S, EK& ek) {
    const Big q = pfc->order();
    size_t n = pol_S.size();
    vector<Big> y  = genShares(msk.alpha, n, q);
    vector<Big> l0 = recoverCoefficients((long)n, q);

    ek.pol_S = pol_S; ek.ek_S.clear();
    for (size_t i = 0; i < n; ++i) {
        int a = auth.idxOf(pol_S[i]);
        Big e = zmul(zmul(l0[i], y[i + 1], q), qInv(auth.attributeSecrets[a], q), q);
        ek.ek_S.push_back(ctx.mult(pp.g, e));
    }
}

static void dkGen(const PP& pp, const MSK& msk, Authority& auth,
                  const vector<string>& pol_R, DK& dk) {
    const Big q = pfc->order();
    size_t n = pol_R.size();
    vector<Big> y  = genShares(msk.beta, n, q);
    vector<Big> l0 = recoverCoefficients((long)n, q);

    dk.pol_R = pol_R; dk.dk_R.clear();
    for (size_t i = 0; i < n; ++i) {
        int a = auth.idxOf(pol_R[i]);
        Big e = zmul(zmul(l0[i], y[i + 1], q), qInv(auth.attributeSecrets[a], q), q);
        dk.dk_R.push_back(ctx.mult(*g2_gen, e));
    }
}

static void pkGen(const PP& pp, const vector<G2>& dk_R, const vector<G2>& rk2,
                  const string& id, PPK& ppk, Big& x) {
    ctx.random(x);
    ppk.ppk1.clear(); ppk.ppk2.clear();
    for (size_t i = 0; i < dk_R.size(); ++i) ppk.ppk1.push_back(ctx.mult(dk_R[i], x));
    for (size_t i = 0; i < rk2.size();  ++i) ppk.ppk2.push_back(ctx.mult(rk2[i],  x));
    ppk.ppk3 = ctx.mult(*g2_gen, x);
    ppk.id = id;
}

static CT enc(const PP& pp, const vector<G1>& rk, const vector<G1>& ek,
              const Big& theta, const vector<unsigned char>& m, const string& id) {
    CT c; c.id = id;
    Big r[5];
    for (int i = 0; i < 5; ++i) ctx.random(r[i]);

    G2 R1 = ctx.mult(*g2_gen, r[1]);
    G2 R2 = ctx.mult(*g2_gen, r[2]);
    G1 R3 = ctx.mult(*g1_gen, r[3]);
    G1 R4 = ctx.mult(*g1_gen, r[4]);
    G1 R0 = ctx.mult(*g1_gen, r[0]);

    GT e_R1R3 = ctx.pairing(R1, R3);
    GT e_R2R4 = ctx.pairing(R2, R4);
    G1 H_r1r3 = hashG1("CRO::H_r1r3|" + gtHex(e_R1R3));
    G1 H_r2r4 = hashG1("CRO::H_r2r4|" + gtHex(e_R2R4));

    c.c0.assign(m.begin(), m.end());
    string s1 = g1Hex(H_r1r3), s2 = g1Hex(H_r2r4);
    for (size_t i = 0; i < c.c0.size(); ++i)
        c.c0[i] = (unsigned char)(c.c0[i] ^ (unsigned char)s1[i % s1.size()]
                                           ^ (unsigned char)s2[i % s2.size()]);
    symXor(theta, c.c0);

    for (size_t i = 0; i < rk.size(); ++i) c.c1.push_back(ctx.mult(rk[i], r[1]));
    for (size_t i = 0; i < ek.size(); ++i) c.c2.push_back(ctx.mult(ek[i], r[2]));

    c.c3 = ctx.pairing(R1, R3) * ctx.pairing(R1, pp.g_beta);
    c.c4 = ctx.pairing(R2, R4) * ctx.pairing(R2, pp.g_alpha);
    G1 t1 = ctx.mult(pp.g_alpha, r[2]);
    G1 t2 = ctx.mult(pp.g_beta,  r[1]);
    c.c5 = t1 + (-t2);
    return c;
}

class Combinations {
    int n_, k_; vector<int> idx_; bool started_, done_;
public:
    Combinations(int n, int k) : n_(n), k_(k), started_(false), done_(false) {
        if (k_ < 0 || k_ > n_) { done_ = true; return; }
        idx_.assign(k_, 0);
    }
    bool next() {
        if (done_) return false;
        if (!started_) {
            started_ = true;
            for (int i = 0; i < k_; ++i) idx_[i] = i;
            if (k_ == 0) { done_ = true; }
            return true;
        }
        int i = k_ - 1;
        while (i >= 0 && idx_[i] == n_ - k_ + i) --i;
        if (i < 0) { done_ = true; return false; }
        ++idx_[i];
        for (int j = i + 1; j < k_; ++j) idx_[j] = idx_[j - 1] + 1;
        return true;
    }
    const vector<int>& cur() const { return idx_; }
};

static bool matchCT(const CT& c, const PPK& ppk, Authority& auth, CPrime& out) {
    const Big q = pfc->order();
    map<string, pair<Big, Big> >::iterator sit = auth.ids.find(c.id);
    map<string, pair<Big, Big> >::iterator rit = auth.ids.find(ppk.id);
    if (sit == auth.ids.end() || rit == auth.ids.end()) return false;

    Big ws = sit->second.first;
    Big wr = rit->second.first;

    if (ppk.ppk2.size() < c.c2.size() || ppk.ppk1.size() > c.c1.size()) return false;

    Big iws = qInv(ws, q), iwr = qInv(wr, q);
    vector<G1> c1_prime, c2_prime;
    for (size_t i = 0; i < c.c1.size(); ++i) c1_prime.push_back(ctx.mult(c.c1[i], iws));
    for (size_t i = 0; i < c.c2.size(); ++i) c2_prime.push_back(ctx.mult(c.c2[i], iwr));

    for (Combinations cb1((int)ppk.ppk2.size(), (int)c2_prime.size()); cb1.next(); ) {
        const vector<int>& I1 = cb1.cur();
        GT verf_up(1);
        for (size_t i = 0; i < c2_prime.size(); ++i)
            verf_up = verf_up * ctx.pairing(ppk.ppk2[I1[i]], c2_prime[i]);

        for (Combinations cb2((int)c1_prime.size(), (int)ppk.ppk1.size()); cb2.next(); ) {
            const vector<int>& I2 = cb2.cur();
            GT verf_down(1);
            for (size_t j = 0; j < ppk.ppk1.size(); ++j)
                verf_down = verf_down * ctx.pairing(ppk.ppk1[j], c1_prime[I2[j]]);

            GT verf = verf_up / verf_down;
            GT rhs  = ctx.pairing(ppk.ppk3, c.c5);
            if (verf == rhs) {
                Big theta = sit->second.second;
                out.c0_prime = c.c0;
                symXor(theta, out.c0_prime);
                out.v1 = verf_up; out.v2 = verf_down; out.c3 = c.c3; out.c4 = c.c4;
                return true;
            }
        }
    }
    return false;
}

static vector<unsigned char> dec(const CPrime& cp, const Big& psk) {
    const Big q = pfc->order();
    GT v1p = ctx.power(cp.v1, qInv(psk, q));
    GT v2p = ctx.power(cp.v2, qInv(psk, q));
    G1 h1 = hashG1("CRO::H_r2r4|" + gtHex(cp.c4 / v1p));
    G1 h2 = hashG1("CRO::H_r1r3|" + gtHex(cp.c3 / v2p));

    vector<unsigned char> m = cp.c0_prime;
    string s1 = g1Hex(h1), s2 = g1Hex(h2);
    for (size_t i = 0; i < m.size(); ++i)
        m[i] = (unsigned char)(m[i] ^ (unsigned char)s1[i % s1.size()]
                                    ^ (unsigned char)s2[i % s2.size()]);
    return m;
}

static size_t szPP (const PP& p)  { (void)p; return 3 * SZ_G1; }
static size_t szMSK(const MSK& m)  { (void)m; return 2 * SZ_SCALAR; }
static size_t szRK (size_t n)      { return n * SZ_G1; }
static size_t szEK (size_t n)      { return n * SZ_G1; }
static size_t szDK (size_t n)      { return n * SZ_G2; }
static size_t szPPK(const PPK& k)  { return (k.ppk1.size() + k.ppk2.size() + 1) * SZ_G2; }
static size_t szCT (const CT& c)   { return c.c0.size() + c.c1.size() * SZ_G1 + c.c2.size() * SZ_G1 + 3 * SZ_GT; }
static size_t szCPr(const CPrime& p){ return p.c0_prime.size() + 4 * SZ_GT; }

struct RunOut {
    double t_setup = 0, t_reg = 0, t_ek = 0, t_dk = 0, t_pk = 0, t_enc = 0, t_match = 0, t_dec = 0;
    Cnt c_setup, c_reg, c_ek, c_dk, c_pk, c_enc, c_match, c_dec;
    size_t s_pp = 0, s_msk = 0, s_rk = 0, s_ek = 0, s_dk = 0, s_ppk = 0, s_ct = 0, s_cpr = 0;
    bool matched = false;   // structural only: says whether Dec could be measured at all
};

// One full pipeline pass.
// Timing discipline: ctx.reset() runs BEFORE the clock starts and all size accounting runs AFTER it
// stops, so the measured interval holds the stage call and nothing else.
static RunOut runOnce(const vector<string>& universe,
                      const vector<string>& senderAtt,
                      const vector<string>& receiverAtt,
                      const vector<string>& pol_S,
                      const vector<string>& pol_R,
                      const vector<unsigned char>& m) {
    RunOut o;
    Authority auth; PP pp; MSK msk;
    vector<G1> rk_sigma, rk_rho;
    vector<G2> rk_sigma2, rk_rho2;
    Big theta, theta_rho;
    EK ek; DK dk; PPK ppk; Big psk; CT c; CPrime cp;

    ctx.reset(); auto t0 = t_now(); setup(pp, msk, auth, universe);
    o.t_setup = ms_since(t0); o.c_setup = ctx.cnt;
    o.s_pp = szPP(pp); o.s_msk = szMSK(msk);

    ctx.reset(); auto t1 = t_now();
    registerUser(auth, "id555", senderAtt,   rk_sigma, rk_sigma2, theta);
    registerUser(auth, "id666", receiverAtt, rk_rho,   rk_rho2,   theta_rho);
    o.t_reg = ms_since(t1); o.c_reg = ctx.cnt;
    o.s_rk = szRK(rk_sigma.size());

    ctx.reset(); auto t2 = t_now(); ekGen(pp, msk, auth, pol_S, ek);
    o.t_ek = ms_since(t2); o.c_ek = ctx.cnt; o.s_ek = szEK(ek.ek_S.size());

    ctx.reset(); auto t3 = t_now(); dkGen(pp, msk, auth, pol_R, dk);
    o.t_dk = ms_since(t3); o.c_dk = ctx.cnt; o.s_dk = szDK(dk.dk_R.size());

    ctx.reset(); auto t4 = t_now(); pkGen(pp, dk.dk_R, rk_rho2, "id666", ppk, psk);
    o.t_pk = ms_since(t4); o.c_pk = ctx.cnt; o.s_ppk = szPPK(ppk);

    ctx.reset(); auto t5 = t_now(); c = enc(pp, rk_sigma, ek.ek_S, theta, m, "id555");
    o.t_enc = ms_since(t5); o.c_enc = ctx.cnt; o.s_ct = szCT(c);

    ctx.reset(); auto t6 = t_now(); o.matched = matchCT(c, ppk, auth, cp);
    o.t_match = ms_since(t6); o.c_match = ctx.cnt;

    if (o.matched) {
        ctx.reset(); auto t7 = t_now(); dec(cp, psk);
        o.t_dec = ms_since(t7); o.c_dec = ctx.cnt; o.s_cpr = szCPr(cp);
    }
    return o;
}

static void printUsage(const char* a0) {
    printf("Usage: %s [options]\n"
           "  --reps N        repetitions of the full pipeline; each stage reports the mean (default 21)\n"
           "  --attrs N       attribute universe size |A| and default sigma/pol size (default 15, same as upstream)\n"
           "  --recv N        receiver sigma/pol size when --scale send (default 15)\n"
           "  --scale both    both sender and receiver sets scale with --attrs (default)\n"
           "  --scale send    only sender set scales with --attrs; receiver uses --recv\n"
           "  --help, -h      show this help\n", a0);
}

int main(int argc, char** argv) {
    long reps = 21, attrs = 15, recvN = 15;
    string scale = "both";

    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if      (a == "--reps"  && i + 1 < argc) reps  = atol(argv[++i]);
        else if (a == "--attrs" && i + 1 < argc) attrs = atol(argv[++i]);
        else if (a == "--recv"  && i + 1 < argc) recvN = atol(argv[++i]);
        else if (a == "--scale" && i + 1 < argc) scale = argv[++i];
        else if (a == "--help" || a == "-h")     { printUsage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown argument: %s\n", a.c_str()); printUsage(argv[0]); return 2; }
    }
    if (reps  < 1) reps  = 1;
    if (attrs < 1) attrs = 1;
    if (recvN < 1) recvN = 1;
    if (scale != "both" && scale != "send") { fprintf(stderr, "--scale must be both or send\n"); return 2; }

    // PFC(128) => BN254/k=12; generators are derived by hash_and_map.
    pfc = new PFC(128);
    const char* seedEnv = getenv("BA_SEED");
    unsigned long seed = (seedEnv && *seedEnv) ? strtoul(seedEnv, NULL, 10) : (unsigned long)time(NULL);
    irand(seed);
    g1_gen = new G1(); pfc->hash_and_map(*g1_gen, (char*)"CRO_ABME_g1");
    g2_gen = new G2(); pfc->hash_and_map(*g2_gen, (char*)"CRO_ABME_g2");
    ctx.p = pfc;
    printf("CRO-ABME @ MIRACL / BN254(k=12), PFC(128), BA_SEED=%lu\n", seed);

    // |A| follows --attrs; only --scale send can need a larger universe (receiver set).
    long uni = (scale == "send" && recvN > attrs) ? recvN : attrs;
    vector<string> universe, senderAtt, receiverAtt, pol_S, pol_R;
    for (long i = 0; i < uni;   ++i) universe.push_back("ATT" + to_string(i));
    for (long i = 0; i < attrs; ++i) senderAtt.push_back("ATT" + to_string(i));
    pol_S = senderAtt;
    if (scale == "send") {
        for (long i = 0; i < recvN; ++i) receiverAtt.push_back("ATT" + to_string(i));
        pol_R = receiverAtt;
    } else {
        receiverAtt = senderAtt;
        pol_R       = pol_S;
    }
    vector<unsigned char> m(32);
    for (size_t i = 0; i < m.size(); ++i) m[i] = (unsigned char)('A' + (int)(i % 26));

    printf("Config: |A|=%ld  |sigma_S|=|pol_S|=%zu  |sigma_R|=|pol_R|=%zu  |m|=%zu  reps=%ld  scale=%s\n",
           uni, senderAtt.size(), receiverAtt.size(), m.size(), reps, scale.c_str());

    vector<RunOut> R;
    R.reserve((size_t)reps);
    for (long i = 0; i < reps; ++i) R.push_back(runOnce(universe, senderAtt, receiverAtt, pol_S, pol_R, m));

    vector<double> v[8];
    for (long i = 0; i < reps; ++i) {
        v[0].push_back(R[i].t_setup); v[1].push_back(R[i].t_reg); v[2].push_back(R[i].t_ek);
        v[3].push_back(R[i].t_dk);    v[4].push_back(R[i].t_pk);  v[5].push_back(R[i].t_enc);
        v[6].push_back(R[i].t_match); v[7].push_back(R[i].t_dec);
    }
    const char* nm[8]  = { "Setup", "Register x2", "EKGen", "DKGen", "PKeyGen", "Enc", "Match", "Dec" };
    const Cnt*  cst[8] = { &R[0].c_setup, &R[0].c_reg, &R[0].c_ek, &R[0].c_dk,
                           &R[0].c_pk, &R[0].c_enc, &R[0].c_match, &R[0].c_dec };

    printf("\n%-12s %11s %8s %6s %7s %7s\n",
           "stage", "Mean (ms)", "pairing", "GTpow", "G1mul", "G2mul");
    double totMean = 0.0;
    for (int i = 0; i < 8; ++i) {
        printf("%-12s %11.3f %8ld %6ld %7ld %7ld\n",
               nm[i], mean(v[i]),
               cst[i]->pairing, cst[i]->gtpow, cst[i]->g1, cst[i]->g2);
        totMean += mean(v[i]);
    }
    printf("%-12s %11.3f   (sum of 8 stages in series, i.e. this scheme's end-to-end time)\n", "Total", totMean);

    const RunOut& z = R[0];
    printf("\nSize (fixed-width serialization, same convention as system_mine): PP=%zu  msk=%zu  rk=%zu  ek_S=%zu  "
           "dk_R=%zu  ppk=%zu  c=%zu  c_prime=%zu  (bytes)\n",
           z.s_pp, z.s_msk, z.s_rk, z.s_ek, z.s_dk, z.s_ppk, z.s_ct, z.s_cpr);

    if (!R[0].matched)
        fprintf(stderr, "[cro-abme] note: match returned false, so Dec was not measurable in this configuration\n");

    return 0;
}

