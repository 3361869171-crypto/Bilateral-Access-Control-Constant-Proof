// Fixed-width, unambiguous Fiat-Shamir transcript.
#ifndef FS_TRANSCRIPT_H
#define FS_TRANSCRIPT_H


#include <string>
#include "pfc_global.h"
#include "monipoly.h"

// [Fallback] Negative/oversized values or bytes too large (defensive; unreachable in the normal domain) ⇒ original cotstr implementation with unchanged semantics.
inline std::string fsHexFixed(const Big& v, size_t bytes) {
    static const char* HX = "0123456789ABCDEF";
    if (v >= 0 && bytes <= 64 && logb2(v.getbig()) <= (int)(bytes * 8)) {
        char buf[64];
        to_binary(v, (int)bytes, buf, TRUE);
        std::string s;
        s.resize(bytes * 2);
        for (size_t i = 0; i < bytes; ++i) {
            const unsigned char b = (unsigned char)buf[i];
            s[2 * i]     = HX[b >> 4];
            s[2 * i + 1] = HX[b & 0xF];
        }
        return s;
    }
    miracl* mip = get_mip();
    const int old = mip->IOBASE;
    mip->IOBASE = 16;
    char buf[4096];
    cotstr(v.getbig(), buf);
    mip->IOBASE = old;
    std::string s(buf);
    const size_t want = bytes * 2;
    if (s.size() < want) s.insert(0, want - s.size(), '0');
    return s;
}

inline std::string fsHexBytes(const char* data, size_t len) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(2 * len);
    for (size_t i = 0; i < len; ++i) {
        const unsigned char b = (unsigned char)data[i];
        out.push_back(H[b >> 4]);
        out.push_back(H[b & 0xF]);
    }
    return out;
}

inline void fsFeed(PFC* pfc, char tag, const std::string& hex) {
    const std::string len = std::to_string(hex.size());
    std::string env;
    env.reserve(10 + hex.size());
    env.push_back(tag);
    if (len.size() < 8) env.append(8 - len.size(), '0');
    env += len;
    env.push_back(':');
    env += hex;
    pfc->add_to_hash((char*)env.c_str());
}


// Per-type field encoding (overloads make the absorbed type and fixed width explicit at each call site).
inline void fsAbsorb(PFC* pfc, const Big& v)    { fsFeed(pfc, 'B', fsHexFixed(v, 32)); }
inline void fsAbsorb(PFC* pfc, const std::string& s) { fsFeed(pfc, 'S', fsHexBytes(s.data(), s.size())); }
inline void fsAbsorb(PFC* pfc, const G1& p) {
    Big X, Y; p.g.get(X, Y);
    fsFeed(pfc, '1', fsHexFixed(X, 32) + fsHexFixed(Y, 32));
}
inline void fsAbsorb(PFC* pfc, const G2& p) {
    ECn2 pt = p.g; ZZn2 X, Y; pt.get(X, Y);
    ZZn a, b, c, d; X.get(a, b); Y.get(c, d);
    fsFeed(pfc, '2', fsHexFixed((Big)a, 32) + fsHexFixed((Big)b, 32) +
                     fsHexFixed((Big)c, 32) + fsHexFixed((Big)d, 32));
}
inline void fsAbsorb(PFC* pfc, const GT& t) {
    ZZn12 v = t.g; ZZn4 u; v.get(u); ZZn2 l, h; u.get(l, h);
    ZZn a, b, c, d; l.get(a, b); h.get(c, d);
    fsFeed(pfc, 'T', fsHexFixed((Big)a, 32) + fsHexFixed((Big)b, 32) +
                     fsHexFixed((Big)c, 32) + fsHexFixed((Big)d, 32));
}

// Goal: changing the commitment/clause/threshold/index/nonce ⇒ c changes ⇒ response verification fails.
inline void hashProof(PFC* pfc, const MoniProof& p) {
    fsAbsorb(pfc, p.commitment);
    fsAbsorb(pfc, p.nonce); // one-time nonce: removes byte-for-byte determinism / prevents replay
    fsAbsorb(pfc, Big((long)p.proofs.size()));
    for (const ClauseProof& c : p.proofs) {
        fsAbsorb(pfc, Big((long)c.clauseIndex));
        fsAbsorb(pfc, Big(static_cast<long>(c.type)));
        fsAbsorb(pfc, Big((long)c.threshold));
        for (const Big& r : c.publicSet) fsAbsorb(pfc, r);
        for (const Big& r : c.revealed)  fsAbsorb(pfc, r);
        fsAbsorb(pfc, c.witness);
        for (const Big& r : c.remainderCoeff) fsAbsorb(pfc, r);
    }
}

#endif
