// SoK + six-step MoniDecide with session binding and nonce anti-replay.
#ifndef KNOWLEDGE_SIGNATURE_H
#define KNOWLEDGE_SIGNATURE_H

#include <vector>
#include <string>
#include "pfc_global.h"
#include "ps_credential.h"
#include "trusted_authority.h"
struct Policy;
struct PedRelationProof;

// This module handles [identity proof] only: the prover holds a PS multi-message signature over the [coefficient vector], whose messages equal the committed coefficients (neither coefficients nor blinds are revealed).

// ① Same SRS-basis representation + opening relation; ② credential messages = this coefficient set (sharing the same responses s_i) ⇒ signed coefficients = committed coefficients = polynomial coefficients = the same attribute set.

// Identity-proof output: the set commitment C and set-relation proof live on the attribute side (MoniProof in monipoly.h) and are added by the prover under the same challenge c ⇒ both proofs bind to the same attribute set.
struct CoeffKnowledgeSignature {
    PSCredential credential;
    Big nonce; // [one-time nonce carried by the SoK] (absorbed into challenge c and used as the anti-replay key)
    ZKPsVectorBinding bind; // credential-side binding: Up = ∏B_i^{t_i} plus challenge c (responses s are reused from mp.rel.s)

    size_t size() const;
};


// CheckStat: ms + pair/gtpow/g1/g2; DecideStats groups stats by step: sok (① identity + anchoring) / rel (② set relation) / match (③ policy).
struct CheckStat { double ms = 0; long pair = 0, gtpow = 0, g1 = 0, g2 = 0; };
struct DecideStats { CheckStat sok, rel, match; };

// ---- Anti-replay (verifier state) ----
std::string NonceHex(const Big& v);
// Key = to_string(msg.size()) + msg + NonceHex(nonce); append to used if fresh; bounded by kNonceStateCap (oldest evicted on overflow; production needs TTL/persistence).
bool NonceFresh(std::vector<std::string>& used, const Big& nonce,
                const std::string& msg, std::string* why = nullptr);

// Verifier-state bound (prevents unbounded memory growth; production requires TTL / persistent storage).
extern const size_t kNonceStateCap;

// ---- [Anti-replay layer 1] session-binding check (verifier side: after issuing/binding sid, msg must end with an unused sid) ----
bool SessionBindFresh(const std::vector<std::string>& issued,
                      std::vector<std::string>& usedSids,
                      const std::string& msg, std::string* why = nullptr);


// Challenge domain-separation label "MODE-PED" ⇒ cross-mode reuse is always rejected; ⚠ [P0 fix] the coefficient vector must be derived only from pr.attrs (otherwise "a credential for A_cred + plaintext A_fake" enables unauthorized claims).
CoeffKnowledgeSignature SignOfKnowledgeCoeffPed(const SystemParams& sys,
                                                const PSCredential& credential,
                                                const PSVerifyKey& issuerPub,
                                                const std::string& msg,
                                                const PedRelationProof& pr);

bool VerifyKnowledgeSignatureCoeffPed(const CoeffKnowledgeSignature& ks,
                                      const PSVerifyKey& issuerPub,
                                      const SystemParams& sys,
                                      const std::string& msg,
                                      const PedRelationProof& pr);

bool DecidePresentationPed(const CoeffKnowledgeSignature& ks,
                           const PSVerifyKey& issuerPub,
                           const SystemParams& sys,
                           const std::string& msg,
                           const PedRelationProof& pr,
                           const Policy& required,
                           std::string* why = nullptr,
                           DecideStats* stats = nullptr);

#endif
