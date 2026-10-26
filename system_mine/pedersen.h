// Pedersen baseline: per-attribute commitments and plaintext policy decision.
#ifndef PEDERSEN_H
#define PEDERSEN_H

#include <vector>
#include <string>
#include "pfc_global.h"
#include "trusted_authority.h"


// Per-attribute commitment A_i = g1^{a_i}·h^{r_i}; fails if attrs and blinds have different lengths; blinds must be fresh each time (otherwise hiding and unlinkability are lost).
std::vector<G1> PedersenCommitAttributes(const SystemParams& sys,
                                         const std::vector<Big>& attrs,
                                         const std::vector<Big>& blinds);

// Per-coefficient commitment C_j = g1^{q_j}·h^{r_j} (since v7 the protocol no longer uses {C_j}; retained as a vector-commitment primitive to keep the module self-contained).
std::vector<G1> PedersenCommitVector(const SystemParams& sys,
                                     const std::vector<Big>& values,
                                     const std::vector<Big>& blinds);

// Opening verification: recompute com[i] == g1^{values[i]}·h^{blinds[i]} for each i; false ⇒ altered value, wrong blind, replaced commitment, or size mismatch (defensive).
bool PedersenOpenVerify(const SystemParams& sys,
                        const std::vector<G1>& com,
                        const std::vector<Big>& values,
                        const std::vector<Big>& blinds);

// ⚠ Privacy difference: the verifier sees the attributes in plaintext.
struct Policy;

struct PedRelationProof {
    Big nonce; // one-time random nonce
    std::vector<G1>  com;
    std::vector<Big> attrs;
    std::vector<Big> blinds;
    size_t size() const;
};

// Prove: commitments + openings + nonce.
PedRelationProof ProveRelationPedersen(const SystemParams& sys,
                                       const std::vector<Big>& attributes);

// Verify: recompute A_i = g1^{a_i}·h^{r_i} for each item.
bool VerifyRelationPedersen(const PedRelationProof& pr, const SystemParams& sys);

bool PolicySatisfiedByPlaintext(const std::vector<Big>& attrs,
                                const Policy& policy, std::string* why = nullptr);

#endif
