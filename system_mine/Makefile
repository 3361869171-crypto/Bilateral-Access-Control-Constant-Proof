# Bilateral access control system - our implementation
#
# Usage:
#   make                 Build ./main
#   make test-difference Set-relation soundness
#   make test-sok        Single-challenge binding
#   make test-moni       Presentation-proof regression
#   make test-commit     Run both commitment tests once each
#   make test-mode       Mode consistency
#   make test-forge      N0 credential-forgery regression
#   make test-blind      Blind-issuance regression
#   make test-session    Session-binding anti-replay
#   make test-base-index Base-index discipline
#   make test-moni-prove x′-shift variant regression
#   make test-miracl-semantics Library budget and official-primitive self-check (nib==5 / modmult·moddiv·inverse / state safety)
#   make test-degenerate Degenerate-credential regression (C1: σ = group identity ⇒ identity proof must be rejected)
#   make test-batch      T2 batch-primitive regression (multiPair/pairEq/powerMulti/g2MultiMult equivalence, degenerate behavior, count accounting)
#   make bench-fusion    Phase F measurement: timing account for T3 fusion (∏e(Y2_i,σ1)^{e_i} ⇒ e(Σe_i·Y2_i,σ1)) (optional, not part of regression)
#   make test-moni SELFCHECK=0  Disable prove-time self-check (pairings 4 → 1: saves 3 pairings + |f| G2 multiplications; soundness is enforced on the verifier side)
#   make test-moni NOFOLD=1     Disable H-B folding on the verifier side (credential equation reverts to the termwise form: verification pairings |f|+2+2+2·clauses;
#                               default folding is 3+2+2·clauses — both produce bit-identical decisions, and count assertions switch with the macro)
#   make check-official  Official-endorsement guard (G4: no bare multiplication / no spill·restore / three library files match upstream)
#   make acceptance      End-to-end acceptance (requires python3)
#   make clean           Remove artifacts in this directory
#
# Dependency: ../miracl_output/lib/libmiracl.a
#
# Header dependencies: -MMD -MP generates *.d files, included at the end via -include.
# Changing a header ⇒ dependent .cpp files rebuild automatically.

CXX      = g++
CXXFLAGS = -m64 -O2 -std=c++17 -Wall -MMD -MP
# Prove-time self-check switch (message check in SigmaCommitZkPs): SELFCHECK=0 ⇒ -DMONI_SOK_NO_SELFCHECK disables it
ifeq ($(SELFCHECK),0)
CXXFLAGS += -DMONI_SOK_NO_SELFCHECK
endif
# Verifier-side H-B folding switch (credential equation in zkPsVerifyWithChallenge): NOFOLD=1 ⇒ -DMONI_NO_VERIFY_FOLD reverts to termwise form
#   Default (unset) = folding: e(Σ_i s_i·Y2_i,σ1) replaces n terms e(Y2_i,σ1)^{s_i} ⇒ verification pairings |f|+2 → 3, G1 mults −|f|, G2 mults +|f|
#   Both builds produce bit-identical decisions (a bilinear identity, not probabilistic equivalence; edge branches in tests/moni_sok_m3_test.cpp (5c))
ifeq ($(NOFOLD),1)
CXXFLAGS += -DMONI_NO_VERIFY_FOLD
endif
INCLUDES = -I. -I../miracl_output/include
LIBS     = -L../miracl_output/lib -lmiracl

SRCS = pfc_global.cpp monipoly.cpp \
       knowledge_signature.cpp \
       ps_credential.cpp trusted_authority.cpp \
       pedersen.cpp main.cpp
OBJS   = $(SRCS:.cpp=.o)
TARGET = main

# This system's headers (belt-and-suspenders with -MMD)
HDRS = $(wildcard *.h) $(wildcard tests/*.h)

# Library object files (excluding main.o)
LIBOBJS = $(filter-out main.o,$(OBJS))

# Test executables
TESTBINS = tests/difference_soundness_test tests/sok_single_challenge_test \
           tests/moni_sok_m3_test tests/commit_moni_test tests/commit_ped_test \
           tests/mode_switch_test tests/forge_from_pp_test tests/blind_issue_test \
           tests/session_bind_test tests/base_index_test tests/moni_prove_test \
           tests/miracl_semantics_test tests/degenerate_credential_test \
           tests/batch_pairing_test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(TARGET)
	rm -f $(TESTBINS) $(TESTBINS:%=%.d)
	rm -f $(BENCHBINS) $(BENCHBINS:%=%.d)

# ===== Difference/intersection wiring soundness =====
tests/difference_soundness_test: tests/difference_soundness_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-difference: tests/difference_soundness_test
	./tests/difference_soundness_test

# ===== Single-challenge binding =====
tests/sok_single_challenge_test: tests/sok_single_challenge_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-sok: tests/sok_single_challenge_test
	./tests/sok_single_challenge_test

# ===== Presentation-proof regression =====
tests/moni_sok_m3_test: tests/moni_sok_m3_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-moni: tests/moni_sok_m3_test
	./tests/moni_sok_m3_test

# ===== Each commitment scheme in its own process =====
tests/commit_moni_test: tests/commit_moni_test.cpp monipoly.o ps_credential.o pfc_global.o trusted_authority.o $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< monipoly.o ps_credential.o pfc_global.o trusted_authority.o $(LIBS)

tests/commit_ped_test: tests/commit_ped_test.cpp pedersen.o pfc_global.o trusted_authority.o $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< pedersen.o pfc_global.o trusted_authority.o $(LIBS)

test-commit-moni: tests/commit_moni_test
	./tests/commit_moni_test

test-commit-ped: tests/commit_ped_test
	./tests/commit_ped_test

test-commit: test-commit-moni test-commit-ped
	@echo "=== Both commitment tests completed ==="

# ===== Mode-selection consistency =====
tests/mode_switch_test: tests/mode_switch_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-mode: tests/mode_switch_test
	./tests/mode_switch_test

# ===== N0: forge a credential from public pp only =====
tests/forge_from_pp_test: tests/forge_from_pp_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-forge: tests/forge_from_pp_test
	./tests/forge_from_pp_test

# ===== Blind issuance (blind ⇒ sign ⇒ unblind) =====
tests/blind_issue_test: tests/blind_issue_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-blind: tests/blind_issue_test
	./tests/blind_issue_test

# ===== Session binding / anti-replay layer 1 =====
tests/session_bind_test: tests/session_bind_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-session: tests/session_bind_test
	./tests/session_bind_test

# ===== Base-index discipline =====
tests/base_index_test: tests/base_index_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-base-index: tests/base_index_test
	./tests/base_index_test

# ===== MoniPoly main-path regression =====
tests/moni_prove_test: tests/moni_prove_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-moni-prove: tests/moni_prove_test
	./tests/moni_prove_test

# ===== MIRACL semantics probe (G0): evidence for replacing "bare multiplication" with official modmult/moddiv =====
tests/miracl_semantics_test: tests/miracl_semantics_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-miracl-semantics: tests/miracl_semantics_test
	./tests/miracl_semantics_test

# ===== Degenerate-credential regression (C1): verifies the fix for identity-proof bypass via σ=(O,O) and Up=1_T =====
tests/degenerate_credential_test: tests/degenerate_credential_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-degenerate: tests/degenerate_credential_test
	./tests/degenerate_credential_test

# ===== T2 batch-primitive regression: equivalence, degenerate behavior, and count accounting for multiPair / pairEq / powerMulti / g2MultiMult =====
# Upper-layer protocol assertions (after T3 fusion: proving pairings = 4/1, proving GT powers = 0, proving G2 mults = 2|f|/|f|;
# verifier-side default H-B folding: verification pairings = 3+2+2·clauses, G1 mults = 6, G2 mults = |f|+4 — with NOFOLD=1 they revert to |f|+2+2+2·clauses / |f|+6 / 4), see test-moni;
# Self-check downgrade: SELFCHECK=0 ⇒ proving pairings 4 → 1 (Up folding only), proving G2 mults 2|f| → |f|; saves 3 pairings (1 fold + 2-term multi-pairing)
# and |f| G2 mults (confirmed both by tests/moni_fusion_bench.cpp timings and by the e2e one-side count dropping 4 → 1);
# test-moni's count assertions switch with the same macros (-DMONI_SOK_NO_SELFCHECK / -DMONI_NO_VERIFY_FOLD); every build must pass.
# This test pins only "batch = pointwise" equivalence and item-count accounting, and covers the identity-element fallback.
tests/batch_pairing_test: tests/batch_pairing_test.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

test-batch: tests/batch_pairing_test
	./tests/batch_pairing_test

# ===== Phase F measurement (optional, not part of make/regression): timing account before and after T3 fusion =====
# Alternately time legacy ① batched GT powers / legacy ② pointwise GT powers / new (fused) using real credentials and key views; assertions pin only equivalence and count accounting;
# also print comparison numbers for the whole proving phase (SigmaCommitZkPs, including self-check) and the verifier side (default H-B folding; NOFOLD=1 disables it). See tests/moni_fusion_bench.cpp.
BENCHBINS = tests/moni_fusion_bench
tests/moni_fusion_bench: tests/moni_fusion_bench.cpp $(LIBOBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBOBJS) $(LIBS)

bench-fusion: tests/moni_fusion_bench
	./tests/moni_fusion_bench

# ===== End-to-end acceptance (requires python3) =====
acceptance: $(TARGET)
	python3 tests/acceptance_main.py ./$(TARGET)

acceptance-ped: $(TARGET)
	python3 tests/acceptance_main.py ./$(TARGET) ped

acceptance-moni: $(TARGET)
	python3 tests/acceptance_main.py ./$(TARGET) shift

# ===== Official-endorsement guard (G4): prevent regressions that deviate from the official API =====
# Basis 1: ../MIRACL-master/source/curve/pairing/pairings.txt:101-103
#         "For arithmetic in Zr ... use the Big functions modmult(x,y,r) (returns
#          x*y mod r), moddiv(x,y,r) and inverse(x,r) to avoid overflow."
#         Mechanism: mad() stores the product in the double-length workspace mr_mip->w0 (mrarth2.c:1556-1583;
#         docs/miracl-explained/reference-manual/low-level-routines.md:495-496)
#         ⇒ intermediate products never enter a normal Big, so no budget increase is needed.
# Basis 2: spill/restore are the only MIRACL entry points that depend on mip->nib (the Big allocation budget)
#         (bn_pair.cpp:410/445/1200/1260/1316/1344/1383/1418) ⇒ calling them leaks the "budget"
#         into the output and breaks the "budget change ⇒ output unchanged" property, so this project forbids them.
# Basis 3: the three library-side files must be byte-identical to upstream (see the header of build_miracl.sh).
AUDIT_SRCS = monipoly.cpp ps_credential.cpp trusted_authority.cpp
FORBIDDEN_BAREMUL = 'poly\[0\] \* m' 'poly\[i - 1\] \+ poly\[i\] \* m' \
                    'poly\[0\] \* o' 'poly\[i - 1\] \+ poly\[i\] \* o' \
                    'r\[target\] \* inv_lc_d' 'scale \* d_copy\[j\]' \
                    'coeff \* inv_lc' 'pow \* a' 'pow \* xprime_'

check-official:
	@fail=0; \
	for f in $(AUDIT_SRCS); do \
	  code=$$(sed 's|//.*||' $$f); \
	  for pat in $(FORBIDDEN_BAREMUL); do \
	    if printf '%s\n' "$$code" | grep -qE "$$pat"; then \
	      echo "  [FAIL] G4-1 bare multiplication found (use official modmult/moddiv): $$f <- $$pat"; fail=1; \
	    fi; \
	  done; \
	done; \
	if [ $$fail -eq 0 ]; then echo "  [PASS] G4-1 no bare multiplication remains (pairings.txt:101-103)"; else exit 1; fi
	@if grep -qE '\b(spill|restore)\b' *.cpp *.h 2>/dev/null; then \
	   echo "  [FAIL] G4-2 project uses nib-sensitive spill/restore"; exit 1; \
	 else echo "  [PASS] G4-2 no spill/restore used"; fi
	@if [ ! -d ../MIRACL-master ] || [ ! -f ../miracl_build/bn_pair.cpp ] || [ ! -f ../miracl_build/mirdef.h ] || [ ! -f ../miracl_build/mrmuldv.c ]; then \
	   echo "  [SKIP] G4-3 official source/build artifacts are not distributed with the repository (../MIRACL-master or ../miracl_build missing); skipping byte-for-byte comparison"; \
	 else \
	   cmp -s ../miracl_build/bn_pair.cpp ../MIRACL-master/source/curve/pairing/bn_pair.cpp \
	     && echo "  [PASS] G4-3a bn_pair.cpp is byte-identical to upstream (no mod_bits patch)" \
	     || { echo "  [FAIL] G4-3a bn_pair.cpp differs from upstream"; exit 1; }; \
	   cmp -s ../miracl_build/mirdef.h ../MIRACL-master/include/mirdef.hpp \
	     && echo "  [PASS] G4-3b mirdef.h == official mirdef.hpp (linux64_cpp:3)" \
	     || { echo "  [FAIL] G4-3b mirdef.h differs from official mirdef.hpp"; exit 1; }; \
	   cmp -s ../miracl_build/mrmuldv.c ../MIRACL-master/source/mrmuldv.g64 \
	     && echo "  [PASS] G4-3c mrmuldv.c == official mrmuldv.g64 (linux64_cpp:54)" \
	     || { echo "  [FAIL] G4-3c mrmuldv.c differs from official mrmuldv.g64"; exit 1; }; \
	 fi
	@echo "===== Official-endorsement guard (G4) check complete ====="

# ===== Auto-generated header dependencies (must be at the end) =====
-include $(OBJS:.o=.d)
-include tests/difference_soundness_test.d
-include tests/sok_single_challenge_test.d
-include tests/moni_sok_m3_test.d
-include tests/commit_moni_test.d
-include tests/commit_ped_test.d
-include tests/mode_switch_test.d
-include tests/forge_from_pp_test.d
-include tests/blind_issue_test.d
-include tests/session_bind_test.d
-include tests/base_index_test.d
-include tests/moni_prove_test.d
-include tests/miracl_semantics_test.d
-include tests/degenerate_credential_test.d
-include tests/batch_pairing_test.d
-include tests/moni_fusion_bench.d
