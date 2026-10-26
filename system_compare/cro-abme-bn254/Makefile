# Makefile for cro-abme-bn254 — a faithful port of upstream CRO-ABME on the same library (MIRACL/BN254)
#
# Usage:
#   make                    Build ./cro-abme-bn254
#   make run                Build and run (default --attrs 15 --reps 21)
#   make run ATTRS=30 REPS=5
#   make bench-attrs        Attribute-size sweep (pure shell, default |A|=3 5 10 15 20 30 50)
#   make clean              Remove artifacts in this directory
#
# Output per stage: mean time (ms), group-operation counts (pairing/GTpow/G1mul/G2mul), object sizes.
# No self-checks, no anchor comparison, no combination cap: this binary measures only.
#
# Dependency: ../../miracl_output/lib/libmiracl.a (same library and curve BN254/k=12 as system_mine)
# Important: this project uses the C++ MIRACL build (MR_CPP) => -DMR_PAIRING_BN is required;
#       and sources including miracl.h must not be wrapped in extern "C".

CXX      = g++
CXXFLAGS = -m64 -O2 -std=c++11 -Wall -DMR_PAIRING_BN
INCLUDES = -I../../miracl_output/include
LIBS     = -L../../miracl_output/lib -lmiracl

TARGET = cro-abme-bn254
SRC    = cro-abme-bn254.cpp

ATTRS ?= 15
REPS  ?= 21
SCALE ?= both

.PHONY: all run bench-attrs clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

run: $(TARGET)
	./$(TARGET) --attrs $(ATTRS) --reps $(REPS) --scale $(SCALE)

# Attribute-size sweep (pure shell, no python): run once per |A| (with REP reps averaged per stage), then print the stage table
ATTRS_LIST ?= 3 5 10 15 20 30 50
SWEEP_REPS ?= 5
bench-attrs: $(TARGET)
	@for a in $(ATTRS_LIST); do \
	  echo "===== |A|=$$a  (--reps $(SWEEP_REPS) --scale $(SCALE)) ====="; \
	  ./$(TARGET) --attrs $$a --reps $(SWEEP_REPS) --scale $(SCALE) || exit 1; \
	  echo; \
	done

clean:
	rm -f $(TARGET)
