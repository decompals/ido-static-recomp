# --- Configuration
# -- select the version and binaries of IDO toolchain to recompile
VERSION ?= 7.1
ifeq ($(VERSION),7.1)
  IDO_VERSION := IDO71
  IDO_TC      := cc as1 cfe ugen umerge uopt
else ifeq ($(VERSION),5.3)
  IDO_VERSION := IDO53
  IDO_TC      := cc acpp as0 as1 cfe copt ugen ujoin uld umerge uopt usplit
  # 5.3 ugen relies on UB stack reads
  # to emulate, pass the conservative flag to `recomp`
  CONSERVATIVE_ugen := --conservative
else
  $(error Unknown or unsupported IDO version - $(VERSION))
endif

# -- Build Directories
BUILD_BASE ?= build
BUILD_DIR  := $(BUILD_BASE)/$(IDO_VERSION)
BUILT_BIN  := $(BUILD_DIR)/bin

# -- Location of original IDO binaries
IRIX_BASE    ?= ido
IRIX_USR_DIR ?= $(IRIX_BASE)/$(VERSION)/usr

# -- Location of the irix tool chain error messages
ERR_STRS_SRC := $(IRIX_USR_DIR)/lib/err.english.cc
ERR_STRS_DST := $(BUILT_BIN)/err.english.cc

# -- ensure build directories exist before compiling anything
ifeq ($(filter clean,$(MAKECMDGOALS)),)
  DUMMY != mkdir -p $(BUILD_BASE) $(BUILD_DIR) $(BUILT_BIN)
endif

# -- Settings for the static recompilation tool `recomp`
RECOMP       := $(BUILD_BASE)/recomp
RECOMP_OPT   ?= -O2
RECOMP_FLAGS ?= -std=c++11 -Wno-switch `pkg-config --cflags --libs capstone`


# -- Settings for libc shim
LIBC_SHIM  := $(BUILD_DIR)/libc_impl.o
LIBC_OPT   ?= -O2
LIBC_FLAGS ?= -fno-strict-aliasing

# -- Settings for recompiling the translated irix binaries
COMPILE_OPT   ?= -O2
COMPILE_FLAGS ?= -Wno-tautological-compare -fno-strict-aliasing -lm
COMPILE_DEPS  := header.h helpers.h $(LIBC_SHIM) $(ERR_STRS_DST)

# -- Host specific configuration
ifeq ($(shell uname -s),Darwin)
  # macOS clang wants `-fno-pie` on intel, but that flag is ignored on ARM
  ifneq ($(shell uname -p),arm)
    COMPILE_FLAGS += -fno-pie
  endif
  # macOS has deprecated some libc functions that the 1992 irix binaries use
  LIBC_FLAGS += -Wno-deprecated-declarations
else
  COMPILE_FLAGS += -no-pie
endif

# --- Functions
# fn irix_binary(ToolName) -> PathToOriginalTool
#     all binaries are in usr/lib expect for cc which is in usr/bin 
irix_binary = $(IRIX_USR_DIR)/$(if $(filter cc,$(1)),bin,lib)/$(1)

# fn translated_src(ToolName) -> PathToOutputCFile
translated_src = $(BUILD_DIR)/$(1).c

# fn recompiled_binary(ToolName) -> PathToOutputBin
recompiled_binary = $(BUILT_BIN)/$(1)

# fn recomple(ToolName) -> MakeRules
define recompile
$(call translated_src,$1): $(call irix_binary,$1) $(RECOMP)
	$(RECOMP) $(CONSERVATIVE_$1) $$< > $$@

$(call recompiled_binary,$1): $(call translated_src,$1) $(COMPILE_DEPS)
	$$(CC) $(LIBC_SHIM) $$< -o $$@ -I. $(COMPILE_OPT) $(COMPILE_FLAGS)
endef

# --- Recipes
ALL_TOOLS := $(foreach tool,$(IDO_TC),$(call recompiled_binary,$(tool)))

all: $(ALL_TOOLS)

clean:
	$(RM) -rf $(BUILD_BASE)

$(RECOMP): recomp.cpp elf.h
	$(CXX) $< -o $@ $(RECOMP_OPT) $(RECOMP_FLAGS)

$(LIBC_SHIM): libc_impl.c libc_impl.h
	$(CC) $< -c $(LIBC_FLAGS) $(LIBC_OPT) -D$(IDO_VERSION) -o $@

$(ERR_STRS_DST): $(ERR_STRS_SRC)
	cp $^ $@

$(foreach tool,$(IDO_TC),$(eval $(call recompile,$(tool))))


.PHONY: all clean

# Remove built-in rules, to improve performance
MAKEFLAGS += --no-builtin-rules

# --- Debugging
# run `make print-VARIABLE` to debug that variable
print-% : ; $(info $* is a $(flavor $*) variable set to [$($*)]) @true
