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

# -- determine the host environment and target
# | Host  | Targets           |
# |-------|-------------------|
# | macOS | native, universal |
# | linux | native            |
#
UNAME_S := $(shell uname -s)
UNAME_P := $(shell uname -p)
ifeq ($(UNAME_S),Darwin)
  HOST_OS := macOS
  TARGET  ?= native
else ifeq ($(UNAME_S),Linux)
  HOST_OS := linux
  TARGET  := native
else
  $(error Unsupported host OS for Makefile)
endif

HOST_TARGET := $(HOST_OS)-$(TARGET)
# clang build targets for ARM and x64 macOS
MACOS_FAT_TARGETS ?= arm64-apple-macos11 x86_64-apple-macos10.14

# -- Build Directories
# designed to work with Make 3.81 (macOS/last GPL-2 version)
# https://ismail.badawi.io/blog/automatic-directory-creation-in-make/
BUILD_BASE ?= build
BUILD_DIR  := $(BUILD_BASE)/$(VERSION)
BUILT_BIN  := $(BUILD_DIR)/out

.PRECIOUS: $(BUILD_BASE)/. $(BUILD_BASE)%/.

$(BUILD_BASE)/.:
	mkdir -p $@

$(BUILD_BASE)%/.:
	mkdir -p $@

# -- Location of original IDO binaries
IRIX_BASE    ?= ido
IRIX_USR_DIR ?= $(IRIX_BASE)/$(VERSION)/usr

# -- Location of the irix tool chain error messages
ERR_STRS_SRC := $(IRIX_USR_DIR)/lib/err.english.cc
ERR_STRS_DST := $(BUILT_BIN)/err.english.cc

# -- Settings for the static recompilation tool `recomp`
RECOMP       := $(BUILD_BASE)/recomp
RECOMP_OPT   ?= -O2
RECOMP_FLAGS ?= -std=c++11 -Wno-switch `pkg-config --cflags --libs capstone`

# -- Settings for libc shim
LIBC_IMPL := libc_impl.c
LIBC_OBJ  := $(LIBC_IMPL:.c=.o)
LIBC_OPT   ?= -O2
LIBC_FLAGS ?= -fno-strict-aliasing 

# -- Settings for recompiling the translated irix binaries
COMPILE_OPT   ?= -O2
COMPILE_FLAGS ?= -Wno-tautological-compare -fno-strict-aliasing -lm
COMPILE_DEPS  := header.h helpers.h $(ERR_STRS_DST)

# -- Host specific configuration
ifeq ($(HOST_OS),macOS)
  # macOS clang wants `-fno-pie` on intel, but that flag is ignored on ARM
  ifeq (,$(findstring arm,$(UNAME_P)))
  ifneq (TARGET,universal)
    COMPILE_FLAGS += -fno-pie
  endif
  endif
  # macOS has deprecated some libc functions that the 1992 irix binaries use
  LIBC_FLAGS += -Wno-deprecated-declarations
else
  COMPILE_FLAGS += -no-pie
endif

# --- Functions
# fn irix_binary(ToolName) -> PathToOriginalTool
#     all binaries are in usr/lib except for cc which is in usr/bin 
irix_binary = $(IRIX_USR_DIR)/$(if $(filter cc,$(1)),bin,lib)/$(1)

# fn translated_src(ToolName) -> PathToOutputCFile
translated_src = $(BUILD_DIR)/$(1).c

# fn recompiled_binary(ToolName) -> PathToOutputBin
recompiled_binary = $(BUILT_BIN)/$(1)

# fn recomple(ToolName, LibcObj) -> MakeRules
define recompile
$(call translated_src,$1): $(call irix_binary,$1) $(RECOMP) | $$$$(@D)/.
	$(RECOMP) $(CONSERVATIVE_$1) $$< > $$@

$(call recompiled_binary,$1): $(call translated_src,$1) $(COMPILE_DEPS) $2 | $$$$(@D)/.
	$$(CC) $2 $$< -o $$@ -I. $(COMPILE_OPT) $(COMPILE_FLAGS)
endef

# fn target_specific(ClangTarget, Artifact) -> Path
target_specific = $(BUILD_DIR)/$1/$2

# fn target_libc(ClangTarget) -> MakeRules
define target_libc
$(call target_specific,$1,$(LIBC_OBJ)): $(LIBC_IMPL) $(LIBC_IMPL:.c=.h) | $$$$(@D)/.
	$$(CC) $$< -c $(LIBC_OPT) $(LIBC_FLAGS) -target $1 -D$(IDO_VERSION) -o $$@
endef
# fn target_tool(ClangTarget, ToolName) -> MakeRules
define target_tool
$(call target_specific,$1,$2): $(call translated_src,$2) $(COMPILE_DEPS) $(call target_specific,$1,$(LIBC_OBJ)) | $$$$(@D)/.
	$$(CC) $(call target_specific,$1,$(LIBC_OBJ)) $$< -o $$@ -I. $(COMPILE_OPT) $(COMPILE_FLAGS) $(if $(findstring x86,$1),-fno-pie) -target $1
endef

# fn recompile_universal(ToolName) -> MakeRules
define recompile_universal
$(call translated_src,$1): $(call irix_binary,$1) $(RECOMP) | $$$$(@D)/.
	$(RECOMP) $(CONSERVATIVE_$1) $$< > $$@

$(foreach target,$(MACOS_FAT_TARGETS),$(eval $(call target_tool,$(target),$1)))

$(call recompiled_binary,$1): $(foreach target,$(MACOS_FAT_TARGETS),$(BUILD_DIR)/$(target)/$1) | $$$$(@D)/.
	lipo -create -output $$@ $$^
endef


# --- Recipes
.DEFAULT_GOAL := all
.PHONY: all clean

.SECONDEXPANSION:

ALL_TOOLS := $(foreach tool,$(IDO_TC),$(call recompiled_binary,$(tool)))

all: $(ALL_TOOLS)

clean:
	$(RM) -rf $(BUILD_BASE)

$(RECOMP): recomp.cpp elf.h | $$(@D)/.
	$(CXX) $< -o $@ $(RECOMP_OPT) $(RECOMP_FLAGS)

$(ERR_STRS_DST): $(ERR_STRS_SRC) | $$(@D)/.
	cp $^ $@

ifeq ($(HOST_TARGET),macOS-universal)

$(foreach target,$(MACOS_FAT_TARGETS),$(eval $(call target_libc,$(target))))
$(foreach tool,$(IDO_TC),$(eval $(call recompile_universal,$(tool))))

else 

LIBC_SHIM := $(BUILD_DIR)/$(LIBC_OBJ)
$(LIBC_SHIM): $(LIBC_IMPL) $(LIBC_IMPL:.c=.h) | $$(@D)/.
	$(CC) $< -c $(LIBC_FLAGS) $(LIBC_OPT) -D$(IDO_VERSION) -o $@

$(foreach tool,$(IDO_TC),$(eval $(call recompile,$(tool),$(LIBC_SHIM))))

endif

# Remove built-in rules, to improve performance
MAKEFLAGS += --no-builtin-rules

# --- Debugging
# run `make print-VARIABLE` to debug that variable
print-% : ; $(info $* is a $(flavor $*) variable set to [$($*)]) @true
