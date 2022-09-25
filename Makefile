# Build options can be changed by modifying the makefile or by building with 'make SETTING=value'.
# It is also possible to override the settings in Defaults in a file called .make_options as 'SETTING=value'.

-include .make_options

#### Defaults ####

# if WERROR is 1, pass -Werror to CC, so warnings would be treated as errors
WERROR ?= 0
#
RELEASE ?= 0

# --- Configuration
# -- select the version and binaries of IDO toolchain to recompile
VERSION ?= 7.1
ifeq ($(VERSION),7.1)
	IDO_VERSION := IDO71
	IDO_TC      := cc as1 cfe ugen umerge uopt
else ifeq ($(VERSION),5.3)
	IDO_VERSION := IDO53
	IDO_TC      := cc acpp as0 as1 cfe copt ugen ujoin uld umerge uopt usplit
else
	$(error Unknown or unsupported IDO version - $(VERSION))
endif



# -- determine the host environment and target
# | Host  | Targets           |
# |-------|-------------------|
# | macOS | native, universal |
# | linux | native            |
# | win   | native            |

UNAME_S := $(shell uname -s)
UNAME_P := $(shell uname -p)
# ifeq ($(UNAME_S),Darwin)
#   HOST_OS := macOS
#   TARGET  ?= native
# else ifeq ($(UNAME_S),Linux)
#   HOST_OS := linux
#   TARGET  := native
# else
#   $(error Unsupported host OS for Makefile)
# endif

MAKE   := make
TARGET ?= native
ifeq ($(OS),Windows_NT)
	DETECTED_OS := windows
else ifeq ($(UNAME_S),Linux)
	DETECTED_OS := linux
else ifeq ($(UNAME_S),Darwin)
	DETECTED_OS := macos
	MAKE := gmake
	CPPFLAGS += -xc++
endif

CC    := gcc
CXX   := g++
STRIP := strip

ifeq ($(RELEASE),0)
	STRIP := @:
endif

CFLAGS       ?= -I.
CSTD         ?= -std=c11
CXXFLAGS     ?=
CXXSTD       ?= -std=c++17
LDFLAGS      ?= -lm
RECOMP_FLAGS ?=


# -- Build Directories
# designed to work with Make 3.81 (macOS/last GPL-2 version)
# https://ismail.badawi.io/blog/automatic-directory-creation-in-make/
BUILD_BASE ?= build
BUILD_DIR  := $(BUILD_BASE)/$(VERSION)
BUILT_BIN  := $(BUILD_DIR)/out

# -- Location of original IDO binaries
IRIX_BASE    ?= ido
IRIX_USR_DIR ?= $(IRIX_BASE)/$(VERSION)/usr

RECOMP_ELF      := $(BUILD_BASE)/recomp.elf
LIBC_IMPL_O     := $(BUILD_DIR)/libc_impl.o

TARGET_BINARIES := $(foreach binary,$(IDO_TC),$(BUILT_BIN)/$(binary))
O_FILES         := $(foreach binary,$(IDO_TC),$(BUILD_DIR)/$(binary).o)
C_FILES         := $(O_FILES:.o=.c)


# create build directories
$(shell mkdir -p $(BUILT_BIN))

# per-file flags
# 5.3 ugen relies on UB stack reads
# to emulate, pass the conservative flag to `recomp`
$(BUILD_BASE)/5.3/ugen.c: RECOMP_FLAGS := --conservative

$(RECOMP_ELF): CXXFLAGS += $(shell pkg-config --cflags capstone)
$(RECOMP_ELF): LDFLAGS  += $(shell pkg-config --libs capstone)


#### Main Targets ###

all: $(TARGET_BINARIES)

setup: $(RECOMP_ELF)

clean:
	$(RM) -r $(BUILD_DIR)

distclean: clean
	$(RM) -r $(BUILD_BASE)


.PHONY: all clean distclean setup
.DEFAULT_GOAL := all
# Prevent removing intermediate files
.SECONDARY:


#### Various Recipes ####

$(BUILD_BASE)/%.elf: %.cpp
	$(CXX) $(CXXSTD) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(LIBC_IMPL_O): libc_impl.c
	$(CC) -c $(CSTD) $(CFLAGS) -o $@ $<

$(BUILT_BIN)/%: $(BUILD_DIR)/%.o $(LIBC_IMPL_O)
	$(CC) $(CSTD) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(BUILD_DIR)/%.c
	$(CC) -c $(CSTD) $(CFLAGS) -o $@ $<
	$(STRIP) $@


$(BUILD_DIR)/%.c: $(IRIX_USR_DIR)/lib/% | $(RECOMP_ELF)
	$(RECOMP_ELF) $(RECOMP_FLAGS) $< > $@

# cc is special and is stored on the `bin` folder instead of the `lib` one
$(BUILD_DIR)/%.c: $(IRIX_USR_DIR)/bin/% | $(RECOMP_ELF)
	$(RECOMP_ELF) $(RECOMP_FLAGS) $< > $@


# Remove built-in rules, to improve performance
MAKEFLAGS += --no-builtin-rules

# --- Debugging
# run `make print-VARIABLE` to debug that variable
print-% : ; $(info $* is a $(flavor $*) variable set to [$($*)]) @true
