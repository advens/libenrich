# libenrich: feed formats and the builders that produce them.
#
#   make           library, pkg-config, enrich, thrtutil
#   make test      ip parse, prevalence, lookup API, enrich build, docs
#   make sanitize  lookup API under ASan+UBSan, then TSan
#   make fuzz      libFuzzer harness for the loaders (FUZZ_CC=clang with libFuzzer)
#   make install   PREFIX (default /usr/local)
#   make clean

PREFIX    ?= /usr/local
DESTDIR   ?=
LIB_MAJOR := 1
LIB_MINOR := 0
LIB_PATCH := 2
SONAME    := libenrich.so.$(LIB_MAJOR)
SOFILE    := libenrich.so.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)

CC        ?= cc
AR        ?= ar
CSTD      := -std=c11
WARN      := -Wall -Wextra -Wpedantic
HARDEN    := -fstack-protector-strong -D_FORTIFY_SOURCE=2
OPT       := -O2
THREADS   := -pthread
JSON_CFLAGS ?= $(shell pkg-config --cflags libfastjson 2>/dev/null)
JSON_LIBS   ?= $(shell pkg-config --libs libfastjson 2>/dev/null)

ARCH := $(shell uname -m)
ifeq ($(ARCH),arm64)
    ARCHFLAGS := -march=armv8-a+crc
else ifeq ($(ARCH),aarch64)
    ARCHFLAGS := -march=armv8-a+crc
else ifeq ($(ARCH),x86_64)
    ARCHFLAGS := -march=x86-64-v2 -msse4.2
else ifeq ($(ARCH),amd64)
    ARCHFLAGS := -march=x86-64-v2 -msse4.2
else
    ARCHFLAGS :=
endif

OS := $(shell uname -s)
ifeq ($(OS),FreeBSD)
    PCDIR := $(PREFIX)/libdata/pkgconfig
    SHLIB := $(SOFILE)
    SHLIB_SONAME := $(SONAME)
    SHLIB_LINK := libenrich.so
else ifeq ($(OS),Darwin)
    PCDIR := $(PREFIX)/lib/pkgconfig
    SHLIB := libenrich.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH).dylib
    SHLIB_SONAME := libenrich.$(LIB_MAJOR).dylib
    SHLIB_LINK := libenrich.dylib
else
    PCDIR := $(PREFIX)/lib/pkgconfig
    CSTD += -D_POSIX_C_SOURCE=200809L
    SHLIB := $(SOFILE)
    SHLIB_SONAME := $(SONAME)
    SHLIB_LINK := libenrich.so
endif

SRCDIR := src
BUILDDIR := build
CFLAGS := $(CSTD) $(WARN) $(HARDEN) $(OPT) $(ARCHFLAGS) -fPIC -I$(SRCDIR)

.PHONY: all test sanitize fuzz install clean

all: $(BUILDDIR)/$(SHLIB) $(BUILDDIR)/libenrich.a $(BUILDDIR)/enrich $(BUILDDIR)/thrtutil enrich.pc

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/enrich_version.o: $(SRCDIR)/enrich_version.c $(LIB_HEADERS) | $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $(SRCDIR)/enrich_version.c

LIB_HEADERS := $(SRCDIR)/enrich.h $(SRCDIR)/thrt_format.h $(SRCDIR)/thrt_logic.h \
               $(SRCDIR)/thrt_ipparse.h $(SRCDIR)/thrt_overlay.h $(SRCDIR)/prev_format.h \
               $(SRCDIR)/thrt_validate.h
LIB_OBJS := $(BUILDDIR)/enrich_version.o $(BUILDDIR)/enrich_lib.o

$(BUILDDIR)/enrich_lib.o: $(SRCDIR)/enrich_lib.c $(LIB_HEADERS) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(THREADS) -O3 -c -o $@ $(SRCDIR)/enrich_lib.c

$(BUILDDIR)/$(SHLIB): $(LIB_OBJS)
ifeq ($(OS),Darwin)
	$(CC) -dynamiclib -install_name $(SHLIB_SONAME) -o $@ $(LIB_OBJS) $(THREADS)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_SONAME)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_LINK)
else
	$(CC) -shared -Wl,-soname,$(SHLIB_SONAME) -o $@ $(LIB_OBJS) $(THREADS)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_SONAME)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_LINK)
endif

$(BUILDDIR)/libenrich.a: $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

enrich.pc: enrich.pc.in
	sed -e 's|@PREFIX@|$(PREFIX)|g' \
	    -e 's|@VERSION@|$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)|g' \
	    enrich.pc.in > enrich.pc

$(BUILDDIR)/thrtutil: $(SRCDIR)/thrtutil.c $(LIB_HEADERS) | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -o $@ $(SRCDIR)/thrtutil.c

$(BUILDDIR)/thrtutil.o: $(SRCDIR)/thrtutil.c $(LIB_HEADERS) | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -Dmain=thrtutil_main -c -o $@ $(SRCDIR)/thrtutil.c

$(BUILDDIR)/thrt_cli.o: $(SRCDIR)/thrt_cli.c $(LIB_HEADERS) | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -Dmain=thrt_cli_main -c -o $@ $(SRCDIR)/thrt_cli.c

$(BUILDDIR)/prev_lookup.o: $(SRCDIR)/prev_lookup.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -Dmain=prev_lookup_main -c -o $@ $(SRCDIR)/prev_lookup.c

$(BUILDDIR)/overlay_tool.o: $(SRCDIR)/overlay_tool.c | $(BUILDDIR)
	@test -n "$(JSON_LIBS)" || { echo "libfastjson is required" >&2; exit 1; }
	$(CC) $(CFLAGS) $(JSON_CFLAGS) -O3 -Dmain=overlay_tool_main -c -o $@ $(SRCDIR)/overlay_tool.c

$(BUILDDIR)/enrich_cmd.o: $(SRCDIR)/enrich_cmd.c | $(BUILDDIR)
	@test -n "$(JSON_LIBS)" || { echo "libfastjson is required" >&2; exit 1; }
	$(CC) $(CFLAGS) $(JSON_CFLAGS) -c -o $@ $(SRCDIR)/enrich_cmd.c

$(BUILDDIR)/enrich: $(BUILDDIR)/enrich_cmd.o $(LIB_OBJS) \
		$(BUILDDIR)/thrtutil.o $(BUILDDIR)/thrt_cli.o \
		$(BUILDDIR)/overlay_tool.o $(BUILDDIR)/prev_lookup.o
	$(CC) -o $@ $(BUILDDIR)/enrich_cmd.o $(LIB_OBJS) \
		$(BUILDDIR)/thrtutil.o $(BUILDDIR)/thrt_cli.o \
		$(BUILDDIR)/overlay_tool.o $(BUILDDIR)/prev_lookup.o $(JSON_LIBS) $(THREADS)

test: $(BUILDDIR)/$(SHLIB) $(BUILDDIR)/enrich $(BUILDDIR)/test_thrt_ipparse $(BUILDDIR)/test_prev \
		$(BUILDDIR)/test_enrich_api
	$(BUILDDIR)/test_thrt_ipparse
	$(BUILDDIR)/test_prev
	rm -rf $(BUILDDIR)/api && mkdir -p $(BUILDDIR)/api
	$(BUILDDIR)/enrich -c testdata/api/enrich.json build >/dev/null
	$(BUILDDIR)/enrich -c testdata/api/second.json build >/dev/null
	$(BUILDDIR)/enrich -c testdata/api/fold.json build >/dev/null
	$(BUILDDIR)/enrich -c testdata/api/fold.json apply-delta \
		--segment testdata/api/withdraw.csv --feed-key pub >/dev/null
	$(BUILDDIR)/test_enrich_api $(BUILDDIR)/api
	rm -rf $(BUILDDIR)/smoke && mkdir -p $(BUILDDIR)/smoke
	$(BUILDDIR)/enrich -c testdata/enrich.json build
	test -s $(BUILDDIR)/smoke/from-cli.thrt
	$(BUILDDIR)/enrich -c testdata/enrich.json lookup 203.0.113.7 >/dev/null
	$(BUILDDIR)/enrich -c testdata/enrich.json lookup 198.51.100.10 >/dev/null
	$(BUILDDIR)/enrich -c testdata/enrich.json lookup 198.51.100.9 >/dev/null
	sh docs/check.sh
	sh docs/check-sync.sh

$(BUILDDIR)/test_thrt_ipparse: $(SRCDIR)/test_thrt_ipparse.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -Werror -o $@ $(SRCDIR)/test_thrt_ipparse.c

$(BUILDDIR)/test_prev: $(SRCDIR)/test_prev.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_prev.c

$(BUILDDIR)/test_enrich_api: $(SRCDIR)/test_enrich_api.c $(SRCDIR)/enrich_lib.c $(SRCDIR)/enrich_version.c \
		$(LIB_HEADERS) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(THREADS) -Werror -o $@ $(SRCDIR)/test_enrich_api.c $(SRCDIR)/enrich_lib.c \
		$(SRCDIR)/enrich_version.c

# libFuzzer harness for the loaders. FUZZ_CC is a clang that ships
# libFuzzer (Apple clang does not). Run, from build/:
#   FUZZ_TARGET=ovly ./fuzz_enrich -max_total_time=60 <corpus dir>
#   FUZZ_TARGET=thrt FUZZ_SEED=api/threat.thrt ./fuzz_enrich -max_len=64 -max_total_time=60 <corpus dir>
FUZZ_CC ?= clang
fuzz: | $(BUILDDIR)
	$(FUZZ_CC) $(CSTD) $(ARCHFLAGS) -I$(SRCDIR) -O1 -g $(THREADS) \
		-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
		-o $(BUILDDIR)/fuzz_enrich $(SRCDIR)/fuzz_enrich.c

# The API test again under AddressSanitizer and UndefinedBehaviorSanitizer,
# then ThreadSanitizer. Needs the fixtures `make test` builds.
SAN_FLAGS := -O1 -g -fno-omit-frame-pointer
sanitize: $(BUILDDIR)/enrich
	rm -rf $(BUILDDIR)/api && mkdir -p $(BUILDDIR)/api
	$(BUILDDIR)/enrich -c testdata/api/enrich.json build >/dev/null
	$(BUILDDIR)/enrich -c testdata/api/second.json build >/dev/null
	$(BUILDDIR)/enrich -c testdata/api/fold.json build >/dev/null
	$(BUILDDIR)/enrich -c testdata/api/fold.json apply-delta \
		--segment testdata/api/withdraw.csv --feed-key pub >/dev/null
	$(CC) $(CSTD) $(WARN) $(ARCHFLAGS) -I$(SRCDIR) $(SAN_FLAGS) -fsanitize=address,undefined \
		-fno-sanitize-recover=all $(THREADS) -o $(BUILDDIR)/test_enrich_api_asan \
		$(SRCDIR)/test_enrich_api.c $(SRCDIR)/enrich_lib.c $(SRCDIR)/enrich_version.c
	$(BUILDDIR)/test_enrich_api_asan $(BUILDDIR)/api
	$(CC) $(CSTD) $(WARN) $(ARCHFLAGS) -I$(SRCDIR) $(SAN_FLAGS) -fsanitize=thread $(THREADS) \
		-o $(BUILDDIR)/test_enrich_api_tsan \
		$(SRCDIR)/test_enrich_api.c $(SRCDIR)/enrich_lib.c $(SRCDIR)/enrich_version.c
	$(BUILDDIR)/test_enrich_api_tsan $(BUILDDIR)/api

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include/enrich \
	         $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PCDIR)
	cp $(BUILDDIR)/$(SHLIB) $(DESTDIR)$(PREFIX)/lib/
	cp $(BUILDDIR)/libenrich.a $(DESTDIR)$(PREFIX)/lib/
	ln -sf $(SHLIB) $(DESTDIR)$(PREFIX)/lib/$(SHLIB_SONAME)
	ln -sf $(SHLIB) $(DESTDIR)$(PREFIX)/lib/$(SHLIB_LINK)
	cp $(SRCDIR)/enrich.h $(SRCDIR)/thrt_format.h $(SRCDIR)/thrt_logic.h \
	   $(SRCDIR)/thrt_ipparse.h $(SRCDIR)/thrt_overlay.h $(SRCDIR)/prev_format.h \
	   $(DESTDIR)$(PREFIX)/include/enrich/
	cp $(BUILDDIR)/enrich $(BUILDDIR)/thrtutil $(DESTDIR)$(PREFIX)/bin/
	cp enrich.pc $(DESTDIR)$(PCDIR)/

clean:
	rm -rf $(BUILDDIR) enrich.pc
