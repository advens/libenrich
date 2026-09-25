# libenrich: feed formats and the central builders mmenrich reads.
#
#   make           library, pkg-config, thrtutil, thrt_cli, prev_lookup
#   make test      ip parse, prevalence lookup, one-row .thrt, enrich build
#   make install   PREFIX (default /usr/local)
#   make clean

PREFIX    ?= /usr/local
DESTDIR   ?=
LIB_MAJOR := 0
LIB_MINOR := 1
LIB_PATCH := 0
SONAME    := libenrich.so.$(LIB_MAJOR)
SOFILE    := libenrich.so.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)

CC        ?= cc
AR        ?= ar
CSTD      := -std=c11
WARN      := -Wall -Wextra -Wpedantic
HARDEN    := -fstack-protector-strong -D_FORTIFY_SOURCE=2
OPT       := -O2
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

.PHONY: all test install clean

all: $(BUILDDIR)/$(SHLIB) $(BUILDDIR)/libenrich.a $(BUILDDIR)/enrich $(BUILDDIR)/thrtutil enrich.pc

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/enrich_version.o: $(SRCDIR)/enrich_version.c $(SRCDIR)/enrich.h | $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $(SRCDIR)/enrich_version.c

$(BUILDDIR)/$(SHLIB): $(BUILDDIR)/enrich_version.o
ifeq ($(OS),Darwin)
	$(CC) -dynamiclib -install_name $(SHLIB_SONAME) -o $@ $(BUILDDIR)/enrich_version.o
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_SONAME)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_LINK)
else
	$(CC) -shared -Wl,-soname,$(SHLIB_SONAME) -o $@ $(BUILDDIR)/enrich_version.o
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_SONAME)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_LINK)
endif

$(BUILDDIR)/libenrich.a: $(BUILDDIR)/enrich_version.o
	$(AR) rcs $@ $(BUILDDIR)/enrich_version.o

enrich.pc: enrich.pc.in
	sed -e 's|@PREFIX@|$(PREFIX)|g' \
	    -e 's|@VERSION@|$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)|g' \
	    enrich.pc.in > enrich.pc

$(BUILDDIR)/thrtutil: $(SRCDIR)/thrtutil.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -o $@ $(SRCDIR)/thrtutil.c

$(BUILDDIR)/thrtutil.o: $(SRCDIR)/thrtutil.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -Dmain=thrtutil_main -c -o $@ $(SRCDIR)/thrtutil.c

$(BUILDDIR)/thrt_cli.o: $(SRCDIR)/thrt_cli.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -Dmain=thrt_cli_main -c -o $@ $(SRCDIR)/thrt_cli.c

$(BUILDDIR)/prev_lookup.o: $(SRCDIR)/prev_lookup.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -Dmain=prev_lookup_main -c -o $@ $(SRCDIR)/prev_lookup.c

$(BUILDDIR)/overlay_tool.o: $(SRCDIR)/overlay_tool.c | $(BUILDDIR)
	@test -n "$(JSON_LIBS)" || { echo "libfastjson is required" >&2; exit 1; }
	$(CC) $(CFLAGS) $(JSON_CFLAGS) -O3 -Dmain=overlay_tool_main -c -o $@ $(SRCDIR)/overlay_tool.c

$(BUILDDIR)/enrich_cmd.o: $(SRCDIR)/enrich_cmd.c | $(BUILDDIR)
	@test -n "$(JSON_LIBS)" || { echo "libfastjson is required" >&2; exit 1; }
	$(CC) $(CFLAGS) $(JSON_CFLAGS) -c -o $@ $(SRCDIR)/enrich_cmd.c

$(BUILDDIR)/enrich: $(BUILDDIR)/enrich_cmd.o $(BUILDDIR)/enrich_version.o \
		$(BUILDDIR)/thrtutil.o $(BUILDDIR)/thrt_cli.o \
		$(BUILDDIR)/overlay_tool.o $(BUILDDIR)/prev_lookup.o
	$(CC) -o $@ $(BUILDDIR)/enrich_cmd.o $(BUILDDIR)/enrich_version.o \
		$(BUILDDIR)/thrtutil.o $(BUILDDIR)/thrt_cli.o \
		$(BUILDDIR)/overlay_tool.o $(BUILDDIR)/prev_lookup.o $(JSON_LIBS)

test: $(BUILDDIR)/$(SHLIB) $(BUILDDIR)/enrich $(BUILDDIR)/test_thrt_ipparse $(BUILDDIR)/test_prev
	$(BUILDDIR)/test_thrt_ipparse
	$(BUILDDIR)/test_prev
	rm -rf $(BUILDDIR)/smoke && mkdir -p $(BUILDDIR)/smoke
	$(BUILDDIR)/enrich -c testdata/enrich.json build
	test -s $(BUILDDIR)/smoke/from-cli.thrt
	$(BUILDDIR)/enrich -c testdata/enrich.json lookup 203.0.113.7 >/dev/null
	$(BUILDDIR)/enrich -c testdata/enrich.json lookup 198.51.100.10 >/dev/null
	$(BUILDDIR)/enrich -c testdata/enrich.json lookup 198.51.100.9 >/dev/null
	sh docs/check.sh

$(BUILDDIR)/test_thrt_ipparse: $(SRCDIR)/test_thrt_ipparse.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -Werror -o $@ $(SRCDIR)/test_thrt_ipparse.c

$(BUILDDIR)/test_prev: $(SRCDIR)/test_prev.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_prev.c

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
