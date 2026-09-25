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

.PHONY: all test tools install clean overlay

all: $(BUILDDIR)/$(SHLIB) $(BUILDDIR)/libenrich.a enrich.pc tools

tools: $(BUILDDIR)/thrtutil $(BUILDDIR)/thrt_cli $(BUILDDIR)/prev_lookup

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

$(BUILDDIR)/thrt_cli: $(SRCDIR)/thrt_cli.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -o $@ $(SRCDIR)/thrt_cli.c

$(BUILDDIR)/prev_lookup: $(SRCDIR)/prev_lookup.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -O3 -o $@ $(SRCDIR)/prev_lookup.c

overlay: $(BUILDDIR)/overlay_tool

$(BUILDDIR)/overlay_tool: $(SRCDIR)/overlay_tool.c | $(BUILDDIR)
	@test -n "$(JSON_LIBS)" || { echo "libfastjson not found; overlay_tool skipped" >&2; exit 1; }
	$(CC) $(CFLAGS) $(JSON_CFLAGS) -O3 -o $@ $(SRCDIR)/overlay_tool.c $(JSON_LIBS)

test: $(BUILDDIR)/$(SHLIB) tools $(BUILDDIR)/test_thrt_ipparse $(BUILDDIR)/test_prev
	$(BUILDDIR)/test_thrt_ipparse
	$(BUILDDIR)/test_prev
	rm -rf $(BUILDDIR)/smoke && mkdir -p $(BUILDDIR)/smoke
	$(BUILDDIR)/thrtutil -o $(BUILDDIR)/smoke/threat.thrt testdata/one.csv
	test -s $(BUILDDIR)/smoke/threat.thrt
	ENRICH_THRTUTIL=$(BUILDDIR)/thrtutil python3 cli/enrich build -c testdata/enrich.json
	test -s $(BUILDDIR)/smoke/from-cli.thrt
	$(BUILDDIR)/thrt_cli $(BUILDDIR)/smoke/from-cli.thrt 203.0.113.7 >/dev/null

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
	cp $(BUILDDIR)/thrtutil $(BUILDDIR)/thrt_cli $(BUILDDIR)/prev_lookup \
	   $(DESTDIR)$(PREFIX)/bin/
	cp cli/enrich $(DESTDIR)$(PREFIX)/bin/enrich
	chmod 755 $(DESTDIR)$(PREFIX)/bin/enrich
	cp enrich.pc $(DESTDIR)$(PCDIR)/

clean:
	rm -rf $(BUILDDIR) enrich.pc
