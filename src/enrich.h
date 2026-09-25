/* Public surface of libenrich.
 *
 * The on-disk formats and their lookup helpers are header-only. The
 * builders are the installed commands (thrtutil, thrt_cli, overlay_tool,
 * prev_lookup). enrich_version() is the SONAME anchor mmenrich links.
 *
 * Copyright 2026 Advens.
 * Licensed under the Apache License, Version 2.0. See LICENSE.
 */
#ifndef ENRICH_H
#define ENRICH_H

#include "thrt_format.h"
#include "thrt_logic.h"
#include "thrt_ipparse.h"
#include "thrt_overlay.h"
#include "prev_format.h"

#define ENRICH_VERSION_MAJOR 0
#define ENRICH_VERSION_MINOR 1
#define ENRICH_VERSION_PATCH 0

const char *enrich_version(void);

#endif
