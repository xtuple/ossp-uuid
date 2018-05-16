/*
**  uuid_vers.h -- Version Information for OSSP uuid (syntax: C/C++)
**  [automatically generated and maintained by GNU shtool]
*/

#ifdef _UUID_VERS_H_AS_HEADER_

#ifndef _UUID_VERS_H_
#define _UUID_VERS_H_

#define _UUID_VERSION 0x102200

typedef struct {
    const int   v_hex;
    const char *v_short;
    const char *v_long;
    const char *v_tex;
    const char *v_gnu;
    const char *v_web;
    const char *v_sccs;
    const char *v_rcs;
} _uuid_version_t;

extern _uuid_version_t _uuid_version;

#endif /* _UUID_VERS_H_ */

#else /* _UUID_VERS_H_AS_HEADER_ */

#define _UUID_VERS_H_AS_HEADER_
#include "uuid_vers.h"
#undef  _UUID_VERS_H_AS_HEADER_

_uuid_version_t _uuid_version = {
    0x102200,
    "1.2.0",
    "1.2.0 (23-Jan-2005)",
    "This is OSSP uuid, Version 1.2.0 (23-Jan-2005)",
    "OSSP uuid 1.2.0 (23-Jan-2005)",
    "OSSP uuid/1.2.0",
    "@(#)OSSP uuid 1.2.0 (23-Jan-2005)",
    "$Id: OSSP uuid 1.2.0 (23-Jan-2005) $"
};

#endif /* _UUID_VERS_H_AS_HEADER_ */

