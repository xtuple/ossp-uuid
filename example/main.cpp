#include "uuid.h"
#include "uuid_sha1.h"
#include <stdio.h>

int main(int argc, char *argv[])
{
    uuid_t *uuid;
    sha1_t *m;

    // Generate a V4 uuid.
    uuid_create(&uuid);
    uuid_make(uuid, UUID_MAKE_V4);
    uuid_destroy(uuid);

    sha1_create(&m);
    sha1_destroy(m);
    return 0;
}
