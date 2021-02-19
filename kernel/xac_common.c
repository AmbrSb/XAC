#include <sys/types.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kernel.h>

#include "xac_common.h"

MALLOC_DEFINE(M_XAC, "mac_xac", "MAC access authentication data");

int current_log_level = 3;
