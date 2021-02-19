#pragma once

#include <sys/malloc.h>

MALLOC_DECLARE(M_XAC);

typedef uint32_t acid_t;
typedef uint32_t itype_t;
typedef uint32_t flag_t;

#define ACID_MAX UINT32_MAX
#define ACID_INVAL ACID_MAX

#define INITIAL_SUBJECTS_CNT 128;
#define INITIAL_OBJECTS_CNT 128;

#define xac_printf(level, fmt, ...)                              \
    do                                                            \
    {                                                             \
        if (level <= current_log_level)                           \
        {                                                         \
            unsigned p_time_now = time_second;                    \
            if (curproc->p_textvp)                                \
                uprintf("%u ms " fmt, p_time_now, ##__VA_ARGS__); \
            else                                                  \
                printf("%u ms " fmt, p_time_now, ##__VA_ARGS__);  \
        }                                                         \
    } while (0)

#define xac_error(msg, ...) \
	xac_printf(0, msg, ##__VA_ARGS__)

extern int current_log_level;
