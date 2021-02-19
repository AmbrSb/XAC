#pragma once

#define xac_log(level, fmt, ...)                             \
    do                                                        \
    {                                                         \
        if (level <= current_log_level)                       \
        {                                                     \
            unsigned p_time_now = time_second;                \
            printf("%u ms " fmt, p_time_now, ##__VA_ARGS__);  \
        }                                                     \
    } while (0)

#define XAC_PATH_PREFIX "/etc/mac_xac"
#define XAC_CONF_PATH (XAC_PATH_PREFIX "/ruleset-usr.bin")
#define XAC_SYMTAB_PATH (XAC_PATH_PREFIX "/ruleset-usr.symtab")
