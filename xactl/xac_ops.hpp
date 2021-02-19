#pragma once

class xac_ops_error: public std::exception {
public:
    xac_ops_error(std::string w)
        : w{w}
    { }

    char const *what() const noexcept {
        return w.c_str();
    }

private:
    std::string w;
};


extern void xac_enable();
extern void xac_disable();
extern void xac_reload();
extern void xac_stats();
extern void xac_loglevel(std::string lvl);
extern void xac_dump_ruleset();
