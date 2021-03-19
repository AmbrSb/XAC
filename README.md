# XAC
# Abstract
- XAC is a FreeBSD MAC framework kernel module
- Performs access control based on
  - __SHA512 hash of executable files__, and
  - __st_dev/i_num of files and directories__
- It can effectively limit processes running as `root`
- Secure configuration hinges on a __secret pin__
- A version of this module is currently being used in production.

# Use Cases
You can define access control (sandboxing) at the level of individual _processes_ and _executables_, and effectively limit each process to the resources it really needs to access. This is mostly useful for defense against privilege escalation attacks, and also in systems that have services/programs that normally run as root.

# Compared to Capsicum
It is usually not trivial to sandbox a program with capsicum, unless the program is intentionally written to operate under capsicum in capability mode. There are methods that use preloading to interpose and manage libc calls to make an unsuspecting program compatible with capsicum, but usually they are not reliable. Notably, you can't efficiently interpose direct system calls that are not routed through libc (e.g. Go executables).

XAC can be used to transparently sandbox an executable without modifying the program or interposing its library calls.

# Effectiveness
Based on the contextual assumption of second-preimage resistance of the employed hash function (SHA512 in this case), we can effectively use the hash of an executable to uniquely identify it. If an executable is modified, it will automatically lose all of its privileges under XAC (and at the same time it will be automatically exempted from limitations imposed on it). So if we are using XAC in a blacklisting manner it is important that we also use a module like Veriexec that prevents execution of unauthorized executables.

However, if XAC is used in a white-listing manner, Veriexec is not required. The administrator can deny all accesses to a resource, except by an executable that has a specified hash.

## Access Control for root Processes

XAC has two properties that make it effective for enforcing access control on processes running as root.

1. XAC policy enforcement does exempt the processes running under root
2. xactl control process requires a pin code to carry out its operations

The second property entails that only an entity that has knowledge of the pin code can tamper with the XAC module operations. The pin is required for changing/reloading the ruleset, disabling the kernel module, etc.

# Internals
TODO
## Architecture
TODO
### Sub-Modules
1. xac_mac
2. xac_config_manager
3. xac_log

### System Calls
XAC defined two sets of system calls. One for management, configuration, and probing of the XAC module itself, and another set of system calls for configuration of a sandboxing environment for a process.

| __Syscall name__ | __Category__ | __Authorized processes__ | __Available in Sandboxing mode?__ |
| ---------------- | ------------ | ------------------------ | --------------------------------- |
| MAC_XAC_SYSCALL_RELOAD | `Management` | xactl | No |
| MAC_XAC_SYSCALL_ENABLE |  `Management` | xactl | No |
| MAC_XAC_SYSCALL_DISABLE |  `Management` | xactl | No |
| MAC_XAC_SYSCALL_STATS |  `Information` | xactl | No |
| MAC_XAC_SYSCALL_LOGLEVEL | `Management` |  xactl | No |
| MAC_XAC_SYSCALL_DUMP |  `Information` | xactl | No |
| MAC_XAC_SYSCALL_VERSION |  `Information` | All | Yes |
| MAC_XAC_SYSCALL_SELFBOX_RULE |  `Sandboxing` | All | No |
| MAC_XAC_SYSCALL_SELFBOX_ENTER |  `Sandboxing` | All | No |

### userspace library

libxac.so serves as a convenient wrapper around XAC kernel module system calls for userspace processes, that want to use its sandboxing capabilities.

# Ruleset File Format
A XAC ruleset consists of a set of subject (`SUB`) rules and object (`OBJ`) rules.

`SUB` rules are defined around subjects and declare which objects they are allowed to access in what mode. In context of XAC, subjects are uniquely identified via the SHA512 hash of their executable files on disk.

Syntax of a `SUB` rule:

```
SUB /path/to/executable
    [!] * | /path/to/object/1 [R][W][X] [LOG]
    [!] * | /path/to/object/2 [R][W][X] [LOG]
    [!] * | /path/to/object/3 [R][W][X] [LOG]
    ...
```

`OBJ` rules are defined around objects and declare which subjects are not/allowed to access them. In context of XAC objects are uniquely identified via their device id and inode number.

Syntax of a `OBJ` rule:

```
OBJ /path/to/object/file
    [!] * | /path/to/suject/1 [R][W][X] [LOG]
    [!] * | /path/to/subject/2 [R][W][X] [LOG]
    [!] * | /path/to/subject/3 [R][W][X] [LOG]
    ...
```

The `!` sign negates the sense of the match. `*` sign can be used to denote `ANY` subject/object. `RWX` tags denote the access modes `READ`, `WRITE`, and `EXECUTE`. Finally, the `LOG` keyword specifies that if this rule is used as the final verdict to allow/disallow an action in XAC, then a log entry should be generated.

The kernel module does not use this textual ruleset directly, but rather this file should first be translated to the binary format used by the kernel. This step also involved translation of subjects paths to their SHA512 hashes, and also translation of object paths to their (device id, inode number) pair. In this process a reverse mapping table from subject/object identities to their paths is created and stored in `ruleset-usr.symtab` which is later used by the logging facility to translate XAC logs to a more usable format.

 This can be done via `xactl` as follows:

```bash
xactl -c /path/to/rules/file
```

Once the rulset is compiled to the binary format usable by the kernel module, which is normally stored in `ruleset-usr.bin`, it can be uploaded to the kernel:

```
xactl -r
```

Also the kernel module will automatically load this binary ruleset at boot time right after the root file system is mounted.

### ptrace / ktrace

Debugging can amount to modification of the executaion of a binary and thus is globally banned under XAC. Because, XAC access control depends on integrity of an executable and its hash digest.


# Logging
Currently XAC access logs are passed through standard kernel logging facility. Eventually, I am going to create a specialized logging interface (i.e. a character device `/dev/xaclog`) for XAC which can be used to filter through XAC logs more efficiently without cluttering system log. Based on `symtab` generated during compilation of the ruleset, these logs can be translated into a format readable by system admin and other programs.

# Profiling Mode (work in progress)

Profiling mode allows us to automatically create a baseline ruleset under which a program can operate normally.

```
xactl -P /path/to/executable [args]
```

# Examples

## Selfboxing

A process can use libxac `xacsb_allow_*()` functions to configure a sandbox on the current process and then make a one-way transition in enforcing mode via `xacsb_enter()`. For example to configure a sandbox that only allows `READ` access to `TARGET_FILE` we can do this:

```c++
#include <sys/vnode.h>
#include "xac_lib.h"

xacsb_allow_path(TARGET_FILE, VREAD);
xacsb_enter();
```

Once sandbox enforcing mode is enabled, the process has no way to leave the sandbox. All processes executed from thereon, via `exec` family of system calls and all children `fork()`ed will also reside in the sandbox.

## Ambient Rulesets

Ambient rulesets are enforced based on hash of executables and dev/inode of object files. These rules are persistent and are automatically enforced when an executable with a matching hash is detected.

An example ruleset:

```bash
OBJ /etc/mac_xac/
    /usr/local/bin/xactl RWX LOG
    ! * RWX

OBJ /etc/mac_xac/pin
    /usr/local/bin/xactl RW LOG
    ! * RWX

OBJ /etc/mac_xac/xac_usr.conf
    /usr/local/bin/xactl RW LOG
    /bin/cat R
    ! * RWX

OBJ /etc/mac_xac/ruleset-usr.bin
    /usr/local/bin/xactl W LOG
    ! * RWX

OBJ /etc/mac_xac/ruleset-usr.symtab
    /usr/local/bin/xactl W LOG
    ! * RWX

OBJ /usr/local/bin/xactl
    /usr/local/bin/xactl RWX
    ! * RW LOG

SUB /usre/local/bin/xxd
    /var/log/binlog RWX
    ! * RWX LOG
```

# Roadmap
- [ ] Add support for __wildcards__ in configuration.
- [ ] Implement an specialized __logging interface__.
- [ ] Implement a permissive __profiling mode__.
- [ ] Add support for identification of objects based on __extended file attributes__.
- [ ] Support __recursive__ directory references in configuration file and selfboxing mode.
- [ ] Come up with a more user friendly format for the ruleset file.




