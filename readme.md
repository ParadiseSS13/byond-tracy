# Para-byond-tracy

Para-byond-tracy glues together a byond server the tracy profiler allowing you to analyze and visualize proc calls. This differs from the standard byond-tracy by the nature of it writing to flatfiles inside `data/profiler/`. While these files can be up to 30 gigabytes in size, they allow the RAM usage of DreamDaemon to remain very low at runtime, which is useful for profiling entire rounds (A profile from a full round needs >48GB of RAM just to view, let alone save at runtime).

Note that the files generated cannot be loaded straight into tracy. You must use `replay.py` to load the `.utracy` file and stream "it over the network" (localhost) into `capture.exe` as part of Tracy. You can stream straight into `Tracy.exe`, but this is not advised due to performance overhead.

The above script requires the `lz4` library with the stream addon. The instructions for that are out of scope of this guide.

Update 2023-12-29: You can now use [https://github.com/AffectedArc07/ParaTracyReplay](https://github.com/AffectedArc07/ParaTracyReplay) to stream the files much faster than the python script.

Update 2024-04-18: You can now use [https://github.com/Dimach/rtracy](https://github.com/Dimach/rtracy) to stream the files even faster than the C# code, as well as split traces and other cool things.

A massive thanks to `mafemergency` for even making this possible. The below readme is adapted from the original repo (branch: `stream-to-file`) [https://github.com/mafemergency/byond-tracy/](https://github.com/mafemergency/byond-tracy/)

## supported byond versions

| windows  | linux    |
| -------- | -------- |
| 516.1675 | 516.1675 |
| 516.1674 | 516.1674 |
| 516.1673 | 516.1673 |
| 516.1672 | 516.1672 |
| 516.1671 | 516.1671 |
| 516.1670 | 516.1670 |
| 516.1669 | 516.1669 |
| 516.1668 | 516.1668 |
| 516.1667 | 516.1667 |
| 516.1666 | 516.1666 |
| 516.1665 | 516.1665 |
| 516.1663 | 516.1664 |
| 516.1664 | 516.1663 |
| 516.1662 | 516.1662 |
| 516.1661 | 516.1661 |
| 516.1660 | 516.1660 |
| 516.1659 | 516.1659 |
| 516.1658 | 516.1658 |
| 516.1657 | 516.1657 |
| 516.1656 | 516.1656 |
| 516.1655 | 516.1655 |
| 516.1654 | N/A      |
| 516.1653 | 516.1653 |
| 516.1652 | 516.1652 |
| 516.1651 | 516.1651 |
| 516.1650 | 516.1650 |
| 516.1649 | 516.1649 |
| 516.1648 | 516.1648 |
| 515.*    | 515.*    |
| 514.*    | 514.*    |

## supported tracy versions

None built in, you need to reply these.

## usage

simply call `init` from `prof.dll` to begin writing to a file inside `data/profiler`

init will return the filename it writes to upon success - the filename will always start with `.`

```dm
// returns a string filename whenever
/proc/prof_init()
    var/lib

    switch(world.system_type)
        if(MS_WINDOWS) lib = "prof.dll"
        if(UNIX) lib = "libprof.so"
        else CRASH("unsupported platform")

    var/init = call_ext(lib, "init")()
    if(length(init) != 0 && init[1] == ".") // if first character is ., then it returned the output filename
        return init
    else if("0" != init)
        CRASH("[lib] init error: [init]")

/world/New()
    var/utracy_filename = prof_init()
    . = ..()
```

## building

no build system included, simply invoke your preferred c11 compiler.
examples:

(AA recommended: If you have the MSVC++ buildchain, open `x86 Native Tools Command Prompt for VS 2022` and then cd to this repo. `cl` should be on your path inside of that CLI environment)
(Absolucy recommended: just use clang on windows, tbh)

```console
cl.exe /nologo /std:c11 /O2 /LD /DNDEBUG prof.c ws2_32.lib /Fe:prof.dll /experimental:c11atomics
```

```console
clang.exe -std=c11 -m32 -shared -Ofast3 -DNDEBUG -fuse-ld=lld-link prof.c -lws2_32 -o prof.dll
```

```console
gcc -D_FILE_OFFSET_BITS=64 -std=c11 -m32 -shared -fPIC -Ofast -s -DNDEBUG prof.c -pthread -o libprof.so
```

## remarks

byond-tracy is in its infancy and is not production ready for live servers.
