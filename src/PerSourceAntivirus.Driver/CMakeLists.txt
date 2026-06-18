# CMakeLists.txt — PerSourceAntivirus Kernel Minifilter Driver
#
# Build instructions:
#   cmake -DCMAKE_MODULE_PATH=<FindWDK_path> -G "Visual Studio 17 2022" -A x64 . ^
#     && cmake --build . --config Release -- /p:Platform=x64
#
# Prerequisites:
#   - Windows Driver Kit (WDK) matching your installed Windows SDK version.
#   - FindWDK helper (https://github.com/SergiusTheBest/FindWDK) placed at
#     <FindWDK_path> so that CMake can locate FindWDK.cmake.
#   - Visual Studio 2022 with "Desktop development with C++" and the
#     "Windows Driver Kit" VS extension installed.
#
# The produced binary is PSAVDriver.sys.  Sign it with a valid EV code-
# signing certificate before deploying to a machine with Secure Boot / HVCI.

cmake_minimum_required(VERSION 3.25)

project(PSAVDriver
    VERSION     1.0.0.0
    DESCRIPTION "PerSourceAntivirus Kernel Minifilter Driver"
    LANGUAGES   C
)

# ---------------------------------------------------------------------------
# Locate the WDK via FindWDK
# ---------------------------------------------------------------------------
find_package(WDK REQUIRED)

# ---------------------------------------------------------------------------
# Driver target
# ---------------------------------------------------------------------------
wdk_add_driver(PSAVDriver
    PerSourceAntivirus.Driver.c
)

# ---------------------------------------------------------------------------
# Link against Filter Manager import library
# wdk_add_driver already links wdmkmdf / wdm; we add fltMgr explicitly.
# FindWDK exposes the wdkminifilter interface target for convenience.
# ---------------------------------------------------------------------------
target_link_libraries(PSAVDriver
    PRIVATE
        wdkminifilter   # convenience target from FindWDK (pulls fltMgr.lib)
        fltMgr          # explicit Filter Manager import lib — belt-and-suspenders
)

# ---------------------------------------------------------------------------
# Compiler options
# ---------------------------------------------------------------------------
target_compile_options(PSAVDriver
    PRIVATE
        /GS-        # disable buffer-security checks (kernel stack layout)
        /W4         # warning level 4
        /WX         # treat warnings as errors
        /Gy         # function-level linking
        /Zp1        # struct packing: 1-byte align (matches pack(1) in source)
        /kernel     # enable kernel-mode code generation
)

# Suppress /GS- linker warning (expected for kernel drivers)
set_property(TARGET PSAVDriver
    APPEND_STRING PROPERTY LINK_FLAGS " /ignore:4210"
)

# ---------------------------------------------------------------------------
# Install rules (copies .sys + .inf to CMAKE_INSTALL_PREFIX\driver)
# ---------------------------------------------------------------------------
install(TARGETS PSAVDriver
    RUNTIME DESTINATION driver
)
install(FILES PerSourceAntivirus.Driver.inf
    DESTINATION driver
)
