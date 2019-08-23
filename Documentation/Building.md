# Building and installing Libevent
### Jump to:
- [Autoconf](#autoconf)
  - [Flags](#autoconf-flags)
- [Building on Windows](#building-on-windows)
- [Building on Unix (With CMake)](#building-on-unix-cmake)
- [CMake Variables](#cmake-variables)

## Autoconf

```
$ ./configure
$ make
```

**Note: If you had downloaded libevent from the Git repository, then you have to run `./autogen.sh` first!**

You can run the regression tests by running
```
$ make verify
```
*Before reporting any problems, please run the regression tests.*

Install as root via
```
$ make install
```

To enable low-level tracing, build the library as:
```
$ CFLAGS=-DUSE_DEBUG ./configure [...]
```

### Autoconf flags

Standard configure flags should work. In particular, see:
```
 --disable-shared          Only build static libraries.
 --prefix                  Install all files relative to this directory.
```

The configure script also supports the following flags:
```
 --enable-gcc-warnings     Enable extra compiler checking with GCC.
 --disable-malloc-replacement
                           Don't let applications replace our memory
                           management functions.
 --disable-openssl         Disable support for OpenSSL encryption.
 --disable-thread-support  Don't support multithreaded environments.
 --enable-doxygen-doc      Build doxygen documentation
```

## Building on Windows
__Download CMake for Windows [here](https://cmake.org/download/)__
```
> md build && cd build
> cmake -G "Visual Studio 10" ..   # Or use any generator you want to use. Run cmake --help for a list
> cmake --build . --config Release # Or "start libevent.sln" and build with menu in Visual Studio.
```
In the above, the ".." refers to the dir containing the Libevent source code. You can build multiple versions (with different compile time settings) from the same source tree by creating other build directories.

It is highly recommended to build "out of source" when using CMake instead of "in source" like the normal behaviour of autoconf for this reason.

The "NMake Makefiles" CMake generator can be used to build entirely via the command line:
```
> cmake -LH ..
```

## Building on Unix (CMake)
__Install Cmake with your distribution's package manager `apt-get`/`dnf`/etc__
```
$ mkdir build && cd build
$ cmake .. # Default to Unix Makefiles
$ make
$ make verify # Optional
```

## CMake Variables
```
# Type of the library to build (SHARED or STATIC)
# Default is: SHARED for MSVC, otherwise BOTH
EVENT__LIBRARY_TYPE:STRING=DEFAULT

# Installation directory for CMake files
EVENT_INSTALL_CMAKE_DIR:PATH=lib/cmake/libevent

# Enable running gcov to get a test coverage report (only works with
# GCC/CLang). Make sure to enable -DCMAKE_BUILD_TYPE=Debug as well.
EVENT__COVERAGE:BOOL=OFF

# Defines if Libevent should build without the benchmark executables
EVENT__DISABLE_BENCHMARK:BOOL=OFF

# Define if Libevent should build without support for a debug mode
EVENT__DISABLE_DEBUG_MODE:BOOL=OFF

# Define if Libevent should not allow replacing the mm functions
EVENT__DISABLE_MM_REPLACEMENT:BOOL=OFF

# Define if Libevent should build without support for OpenSSL encryption
EVENT__DISABLE_OPENSSL:BOOL=OFF

# Disable the regress tests
EVENT__DISABLE_REGRESS:BOOL=OFF

# Disable sample files
EVENT__DISABLE_SAMPLES:BOOL=OFF

# If tests should be compiled or not
EVENT__DISABLE_TESTS:BOOL=OFF

# Define if Libevent should not be compiled with thread support
EVENT__DISABLE_THREAD_SUPPORT:BOOL=OFF

# Enables verbose debugging
EVENT__ENABLE_VERBOSE_DEBUG:BOOL=OFF

# When cross compiling, forces running a test program that verifies that Kqueue
# works with pipes. Note that this requires you to manually run the test program
# on the the cross compilation target to verify that it works. See CMake
# documentation for try_run for more details
EVENT__FORCE_KQUEUE_CHECK:BOOL=OFF

# Build documentation with doxygen
EVENT__DOXYGEN:BOOL=OFF
```
__More variables can be found by running `cmake -LAH <sourcedir_path>`__

[Back to top &uarr;](#jump-to)
