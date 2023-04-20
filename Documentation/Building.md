# Building and installing Libevent

### Jump to:

- [Prerequisites](#Prerequisites)
- [Building on Unix using CMake](#building-on-unix-cmake)
- [Autotools (deprecated)](#autotools-deprecated)
  - [Flags](#autotools-flags)
- [Building on Windows](#building-on-windows)
- [CMake Variables](#cmake-variables)

## Prerequisites

### Linux deb-like (ubuntu/debian/...)

Install build tools using your preferred package manager. For CMake:

```sh
sudo apt-get install cmake
```

or using Autotools (deprecated):

```sh
sudo apt-get install automake autoconf libtool pkg-config
```

Doxygen is used for generating documentation.
Git is used to fetch the package version.
Install them if needed:

```sh
sudo apt-get install doxygen git
```

libevent has encryption layer, you need OpenSSL or MbedTLS for it, you can
install one of this using:

```sh
sudo apt-get install libssl-dev libmbedtls-dev
```

To support multithreaded environments, libpthread is a must, and it already exists in the system.

To run the tests, you should install zlib:

```sh
sudo apt-get install zlib1g-dev
```

Finally, a python interpreter should be installed if you want to run regression tests:
```sh
sudo apt-get install python3
```

### MacOS

On MacOS you can use `brew` to manage packages.

The installation process on MacOS is roughly the same as on Linux,
the difference is installation of openssl and zlib:

```sh
brew install openssl zlib
```

### Windows

To install it, there are two choices: installer and zip file.

If using zip file, you should set the PATH variable in the Environment
Variables for your User to include the installation path of cmake.

Install Visual Studio which is the true compiler that will be used.

Install OpenSSL to support for encryption, then add the installation path into the PATH variable in the Environment Variables,
or set OPENSSL_ROOT_DIR in command prompt:

```sh
set "OPENSSL_ROOT_DIR=C:\path\to\OpenSSL"
```

or add `OPENSSL_ROOT_DIR` definition to the cmake command:

```sh
cmake -DOPENSSL_ROOT_DIR=C:/path/to/OpenSSL ...
```

## Building on Unix (CMake)
```sh
mkdir build && cd build
cmake .. # Default to Unix Makefiles
make
make verify # Optional
```

## Autotools (deprecated)

```sh
./configure
make
```

**Note: If you had downloaded libevent from the Git repository, then you have to run `./autogen.sh` first!**

You can run the regression tests by running
```sh
make verify
```
*Before reporting any problems, please run the regression tests.*

Install as root via
```sh
make install
```

To enable low-level tracing, build the library as:
```sh
CFLAGS=-DUSE_DEBUG ./configure [...]
```

### Autotools flags

Standard configure flags should work. In particular, see:
```sh
 --disable-shared          Only build static libraries.
 --prefix                  Install all files relative to this directory.
```

The configure script also supports the following flags:
```sh
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
```sh
md build && cd build
cmake -G "Visual Studio 10" ..   # Or use any generator you want to use. Run cmake --help for a list
cmake --build . --config Release # Or "start libevent.sln" and build with menu in Visual Studio.
```
In the above, the ".." refers to the dir containing the Libevent source code. You can build multiple versions (with different compile time settings) from the same source tree by creating other build directories.

It is highly recommended to build "out of source" when using CMake instead of "in source" like the normal behaviour of autoconf for this reason.

The "NMake Makefiles" CMake generator can be used to build entirely via the command line:
```sh
cmake -LH ..
```

## CMake Variables
General options:
```sh
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
MSVC specific options:
```sh
# Link static runtime libraries.
# Defaults to ON if EVENT_LIBRARY_TYPE is equal to "STATIC", otherwise OFF
EVENT__MSVC_STATIC_RUNTIME:BOOL
```
GNUC specific options:
```sh
# Disable verbose warnings with GCC
EVENT__DISABLE_GCC_WARNINGS:BOOL=OFF

# Enable compiler security checks
EVENT__ENABLE_GCC_HARDENING:BOOL=OFF

# Enable gcc function sections
EVENT__ENABLE_GCC_FUNCTION_SECTIONS:BOOL=OFF

# Make all GCC warnings into errors
EVENT__ENABLE_GCC_WARNINGS:BOOL=OFF
```
__More variables can be found by running `cmake -LAH <sourcedir_path>`__

[Back to top &uarr;](#jump-to)
