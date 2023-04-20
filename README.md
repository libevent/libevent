<p align="center">
  <img src="https://libevent.org/libevent3.png" alt="libevent logo"/>
</p>



[![CI](https://github.com/libevent/libevent/actions/workflows/build.yml/badge.svg)](https://github.com/libevent/libevent/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/libevent/libevent/badge.svg)](https://coveralls.io/github/libevent/libevent)
[![Join the chat at https://gitter.im/libevent/libevent](https://badges.gitter.im/libevent/libevent.svg)](https://gitter.im/libevent/libevent?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![doxygen](https://img.shields.io/badge/doxygen-documentation-blue.svg)](https://libevent.org/doc)



# 1. BUILDING AND INSTALLATION

## CMake (Unix)

```sh
mkdir build && cd build
cmake ..     # Default to Unix Makefiles.
make
make verify  # (optional)
```

See [Documentation/Building#Building on Unix using CMake](/Documentation/Building.md#building-on-unix-cmake) for more information.

## CMake (Windows)

Install CMake: <https://cmake.org/>

```sh
md build && cd build
cmake -G "Visual Studio 10" ..   # Or use any generator you want to use. Run cmake --help for a list
cmake --build . --config Release # Or "start libevent.sln" and build with menu in Visual Studio.
```

See [Documentation/Building#Building on Windows](/Documentation/Building.md#building-on-windows) for more information.

## Package Managers

You can download and install libevent using the [vcpkg](https://github.com/Microsoft/vcpkg) dependency manager:
```sh
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
./vcpkg install libevent
```

The libevent port in vcpkg is kept up to date by Microsoft team members and community contributors. If the version is out of date, please [create an issue or pull request](https://github.com/Microsoft/vcpkg) on the vcpkg repository.

## Autoconf

*Note, since 2.2 it is deprecated*

```sh
./configure
make
make verify   # (optional)
sudo make install
```

See [Documentation/Building#Autoconf](/Documentation/Building.md#autotools-deprecated) for more information.

# 2. USEFUL LINKS:

For the latest released version of Libevent, see the official website at
<https://libevent.org/> .

There's a pretty good work-in-progress manual up at
   <http://www.wangafu.net/~nickm/libevent-book/> .

For the latest development versions of Libevent, access our Git repository
via

```sh
$ git clone https://github.com/libevent/libevent.git
```

You can browse the git repository online at:

<https://github.com/libevent/libevent>

To report bugs, issues, or ask for new features:

__Patches__: https://github.com/libevent/libevent/pulls
> OK, those are not really _patches_. You fork, modify, and hit the "Create Pull Request" button.
> You can still submit normal git patches via the mailing list.

__Bugs, Features [RFC], and Issues__: https://github.com/libevent/libevent/issues
> Or you can do it via the mailing list.

There's also a libevent-users mailing list for talking about Libevent
use and development: 

<https://archives.seul.org/libevent/users/>

# 3. ACKNOWLEDGMENTS

The [following people](/CONTRIBUTORS.md) have helped with suggestions, ideas,
code or fixing bugs.
