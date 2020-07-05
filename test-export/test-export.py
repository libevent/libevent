#!/usr/bin/env python3
#
# Check if find_package(Libevent COMPONENTS xxx) can get the correct library.
# Note: this script has only been tested on python3.
# Usage:
#   cd cmake-build-dir
#   cmake <options> .. && cmake --build .
#   python /path/to/test-export.py [static|shared]

import sys
import os
import shutil
import platform
import subprocess
import tempfile

results = ("success", "failure")
FNULL = open(os.devnull, 'wb')
script_dir = os.path.split(os.path.realpath(sys.argv[0]))[0]
# working_dir is cmake build dir
working_dir = os.getcwd()
if len(sys.argv) > 1 and sys.argv[1] == "static":
    link_type = sys.argv[1]
else:
    link_type = "shared"


def exec_cmd(cmd, silent):
    if silent:
        p = subprocess.Popen(cmd, stdout=FNULL, stderr=FNULL, shell=True)
    else:
        p = subprocess.Popen(cmd, shell=True)
    p.communicate()
    return p.poll()


def link_and_run(link, code):
    """Check if the source code matches the library component.

    Compile source code relative to one component and link to another component.
    Then run the generated executor.

    Args:
        link: The name of component that the source code will link with.
        code: The source code related component name.

    Returns:
        Returns 0 if links and runs successfully, otherwise 1.
    """
    exec_cmd("cmake --build . --target clean", True)
    arch = ''
    if platform.system() == "Windows":
        arch = '-A x64'
    cmd = 'cmake .. %s -DEVENT__LINK_COMPONENT=%s -DEVENT__CODE_COMPONENT=%s' % (
        arch, link, code)
    if link_type == "static":
        cmd = "".join([cmd, " -DLIBEVENT_STATIC_LINK=1"])
    r = exec_cmd(cmd, True)
    if r == 0:
        r = exec_cmd('cmake --build .', True)
        if r == 0:
            r = exec_cmd('ctest', True)
    if r != 0:
        r = 1
    return r

# expect  0:success 1:failure
def testcase(link, code, expect):
    r = link_and_run(link, code)
    if link == "":
        link = "all"
    if code == "":
        code = "all"
    if r != expect:
        print('[test-export] fail: link %s and run %s expects %s but gets %s.' %
              (link, code, results[expect], results[r]))
        sys.exit(1)
    else:
        print('[test-export] success: link %s and run %s expects and gets %s.' %
              (link, code, results[r]))

# Dependency relationships between libevent libraries:
#   core:        none
#   extra:       core
#   pthreads:    core,pthread
#   openssl:     core,openssl
def test_group():
    testcase("core", "core", 0)
    testcase("extra", "extra", 0)
    testcase("openssl", "openssl", 0)
    testcase("", "", 0)
    testcase("extra", "core", 0)
    testcase("openssl", "core", 0)
    testcase("core", "extra", 1)
    testcase("core", "openssl", 1)
    testcase("extra", "openssl", 1)
    testcase("openssl", "extra", 1)
    if platform.system() != "Windows":
        testcase("pthreads", "pthreads", 0)
        testcase("pthreads", "core", 0)
        testcase("core", "pthreads", 1)
        testcase("extra", "pthreads", 1)
        testcase("pthreads", "extra", 1)
        testcase("pthreads", "openssl", 1)
        testcase("openssl", "pthreads", 1)


def config_restore():
    if os.path.isfile("tempconfig") and not os.path.isfile("LibeventConfig.cmake"):
        os.rename("tempconfig", "LibeventConfig.cmake")


def config_backup():
    if os.path.isfile("tempconfig"):
        os.remove("tempconfig")
    if os.path.isfile("LibeventConfig.cmake"):
        os.rename("LibeventConfig.cmake", "tempconfig")


shutil.rmtree(os.path.join(script_dir, "build"), ignore_errors=True)


def run_test_group():
    os.chdir(script_dir)
    if not os.path.isdir("build"):
        os.mkdir("build")
    os.chdir("build")
    test_group()
    os.chdir(working_dir)


need_exportdll = False
if link_type == "shared" and platform.system() == "Windows":
    need_exportdll = True

# On Windows, we need to add the directory containing the dll to the
# 'PATH' environment variable so that the program can call it.
def export_dll(dir):
    if need_exportdll:
        os.environ["PATH"] += os.pathsep + dir


def unexport_dll(dir):
    if need_exportdll:
        paths = os.environ["PATH"].split(os.pathsep)
        paths = list(set(paths))
        if dir in paths:
            paths.remove(dir)
        os.environ["PATH"] = os.pathsep.join(paths)


print("[test-export] use %s library" % link_type)

# Test for build tree.
print("[test-export] test for build tree")
dllpath = os.path.join(working_dir, "bin", "Debug")
config_restore()
os.environ["CMAKE_PREFIX_PATH"] = working_dir
export_dll(dllpath)
run_test_group()
del os.environ["CMAKE_PREFIX_PATH"]
unexport_dll(dllpath)

# Install libevent libraries to system path. Remove LibeventConfig.cmake
# from build directory to avoid confusion when using find_package().
print("[test-export] test for install tree(in system-wide path)")
if platform.system() == "Windows":
    prefix = "C:\\Program Files\\libevent"
    dllpath = os.path.join(prefix, "lib")
else:
    prefix = "/usr/local"
exec_cmd('cmake -DCMAKE_INSTALL_PREFIX="%s" ..' % prefix, True)
exec_cmd('cmake --build . --target install', True)
config_backup()
os.environ["CMAKE_PREFIX_PATH"] = os.path.join(prefix, "lib/cmake/libevent")
export_dll(dllpath)
run_test_group()
unexport_dll(dllpath)
del os.environ["CMAKE_PREFIX_PATH"]

# Uninstall the libraries installed in the above steps. Install the libraries
# into a temporary directory. Same as above, remove LibeventConfig.cmake from
# build directory to avoid confusion when using find_package().
print("[test-export] test for install tree(in non-system-wide path)")
exec_cmd("cmake --build . --target uninstall", True)
tempdir = tempfile.TemporaryDirectory()
cmd = 'cmake -DCMAKE_INSTALL_PREFIX="%s" ..' % tempdir.name
exec_cmd(cmd, True)
exec_cmd("cmake --build . --target install", True)
config_backup()
os.environ["CMAKE_PREFIX_PATH"] = os.path.join(tempdir.name, "lib/cmake/libevent")
dllpath = os.path.join(tempdir.name, "lib")
export_dll(dllpath)
run_test_group()
unexport_dll(dllpath)
del os.environ["CMAKE_PREFIX_PATH"]
config_restore()

print("[test-export] all testcases have run successfully")
