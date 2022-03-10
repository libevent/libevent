# Disable RPATH for install tree by default.
#
# PreLoad is used to change the default, since CMakeLists.txt will already have
# the default, and it will NO.
if (NOT DEFINED CMAKE_SKIP_INSTALL_RPATH)
    set(CMAKE_SKIP_INSTALL_RPATH ON CACHE STRING "" FORCE)
endif()
