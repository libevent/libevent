# Copyright 2017-2019 AVSystem <avsystem@avsystem.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#.rst:
# FindMbedTLS
# -----------
#
# Find the mbedTLS encryption library.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following :prop_tgt:`IMPORTED` targets:
#
# ``mbedtls``
#   The mbedTLS ``mbedtls`` library, if found.
# ``mbedcrypto``
#   The mbedtls ``crypto`` library, if found.
# ``mbedx509``
#   The mbedtls ``x509`` library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``MBEDTLS_FOUND``
#   System has the mbedTLS library.
# ``MBEDTLS_INCLUDE_DIR``
#   The mbedTLS include directory.
# ``MBEDTLS_LIBRARY``
#   The mbedTLS SSL library.
# ``MBEDTLS_CRYPTO_LIBRARY``
#   The mbedTLS crypto library.
# ``MBEDTLS_X509_LIBRARY``
#   The mbedTLS x509 library.
# ``MBEDTLS_LIBRARIES``
#   All mbedTLS libraries.
# ``MBEDTLS_VERSION``
#   This is set to ``$major.$minor.$patch``.
# ``MBEDTLS_VERSION_MAJOR``
#   Set to major mbedTLS version number.
# ``MBEDTLS_VERSION_MINOR``
#   Set to minor mbedTLS version number.
# ``MBEDTLS_VERSION_PATCH``
#   Set to patch mbedTLS version number.
#
# Hints
# ^^^^^
#
# Set ``MBEDTLS_ROOT_DIR`` to the root directory of an mbedTLS installation.
# Set ``MBEDTLS_USE_STATIC_LIBS`` to ``TRUE`` to look for static libraries.

if(MBEDTLS_ROOT_DIR)
    # Disable re-rooting paths in find_path/find_library.
    # This assumes MBEDTLS_ROOT_DIR is an absolute path.
    set(_EXTRA_FIND_ARGS "NO_CMAKE_FIND_ROOT_PATH")
endif()

find_path(MBEDTLS_INCLUDE_DIR
          NAMES mbedtls/ssl.h
          PATH_SUFFIXES include
          HINTS ${MBEDTLS_ROOT_DIR}
          ${_EXTRA_FIND_ARGS})

# based on https://github.com/ARMmbed/mbedtls/issues/298
if(MBEDTLS_INCLUDE_DIR AND EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")
    file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" VERSION_STRING_LINE REGEX "^#define MBEDTLS_VERSION_STRING[ \\t\\n\\r]+\"[^\"]*\"$")
    file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" VERSION_MAJOR_LINE REGEX "^#define MBEDTLS_VERSION_MAJOR[ \\t\\n\\r]+[0-9]+$")
    file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" VERSION_MINOR_LINE REGEX "^#define MBEDTLS_VERSION_MINOR[ \\t\\n\\r]+[0-9]+$")
    file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" VERSION_PATCH_LINE REGEX "^#define MBEDTLS_VERSION_PATCH[ \\t\\n\\r]+[0-9]+$")

    string(REGEX REPLACE "^#define MBEDTLS_VERSION_STRING[ \\t\\n\\r]+\"([^\"]*)\"$" "\\1" MBEDTLS_VERSION "${VERSION_STRING_LINE}")
    string(REGEX REPLACE "^#define MBEDTLS_VERSION_MAJOR[ \\t\\n\\r]+([0-9]+)$" "\\1" MBEDTLS_VERSION_MAJOR "${VERSION_MAJOR_LINE}")
    string(REGEX REPLACE "^#define MBEDTLS_VERSION_MINOR[ \\t\\n\\r]+([0-9]+)$" "\\1" MBEDTLS_VERSION_MINOR "${VERSION_MINOR_LINE}")
    string(REGEX REPLACE "^#define MBEDTLS_VERSION_PATCH[ \\t\\n\\r]+([0-9]+)$" "\\1" MBEDTLS_VERSION_PATCH "${VERSION_PATCH_LINE}")
endif()


if(MBEDTLS_USE_STATIC_LIBS)
    set(_MBEDTLS_LIB_NAME libmbedtls.a)
    set(_MBEDTLS_CRYPTO_LIB_NAME libmbedcrypto.a)
    set(_MBEDTLS_X509_LIB_NAME libmbedx509.a)
else()
    set(_MBEDTLS_LIB_NAME mbedtls)
    set(_MBEDTLS_CRYPTO_LIB_NAME mbedcrypto)
    set(_MBEDTLS_X509_LIB_NAME mbedx509)
endif()

find_library(MBEDTLS_LIBRARY
             NAMES ${_MBEDTLS_LIB_NAME}
             PATH_SUFFIXES lib
             HINTS ${MBEDTLS_ROOT_DIR}
             ${_EXTRA_FIND_ARGS})

find_library(MBEDTLS_CRYPTO_LIBRARY
             NAMES ${_MBEDTLS_CRYPTO_LIB_NAME}
             PATH_SUFFIXES lib
             HINTS ${MBEDTLS_ROOT_DIR}
             ${_EXTRA_FIND_ARGS})

find_library(MBEDTLS_X509_LIBRARY
             NAMES ${_MBEDTLS_X509_LIB_NAME}
             PATH_SUFFIXES lib
             HINTS ${MBEDTLS_ROOT_DIR}
             ${_EXTRA_FIND_ARGS})

set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDTLS_CRYPTO_LIBRARY} ${MBEDTLS_X509_LIBRARY})

if(MBEDTLS_INCLUDE_DIR)
    set(MBEDTLS_FOUND TRUE)
endif()


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
                                  FOUND_VAR MBEDTLS_FOUND
                                  REQUIRED_VARS
                                      MBEDTLS_INCLUDE_DIR
                                      MBEDTLS_LIBRARY
                                      MBEDTLS_CRYPTO_LIBRARY
                                      MBEDTLS_X509_LIBRARY
                                      MBEDTLS_LIBRARIES
                                      MBEDTLS_VERSION
                                  VERSION_VAR MBEDTLS_VERSION)


if(NOT TARGET mbedtls)
    add_library(mbedtls UNKNOWN IMPORTED)
    set_target_properties(mbedtls PROPERTIES
                          INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIR}"
                          IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                          IMPORTED_LOCATION "${MBEDTLS_LIBRARY}")
endif()

if(NOT TARGET mbedcrypto)
    add_library(mbedcrypto UNKNOWN IMPORTED)
    set_target_properties(mbedcrypto PROPERTIES
                          IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                          IMPORTED_LOCATION "${MBEDTLS_CRYPTO_LIBRARY}")
endif()

if(NOT TARGET mbedx509)
    add_library(mbedx509 UNKNOWN IMPORTED)
    set_target_properties(mbedx509 PROPERTIES
                          IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                          IMPORTED_LOCATION "${MBEDTLS_X509_LIBRARY}")
endif()
