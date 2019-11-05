include(CMakeParseArguments)

set(LIBEVENT_SHARED_LIBRARIES "")
set(LIBEVENT_STATIC_LIBRARIES "")

macro(set_event_shared_lib_flags LIB_NAME)
    set_target_properties("${LIB_NAME}_shared" PROPERTIES
        COMPILE_FLAGS ${ARGN})
    set_target_properties("${LIB_NAME}_shared" PROPERTIES
        LINK_FLAGS ${ARGN})
endmacro()

macro(generate_pkgconfig LIB_NAME)
    set(prefix      ${CMAKE_INSTALL_PREFIX})
    set(exec_prefix ${CMAKE_INSTALL_PREFIX})
    set(libdir      ${CMAKE_INSTALL_PREFIX}/lib)
    set(includedir  ${CMAKE_INSTALL_PREFIX}/include)

    set(VERSION ${EVENT_ABI_LIBVERSION})

    set(LIBS         "")
    foreach (LIB ${LIB_PLATFORM})
        set(LIBS "${LIBS} -L${LIB}")
    endforeach()

    set(OPENSSL_LIBS "")
    foreach(LIB ${OPENSSL_LIBRARIES})
        set(OPENSSL_LIBS "${OPENSSL_LIBS} -L${LIB}")
    endforeach()

    configure_file("lib${LIB_NAME}.pc.in" "lib${LIB_NAME}.pc" @ONLY)
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/lib${LIB_NAME}.pc"
        DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig"
    )
endmacro()


# Global variables that it uses:
# - EVENT_ABI_LIBVERSION
# - EVENT_ABI_LIBVERSION_CURRENT
# - EVENT_ABI_LIBVERSION_REVISION
# - EVENT_ABI_LIBVERSION_AGE
# - EVENT_PACKAGE_RELEASE
# - CMAKE_THREAD_LIBS_INIT LIB_PLATFORM
# - OPENSSL_LIBRARIES
# - EVENT_SHARED_FLAGS
# - EVENT_LIBRARY_STATIC
# - EVENT_LIBRARY_SHARED
#
# Exported variables:
# - LIBEVENT_SHARED_LIBRARIES
# - LIBEVENT_STATIC_LIBRARIES
macro(add_event_library LIB_NAME)
    cmake_parse_arguments(LIB
        "" # Options
        "VERSION" # One val
        "SOURCES;LIBRARIES" # Multi val
        ${ARGN}
    )

    set(ADD_EVENT_LIBRARY_TARGETS)
    set(ADD_EVENT_LIBRARY_INTERFACE)

    if (${EVENT_LIBRARY_STATIC})
        add_library("${LIB_NAME}_static" STATIC ${LIB_SOURCES})
        set_target_properties("${LIB_NAME}_static" PROPERTIES
            OUTPUT_NAME "${LIB_NAME}"
            CLEAN_DIRECT_OUTPUT 1)

        list(APPEND LIBEVENT_STATIC_LIBRARIES "${LIB_NAME}_static")
        list(APPEND ADD_EVENT_LIBRARY_TARGETS "${LIB_NAME}_static")

        set(ADD_EVENT_LIBRARY_INTERFACE "${LIB_NAME}_static")
    endif()

    if (${EVENT_LIBRARY_SHARED})
        add_library("${LIB_NAME}_shared" SHARED ${LIB_SOURCES})

        target_link_libraries("${LIB_NAME}_shared"
            ${CMAKE_THREAD_LIBS_INIT}
            ${LIB_PLATFORM}
            ${LIB_LIBRARIES})

        if (EVENT_SHARED_FLAGS)
            set_event_shared_lib_flags("${LIB_NAME}" "${EVENT_SHARED_FLAGS}")
        endif()

        if (WIN32)
            set_target_properties(
                "${LIB_NAME}_shared" PROPERTIES
                OUTPUT_NAME "${LIB_NAME}"
                SOVERSION ${EVENT_ABI_LIBVERSION})
        elseif (APPLE)
            math(EXPR COMPATIBILITY_VERSION "${EVENT_ABI_LIBVERSION_CURRENT}+1")
            math(EXPR CURRENT_MINUS_AGE "${EVENT_ABI_LIBVERSION_CURRENT}-${EVENT_ABI_LIBVERSION_AGE}")
            set_target_properties(
                "${LIB_NAME}_shared" PROPERTIES
                OUTPUT_NAME "${LIB_NAME}-${EVENT_PACKAGE_RELEASE}.${CURRENT_MINUS_AGE}"
                INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib"
                LINK_FLAGS "-compatibility_version ${COMPATIBILITY_VERSION} -current_version ${COMPATIBILITY_VERSION}.${EVENT_ABI_LIBVERSION_REVISION}")
        else()
            math(EXPR CURRENT_MINUS_AGE "${EVENT_ABI_LIBVERSION_CURRENT}-${EVENT_ABI_LIBVERSION_AGE}")
            set_target_properties(
                "${LIB_NAME}_shared" PROPERTIES
                OUTPUT_NAME "${LIB_NAME}-${EVENT_PACKAGE_RELEASE}"
                VERSION "${CURRENT_MINUS_AGE}.${EVENT_ABI_LIBVERSION_AGE}.${EVENT_ABI_LIBVERSION_REVISION}"
                SOVERSION "${CURRENT_MINUS_AGE}")
        endif()

        if (NOT WIN32)
            set(LIB_LINK_NAME
                "${CMAKE_SHARED_LIBRARY_PREFIX}${LIB_NAME}${CMAKE_SHARED_LIBRARY_SUFFIX}")

            add_custom_command(TARGET ${LIB_NAME}_shared
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E create_symlink
                    "$<TARGET_FILE_NAME:${LIB_NAME}_shared>"
                    "${LIB_LINK_NAME}"
                WORKING_DIRECTORY "lib")
        endif()

        list(APPEND LIBEVENT_SHARED_LIBRARIES "${LIB_NAME}_shared")
        list(APPEND ADD_EVENT_LIBRARY_TARGETS "${LIB_NAME}_shared")

        set(ADD_EVENT_LIBRARY_INTERFACE "${LIB_NAME}_shared")
    endif()

    export(TARGETS ${ADD_EVENT_LIBRARY_TARGETS}
       FILE "${PROJECT_BINARY_DIR}/LibeventTargets.cmake"
       APPEND
    )

    install(TARGETS ${ADD_EVENT_LIBRARY_TARGETS}
        EXPORT LibeventTargets
        LIBRARY DESTINATION "lib" COMPONENT lib
        ARCHIVE DESTINATION "lib" COMPONENT lib
        RUNTIME DESTINATION "lib" COMPONENT lib
        COMPONENT dev
    )
    if (NOT WIN32 AND ${EVENT_LIBRARY_SHARED})
        install(FILES
            "$<TARGET_FILE_DIR:${LIB_NAME}_shared>/${LIB_LINK_NAME}"
            DESTINATION "lib"
            COMPONENT lib)
    endif()

    add_library(${LIB_NAME} INTERFACE)
    target_link_libraries(${LIB_NAME} INTERFACE ${ADD_EVENT_LIBRARY_INTERFACE})

    generate_pkgconfig("${LIB_NAME}")
endmacro()

## Register installed package with CMake
#
# This function adds an entry to the CMake registry for packages with the
# path of the directory where the package configuration file of the installed
# package is located in order to help CMake find the package in a custom
# installation prefix. This differs from CMake's export(PACKAGE) command
# which registers the build directory instead.
function(register_package CONFIG_DIR)
    if (NOT IS_ABSOLUTE "${CONFIG_DIR}")
        set (CONFIG_DIR "${CMAKE_INSTALL_PREFIX}/${CONFIG_DIR}")
    endif()
    string (MD5 REGISTRY_ENTRY "${CONFIG_DIR}")
    if (WIN32)
        install(CODE
            "execute_process(
                COMMAND reg add \"HKCU\\\\Software\\\\Kitware\\\\CMake\\\\Packages\\\\${PROJECT_NAME}\" /v \"${REGISTRY_ENTRY}\" /d \"${CONFIG_DIR}\" /t REG_SZ /f
                RESULT_VARIABLE RT
                ERROR_VARIABLE  ERR
                OUTPUT_QUIET
            )
            if (NOT RT EQUAL 0)
                string (STRIP \"\${ERR}\" ERR)
                message (STATUS \"Register:   Failed to add registry entry: \${ERR}\")
            endif ()"
        )
    elseif (IS_DIRECTORY "$ENV{HOME}")
        file(WRITE "${PROJECT_BINARY_DIR}/${PROJECT_NAME}-registry-entry" "${CONFIG_DIR}")
        install(
            FILES       "${PROJECT_BINARY_DIR}/${PROJECT_NAME}-registry-entry"
            DESTINATION "$ENV{HOME}/.cmake/packages/${PROJECT_NAME}"
            RENAME      "${REGISTRY_ENTRY}"
        )
    endif()
endfunction()
