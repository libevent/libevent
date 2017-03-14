include(CMakeParseArguments)

set(LIBEVENT_SHARED_LIBRARIES "")
set(LIBEVENT_STATIC_LIBRARIES "")

macro(set_event_lib_properties LIB_NAME)
    set_target_properties("${LIB_NAME}_static" PROPERTIES ${ARGN})
    set_target_properties("${LIB_NAME}_shared" PROPERTIES ${ARGN})
endmacro()

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
# - CMAKE_THREAD_LIBS_INIT LIB_PLATFORM
# - OPENSSL_LIBRARIES
# - HDR_PUBLIC
# - EVENT_INSTALL_INCLUDE_DIR
# - EVENT_SHARED_FLAGS
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

    add_library("${LIB_NAME}_static" STATIC ${LIB_SOURCES})
    add_library("${LIB_NAME}_shared" SHARED ${LIB_SOURCES})

    target_link_libraries("${LIB_NAME}_shared"
        ${CMAKE_THREAD_LIBS_INIT}
        ${LIB_PLATFORM}
        ${LIB_LIBRARIES})

    if (EVENT_SHARED_FLAGS)
        set_event_shared_lib_flags("${LIB_NAME}" "${EVENT_SHARED_FLAGS}")
    endif()

    set_event_lib_properties("${LIB_NAME}"
        OUTPUT_NAME "${LIB_NAME}"
        CLEAN_DIRECT_OUTPUT 1
    )

    set_target_properties(
        "${LIB_NAME}_shared" PROPERTIES
        PUBLIC_HEADER "${HDR_PUBLIC}")
    set_target_properties(
        "${LIB_NAME}_static" PROPERTIES
        PUBLIC_HEADER "${HDR_PUBLIC}")

    set_target_properties(
        "${LIB_NAME}_shared" PROPERTIES
        SOVERSION ${EVENT_ABI_LIBVERSION}
    )

    export(TARGETS "${LIB_NAME}_static" "${LIB_NAME}_shared"
       FILE "${PROJECT_BINARY_DIR}/LibeventTargets.cmake"
       APPEND
    )

    install(TARGETS "${LIB_NAME}_static" "${LIB_NAME}_shared"
        EXPORT LibeventTargets
        LIBRARY DESTINATION "lib" COMPONENT lib
        ARCHIVE DESTINATION "lib" COMPONENT lib
        PUBLIC_HEADER DESTINATION "include/event2"
        COMPONENT dev
    )

    list(APPEND LIBEVENT_SHARED_LIBRARIES "${LIB_NAME}_shared")
    list(APPEND LIBEVENT_STATIC_LIBRARIES "${LIB_NAME}_static")

    generate_pkgconfig("${LIB_NAME}")
endmacro()
