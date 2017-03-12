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

# Global variables that it uses:
# - EVENT_ABI_LIBVERSION
# - CMAKE_THREAD_LIBS_INIT LIB_PLATFORM
# - HDR_PUBLIC
# - EVENT_INSTALL_BIN_DIR
# - EVENT_INSTALL_LIB_DIR
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
    )

    install(TARGETS "${LIB_NAME}_static" "${LIB_NAME}_shared"
        EXPORT LibeventTargets
        RUNTIME DESTINATION "${EVENT_INSTALL_BIN_DIR}" COMPONENT bin
        LIBRARY DESTINATION "${EVENT_INSTALL_LIB_DIR}" COMPONENT lib
        ARCHIVE DESTINATION "${EVENT_INSTALL_LIB_DIR}" COMPONENT lib
        PUBLIC_HEADER DESTINATION "${EVENT_INSTALL_INCLUDE_DIR}/event2"
        COMPONENT dev
    )

    list(APPEND LIBEVENT_SHARED_LIBRARIES "${LIB_NAME}_shared")
    list(APPEND LIBEVENT_STATIC_LIBRARIES "${LIB_NAME}_static")
endmacro()
