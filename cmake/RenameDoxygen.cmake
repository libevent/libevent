# Add prefix "libevent_" for manual pages

message(STATUS "Rename man pages in ${CMAKE_BINARY_DIR}")

# Remove old pages to avoid stalled copies
file(GLOB LIBEVENT_MAN_PAGES RELATIVE ${CMAKE_BINARY_DIR} libevent_*)
list(LENGTH LIBEVENT_MAN_PAGES LEN)
if (${LEN} GREATER 0)
    file(REMOVE ${LIBEVENT_MAN_PAGES})
endif()

# Create new
file(GLOB LIBEVENT_MAN_PAGES RELATIVE ${CMAKE_BINARY_DIR} *)
list(FILTER LIBEVENT_MAN_PAGES EXCLUDE REGEX ^libevent_.*$)
foreach(MAN_PAGE ${LIBEVENT_MAN_PAGES})
  file(RENAME ${CMAKE_BINARY_DIR}/${MAN_PAGE} ${CMAKE_BINARY_DIR}/libevent_${MAN_PAGE})
endforeach()
