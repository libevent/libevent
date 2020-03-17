# Check if each symbol in the symbol list exists,
# and define PREFIX__HAVE_SYMNAME to 1 if yes.
#

include(CheckSymbolExists)

# SYMLIST: list of symbols to check
# HEADERS: header files to be included in check code
# PREFIX: the prefix of definition
macro(CHECK_SYMBOLS_EXIST SYMLIST HEADERS PREFIX)
  foreach(SYMNAME ${SYMLIST})
    string(TOUPPER "${SYMNAME}" SYMNAME_UPPER)
    if("${PREFIX}" STREQUAL "")
      set(HAVE_SYM_DEF "HAVE_${SYMNAME_UPPER}")
    else()
      set(HAVE_SYM_DEF "${PREFIX}__HAVE_${SYMNAME_UPPER}")
    endif()
    CHECK_SYMBOL_EXISTS(${SYMNAME} "${HEADERS}" ${HAVE_SYM_DEF})
  endforeach()
endmacro()
