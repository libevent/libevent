include(CheckLinkerFlag)

macro(add_linker_flags)
	foreach(flag ${ARGN})
		string(REGEX REPLACE "[-.+/:= ]" "_" _flag_esc "${flag}")

		check_linker_flag(C "${flag}" check_c_linker_flag_${_flag_esc})

		if (check_c_linker_flag_${_flag_esc})
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${flag}")
			set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${flag}")
		endif()
	endforeach()
endmacro()
