include(CheckLinkerFlag)

macro(add_linker_flags)
	foreach(flag ${ARGN})
		string(REGEX REPLACE "[-.+/:= ]" "_" _flag_esc "${flag}")

# Let's make Centos7 users (cmake 3.17) happy
if (NOT CMAKE_VERSION VERSION_LESS 3.18)
		check_linker_flag(C "${flag}" check_c_linker_flag_${_flag_esc})
endif()

		if (check_c_linker_flag_${_flag_esc})
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${flag}")
			set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${flag}")
		endif()
	endforeach()
endmacro()
