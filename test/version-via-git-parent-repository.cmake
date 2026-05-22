cmake_minimum_required(VERSION 3.15)

if (NOT DEFINED SOURCE_DIR)
	message(FATAL_ERROR "SOURCE_DIR is required")
endif()

if (NOT DEFINED TEST_ROOT OR TEST_ROOT STREQUAL "" OR TEST_ROOT STREQUAL "/")
	message(FATAL_ERROR "TEST_ROOT is required")
endif()

find_package(Git)
if (NOT GIT_FOUND)
	message(STATUS "Git not found; skipping VersionViaGit parent repository test")
	return()
endif()

function(run_git WORKING_DIRECTORY)
	execute_process(
		COMMAND
			${GIT_EXECUTABLE} ${ARGN}
		WORKING_DIRECTORY
			${WORKING_DIRECTORY}
		RESULT_VARIABLE
			RESULT
		OUTPUT_VARIABLE
			OUTPUT
		ERROR_VARIABLE
			ERROR
	)

	if (NOT RESULT EQUAL 0)
		message(FATAL_ERROR "git ${ARGN} failed: ${OUTPUT}${ERROR}")
	endif()
endfunction()

file(REMOVE_RECURSE "${TEST_ROOT}")
file(MAKE_DIRECTORY "${TEST_ROOT}/parent/libevent-2.5.0/cmake")

file(WRITE "${TEST_ROOT}/parent/parent.txt" "parent repository\n")
run_git("${TEST_ROOT}/parent" init)
run_git("${TEST_ROOT}/parent" add parent.txt)
run_git("${TEST_ROOT}/parent"
	-c user.name=LibeventTest
	-c user.email=libevent-test@example.invalid
	commit -m "create parent repository")
run_git("${TEST_ROOT}/parent"
	-c user.name=LibeventTest
	-c user.email=libevent-test@example.invalid
	tag -a release-9.9.9-stable -m "parent tag")

file(COPY
	"${SOURCE_DIR}/cmake/VersionViaGit.cmake"
	DESTINATION
	"${TEST_ROOT}/parent/libevent-2.5.0/cmake")

file(WRITE "${TEST_ROOT}/parent/libevent-2.5.0/CMakeLists.txt" [=[
cmake_minimum_required(VERSION 3.15)
project(version-via-git-test NONE)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(VersionViaGit)

event_fuzzy_version_from_git()
file(WRITE
	"${PROJECT_BINARY_DIR}/version.txt"
	"${EVENT_GIT___VERSION_MAJOR}.${EVENT_GIT___VERSION_MINOR}.${EVENT_GIT___VERSION_PATCH}-${EVENT_GIT___VERSION_STAGE}\n")
]=])

execute_process(
	COMMAND
		${CMAKE_COMMAND}
		-S "${TEST_ROOT}/parent/libevent-2.5.0"
		-B "${TEST_ROOT}/build"
	RESULT_VARIABLE
		RESULT
	OUTPUT_VARIABLE
		OUTPUT
	ERROR_VARIABLE
		ERROR
)

if (NOT RESULT EQUAL 0)
	message(FATAL_ERROR "nested configure failed: ${OUTPUT}${ERROR}")
endif()

file(READ "${TEST_ROOT}/build/version.txt" VERSION)
string(STRIP "${VERSION}" VERSION)

if (NOT VERSION STREQUAL "2.2.1-alpha-dev")
	message(FATAL_ERROR "expected default version, got ${VERSION}")
endif()
