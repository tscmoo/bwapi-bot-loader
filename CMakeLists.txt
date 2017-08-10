cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../cmake")

set(CMAKE_SHARED_LIBRARY_PREFIX "")

add_library(bwloader SHARED
	advapi32.cpp
	gdi32.cpp
	modules.cpp
	ws2_32.cpp
	ddraw.cpp
	kernel32.cpp
	native_api.cpp
	user32.cpp
	environment.cpp
	main.cpp
	null_gfx.cpp
	version.cpp
)

set_property(TARGET bwloader PROPERTY POSITION_INDEPENDENT_CODE ON)

if (NOT MSVC)
	set_target_properties(bwloader PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
endif()
