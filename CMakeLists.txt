# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

project ("QMC2")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c18")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a")

# Include sub-projects.
add_subdirectory ("QMC2-crypto")

if (EMSCRIPTEN)
	add_subdirectory ("QMC2-wasm")
else()
	add_subdirectory ("QMC2-decoder")
endif()
