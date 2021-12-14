# CMakeList.txt : CMake project for QMC2-decoder, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.

include_directories(
	$<TARGET_PROPERTY:QMC2-crypto,INTERFACE_INCLUDE_DIRECTORIES>
)

# We don't want to ship with dlls
if (MINGW)
	set(CMAKE_EXE_LINKER_FLAGS "-s -static-libgcc -static-libstdc++ -static")
endif()

add_executable (QMC2-decoder
	"QMC2-decoder.cpp"
	"QMC2-decoder.h"
)

target_link_libraries(QMC2-decoder QMC2-crypto)
