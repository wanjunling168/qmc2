# CMakeList.txt : CMake project for QMC2-wasm, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

set(CMAKE_CXX_STANDARD 14)

# Add source to this project's executable.
add_executable (QMC2-wasm
	QMC2-wasm.cpp
)

include_directories(
	$<TARGET_PROPERTY:QMC2-crypto,INTERFACE_INCLUDE_DIRECTORIES>
)

target_link_libraries(QMC2-wasm QMC2-crypto)

set(RUNTIME_METHODS_LIST
	getValue
	writeArrayToMemory
	UTF8ToString
)
list(JOIN RUNTIME_METHODS_LIST "," RUNTIME_METHODS)

set(EMSCRIPTEN_FLAG_LIST
	"--bind"
	"-s MODULARIZE=1"
	"-s EXPORT_NAME=QMCCryptoModule"
	"-s EXPORTED_RUNTIME_METHODS=${RUNTIME_METHODS}"
)
list(JOIN EMSCRIPTEN_FLAG_LIST " " EMSCRIPTEN_FLAGS)

set_target_properties(
	QMC2-wasm
	PROPERTIES LINK_FLAGS "${EMSCRIPTEN_FLAGS}"
)
