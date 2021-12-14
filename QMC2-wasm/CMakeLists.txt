# CMakeList.txt : CMake project for QMC2-wasm, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

set(CMAKE_CXX_STANDARD 14)

include_directories(
	$<TARGET_PROPERTY:QMC2-crypto,INTERFACE_INCLUDE_DIRECTORIES>
)

# Add source to this project's executable.
set(RUNTIME_METHODS_LIST
	getValue
	writeArrayToMemory
	UTF8ToString
)
list(JOIN RUNTIME_METHODS_LIST "," RUNTIME_METHODS)

set(EMSCRIPTEN_FLAGS
	"--bind"
	"-s MODULARIZE=1"
	"-s EXPORT_NAME=QMCCryptoModule"
	"-s EXPORTED_RUNTIME_METHODS=${RUNTIME_METHODS}"
)
set(EMSCRIPTEN_LEGACY_FLAGS
	${EMSCRIPTEN_FLAGS}
	"-s WASM=0"
	"-s ENVIRONMENT=web"
	"--memory-init-file 0"
)

list(JOIN EMSCRIPTEN_FLAGS         " " EMSCRIPTEN_FLAGS_STR)
list(JOIN EMSCRIPTEN_LEGACY_FLAGS " " EMSCRIPTEN_LEGACY_FLAGS_STR)

# Define projects config
set(WASM_SOURCES
	"QMC2-wasm.cpp"
)

link_libraries(QMC2-crypto)


add_executable(QMC2-wasm ${WASM_SOURCES})
set_target_properties(
	QMC2-wasm
	PROPERTIES LINK_FLAGS ${EMSCRIPTEN_FLAGS_STR}
)

add_executable(QMC2-legacy ${WASM_SOURCES})
set_target_properties(
	QMC2-legacy
	PROPERTIES LINK_FLAGS ${EMSCRIPTEN_LEGACY_FLAGS_STR}
)
