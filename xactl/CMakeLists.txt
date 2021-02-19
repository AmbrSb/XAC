cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(xactl VERSION 0.0.1 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)

set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -O0")
set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -O0")

include_directories(include
                    /usr/src/sys
)

add_executable(${PROJECT_NAME}
                xactl.cpp
                pin.cpp
                terminal.cpp
                xac_parser.cpp
                fs_utils.cpp
                crypto_utils.cpp
                xac_ops.cpp
                args_parser.cpp
)

target_compile_definitions(
	${PROJECT_NAME}
	PUBLIC "$<$<CONFIG:DEBUG>:DEBUG>")

target_link_libraries(${PROJECT_NAME} PRIVATE
                        crypto
)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
