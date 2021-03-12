# BSD 2-Clause License
# 
# Copyright (c) 2021, Amin Saba
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(xactl VERSION 0.0.1 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -O0")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined -O0")

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

set(LIBXAC_SOURCES xac_lib.c xac_lib.h)

add_library(xac STATIC ${LIBXAC_SOURCES})
add_library(xac_static SHARED ${LIBXAC_SOURCES})

target_compile_definitions(
	${PROJECT_NAME}
	PUBLIC "$<$<CONFIG:DEBUG>:DEBUG>")

target_link_libraries(${PROJECT_NAME} PRIVATE
                        crypto
)

enable_testing()
add_executable(${PROJECT_NAME}_sbtest_p_01
				tests/sbtest_p.cpp
				tests/sbtest_common.h)
target_link_libraries(${PROJECT_NAME}_sbtest_p_01 xac)
add_executable(${PROJECT_NAME}_sbtest_c_01
				tests/sbtest_c.cpp
				tests/sbtest_common.h)
target_link_libraries(${PROJECT_NAME}_sbtest_c_01 xac)
add_test(NAME ${PROJECT_NAME}_sbtest_01
		 COMMAND ${PROJECT_NAME}_sbtest_p_01)
 
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
