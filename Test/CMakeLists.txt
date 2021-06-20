include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

include_directories(${ROOT_DIR}/Inc)
include_directories(${CONAN_INCLUDE_DIRS})

add_executable(test_wallet test_wallet.cpp)

target_link_libraries(test_wallet wallet ${CONAN_LIBS_GTEST})