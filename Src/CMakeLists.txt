include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

include_directories(${ROOT_DIR}/Inc)
include_directories(${CONAN_INCLUDE_DIRS})

add_library(utils STATIC utils.cpp)

add_library(wallet STATIC wallet.cpp)
target_link_libraries(wallet ${CONAN_LIBS_OPENSSL})

add_executable(full_node main.cpp)
target_link_libraries(full_node wallet utils)

install(TARGETS wallet DESTINATION ${ROOT_DIR}/lib)
install(TARGETS utils DESTINATION ${ROOT_DIR}/lib)
install(TARGETS full_node DESTINATION ${ROOT_DIR}/bin)