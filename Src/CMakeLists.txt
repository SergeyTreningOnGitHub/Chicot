include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

include_directories(${ROOT_DIR}/Inc)
include_directories(${CONAN_INCLUDE_DIRS})

add_library(transaction STATIC transaction.cpp transaction.capnp.cpp)
target_link_libraries(transaction ${CONAN_LIBS_CAPNPROTO})

add_library(wallet STATIC wallet.cpp)
target_link_libraries(wallet ${CONAN_LIBS_OPENSSL})

add_executable(full_node main.cpp utils.cpp)
target_link_libraries(full_node wallet)

install(TARGETS wallet DESTINATION ${ROOT_DIR}/lib)
install(TARGETS transaction DESTINATION ${ROOT_DIR}/lib)
install(TARGETS full_node DESTINATION ${ROOT_DIR}/bin)