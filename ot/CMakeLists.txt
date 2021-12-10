cmake_minimum_required(VERSION 3.10)
message("===>>PROJECT_SOURCE_DIR:" ${PROJECT_SOURCE_DIR})
project( DEMO_TEST VERSION 1.1 LANGUAGES CXX)
# message("===>>KKRT:" ${KKRT})
set(CMAKE_CXX_STANDARD 11)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
# set(CMAKE_EXE_LINKER_FLAGS"${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")

# add_definitions("-O2 -msse3 -msse2 -msse4.1 -g -maes -DENABLE_MIRACL -DOMP_POOL")
add_definitions("-O3 -DNDEBUG -O2 -g -O0 -ffunction-sections -Wall -Wfatal-errors -maes -msse2 -msse3 -msse4.1 -mpclmul -pthread -DNO_INTEL_ASM_SHA1=1")
add_definitions(" -DNP99_TEST")
# add_definitions(" -DIKNP_TEST")
# add_definitions(" -DKKRT_TEST")


#-L,链接库目录
link_directories(${PROJECT_SOURCE_DIR}/../mPSI/thirdparty/linux/boost/stage/lib)
link_directories(${PROJECT_SOURCE_DIR}/../mPSI/thirdparty/linux/miracl/miracl/source)
# link_directories(${PROJECT_SOURCE_DIR}/../thirdparty/linux/miracl/miracl/source)
#头文件
include_directories(${PROJECT_SOURCE_DIR}/../mPSI)
include_directories(${PROJECT_SOURCE_DIR}/../mPSI/cryptoTools)
include_directories(${PROJECT_SOURCE_DIR}/../mPSI/thirdparty/linux/boost/includes)
include_directories(${PROJECT_SOURCE_DIR}/../mPSI/libOTe)
include_directories(${PROJECT_SOURCE_DIR}/../mPSI/thirdparty/linux/miracl/)
include_directories(${PROJECT_SOURCE_DIR})
#源文件
file(GLOB NETWORK_CPP ${PROJECT_SOURCE_DIR}/../mPSI/cryptoTools/Network/*.cpp)
file(GLOB CRYPTO_CPP ${PROJECT_SOURCE_DIR}/../mPSI/cryptoTools/Crypto/*.cpp)
file(GLOB COMMON_CPP ${PROJECT_SOURCE_DIR}/../mPSI/cryptoTools/Common/*.cpp)
# file(GLOB TWO_ONE_CPP ${PROJECT_SOURCE_DIR}/../libOTe/TwoChooseOne/*.cpp)
# file(GLOB N_ONE_CPP ${PROJECT_SOURCE_DIR}/../libOTe/NChooseOne/*.cpp)
# file(GLOB BASE_OT_CPP ${PROJECT_SOURCE_DIR}/../libOTe/Base/*.cpp)
file(GLOB TOOLS_OT_CPP ${PROJECT_SOURCE_DIR}/../mPSI/libOTe/Tools/*.cpp)
file(GLOB MAIN_CPP ${PROJECT_SOURCE_DIR}/*.cpp)
message("===>>MAIN_CPP:" ${MAIN_CPP})
message("===>>TOOLS_OT_CPP:" ${TOOLS_OT_CPP})

# add_library(hidetrance SHARED
#     ${MAIN_CPP}
#     ${COMMON_SRC_FILE}
#     # ${MIRACL_SRC_FILE}
#     ${BLAKE_SRC_FILE}
#     ${CRYPTO_SRC_FILE}
#     ${OT_SRC_FILE}
# )
#可执行文件
add_executable(demo
    ${NETWORK_CPP}
    ${CRYPTO_CPP}
    ${COMMON_CPP}    
    ${TOOLS_OT_CPP}
    ${MAIN_CPP}
)
# add_executable(demo
#     ${NETWORK_CPP}
#     ${CRYPTO_CPP}
#     ${COMMON_CPP}
#     ${TWO_ONE_CPP}
#     ${N_ONE_CPP}
#     ${BASE_OT_CPP}
#     ${TOOLS_OT_CPP}
#     ${MAIN_CPP}
# )
#-l,动态库链接
# target_link_libraries(demo libmiracl.a boost_system pthread)
target_link_libraries(demo libmiracl.a boost_system pthread)