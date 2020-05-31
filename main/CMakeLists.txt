idf_component_register(SRCS in3_main.c in3_http.c
                    INCLUDE_DIRS "in3-core" 
                    INCLUDE_DIRS ".")


ADD_DEFINITIONS(-DTEST)
ADD_DEFINITIONS(-DETH_FULL)
ADD_DEFINITIONS(-DEVM_GAS)
ADD_DEFINITIONS(-DESP_IDF)
ADD_DEFINITIONS(-DERR_MSG)
OPTION(ESP_IDF "Esp-idf framework" ON)
ADD_DEFINITIONS(-DIN3_MATH_LITE)
add_subdirectory(in3-core/c/src/signer/pk-signer)
add_subdirectory(in3-core/c/src/third-party/tommath)
add_subdirectory(in3-core/c/src/third-party/crypto)
add_subdirectory(in3-core/c/src/core)
add_subdirectory(in3-core/c/src/verifier/eth1/basic)
add_subdirectory(in3-core/c/src/verifier/eth1/nano)
add_subdirectory(in3-core/c/src/verifier/eth1/full)
add_subdirectory(in3-core/c/src/verifier/eth1/evm)
add_subdirectory(in3-core/c/src/api/eth1)
add_subdirectory(in3-core/c/src/api/utils)

set(IN3_LIBS 
        $<TARGET_OBJECTS:pk_signer_o>
        $<TARGET_OBJECTS:core_o>
        $<TARGET_OBJECTS:init_o>
        $<TARGET_OBJECTS:crypto_o> 
        $<TARGET_OBJECTS:tommath_o> 
        $<TARGET_OBJECTS:eth_api_o> 
        $<TARGET_OBJECTS:eth_basic_o> 
        $<TARGET_OBJECTS:eth_nano_o>
        $<TARGET_OBJECTS:eth_full_o>
        $<TARGET_OBJECTS:evm_o>
        $<TARGET_OBJECTS:api_utils_o>
)
 
#set(CMAKE_C_FLAGS "-Og -mlongcalls")
add_library(in3_bundle STATIC ${IN3_LIBS})
target_link_libraries(${COMPONENT_LIB} PUBLIC in3_bundle)
target_include_directories(${COMPONENT_LIB} PUBLIC in3-core/c/include)
