#############################################
#               Build mp20_client              #
#############################################

file(GLOB_RECURSE SRCS_TEST ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_executable(mp20_client.exe ${SRCS_TEST})

#############################################
#            Link our libraries             #
#############################################
target_link_libraries(mp20_client.exe PSI)
