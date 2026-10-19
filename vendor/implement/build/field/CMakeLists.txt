cmake_minimum_required(VERSION 3.20)
project(atfield_field LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(LLVM 22.1.8 CONFIG REQUIRED)
separate_arguments(ATFIELD_LLVM_DEFINITIONS NATIVE_COMMAND "${LLVM_DEFINITIONS}")

add_library(atfield-field-transform STATIC
  annotation_adapter.cpp
  boundary_transform.cpp
  boundary_assembly_transform.cpp
  include/atfield/analyze/annotation_adapter.h
  include/atfield/boundary_transform.h
  include/atfield/boundary_assembly_transform.h)
target_include_directories(atfield-field-transform
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${LLVM_INCLUDE_DIRS}")
target_compile_options(atfield-field-transform PRIVATE ${ATFIELD_LLVM_DEFINITIONS})
target_link_libraries(atfield-field-transform PUBLIC LLVM)

add_executable(atfield-field field_main.cpp)
target_include_directories(atfield-field PRIVATE "${LLVM_INCLUDE_DIRS}")
target_link_libraries(atfield-field PRIVATE atfield-field-transform LLVM)
install(TARGETS atfield-field RUNTIME DESTINATION bin)
