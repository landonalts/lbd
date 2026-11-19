cmake_minimum_required(VERSION 3.20)
project(ldbwatch LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
  message(FATAL_ERROR "MSVC required")
endif()

include(FetchContent)
FetchContent_Declare(minhook
  GIT_REPOSITORY https://github.com/TsudaKageyu/minhook
  GIT_TAG        v1.3.4)
set(MH_BUILD_SHARED OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(minhook)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(BITS 64)
else()
  set(BITS 32)
endif()

add_library(hide SHARED src/hide.cpp)
target_link_libraries(hide PRIVATE minhook psapi)
set_target_properties(hide PROPERTIES
  OUTPUT_NAME "hide${BITS}"
  PREFIX "")

add_executable(inject32 src/inject32.cpp)
target_link_libraries(inject32 PRIVATE)

if(BITS EQUAL 64)
  add_executable(ldbwatch src/ldbwatch.cpp)
  target_link_libraries(ldbwatch PRIVATE user32 dwmapi)
endif()
