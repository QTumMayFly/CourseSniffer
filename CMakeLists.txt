cmake_minimum_required(VERSION 3.21)
project(CourseSniffer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
option(SNIFFER_BUILD_GUI "Build the Qt desktop application" ON)
option(SNIFFER_ENABLE_SANITIZERS "Enable address and undefined behavior checks" OFF)

add_library(sniffer_core STATIC
    src/core/PacketRecord.cpp
    src/core/PacketParser.cpp
    src/core/FilterParser.cpp
    src/core/HttpParser.cpp
    src/core/TcpTracker.cpp
)
target_include_directories(sniffer_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(sniffer_core PRIVATE -Wall -Wextra -Wpedantic)
    if(SNIFFER_ENABLE_SANITIZERS)
        target_compile_options(sniffer_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(sniffer_core PUBLIC -fsanitize=address,undefined)
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(sniffer_core_tests
        tests/core_main.cpp
        tests/test_parser.cpp
        tests/test_filter.cpp
        tests/test_http.cpp
        tests/test_tcp.cpp
    )
    target_link_libraries(sniffer_core_tests PRIVATE sniffer_core)
    add_test(NAME core_protocol_filter_stream COMMAND sniffer_core_tests)
endif()

if(SNIFFER_BUILD_GUI)
    find_package(Qt6 6.2 REQUIRED COMPONENTS Core Widgets Test)
    set(CMAKE_AUTOMOC ON)
    find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h
        HINTS "${CMAKE_OSX_SYSROOT}/usr/include")
    find_library(PCAP_LIBRARY NAMES pcap
        HINTS "${CMAKE_OSX_SYSROOT}/usr/lib")
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR "libpcap headers and library are required. On macOS use the Command Line Tools SDK; on Linux install libpcap-dev.")
    endif()
    file(GLOB CAPTURE_SOURCES CONFIGURE_DEPENDS src/capture/*.cpp src/capture/*.h)
    file(GLOB UI_SOURCES CONFIGURE_DEPENDS src/ui/*.cpp src/ui/*.h)
    add_library(sniffer_desktop STATIC ${CAPTURE_SOURCES} ${UI_SOURCES})
    target_include_directories(sniffer_desktop PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${PCAP_INCLUDE_DIR})
    target_link_libraries(sniffer_desktop PUBLIC sniffer_core Qt6::Core Qt6::Widgets ${PCAP_LIBRARY})
    add_executable(CourseSniffer MACOSX_BUNDLE src/main.cpp)
    target_link_libraries(CourseSniffer PRIVATE sniffer_desktop)
    set_target_properties(CourseSniffer PROPERTIES
        MACOSX_BUNDLE_BUNDLE_NAME "CourseSniffer"
        MACOSX_BUNDLE_GUI_IDENTIFIER "edu.course.sniffer.ex1a"
        MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
        MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION}
    )
    if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gui.cpp")
        add_executable(sniffer_gui_tests tests/test_gui.cpp)
        target_link_libraries(sniffer_gui_tests PRIVATE sniffer_desktop Qt6::Test)
        target_compile_definitions(sniffer_gui_tests PRIVATE SNIFFER_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
        add_test(NAME desktop_interaction COMMAND sniffer_gui_tests)
        set_tests_properties(desktop_interaction PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    endif()
    if(BUILD_TESTING)
        add_test(NAME desktop_startup COMMAND CourseSniffer --smoke-test)
        set_tests_properties(desktop_startup PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 15)
    endif()
endif()
