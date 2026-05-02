cmake_minimum_required(VERSION 3.15)

# 项目名称
project(ManualMapInjector CXX)

# 设置 C++17 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# SRC目录
set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")

# 收集源码文件
set(PROJECT_SOURCES
    ${SRC_DIR}/main.cpp
    ${SRC_DIR}/injector.cpp
    ${SRC_DIR}/injector.h
)

# 生成可执行文件
add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})

# MSVC
if(MSVC)
    # 字符集设置为 Unicode
    target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE _UNICODE)

    # 2. 核心编译器选项
    target_compile_options(${PROJECT_NAME} PRIVATE
        /GS-      # 禁用缓冲区安全检查 (防止 Shellcode 崩溃)
    )

    # 核心链接器选项
    target_link_options(${PROJECT_NAME} PRIVATE
        /INCREMENTAL:NO  # 禁用增量链接
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" # 强制请求管理员权限运行
    )
endif()