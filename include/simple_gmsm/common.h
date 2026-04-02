#ifndef SM_COMMON_H_
#define SM_COMMON_H_

/// @file simple_gmsm/common.h
/// @brief simple_gmsm 库的公共定义。
/// @details 本文件包含 simple_gmsm 库的通用宏定义，主要用于控制符号导出行为，
/// 以支持静态库和动态库两种编译模式。

/// @defgroup common 公共定义
/// @brief simple_gmsm 库的公共宏定义与通用配置。
/// @{

/// @def SM_EXPORT
/// @brief 符号导出宏，用于控制库的符号可见性。
/// @details 根据编译模式自动选择正确的符号导出/导入属性：
/// - 静态库编译时，SM_EXPORT 为空定义。
/// - 动态库编译时，在 Windows 上使用 __declspec，在其他平台使用 GCC visibility 属性。
/// @note 使用方式：
/// - 定义 @c SM_SHARED_LIBRARY 表示以动态库方式编译或链接。
/// - 在编译库本身时同时定义 @c SM_COMPILE_LIBRARY，此时符号将被导出（dllexport）。
/// - 在使用库的应用程序中不定义 @c SM_COMPILE_LIBRARY，此时符号将被导入（dllimport）。
/// - 如果未定义 @c SM_SHARED_LIBRARY，则 SM_EXPORT 为空，适用于静态库场景。
/// @ingroup common

#if !defined(SM_EXPORT)
#if defined(SM_SHARED_LIBRARY)
#if defined(_WIN32)
// Compile DLL with __declspec(dllexport)
// Compile executable program with __declspec(dllimport)
#if defined(SM_COMPILE_LIBRARY)
#define SM_EXPORT __declspec(dllexport)
#else
#define SM_EXPORT __declspec(dllimport)
#endif
#else
#define SM_EXPORT __attribute__((visibility("default")))
#endif

#else
#define SM_EXPORT
#endif
#endif

/// @}

#endif  // SM_COMMON_H_
