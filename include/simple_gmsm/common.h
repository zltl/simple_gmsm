#ifndef SM_COMMON_H_
#define SM_COMMON_H_

/// @file simple_gmsm/common.h
/// @brief Common definitions for simple_gmsm.

/// @def SM_EXPORT
/// @brief Export symbol.

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

#endif  // SM_COMMON_H_
