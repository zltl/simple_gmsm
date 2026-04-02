/// @file simple_gmsm/big.h
/// @brief 国密大数运算的别名头文件。
/// @details 本文件是 slow_dirty_bigint.h 的别名头文件，提供统一的大数运算接口入口。
/// 使用者可以直接包含本文件来获取大数运算的所有功能。
/// @note 本文件本身不包含任何声明，所有大数运算的类型和函数均定义在
/// slow_dirty_bigint.h 中。本文件仅作为便捷的包含入口。
/// @see slow_dirty_bigint.h

/// @defgroup big 大数运算
/// @brief 国密算法所需的大数运算模块。
/// @details 本模块提供大数运算的外部接口，实际实现由 @ref bigint 模块提供。
/// @see bigint

#include "slow_dirty_bigint.h"

