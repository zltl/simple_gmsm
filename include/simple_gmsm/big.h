/// @file simple_gmsm/big.h
/// @brief 国密大数运算的别名头文件。
/// @details 本文件提供统一的大数运算接口入口。默认使用高性能 fast_bigint 实现，
/// 定义 USE_SLOW_BIGINT 宏可切换到兼容性更好的 slow_dirty_bigint 实现。
/// @note 本文件本身不包含任何声明，所有大数运算的类型和函数均定义在
/// 对应的实现头文件中。

/// @defgroup big 大数运算
/// @brief 国密算法所需的大数运算模块。
/// @details 本模块提供大数运算的外部接口，实际实现由 @ref bigint 模块提供。
/// @see bigint

#ifdef USE_SLOW_BIGINT
#include "slow_dirty_bigint.h"
#else
#include "fast_bigint.h"
#endif

