#ifndef QLGMSM_SM_ENDIAN_H_
#define QLGMSM_SM_ENDIAN_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GETU32
#define GETU32(n, b, i)                             \
    {                                               \
        (n) = ((unsigned long)(b)[(i)] << 24) |     \
              ((unsigned long)(b)[(i) + 1] << 16) | \
              ((unsigned long)(b)[(i) + 2] << 8) |  \
              ((unsigned long)(b)[(i) + 3]);        \
    }
#endif
#ifndef PUTU32
#define PUTU32(n, b, i)                            \
    {                                              \
        (b)[(i)] = (unsigned char)((n) >> 24);     \
        (b)[(i) + 1] = (unsigned char)((n) >> 16); \
        (b)[(i) + 2] = (unsigned char)((n) >> 8);  \
        (b)[(i) + 3] = (unsigned char)((n));       \
    }
#endif

#ifdef __cplusplus
}
#endif

#endif /* QLGMSM_SM_ENDIAN_H_ */