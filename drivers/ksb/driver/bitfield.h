/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2013 Solarflare Communications Inc.
 * Copyright (C) 2022-2023, Advanced Micro Devices, Inc.
 */

#ifndef KSB_BITFIELD_H
#define KSB_BITFIELD_H

#include <linux/bitfield.h>

/* Lowest bit numbers and widths */
#define KSB_DWORD_LBN 0
#define KSB_DWORD_WIDTH 32

/* Specified attribute (e.g. LBN) of the specified field */
#define KSB_VAL(field, attribute) field ## _ ## attribute
/* Low bit number of the specified field */
#define KSB_LOW_BIT(field) KSB_VAL(field, LBN)
/* Bit width of the specified field */
#define KSB_WIDTH(field) KSB_VAL(field, WIDTH)
/* High bit number of the specified field */
#define KSB_HIGH_BIT(field) (KSB_LOW_BIT(field) + KSB_WIDTH(field) - 1)

/* A doubleword (i.e. 4 byte) datatype - little-endian in HW */
struct ksb_dword {
	__le32 ksb_u32;
};

/* A quadword (i.e. 8 byte) datatype - little-endian in HW */
typedef union ksb_qword {
	__le64 u64[1];
	__le32 u32[2];
	struct ksb_dword dword[2];
} ksb_qword_t;

/* An octword (eight-word, i.e. 16 byte) datatype - little-endian in HW */
typedef union ksb_oword {
	__le64 u64[2];
	__le32 u32[4];
} ksb_oword_t;

/* Value expanders for printk */
#define KSB_DWORD_VAL(dword)				\
	((unsigned int)le32_to_cpu((dword).ksb_u32))

/*
 * Extract bit field portion [low,high) from the 32-bit little-endian
 * element which contains bits [min,max)
 */
#define KSB_DWORD_FIELD(dword, field)					\
	(FIELD_GET(GENMASK(KSB_HIGH_BIT(field), KSB_LOW_BIT(field)),	\
		   le32_to_cpu((dword).ksb_u32)))

/*
 * Creates the portion of the named bit field that lies within the
 * range [min,max).
 */
#define KSB_INSERT_FIELD(field, value)				\
	(FIELD_PREP(GENMASK(KSB_HIGH_BIT(field),		\
			    KSB_LOW_BIT(field)), value))

/*
 * Creates the portion of the named bit fields that lie within the
 * range [min,max).
 */
#define KSB_INSERT_FIELDS(field1, value1,		\
			  field2, value2,		\
			  field3, value3,		\
			  field4, value4,		\
			  field5, value5,		\
			  field6, value6,		\
			  field7, value7)		\
	(KSB_INSERT_FIELD(field1, (value1)) |		\
	 KSB_INSERT_FIELD(field2, (value2)) |		\
	 KSB_INSERT_FIELD(field3, (value3)) |		\
	 KSB_INSERT_FIELD(field4, (value4)) |		\
	 KSB_INSERT_FIELD(field5, (value5)) |		\
	 KSB_INSERT_FIELD(field6, (value6)) |		\
	 KSB_INSERT_FIELD(field7, (value7)))

#define KSB_POPULATE_DWORD(dword, ...)					\
	(dword).ksb_u32 = cpu_to_le32(KSB_INSERT_FIELDS(__VA_ARGS__))

/* Populate a dword field with various numbers of arguments */
#define KSB_POPULATE_DWORD_7 KSB_POPULATE_DWORD
#define KSB_POPULATE_DWORD_6(dword, ...) \
	KSB_POPULATE_DWORD_7(dword, KSB_DWORD, 0, __VA_ARGS__)
#define KSB_POPULATE_DWORD_5(dword, ...) \
	KSB_POPULATE_DWORD_6(dword, KSB_DWORD, 0, __VA_ARGS__)
#define KSB_POPULATE_DWORD_4(dword, ...) \
	KSB_POPULATE_DWORD_5(dword, KSB_DWORD, 0, __VA_ARGS__)
#define KSB_POPULATE_DWORD_3(dword, ...) \
	KSB_POPULATE_DWORD_4(dword, KSB_DWORD, 0, __VA_ARGS__)
#define KSB_POPULATE_DWORD_2(dword, ...) \
	KSB_POPULATE_DWORD_3(dword, KSB_DWORD, 0, __VA_ARGS__)
#define KSB_POPULATE_DWORD_1(dword, ...) \
	KSB_POPULATE_DWORD_2(dword, KSB_DWORD, 0, __VA_ARGS__)
#define KSB_SET_DWORD(dword) \
	KSB_POPULATE_DWORD_1(dword, KSB_DWORD, 0xffffffff)

/* Lowest bit numbers and widths */
#define KSB_DUMMY_FIELD_LBN 0
#define KSB_DUMMY_FIELD_WIDTH 0
#define KSB_WORD_0_LBN 0
#define KSB_WORD_0_WIDTH 16
#define KSB_WORD_1_LBN 16
#define KSB_WORD_1_WIDTH 16
#define KSB_DWORD_0_LBN 0
#define KSB_DWORD_0_WIDTH 32
#define KSB_DWORD_1_LBN 32
#define KSB_DWORD_1_WIDTH 32
#define KSB_DWORD_2_LBN 64
#define KSB_DWORD_2_WIDTH 32
#define KSB_DWORD_3_LBN 96
#define KSB_DWORD_3_WIDTH 32
#define KSB_QWORD_0_LBN 0
#define KSB_QWORD_0_WIDTH 64

/* Specified attribute (e.g. LBN) of the specified field */
#define KSB_VAL(field, attribute) field ## _ ## attribute
/* Low bit number of the specified field */
#define KSB_LOW_BIT(field) KSB_VAL(field, LBN)
/* Bit width of the specified field */
#define KSB_WIDTH(field) KSB_VAL(field, WIDTH)
/* High bit number of the specified field */
#define KSB_HIGH_BIT(field) (KSB_LOW_BIT(field) + KSB_WIDTH(field) - 1)
/* Mask equal in width to the specified field.
 *
 * For example, a field with width 5 would have a mask of 0x1f.
 *
 * The maximum width mask that can be generated is 64 bits.
 */
#define KSB_MASK64(width)           \
    ((width) == 64 ? ~((u64) 0) :       \
     (((((u64) 1) << (width))) - 1))

/* Mask equal in width to the specified field.
 *
 * For example, a field with width 5 would have a mask of 0x1f.
 *
 * The maximum width mask that can be generated is 32 bits.  Use
 * KSB_MASK64 for higher width fields.
 */
#define KSB_MASK32(width)           \
    ((width) == 32 ? ~((u32) 0) :       \
     (((((u32) 1) << (width))) - 1))

#define BITFIELD_MASK(_field) \
	((_field ## _WIDTH == 32) ? 0xffffffff : (((1 << _field ## _WIDTH) - 1) << (_field##_LBN)))

#define BITFIELD_GET(_dword, _field) \
	((_dword & BITFIELD_MASK(_field)) >> (_field ## _LBN))
/*
 * Extract bit field portion [low,high) from the native-endian element
 * which contains bits [min,max).
 *
 * For example, suppose "element" represents the high 32 bits of a
 * 64-bit value, and we wish to extract the bits belonging to the bit
 * field occupying bits 28-45 of this 64-bit value.
 *
 * Then KSB_EXTRACT ( element, 32, 63, 28, 45 ) would give
 *
 *   ( element ) << 4
 *
 * The result will contain the relevant bits filled in in the range
 * [0,high-low), with garbage in bits [high-low+1,...).
 */
#define KSB_EXTRACT_NATIVE(native_element, min, max, low, high)     \
    ((low) > (max) || (high) < (min) ? 0 :              \
     (low) > (min) ?                        \
     (native_element) >> ((low) - (min)) :              \
     (native_element) << ((min) - (low)))

/*
 * Extract bit field portion [low,high) from the 64-bit little-endian
 * element which contains bits [min,max)
 */
#define KSB_EXTRACT64(element, min, max, low, high)         \
    KSB_EXTRACT_NATIVE(le64_to_cpu(element), min, max, low, high)

/*
 * Extract bit field portion [low,high) from the 32-bit little-endian
 * element which contains bits [min,max)
 */
#define KSB_EXTRACT32(element, min, max, low, high)         \
    KSB_EXTRACT_NATIVE(le32_to_cpu(element), min, max, low, high)

#define KSB_EXTRACT_OWORD64(oword, low, high)               \
    ((KSB_EXTRACT64((oword).u64[0], 0, 63, low, high) |     \
      KSB_EXTRACT64((oword).u64[1], 64, 127, low, high)) &      \
     KSB_MASK64((high) + 1 - (low)))

#define KSB_EXTRACT_QWORD64(qword, low, high)               \
    (KSB_EXTRACT64((qword).u64[0], 0, 63, low, high) &      \
     KSB_MASK64((high) + 1 - (low)))

#define KSB_EXTRACT_OWORD32(oword, low, high)               \
    ((KSB_EXTRACT32((oword).u32[0], 0, 31, low, high) |     \
      KSB_EXTRACT32((oword).u32[1], 32, 63, low, high) |        \
      KSB_EXTRACT32((oword).u32[2], 64, 95, low, high) |        \
      KSB_EXTRACT32((oword).u32[3], 96, 127, low, high)) &      \
     KSB_MASK32((high) + 1 - (low)))

#define KSB_EXTRACT_QWORD32(qword, low, high)               \
    ((KSB_EXTRACT32((qword).u32[0], 0, 31, low, high) |     \
      KSB_EXTRACT32((qword).u32[1], 32, 63, low, high)) &       \
     KSB_MASK32((high) + 1 - (low)))

#define KSB_EXTRACT_DWORD(dword, low, high)         \
    (KSB_EXTRACT32((dword).u32[0], 0, 31, low, high) &  \
     KSB_MASK32((high) + 1 - (low)))

#define KSB_OWORD_FIELD64(oword, field)             \
    KSB_EXTRACT_OWORD64(oword, KSB_LOW_BIT(field),      \
                KSB_HIGH_BIT(field))

#define KSB_QWORD_FIELD64(qword, field)             \
    KSB_EXTRACT_QWORD64(qword, KSB_LOW_BIT(field),      \
                KSB_HIGH_BIT(field))

#define KSB_OWORD_FIELD32(oword, field)             \
    KSB_EXTRACT_OWORD32(oword, KSB_LOW_BIT(field),      \
                KSB_HIGH_BIT(field))
#define KSB_QWORD_FIELD32(qword, field)             \
    KSB_EXTRACT_QWORD32(qword, KSB_LOW_BIT(field),      \
                KSB_HIGH_BIT(field))
#if 0
#define KSB_DWORD_FIELD(dword, field)               \
    KSB_EXTRACT_DWORD(dword, KSB_LOW_BIT(field),        \
              KSB_HIGH_BIT(field))
#endif
#define KSB_OWORD_IS_ZERO64(oword)                  \
    (((oword).u64[0] | (oword).u64[1]) == (__force __le64) 0)

#define KSB_QWORD_IS_ZERO64(qword)                  \
    (((qword).u64[0]) == (__force __le64) 0)

#define KSB_OWORD_IS_ZERO32(oword)                       \
    (((oword).u32[0] | (oword).u32[1] | (oword).u32[2] | (oword).u32[3]) \
     == (__force __le32) 0)

#define KSB_QWORD_IS_ZERO32(qword)                  \
    (((qword).u32[0] | (qword).u32[1]) == (__force __le32) 0)

#define KSB_DWORD_IS_ZERO(dword)                    \
    (((dword).u32[0]) == (__force __le32) 0)

#define KSB_OWORD_IS_ALL_ONES64(oword)                  \
    (((oword).u64[0] & (oword).u64[1]) == ~((__force __le64) 0))

#define KSB_QWORD_IS_ALL_ONES64(qword)                  \
    ((qword).u64[0] == ~((__force __le64) 0))

#define KSB_OWORD_IS_ALL_ONES32(oword)                  \
    (((oword).u32[0] & (oword).u32[1] & (oword).u32[2] & (oword).u32[3]) \
     == ~((__force __le32) 0))

#define KSB_QWORD_IS_ALL_ONES32(qword)                  \
    (((qword).u32[0] & (qword).u32[1]) == ~((__force __le32) 0))

#define KSB_DWORD_IS_ALL_ONES(dword)                    \
    ((dword).u32[0] == ~((__force __le32) 0))

#if BITS_PER_LONG == 64
#define KSB_OWORD_FIELD     KSB_OWORD_FIELD64
#define KSB_QWORD_FIELD     KSB_QWORD_FIELD64
#define KSB_OWORD_IS_ZERO   KSB_OWORD_IS_ZERO64
#define KSB_QWORD_IS_ZERO   KSB_QWORD_IS_ZERO64
#define KSB_OWORD_IS_ALL_ONES   KSB_OWORD_IS_ALL_ONES64
#define KSB_QWORD_IS_ALL_ONES   KSB_QWORD_IS_ALL_ONES64
#else
#define KSB_OWORD_FIELD     KSB_OWORD_FIELD32
#define KSB_QWORD_FIELD     KSB_QWORD_FIELD32
#define KSB_OWORD_IS_ZERO   KSB_OWORD_IS_ZERO32
#define KSB_QWORD_IS_ZERO   KSB_QWORD_IS_ZERO32
#define KSB_OWORD_IS_ALL_ONES   KSB_OWORD_IS_ALL_ONES32
#define KSB_QWORD_IS_ALL_ONES   KSB_QWORD_IS_ALL_ONES32
#endif

/*
 * Construct bit field portion
 *
 * Creates the portion of the bit field [low,high) that lies within
 * the range [min,max).
 */
#define KSB_INSERT_NATIVE64(min, max, low, high, value)     \
    (((low > max) || (high < min)) ? 0 :            \
     ((low > min) ?                     \
      (((u64) (value)) << (low - min)) :        \
      (((u64) (value)) >> (min - low))))

#define KSB_INSERT_NATIVE32(min, max, low, high, value)     \
    (((low > max) || (high < min)) ? 0 :            \
     ((low > min) ?                     \
      (((u32) (value)) << (low - min)) :        \
      (((u32) (value)) >> (min - low))))

#define KSB_INSERT_NATIVE(min, max, low, high, value)       \
    ((((max - min) >= 32) || ((high - low) >= 32)) ?    \
     KSB_INSERT_NATIVE64(min, max, low, high, value) :  \
     KSB_INSERT_NATIVE32(min, max, low, high, value))

/*
 * Construct bit field portion
 *
 * Creates the portion of the named bit field that lies within the
 * range [min,max).
 */
#define KSB_INSERT_FIELD_NATIVE(min, max, field, value)     \
    KSB_INSERT_NATIVE(min, max, KSB_LOW_BIT(field),     \
              KSB_HIGH_BIT(field), value)

#define KSB_INSERT64(min, max, low, high, value)            \
    cpu_to_le64(KSB_INSERT_NATIVE(min, max, low, high, value))

#define KSB_INSERT32(min, max, low, high, value)            \
    cpu_to_le32(KSB_INSERT_NATIVE(min, max, low, high, value))

#define KSB_INPLACE_MASK64(min, max, low, high)             \
    KSB_INSERT64(min, max, low, high, KSB_MASK64((high) + 1 - (low)))

#define KSB_INPLACE_MASK32(min, max, low, high)             \
    KSB_INSERT32(min, max, low, high, KSB_MASK32((high) + 1 - (low)))

#define KSB_SET_OWORD64(oword, low, high, value) do {           \
    (oword).u64[0] = (((oword).u64[0]               \
               & ~KSB_INPLACE_MASK64(0,  63, low, high))    \
              | KSB_INSERT64(0,  63, low, high, value));    \
    (oword).u64[1] = (((oword).u64[1]               \
               & ~KSB_INPLACE_MASK64(64, 127, low, high))   \
              | KSB_INSERT64(64, 127, low, high, value));   \
    } while (0)

#define KSB_SET_QWORD64(qword, low, high, value) do {           \
    (qword).u64[0] = (((qword).u64[0]               \
               & ~KSB_INPLACE_MASK64(0, 63, low, high)) \
              | KSB_INSERT64(0, 63, low, high, value)); \
    } while (0)

#define KSB_SET_OWORD32(oword, low, high, value) do {           \
    (oword).u32[0] = (((oword).u32[0]               \
               & ~KSB_INPLACE_MASK32(0, 31, low, high)) \
              | KSB_INSERT32(0, 31, low, high, value)); \
    (oword).u32[1] = (((oword).u32[1]               \
               & ~KSB_INPLACE_MASK32(32, 63, low, high))    \
              | KSB_INSERT32(32, 63, low, high, value));    \
    (oword).u32[2] = (((oword).u32[2]               \
               & ~KSB_INPLACE_MASK32(64, 95, low, high))    \
              | KSB_INSERT32(64, 95, low, high, value));    \
    (oword).u32[3] = (((oword).u32[3]               \
               & ~KSB_INPLACE_MASK32(96, 127, low, high))   \
              | KSB_INSERT32(96, 127, low, high, value));   \
    } while (0)
#define KSB_SET_QWORD32(qword, low, high, value) do {           \
    (qword).u32[0] = (((qword).u32[0]               \
               & ~KSB_INPLACE_MASK32(0, 31, low, high)) \
              | KSB_INSERT32(0, 31, low, high, value)); \
    (qword).u32[1] = (((qword).u32[1]               \
               & ~KSB_INPLACE_MASK32(32, 63, low, high))    \
              | KSB_INSERT32(32, 63, low, high, value));    \
    } while (0)

#define KSB_SET_DWORD32(dword, low, high, value) do {           \
    (dword).ksb_u32 = (((dword).ksb_u32             \
               & ~KSB_INPLACE_MASK32(0, 31, low, high)) \
              | KSB_INSERT32(0, 31, low, high, value)); \
    } while (0)

#define KSB_SET_OWORD_FIELD64(oword, field, value)          \
    KSB_SET_OWORD64(oword, KSB_LOW_BIT(field),          \
             KSB_HIGH_BIT(field), value)

#define KSB_SET_QWORD_FIELD64(qword, field, value)          \
    KSB_SET_QWORD64(qword, KSB_LOW_BIT(field),          \
             KSB_HIGH_BIT(field), value)

#define KSB_SET_OWORD_FIELD32(oword, field, value)          \
    KSB_SET_OWORD32(oword, KSB_LOW_BIT(field),          \
             KSB_HIGH_BIT(field), value)

#define KSB_SET_QWORD_FIELD32(qword, field, value)          \
    KSB_SET_QWORD32(qword, KSB_LOW_BIT(field),          \
             KSB_HIGH_BIT(field), value)

#define KSB_SET_DWORD_FIELD(dword, field, value)            \
    KSB_SET_DWORD32(dword, KSB_LOW_BIT(field),          \
             KSB_HIGH_BIT(field), value)

#if BITS_PER_LONG == 64
#define KSB_SET_OWORD_FIELD KSB_SET_OWORD_FIELD64
#define KSB_SET_QWORD_FIELD KSB_SET_QWORD_FIELD64
#else
#define KSB_SET_OWORD_FIELD KSB_SET_OWORD_FIELD32
#define KSB_SET_QWORD_FIELD KSB_SET_QWORD_FIELD32
#endif

#endif /* KSB_BITFIELD_H */
