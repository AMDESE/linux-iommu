// SPDX-License-Identifier: GPL-2.0-only
/*
 * Transitional AMD SDXI QoS KUnit placeholder.
 */

#include <kunit/test.h>
#include <linux/module.h>

static void sdxi_kunit_qos_placeholder(struct kunit *t)
{
}

static struct kunit_case sdxi_qos_cases[] = {
	KUNIT_CASE(sdxi_kunit_qos_placeholder),
	{}
};

static struct kunit_suite sdxi_qos_suite = {
	.name = "SDXI AMD QoS placeholder",
	.test_cases = sdxi_qos_cases,
};
kunit_test_suite(sdxi_qos_suite);

MODULE_LICENSE("GPL");
