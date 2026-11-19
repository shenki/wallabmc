/*
 * SPDX-FileCopyrightText: © 2026 Tenstorrent USA, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * mbedtls heap (CONFIG_MBEDTLS_HEAP_CUSTOM_SECTION) in DTCM.
 *
 * mbedtls_memory_buffer_alloc_init() zeroes the buffer before use.
 */
SECTION_PROLOGUE(.mbedtls_heap, (NOLOAD), ALIGN(4))
{
	*(.mbedtls_heap)
} GROUP_LINK_IN(DTCM)
