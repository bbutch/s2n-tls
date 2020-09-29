/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "s2n_pq.h"

#if defined(S2N_CPUID_AVAILABLE)
/* https://en.wikipedia.org/wiki/CPUID */
#include <cpuid.h>

/* For older versions of GCC (notably 4.8), <cpuid.h> doesn't
 * include the __get_cupid_count() function that we need, but
 * it does include all the components necessary to define our
 * own. This is just a wrapper around __cpuid_count to ensure
 * the cpuid instruction supports the requested leaf. */
bool s2n_get_cpuid_count(uint32_t leaf, uint32_t sub_leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    /* 0x80000000 probes for extended cpuid info */
    uint32_t max_level = __get_cpuid_max(leaf & 0x80000000, 0);

    if (max_level == 0 || max_level < leaf) {
        return false;
    }

    __cpuid_count(leaf, sub_leaf, *eax, *ebx, *ecx, *edx);
    return true;
}
#endif

static bool sikep434r2_asm_enabled = false;

/* https://en.wikipedia.org/wiki/Bit_manipulation_instruction_set#BMI2_(Bit_Manipulation_Instruction_Set_2) */
bool s2n_cpu_supports_bmi2() {
#if defined(S2N_CPUID_AVAILABLE)
    uint32_t eax, ebx, ecx, edx;
    if (!s2n_get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    if (ebx & bit_BMI2) {
        return true;
    }
#endif

    return false;
}

/* https://en.wikipedia.org/wiki/Intel_ADX */
bool s2n_cpu_supports_adx() {
#if defined(S2N_CPUID_AVAILABLE)
    uint32_t eax, ebx, ecx, edx;
    if (!s2n_get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return false;
    }

    if (ebx & bit_ADX) {
        return true;
    }
#endif

    return false;
}

bool s2n_cpu_supports_sikep434r2_asm() {
#if defined(S2N_SIKEP434R2_ASM)
    /* The sikep434r2 assembly code always requires BMI2. If ADX support
     * was detected at compile time, the code would have been compiled
     * with ADX support turned on, so we must check ADX at runtime. */
    #if defined(S2N_ADX)
        return s2n_cpu_supports_bmi2() && s2n_cpu_supports_adx();
    #else
        return s2n_cpu_supports_bmi2();
    #endif
#else
    /* sikep434r2 assembly was not supported at compile time */
    return false;
#endif
}

bool s2n_is_sikep434r2_asm_enabled() {
    return sikep434r2_asm_enabled;
}

S2N_RESULT s2n_disable_sikep434r2_asm() {
    sikep434r2_asm_enabled = false;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_try_enable_sikep434r2_asm() {
    if (s2n_cpu_supports_sikep434r2_asm()) {
        sikep434r2_asm_enabled = true;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_pq_init() {
    ENSURE_OK(s2n_try_enable_sikep434r2_asm(), S2N_ERR_SAFETY);

    return S2N_RESULT_OK;
}
