// SPDX-License-Identifier: CC0 OR Apache-2.0
#ifndef _PARAMS_PQM4_H_
#define _PARAMS_PQM4_H_

/// Parameter selection for this pqm4 scheme directory.  Everything else is
/// taken from the pqov submodule, so this file does not drift when it moves.
#define _OV16_160_64
#define _OV_CLASSIC
#define KEYS_IN_FLASH

#include "../../../pqov/src/params.h"

/// pqm4 keeps the pqov symbol namespacing switched off: the hand-written
/// Cortex-M4 assembly under m4asm/ calls symbols such as prng_gen_publicinputs
/// by their un-namespaced names.  Each implementation is linked into its own
/// binary here, so there is nothing to disambiguate.
#if (_PUB_N != 160) || (_PUB_M != 64)
#error "pqov selected a different parameter set than this directory expects"
#endif

#undef  PQOV_NAMESPACE
#define PQOV_NAMESPACE(s) s

#endif  // _PARAMS_PQM4_H_
