// Authored stub, translated success payload, and unsupported old-physical decoy.
.text
.global _start
_start:
    add x2, x2, #1
    msr sctlr_el1, x0
    isb sy
    mrs x0, sctlr_el1
    ldr x3, [x1]
    add x3, x3, #1
    str x3, [x1]
    stp x2, x3, [x1]
    ldp x3, x2, [x1]
    dsb sy
    tlbi vmalle1
    dsb sy
    isb sy
    ldr x0, [x1]
    hlt #0
    hvc #0
