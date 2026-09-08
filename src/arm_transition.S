// Independent, non-returning EL1 adapter. QEMU virt test profile only.
// x0 boot_args PA, x1 entry PA, x2 stack-top PA. No memory/stack access.
.text
.balign 16
.global nxc_arm_enter
.global nxc_arm_enter_end
nxc_arm_enter:
    msr daifset, #15
    dsb sy
    // Preflight excludes FEAT_CCIDX, so the architectural CCSIDR legacy
    // fields describe the set/way geometry for each data or unified cache.
    mrs x3, clidr_el1
    ubfx x4, x3, #24, #3
    mov x5, #0
1:
    cmp x5, x4
    b.hs 5f
    add x6, x5, x5, lsl #1
    lsr x6, x3, x6
    and x6, x6, #7
    cmp x6, #2
    b.lo 4f
    lsl x7, x5, #1
    msr csselr_el1, x7
    isb
    mrs x8, ccsidr_el1
    and x9, x8, #7
    add x9, x9, #4
    ubfx x10, x8, #3, #10
    clz w11, w10
    ubfx x12, x8, #13, #15
2:
    mov x13, x10
3:
    lsl x14, x12, x9
    lsl x15, x13, x11
    orr x14, x14, x15
    orr x14, x14, x7
    dc cisw, x14
    subs x13, x13, #1
    b.ge 3b
    subs x12, x12, #1
    b.ge 2b
4:
    add x5, x5, #1
    b 1b
5:
    msr csselr_el1, xzr
    dsb sy
    ic iallu
    dsb sy
    isb
    mov sp, x2
    mrs x3, sctlr_el1
    bic x3, x3, #1
    bic x3, x3, #4
    bic x3, x3, #4096
    msr sctlr_el1, x3
    isb
    tlbi vmalle1
    dsb sy
    isb
    br x1
nxc_arm_enter_end:
