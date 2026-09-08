// Independently assembled authored single-root wire fixture: value offset84.
.text
.global _start
_start:
    add x3, x3, #0
    ldr w2, [x0, #0]
    str w2, [x1, #0]
    ldr w2, [x0, #4]
    str w2, [x1, #4]
    ldr w2, [x0, #84]
    str w2, [x1, #8]
    ldr w2, [x0, #88]
    str w2, [x1, #12]
    ldr w2, [x0, #92]
    str w2, [x1, #16]
    ldr w2, [x0, #96]
    str w2, [x1, #20]
    movz w2, #0xabcd
    str w2, [x1, #24]
    hlt #0
