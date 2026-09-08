.text
add x1,x1,#0
stp x2,x3,[x0]
ldp x2,x3,[x0]
stp x2,x3,[x0,#8]!
stp x2,x3,[x0],#16
ldp x2,x3,[x0,#-16]
hlt #0
