.globl bad_coroutine_switch
bad_coroutine_switch:
    // Store callee-save registers
	stp x19, x20, [x0, #0]
	stp x21, x22, [x0, #0x10]
	stp x23, x24, [x0, #0x20]
	stp x25, x26, [x0, #0x30]
	stp x27, x29, [x0, #0x40]
	
	// Store sp at 0x50
	mov x2, sp
	str x2, [x0, #0x50]
	// Store lr at 0x58
	str lr, [x0, #0x58]

	// load callee-save registers of new coroutine
	ldp x19, x20, [x0, #0]
	ldp x21, x22, [x0, #0x10]
	ldp x23, x24, [x0, #0x20]
	ldp x25, x26, [x0, #0x30]
	ldp x27, x29, [x0, #0x40]

	// load new sp
	ldr x2, [x1, #0x50]
	mov sp, x2

	// load x0 for kicks from 0x60
	ldr x0, [x1, #0x60]
	
	// load new pc (ie, lr) from 0x58
	ldr x1, [x1, #0x58]
	br x1