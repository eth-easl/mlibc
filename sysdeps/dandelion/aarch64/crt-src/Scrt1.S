.section .text
.global _start
_start:
	mov x0, sp
	adr x1, main
	adr x2, __mlibc_entry
	blr x2
	brk #0

.section .note.GNU-stack,"",%progbits

