.section .text
.global _start
_start:
	mov %rsp, %rdi
	lea main(%rip), %rsi
	lea __mlibc_entry(%rip), %rax
	call *%rax
.section .note.GNU-stack,"",%progbits

