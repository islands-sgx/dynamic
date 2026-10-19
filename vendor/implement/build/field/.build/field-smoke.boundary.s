	.file	"field-smoke.c"
	.section	.text.protected_choice,"ax",@progbits
	.globl	protected_choice                # -- Begin function protected_choice
	.p2align	4
	.type	protected_choice,@function
protected_choice:                       # @protected_choice
	.cfi_startproc
# %bb.0:                                # %atfield.entry.6864127729266408981
	pushq	%rbp
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %rbp, -16
	movl	%edi, %ebp
	movabsq	$6864127729266408981, %rbx      # imm = 0x5F4247CD53D53E15
	#APP
	.globl	__atfield_field_enter_6864127729266408981
	.hidden	__atfield_field_enter_6864127729266408981
__atfield_field_enter_6864127729266408981:

	#NO_APP
	movq	%rbx, %rdi
	callq	field_enter@PLT
	callq	__atfield_marker_6864127729266408981
	#APP
	.globl	__atfield_body_6864127729266408981
	.hidden	__atfield_body_6864127729266408981
__atfield_body_6864127729266408981:

	#NO_APP
	cmpl	$17, %ebp
	jne	.LBB0_2
# %bb.1:
	movl	$20, sink(%rip)
	movl	sink(%rip), %ebp
	jmp	.LBB0_3
.LBB0_2:
	addl	%ebp, %ebp
	movl	%ebp, sink(%rip)
	movl	sink(%rip), %ebp
	incl	%ebp
.LBB0_3:                                # %atfield.normal-close.6864127729266408981
	#APP
	.globl	__atfield_normal_close_6864127729266408981
	.hidden	__atfield_normal_close_6864127729266408981
__atfield_normal_close_6864127729266408981:

	#NO_APP
	#APP
	.globl	__atfield_field_exit_6864127729266408981
	.hidden	__atfield_field_exit_6864127729266408981
__atfield_field_exit_6864127729266408981:

	#NO_APP
	movq	%rbx, %rdi
	callq	field_exit@PLT
	movl	%ebp, %eax
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end0:
	.size	protected_choice, .Lfunc_end0-protected_choice
	.cfi_endproc
                                        # -- End function
	.section	.text.public_wrapper,"ax",@progbits
	.globl	public_wrapper                  # -- Begin function public_wrapper
	.p2align	4
	.type	public_wrapper,@function
public_wrapper:                         # @public_wrapper
	.cfi_startproc
# %bb.0:
	jmp	protected_choice                # TAILCALL
.Lfunc_end1:
	.size	public_wrapper, .Lfunc_end1-public_wrapper
	.cfi_endproc
                                        # -- End function
	.type	sink,@object                    # @sink
	.section	.bss.sink,"aw",@nobits
	.p2align	2, 0x0
sink:
	.long	0                               # 0x0
	.size	sink, 4

	.hidden	__atfield_marker_6864127729266408981
	.ident	"clang version 22.1.8"
	.section	".note.GNU-stack","",@progbits
