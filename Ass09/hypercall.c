#include <asm/kvm_para.h>
#include <asm/alternative.h>
#define KVM_HYPERCALL \
        ALTERNATIVE(".byte 0x0f,0x01,0xc1", ".byte 0x0f,0x01,0xd9", X86_FEATURE_VMMCALL)

int main(int argc, char *argv[]) {
	long ret;
	unsigned int nr = 99;	// my hypercall
	unsigned long p1 = 20; // arbitrary value
//	ret = kvm_hypercall1(nr,p1);
	asm volatile(KVM_HYPERCALL
			: "=a"(ret)
			: "a"(nr), "b"(p1)
			: "memory");
	return ret;
}
