
#include "defines.h"
#include "fw_defines.h"
#include "kernel_utils.h"

uint64_t __readmsr(uint32_t __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	uint32_t __edx;
	uint32_t __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

int kpayload_jailbreak(struct thread *td, struct kpayload_jailbreak_args *args) 
{
	struct filedesc *fd;
	struct ucred *cred;
	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;
	
	void *kernel_base = 0;
	uint8_t *kernel_ptr;
	void **got_prison0;
	void **got_rootvnode;
	
	// Kernel base resolving followed by function resolving
	uint64_t fw_version = args->kpayload_jailbreak_info->fw_version;
	switch (fw_version) {
	case 315: 
		kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-KERN_315_XFAST_SYSCALL];
		kernel_ptr    = (uint8_t *)kernel_base;
		got_prison0   = (void **)&kernel_ptr[KERN_315_PRISON_0];
		got_rootvnode = (void **)&kernel_ptr[KERN_315_ROOTVNODE];
		break;
    case 350: 
		kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-KERN_350_XFAST_SYSCALL];
		kernel_ptr    = (uint8_t *)kernel_base;
		got_prison0   = (void **)&kernel_ptr[KERN_350_PRISON_0];
		got_rootvnode = (void **)&kernel_ptr[KERN_350_ROOTVNODE];
		break;
	case 355: 
		kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-KERN_355_XFAST_SYSCALL];
		kernel_ptr    = (uint8_t *)kernel_base;
		got_prison0   = (void **)&kernel_ptr[KERN_355_PRISON_0];
		got_rootvnode = (void **)&kernel_ptr[KERN_355_ROOTVNODE];
		break;
	case 405:
		kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];
		kernel_ptr    = (uint8_t *)kernel_base;
		got_prison0   = (void **)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void **)&kernel_ptr[KERN_405_ROOTVNODE];
		break;
	case 455:
		kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		kernel_ptr    = (uint8_t *)kernel_base;
		got_prison0   = (void **)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void **)&kernel_ptr[KERN_455_ROOTVNODE];
		break;
	case 474:
		kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-KERN_474_XFAST_SYSCALL];
		kernel_ptr    = (uint8_t *)kernel_base;
		got_prison0   = (void **)&kernel_ptr[KERN_474_PRISON_0];
		got_rootvnode = (void **)&kernel_ptr[KERN_474_ROOTVNODE];
		break;
	case 500:
		kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-KERN_500_XFAST_SYSCALL];
		kernel_ptr    = (uint8_t *)kernel_base;
		got_prison0   = (void **)&kernel_ptr[KERN_500_PRISON_0];
		got_rootvnode = (void **)&kernel_ptr[KERN_500_ROOTVNODE];
		break;
	case 501:
		kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-KERN_501_XFAST_SYSCALL];
		kernel_ptr    = (uint8_t *)kernel_base;
		got_prison0   = (void **)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void **)&kernel_ptr[KERN_501_ROOTVNODE];
		break;
	case 505:
		kernel_base   = &((uint8_t *)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		kernel_ptr    = (uint8_t *)kernel_base;
		got_prison0   = (void **)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void **)&kernel_ptr[KERN_505_ROOTVNODE];
		break;
	default:
		return -1;
	}
	
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;
	
	// Escalate ucred privileges, needed for userland access to the file system (e.g mounting & decrypting files)
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType for SceShellcore paid
	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3800000000000010;
	
	// sceSblACMgrHasSceProcessCapability for Max capability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff;
	
	return 0;
}

int get_fw_version() 
{
	uint64_t name = 0x400000001;
	char kstring[128];
	size_t kstring_len = 64;
	sysctl((int *)&name, 2, kstring, &kstring_len, NULL, 0);
	char *split = strtok(kstring, " ");
	int split_len = strlen(split);
	int major = strtol(split + split_len - 6, NULL, 10);
	int minor = strtol(split + split_len - 3, NULL, 10);
	int fw_version = major * 100 + minor / 10;
	return fw_version;
}

int jailbreak(uint64_t fw_version) {
	struct kpayload_jailbreak_info kpayload_jailbreak_info;
	kpayload_jailbreak_info.fw_version = fw_version;
	kexec(&kpayload_jailbreak, &kpayload_jailbreak_info);
	return 0;
}
