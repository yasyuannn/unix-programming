#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <libgen.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <capstone/capstone.h>

typedef unsigned long long ULL;

typedef struct {
	bool is_used;
	ULL addr;
	ULL orig_data;
} bp_t;

typedef struct {
	csh cshandle;
	char prog_path[128];
	pid_t pid;
	bp_t bp[10];
} sdb_t;

sdb_t* sdb_init() {
	sdb_t* sdb = (sdb_t*)malloc(sizeof(sdb_t));

	cs_open(CS_ARCH_X86, CS_MODE_64, &(sdb->cshandle));
	sdb->prog_path[0] = 0;
	sdb->pid = -1;
	for(int i = 0; i < 10; i++)
		sdb->bp[i].is_used = false;
	return sdb;
}

bool sdb_is_loaded(sdb_t* sdb) {
	// If path is NULL, not loaded.
	return (!strcmp(sdb->prog_path, "")) ? false : true;
}

bool sdb_is_running(sdb_t* sdb) {
	// If pid is -1, not running.
	return (sdb->pid == -1) ? false : true;
}

void sdb_load(sdb_t* sdb, char* prog_name) {
	ULL buff[128];
    FILE* fp = fopen(prog_name, "rb");
    fseek(fp, 24, SEEK_SET);
    if(fread(buff, sizeof(ULL), 1, fp) != -1) {
		printf("** program '%s' loaded. entry point 0x%llx\n", prog_name, buff[0]);
    } else {
        printf("** open failed!\n");
        return;
    }
    fclose (fp);
	
	// init sdb
	sdb->pid = -1;
	strncpy(sdb->prog_path, prog_name, sizeof(sdb->prog_path));
	for(int i = 0; i < 10; i++)
		sdb->bp[i].is_used = false;
	return ;
}

// ----------------------------------------------------------------------------------
// |	address	 	 |	permission	|	offset	|	dev	  |  inode	|	pathname	|
// ----------------------------------------------------------------------------------
// |08048000-08056000|     r-xp 	|  00000000 |  03:0c  |  64593  | /usr/sbin/gpm |
// ----------------------------------------------------------------------------------
void print_vmmap(char* line) {
	char* token = strtok(line, " \n");

	while(token != NULL) {
        for(int i = 0; i < 6; i++) {
            if(i == 0) {      
                char* tail = strchr(token, '-');
                tail++;
                ULL begin, end;
                sscanf(token, "%llx", &begin);
                sscanf(tail, "%llx", &end);
                printf("%016llx-%016llx ", begin, end);
            } else if(i == 1) { 
                token[3] = 0;
                printf("%s ", token);
            } else if(i == 4) { // offset? inode?
                long int inode;
                sscanf(token, "%ld", &inode);
                printf("%-8ld ", inode);
            } else if(i == 5) {
                printf("%s ", token);
            }
		    token = strtok(NULL, " \n");
        }
    }
    printf("\n");
    return;
}

void sdb_vmmap(sdb_t* sdb) {
	char* line = NULL;
	size_t len = 0;
	char proc_info_path[64];

	if(!sdb_is_loaded(sdb)) {
		printf("** no program loaded.\n");
		return;
	} else if(!sdb_is_running(sdb)) {
		printf("** no program is running.\n");
		return;
	} else { 
		sprintf(proc_info_path, "/proc/%d/maps", sdb->pid);
		FILE* fp = fopen(proc_info_path, "r");
		while(getline(&line, &len, fp) != -1) {
			print_vmmap(line);
		}
		if(line)	free(line);
		fclose(fp);
	}
	return;
}

ULL sdb_get(sdb_t* sdb, char* reg_name) {
	ULL val;
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

	if(!strcmp(reg_name, "rax"))	val = regs.rax;
	if(!strcmp(reg_name, "rbx"))	val = regs.rbx;
	if(!strcmp(reg_name, "rcx"))	val = regs.rcx;
	if(!strcmp(reg_name, "rdx"))	val = regs.rdx;
	if(!strcmp(reg_name, "r8"))		val = regs.r8;
	if(!strcmp(reg_name, "r9"))		val = regs.r9;
	if(!strcmp(reg_name, "r10"))	val = regs.r10;
	if(!strcmp(reg_name, "r11"))	val = regs.r11;
	if(!strcmp(reg_name, "r12"))	val = regs.r12;
	if(!strcmp(reg_name, "r13"))	val = regs.r13;
	if(!strcmp(reg_name, "r14"))	val = regs.r14;
	if(!strcmp(reg_name, "r15"))	val = regs.r15;
	if(!strcmp(reg_name, "rdi"))	val = regs.rdi;
	if(!strcmp(reg_name, "rsi"))	val = regs.rsi;
	if(!strcmp(reg_name, "rbp"))	val = regs.rbp;
	if(!strcmp(reg_name, "rsp"))	val = regs.rsp;
	if(!strcmp(reg_name, "rip"))	val = regs.rip;
	if(!strcmp(reg_name, "eflags"))	val = regs.eflags;

	printf("%s = %llu (0x%llx)\n", reg_name, val, val);
	return val;
}

void sdb_patch_bp(sdb_t* sdb) {
	struct user_regs_struct regs;
	
	for(int i = 0; i < 10; ++i) {
		bp_t* bp = &(sdb->bp[i]);

		if(bp->is_used) {
			ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);
			if(regs.rip == bp->addr) {
				ptrace(PTRACE_SINGLESTEP, sdb->pid, 0,0);
				if(waitpid(sdb->pid, 0, 0) < 0) {
					puts("** failed to waitpid!");
					return;
				}
			}

			ULL data = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->addr, 0);
			if((data & 0xff) == 0xcc)
				continue;
			bp->orig_data = data;

			// patch 0xcc into addr
			if(ptrace(PTRACE_POKETEXT, sdb->pid, bp->addr, ((data & 0xffffffffffffff00) | 0xcc)) != 0) {
				puts("** failed to patch bp!");
				return;
			}
		}
	}
	return;
}

void sdb_start(sdb_t* sdb) {
	if(!sdb_is_loaded(sdb)) {
		printf("** no program loaded.\n");
		return;
	}

	if((sdb->pid = fork()) < 0) perror("fork");
	if(sdb->pid == 0) {						
		if(ptrace(PTRACE_TRACEME, 0,0,0) < 0) perror("ptrace@child"); 
		execlp(sdb->prog_path, sdb->prog_path, NULL);
		perror("execlp");
	} else {									
		int wait_status;
		if(waitpid(sdb->pid, &wait_status, 0) < 0) perror("wait"); 
		ptrace(PTRACE_SETOPTIONS, sdb->pid, 0, PTRACE_O_EXITKILL);
		// start successfully, print pid
		printf("** pid %d\n", sdb->pid);
	}

	//sdb_patch_bp(sdb);
	return;
}

void sdb_getregs(sdb_t* sdb) {
	if(!sdb_is_running(sdb)) {
		printf("** no program is running.\n");
		return;
	}

	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);

	printf("RAX %-18llxRBX %-18llxRCX %-18llxRDX %-18llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
	printf("R8  %-18llxR9  %-18llxR10 %-18llxR11 %-18llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
	printf("R12 %-18llxR13 %-18llxR14 %-18llxR15 %-18llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
	printf("RDI %-18llxRSI %-18llxRBP %-18llxRSP %-18llx\n", regs.rdi, regs.rsi, regs.rbp, regs.rsp);
	printf("RIP %-18llxFLAGS %016llx\n", regs.rip, regs.eflags);

	return;
}

void sdb_cont(sdb_t* sdb) {
	if(!sdb_is_running(sdb)) {
		printf("** no program is running.\n");
		return;
	}
	
	// set bp
	sdb_patch_bp(sdb);

	// continue execution
	ptrace(PTRACE_CONT, sdb->pid, 0, 0);
	int wait_status;
	while(waitpid(sdb->pid, &wait_status, 0) > 0) {
		struct user_regs_struct regs;
		if(!WIFSTOPPED(wait_status)) continue;
		if(ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs) != 0) perror("ptrace(GETREGS)");

		// Once hit bp : restore the orig byte, restore RIP, cont prog execution
		for(int i = 0; i < 10; i++) {
			bp_t* bp = &(sdb->bp[i]);

			if(bp->is_used && (regs.rip-1) == bp->addr) {
				ptrace(PTRACE_POKETEXT, sdb->pid, bp->addr, bp->orig_data);
				regs.rip--;
				ptrace(PTRACE_SETREGS, sdb->pid, 0, &regs);

				ULL buf = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->addr, 0);
				cs_insn *insn;
				size_t count;
				if((count = cs_disasm(sdb->cshandle, (uint8_t*)&buf, 8, bp->addr, 0, &insn)) > 0) {
					char byte[8] = "", byte_str[16] = "";
					for(int j = 0; j < insn[0].size; j++) {
						sprintf(byte, "%02x ", insn[0].bytes[j]);
						strncat(byte_str, byte, sizeof(byte_str));
					}
					printf("** breakpoint @ %10lx: %-21s", insn[0].address, byte_str);
					printf("%-7s%s\n", insn[0].mnemonic, insn[i].op_str);
					cs_free(insn, count);
				}
				//cs_close(&sdb->cshandle);
				return;
			}
		}
	}

	// When the program goes to end 
	printf("** child process %d terminated normally (code %d)\n", sdb->pid, wait_status);
	sdb->pid = -1;
	return;
}

void sdb_run(sdb_t* sdb) {
	if(!sdb_is_loaded(sdb)) {
		printf("** no program loaded.\n");
		return;
	}

	if(!sdb_is_running(sdb)) {
		if((sdb->pid = fork()) < 0) perror("fork"); 

		if(sdb->pid == 0) {								
			if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) perror("trace@child"); 
			execlp(sdb->prog_path, sdb->prog_path, NULL);
			perror("execlp");
		} else {									
			int wait_status;
			if(waitpid(sdb->pid, &wait_status, 0) < 0) perror("wait"); 
			ptrace(PTRACE_SETOPTIONS, sdb->pid, 0, PTRACE_O_EXITKILL);
			// run successfully, print pid
			printf("** pid %d\n", sdb->pid);
		}
	} else {
		printf("** program '%s' is already running.\n", sdb->prog_path);
	}

	sdb_patch_bp(sdb);

	// continue execution
	ptrace(PTRACE_CONT, sdb->pid, 0, 0);
	int wait_status;
	while(waitpid(sdb->pid, &wait_status, 0) > 0) {
		struct user_regs_struct regs;
		if(!WIFSTOPPED(wait_status)) continue;
		if(ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs) != 0) perror("ptrace(GETREGS)");

		// Once hit bp : restore the orig byte, restore RIP, cont prog execution
		for(int i = 0; i < 10; i++) {
			bp_t* bp = &(sdb->bp[i]);

			if(bp->is_used && (regs.rip-1) == bp->addr) {
				ptrace(PTRACE_POKETEXT, sdb->pid, bp->addr, bp->orig_data);
				regs.rip--;
				ptrace(PTRACE_SETREGS, sdb->pid, 0, &regs);

				ULL buf = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->addr, 0);
				cs_insn *insn;
				size_t count;
				if((count = cs_disasm(sdb->cshandle, (uint8_t*)&buf, 8, bp->addr, 0, &insn)) > 0) {
					char byte[8], byte_str[16] = "";
					for(int j = 0; j < insn[0].size; j++) {
						sprintf(byte, "%02x ", insn[0].bytes[j]);
						strncat(byte_str, byte, sizeof(byte_str));
					}

					printf("** breakpoint @ %10lx: %-21s", insn[0].address, byte_str);
					printf("%-7s%s\n", insn[0].mnemonic, insn[i].op_str);
					cs_free(insn, count);
				}
				//cs_close(&sdb->cshandle);
				return;
			}
		}
	}

	// When the program goes to end
	printf("** child process %d terminated normally (code %d)\n", sdb->pid, wait_status);
	sdb->pid = -1;
	return;
}

void sdb_set(sdb_t* sdb, char* reg_name, ULL val) {
	if(!sdb_is_running(sdb)) {
		printf("** no program is running.\n");
		return;
	}

	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, sdb->pid, 0, &regs);
	
	if(!strcmp(reg_name, "rax"))	regs.rax = val;
	if(!strcmp(reg_name, "rbx"))	regs.rbx = val;
	if(!strcmp(reg_name, "rcx"))	regs.rcx = val;
	if(!strcmp(reg_name, "rdx"))	regs.rdx = val;
	if(!strcmp(reg_name, "r8"))		regs.r8 = val;
	if(!strcmp(reg_name, "r9"))		regs.r9 = val;
	if(!strcmp(reg_name, "r10"))	regs.r10 = val;
	if(!strcmp(reg_name, "r11"))	regs.r11 = val;
	if(!strcmp(reg_name, "r12"))	regs.r12 = val;
	if(!strcmp(reg_name, "r13"))	regs.r13 = val;
	if(!strcmp(reg_name, "r14"))	regs.r14 = val;
	if(!strcmp(reg_name, "r15"))	regs.r15 = val;
	if(!strcmp(reg_name, "rdi"))	regs.rdi = val;
	if(!strcmp(reg_name, "rsi"))	regs.rsi = val;
	if(!strcmp(reg_name, "rbp"))	regs.rbp = val;
	if(!strcmp(reg_name, "rsp"))	regs.rsp = val;
	if(!strcmp(reg_name, "rip"))	regs.rip = val;
	if(!strcmp(reg_name, "eflags"))	regs.eflags = val;

	if(ptrace(PTRACE_SETREGS, sdb->pid, 0, &regs) != 0) perror("setregs"); 
	return;
}

void sdb_disasm(sdb_t* sdb, char* addr_str) {
    if(!sdb_is_running(sdb)) {
		printf("** no program is running.\n");
		return;
	}

    ULL addr;
	if(addr_str[1] == 'x') {
        addr_str += 2;
	    sscanf(addr_str, "%llx", &addr);
    } else {
		printf("** no addr is given.\n");
		return;
    }

	// restore the orig byte
	for(int i = 0; i < 10; i++) {
		bp_t* bp = &(sdb->bp[i]);
		if(bp->is_used) {
			ULL ret;
			ret = ptrace(PTRACE_POKETEXT, sdb->pid, bp->addr, bp->orig_data);
			if(ret == -1) perror("ptrace@poketext");
		} 
	}    	

    ULL ptr;
	unsigned char buf[64] = {0};
	for(ptr = addr; ptr < addr + sizeof(buf); ptr += 8) {
		errno = 0;
		ULL peektext = ptrace(PTRACE_PEEKTEXT, sdb->pid, ptr, NULL);
		if(peektext == -1 && errno != 0) {
			perror("ptrace@peektext");
            break;
		}
	    memcpy(&buf[ptr - addr], &peektext, 8);
	}

	// reset bp
	sdb_patch_bp(sdb);

	cs_insn *insn;
	size_t count;
	if((count = cs_disasm(sdb->cshandle, (uint8_t*)buf, sizeof(buf)-1, addr, 0, &insn)) > 0) {
		for(int i = 0; i < count && i < 10; i++) {
			char byte[8], byte_str[16] = "";
			for(int j = 0; j < insn[i].size; j++) {
				sprintf(byte, "%02x ", insn[i].bytes[j]);
				strncat(byte_str, byte, sizeof(byte_str));
			}
			printf("%10lx: %-21s", insn[i].address, byte_str);
			printf("%-7s%s\n", insn[i].mnemonic, insn[i].op_str);
		}
		cs_free(insn, count);
	}
	//cs_close(&sdb->cshandle);
    return;
}

void sdb_dump(sdb_t* sdb, char* addr_str) {
	if(!sdb_is_running(sdb)) {
		printf("** no program is running.\n");
		return;
	}

    ULL addr;
	if(addr_str[1] == 'x') {
        addr_str += 2;
	    sscanf(addr_str, "%llx", &addr);
    } else {
		printf("** no addr is given.\n");
		return;
    }

	ULL ptr;
	unsigned char buf[80];
	for(ptr = addr; ptr < addr + sizeof(buf); ptr += 8) {
		errno = 0;
		ULL peektext = ptrace(PTRACE_PEEKTEXT, sdb->pid, ptr, NULL);
		if(peektext == -1 && errno != 0) {
			perror("ptrace@peektext");
			exit(-1);
		}
		memcpy(&buf[ptr - addr], &peektext, 8);
	}

	// print addr, hex value, printable ascii char
	for(int i = 0; i < 5; i++) {
		printf("%10llx:", (addr + i*16));

		for(int j = 0; j < 16; j++) {
			unsigned char c = buf[i*16 + j];
			printf(" %02x", c);
		}

		printf("  |");
		for(int j = 0; j < 16; j++) {
			char c = buf[i*16 + j];
			if(isprint(c))	printf("%c", c);
			else			printf(".");
		}
		printf("|\n");
	}
	return;
}

void sdb_set_break(sdb_t* sdb, char* addr_str) {
	if(!sdb_is_running(sdb)) {
		printf("** no program is running.\n");
		return;
	}

	if(addr_str[1] == 'x') addr_str += 2;
	ULL addr;
	sscanf(addr_str, "%llx", &addr);

	bp_t* bp;
	for(int i = 0; i < 10; ++i) {
		if(!(sdb->bp[i].is_used)) {
			bp = &(sdb->bp[i]);
			break;
		}
	}

	bp->is_used = true;
	bp->addr = addr;
	sdb_patch_bp(sdb);
	return;
}

void sdb_list(sdb_t* sdb) {
	for(int i = 0; i < 10; i++) {
		bp_t* bp = &(sdb->bp[i]);
		if(bp->is_used)	{
			printf("%3d:  %llx\n", i, bp->addr);
		}
	}
	return;
}

void sdb_delete(sdb_t* sdb, int index) {
	if(index >= 0 && index < 10 && sdb->bp[index].is_used) {
		bp_t* bp = &(sdb->bp[index]);
		ULL data = ptrace(PTRACE_PEEKTEXT, sdb->pid, bp->addr, 0);
		
		// restore the orig byte
		if ((data & 0xff) == 0xcc) {
			ptrace(PTRACE_POKETEXT, sdb->pid, bp->addr, bp->orig_data);
		}
		bp->is_used = false;
		printf("** breakpoint %d deleted.\n", index);
	}
	return;
}

void sdb_step(sdb_t* sdb) {
	if(!sdb_is_running(sdb)) {
		printf("** no program is running.\n");
		return;
	}

	if(ptrace(PTRACE_SINGLESTEP, sdb->pid, 0,0) < 0) perror("ptrace@singlestep"); 
	if(waitpid(sdb->pid, 0, 0) < 0) perror("waitpid");
	return;
}
