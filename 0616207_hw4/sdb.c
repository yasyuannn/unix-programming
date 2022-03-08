#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdb.h"

bool to_exit;

void run_cmd(sdb_t* sdb, char* command, char* line) {
    to_exit = false;

	if(strcmp(command, "break") == 0 || strcmp(command, "b") == 0) {
		// break [bp_addr] 
	    char bp_addr[16] = {0};
		sscanf(line, "%s %s", command, bp_addr);
		sdb_set_break(sdb, bp_addr);
	} else if(strcmp(command, "cont") == 0 || strcmp(command, "c") == 0) {
		// cont
		sdb_cont(sdb);
	} else if(strcmp(command, "delete") == 0) {
		// delete [bp_index] 
		int bp_index;
		sscanf(line, "%s %d", command, &bp_index);
		sdb_delete(sdb, bp_index);
	} else if(strcmp(command, "disasm") == 0 || strcmp(command, "d") == 0) {
		// disasm [addr]
		char addr[16] = {0};
		sscanf(line, "%s %s", command, addr);
		sdb_disasm(sdb, addr);
	} else if(strcmp(command, "dump") == 0) {
		// dump [addr] 
		char addr[16] = {0};
		sscanf(line, "%s %s", command, addr);
		sdb_dump(sdb, addr);
	} else if(strcmp(command, "exit") == 0 || strcmp(command, "q") == 0) {
		// exit
        to_exit = true;
		return;
	} else if(strcmp(command, "get") == 0 || strcmp(command, "g") == 0) {
		// get [reg]
		char reg[16] = {0};
		sscanf(line, "%s %s", command, reg);
		sdb_get(sdb, reg);
	} else if(strcmp(command, "getregs") == 0) {
		// get regs
		sdb_getregs(sdb);
	} else if(strcmp(command, "help") == 0 || strcmp(command, "h") == 0) {
		// help
		printf("%s\n", "- break {instruction-address}: add a break point");
		printf("%s\n", "- cont: continue execution");
		printf("%s\n", "- delete {break-point-id}: remove a break point");
		printf("%s\n", "- disasm addr: disassemble instructions in a file or a memory region");
		printf("%s\n", "- dump addr [length]: dump memory content");
		printf("%s\n", "- exit: terminate the debugger");
		printf("%s\n", "- get reg: get a single value from a register");
		printf("%s\n", "- getregs: show registers");
		printf("%s\n", "- help: show this message");
		printf("%s\n", "- list: list break points");
		printf("%s\n", "- load {path/to/a/program}: load a program");
		printf("%s\n", "- run: run the program");
		printf("%s\n", "- vmmap: show memory layout");
		printf("%s\n", "- set reg val: get a single value to a register");
		printf("%s\n", "- si: step into instruction");
		printf("%s\n", "- start: start the program and stop at the first instruction");
	} else if(strcmp(command, "list") == 0 || strcmp(command, "l") == 0) {
		// list
		sdb_list(sdb);
	} else if(strcmp(command, "load") == 0) {
		// load [filename] 
		char filename[64] = {0};
		sscanf(line, "%s %s", command, filename);
		sdb_load(sdb, filename);
	} else if(strcmp(command, "run") == 0 || strcmp(command, "r") == 0) {
		// run
		sdb_run(sdb);
	} else if(strcmp(command, "vmmap") == 0 || strcmp(command, "m") == 0) {
		// vmmap
		sdb_vmmap(sdb);
	} else if(strcmp(command, "set") == 0 || strcmp(command, "s") == 0) {
		// set [reg] [val]
		char reg[16] = {0};
		char oprand[16] = {0};
		unsigned long long val;
		sscanf(line, "%s %s %s", command, reg, oprand);
		if(oprand[0] == '0' && oprand[1] == 'x') { // 64-bit hex
			sscanf(oprand + 2, "%llx", &val);
		}else { 								   // 64-bit unsigned int
			sscanf(oprand, "%llu", &val);
		}
		sdb_set(sdb, reg, val);
	} else if(strcmp(command, "si") == 0) {
		// single step
		sdb_step(sdb);
	} else if(strcmp(command, "start") == 0) {
		// start
		sdb_start(sdb);
	} else {
		printf("** unknown command: %s\n", command);
	}
    return;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

	char* line = NULL;
	size_t len = 0;
    ssize_t read;
	char command[64];

	sdb_t* sdb = sdb_init();

    // usage: ./hw4 [-s script] [program]
    if(argc > 1 && argv[1][0] == '-' && argv[1][1] == 's') {
        FILE* fp = fopen(argv[2], "rb");
        if(fp != NULL) {
            FILE * prog = fopen(argv[3], "rb");
            if(prog != NULL) {
                fclose(prog);
                sdb_load(sdb, argv[3]);
            }
            while((read = getline(&line, &len, fp) != -1)) {
                //printf("%s", line);
                sscanf(line, "%s", command);
                run_cmd(sdb, command, line);
                if(to_exit)    break;
            }
            fclose(fp);
            printf("Bye.\n");
        }
        if(line) free(line);
        return 0;
    }
	
    // usage: ./hw4 [filename]
	if(argc == 2) {
		sdb_load(sdb, argv[1]);
	}

	while(1) {
		printf("sdb> ");
		getline(&line, &len, stdin);
		sscanf(line, "%s", command);
	    run_cmd(sdb, command, line);
        if(to_exit)    break;
    }
    if(line) free(line);
	return 0;
}
