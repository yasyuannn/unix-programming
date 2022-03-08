#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#define PATH_MAX 4096

char so_path[PATH_MAX];
char file_name[50];
char cmd[50];
char cmdline[150];
int tofile_flag = 0 ;

int main(int argc, char *argv[]) {
    strncpy(cmd, "", sizeof(cmd));
    strncpy(so_path, "./logger.so", sizeof(so_path));

    if(argc == 1) {
        printf("no command given.\n");
        return 0;
    }

    for(int i = 1; i < argc; i++) {
        if(argv[i][0] == '-') {
            char c = argv[i][1];
            if(c == 'p') 
                strncpy(so_path, argv[++i], sizeof(so_path));
            else if(c == 'o') {
                i++;
                if(argv[i] && isalnum(argv[i][0])) {
                    tofile_flag = 1;
                    strncpy(file_name, argv[i], sizeof(file_name));
                }else        
                    fprintf(stderr, "no file specified.\n");
            }
            else if(c == '-') {
                while(++i < argc) {
                    strncat(cmd, " ", sizeof(cmd)-1);
                    strncat(cmd, argv[i], sizeof(cmd)-1);
                }
                break;
            }  
            else {
                fprintf(stderr, "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n");
                fprintf(stderr, "        -p: set the path to logger.so, default = ./logger.so\n");
                fprintf(stderr, "        -o: print output to file, print to \"stderr\" if no file specified\n");
                fprintf(stderr, "        --: separate the arguments for logger and for the command\n");
                strncpy(cmd, "", sizeof(cmd));
                break;
            }
        }// Only cmd
        else {
            while(i < argc) {
                strncat(cmd, " ", sizeof(cmd)-1);
                strncat(cmd, argv[i], sizeof(cmd)-1);
                i++;
            }
        }
    }
    strncpy(cmdline, "LD_PRELOAD=", sizeof(cmdline));
    strncat(cmdline, so_path, sizeof(cmdline)-1);
    strncat(cmdline, cmd, sizeof(cmdline)-1);
    if(tofile_flag) {
        strncat(cmdline, " 2> ", sizeof(cmdline)-1);
        strncat(cmdline, file_name, sizeof(cmdline)-1);
    }
    //printf("cmdline: %s\n", cmdline);
    //printf("cmd: %s\n", cmd);
    //printf("so_path: %s\n", so_path);
    //printf("file_name: %s\n", file_name);
    system(cmdline);

    return 0;
}
