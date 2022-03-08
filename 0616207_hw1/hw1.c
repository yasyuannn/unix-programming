#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#define PATH_MAX 4096
/*
struct stat
{
    dev_t       st_dev;    
    ino_t       st_ino;     
    mode_t      st_mode;    
    nlink_t     st_nlink;   
    uid_t       st_uid;     
    gid_t       st_gid;     
    dev_t       st_rdev;    
    off_t       st_size;    
    blksize_t   st_blksize; 
    blkcnt_t    st_blocks;  
    time_t      st_atime;    
    time_t      st_mtime;   
    time_t      st_ctime;   
}
*/

// Check if file descriptor: [0-9].
bool flag_fd = 0;
bool cmd_filter = 0;
bool type_filter = 0;
bool file_filter = 0;
char cmd_regex[50];
char type_regex[50];
char file_regex[50];

struct pid_info {
    pid_t pid;
    char cmd[50];
    char user[50];
    char fd[10];
    char type[50];
    char inode[50];
    char path[PATH_MAX];
    ssize_t parent_len;
};

void print_header()
{
    printf("%-30s %8s %18s %7s %10s %12s %-10s\n",
            "COMMAND",
            "PID",
            "USER",
            "FD",
            "TYPE",
            "NODE",
            "NAME");
}

char get_fdinfo(char* fdinfo_path, char* fd)
{
    char ret;
    fdinfo_path[strlen(fdinfo_path) - 3] = '\0';
    strncat(fdinfo_path, "fdinfo/", sizeof(fdinfo_path));
    //printf("--------|Before|fdinfo_path:%s\n", fdinfo_path);
    strncat(fdinfo_path, fd, sizeof(fdinfo_path));
    //printf("--------|After|fdinfo_path:%s\n", fdinfo_path);

    FILE* fp = fopen(fdinfo_path, "r");
    if (fp == NULL) {
        fprintf(stderr, "--------Couldn't read %s\n", fdinfo_path);
        return -1;
    }
    else{
        int c; 
        while ((c = fgetc(fp)) != '\n');
	    char buf[50], flags[50];
        fgets(buf, 50, fp);
        buf[strlen(buf) - 1] = '\0';
        if(strstr(buf, "flags")) {
            sscanf(buf, "%*7s %s", flags);
            //printf("-------|get_fdinfo|%s\n", flags); 
            ret = flags[strlen(flags)-1];
	    }
    }
    fclose(fp);
    return ret;
}

void get_type_node(char* link_path, struct stat *pid_stat, struct pid_info *proc)
{
    long int inode;
    // get TYPE
    if (!stat(link_path, pid_stat)) {
        if(S_ISDIR(pid_stat->st_mode))   strncpy(proc->type, "DIR", sizeof(proc->type));
        else if(S_ISREG(pid_stat->st_mode))   strncpy(proc->type, "REG", sizeof(proc->type));
        else if(S_ISCHR(pid_stat->st_mode))   strncpy(proc->type, "CHR", sizeof(proc->type));
        else if(S_ISFIFO(pid_stat->st_mode))   strncpy(proc->type, "FIFO", sizeof(proc->type));
        else if(S_ISSOCK(pid_stat->st_mode))   strncpy(proc->type, "SOCK", sizeof(proc->type));
        else    strncpy(proc->type, "unknown", sizeof(proc->type));
        // get NODE
        inode = pid_stat->st_ino;
        sprintf(proc->inode, "%ld", inode);
    }
    // get TYPE = SOCK, FIFO, unknown
    else {
        //printf("-----------(type: %s)\n", strerror(errno));
        if (errno == ENOENT) {
            if(!strncmp(link_path, "socket:", 7)){
                strncpy(proc->type, "SOCK", sizeof(proc->type));
                sscanf(link_path, "%*8s %ld %*1s", &inode);
                sprintf(proc->inode, "%ld", inode);
            }
            else if(!strncmp(link_path, "pipe:", 5)){   
                strncpy(proc->type, "FIFO", sizeof(proc->type));
                sscanf(link_path, "%*6s %ld %*1s", &inode);
                sprintf(proc->inode, "%ld", inode);
            }
            else{    
                strncpy(proc->type, "unknown", sizeof(proc->type));
                strncpy(proc->inode, "", sizeof(proc->inode));
            }
        }
        else{    
            strncpy(proc->type, "unknown", sizeof(proc->type));
            strncpy(proc->inode, "", sizeof(proc->inode));
        }
    }
    //printf("-------|get_type_node|link_path:%s\n", link_path);
    //printf("-------|get_type_node|type:%s\n", proc->type);
    //printf("-------|get_type_node|inode:%s\n", proc->inode);
}

// fd: cwd, root, exe, file[0-9] 
void print_which_type(char* fd, struct pid_info* proc)
{
    char link_dest[PATH_MAX];
    ssize_t dest_size;
    struct stat pid_stat;
    
    char fdinfo_path[PATH_MAX];
    strncpy(fdinfo_path, proc->path, sizeof(fdinfo_path)); 

    // Read in proc/[pid]/[fd] directory
    //printf("-------|Before|proc->path:%s\n", proc->path);
    strncat(proc->path, fd, sizeof(proc->path));
    //printf("-------|After|proc->path:%s\n", proc->path);
    //printf("-------fd:%s\n", fd);
    dest_size = readlink(proc->path, link_dest, sizeof(link_dest)-1);
    if (dest_size < 0) {
        // if No Entry
        if (errno == ENOENT) {
            proc->path[proc->parent_len] = '\0';
            return;
        }
  
        // ex: [path] (readlink: Permission denied)
        snprintf(link_dest, sizeof(link_dest), "%s (readlink: %s)", proc->path, strerror(errno));
        strncpy(proc->type, "unknown", sizeof(proc->type));
        strncpy(proc->inode, " ", sizeof(proc->inode));
    } else {
        link_dest[dest_size] = '\0';
        //strncpy(proc->type, "---", sizeof(proc->type));
        //strncpy(proc->inode, "---", sizeof(proc->inode));
        get_type_node(link_dest, &pid_stat, proc);
        //printf("-------link_dest: %s\n", link_dest);
    }

    // file decriptor: [0-9], decide[rwu]
    if (flag_fd){
	    char ret = get_fdinfo(fdinfo_path, fd);
        //printf("--------|print_which_type|%c\n", ret);	
        switch(ret){
            case '0':
                strncat(fd, "r", sizeof(fd));
                break;
            case '1':
                strncat(fd, "w", sizeof(fd));
                break;
            case '2':
                strncat(fd, "u", sizeof(fd));
                break;
            default:
                break;
        }
        flag_fd = 0;
    }

    // If there is a (deleted) mark right after the filename
    //if(strstr(link_dest, "(deleted)"))  strcpy(fd, "del");

    // Fiter
    if(cmd_filter && !strstr(proc->cmd, cmd_regex))    return;
    if(type_filter && strcmp(proc->type, type_regex))    return;
    if(file_filter && strcmp(link_dest, file_regex))    return;    

    printf("%-30s %8d %18s %7s %10s %12s %-10s\n",
            proc->cmd, 
            proc->pid, 
            proc->user, 
            fd,
            proc->type, 
            proc->inode,
            link_dest);
}

void print_openfile(struct pid_info* proc)
{
    //printf("-------|Before|proc->path: %s\n", proc->path);
    char err_msg[1024];
    strncat(proc->path, "fd/", sizeof(proc->path));
    int previous_len = proc->parent_len;
    proc->parent_len += 3;
    
    //printf("-------|After|proc->path: %s\n", proc->path);
    DIR* dir = opendir(proc->path);
    if (dir == NULL) {
        proc->path[proc->parent_len-1] = '\0';
        // ex: /proc/1/fd (opendir: Permission denied)
        snprintf(err_msg, sizeof(err_msg), "%s (opendir: %s)", proc->path, strerror(errno));
        proc->parent_len = previous_len;
        proc->path[proc->parent_len] = '\0';
        
        // Fiter
        if(cmd_filter && !strstr(proc->cmd, cmd_regex))    return;
        if(type_filter) return;
        if(file_filter && !strstr(err_msg, file_regex))    return; 

        printf("%-30s %8d %18s %7s %10s %12s %-10s\n",
                proc->cmd,
                proc->pid,
                proc->user,
                "NOFD",
                "",
                "",
                err_msg);
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir))) {
        // Skip entries '.' and '..' (and any hidden file)
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
            
        proc->path[proc->parent_len] = '\0';
        //printf("-------|while|proc->path: %s\n", proc->path);
        //printf("-------|while|entry->d_name: %s\n", entry->d_name);
        flag_fd = 1;
        print_which_type(entry->d_name, proc);
    }
    closedir(dir);
}

void print_maps(struct pid_info* proc)
{
    char file_path[PATH_MAX];
    char device[10];
    size_t offset;
    long int inode;
    struct stat pid_stat;
    char fd[10];

    // Read in proc/[pid]/maps directory.
    //printf("-------|Before|proc->path: %s\n", proc->path);
    strncat(proc->path, "maps", sizeof(proc->path));
    //printf("-------|After| proc->path: %s\n", proc->path);
    FILE* fp = fopen(proc->path, "r");
    if (fp == NULL) {
        // Couldn't open the dir, let path = proc/[pid].
        proc->path[proc->parent_len] = '\0';
        //fprintf(stderr, "--------Couldn't read %s\n", proc->path);
        return;
    }
    /* 
    // print proc->path content
    else{
        int c; 
        while ((c = fgetc(fp)) != EOF)  putchar(c);
    }
    */  
    
    // ex: 55a7c4f06000-55a7c4f07000 r--p 00000000 fc:05 665613 /home/unix/hw1/pid.out
    // format: %[*][width][modifiers]type] ; [*]表示可省略
    long int last_inode = 0;
    while (fscanf(fp, "%*x-%*x %*s %zx %5s %ld %s\n", &offset, device, &inode, file_path) == 4) {
        //printf("-------proc->path: %s\n", proc->path);
        // Skip non-file maps
        if (inode == 0 || !strcmp(device, "00:00") || inode == last_inode)
            continue;
        
        get_type_node(file_path, &pid_stat, proc);
        
        // If there is a (deleted) mark right after the filename
        if(strstr(file_path, "(deleted)"))  strcpy(fd, "del");
        else    strcpy(fd, "mem");
        
        // Fiter
        if(cmd_filter && !strstr(proc->cmd, cmd_regex))    continue;
        if(type_filter && strcmp(proc->type, type_regex))    continue;
        if(file_filter && strcmp(file_path, file_regex))    continue;    

        //strncpy(proc->type, "---", sizeof(proc->type));
        printf("%-30s %8d %18s %7s %10s %12ld %-10s\n",
                proc->cmd, 
                proc->pid, 
                proc->user, 
                fd,
                proc->type, 
                inode,
                file_path);
        
        last_inode = inode;
    }
    fclose(fp);
}

void lsof_dump(pid_t pid)
{
    int fd;
    char cmd[PATH_MAX];
    struct pid_info proc;
    struct stat pid_stat;
    struct passwd *pw;

    proc.pid = pid;
    snprintf(proc.path, sizeof(proc.path), "/proc/%d/", pid);
    proc.parent_len = strlen(proc.path);

    // Get UID & username in the proc/[pid] directory
    if (!stat(proc.path, &pid_stat)) {
        pw = getpwuid(pid_stat.st_uid);
        strncpy(proc.user, pw->pw_name, sizeof(proc.user));
    } else {
        strcpy(proc.user, "ERROR!");
    }

    // Read command in the proc/[pid]/cmdline
    strncat(proc.path, "comm", sizeof(proc.path)-1);
    fd = open(proc.path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "-------Couldn't read %s\n", proc.path);
        return;
    }
    int num_word = read(fd, cmd, sizeof(cmd) - 1);
    close(fd);
    if (num_word < 0) {
        fprintf(stderr, "-------Couldn't read %s\n", proc.path);
        return;
    }
    cmd[num_word-1] = '\0';
    strncpy(proc.cmd, cmd, sizeof(proc.cmd)-1);
    //printf("---------%s", proc.cmdline);    
    
    // Read each case of file descriptor
    proc.path[proc.parent_len] = '\0';
    print_which_type("cwd", &proc);
    proc.path[proc.parent_len] = '\0';
    print_which_type("root", &proc);
    proc.path[proc.parent_len] = '\0';
    print_which_type("exe", &proc);
    proc.path[proc.parent_len] = '\0';
    print_maps(&proc);
    proc.path[proc.parent_len] = '\0';
    print_openfile(&proc);
}

int main(int argc, char *argv[])
{
    long int pid = 0;
    char *endptr;
    char c;

    while((c = getopt(argc, argv, "c:t:f:")) != -1) {
        switch(c){
            case 'c':
                cmd_filter = 1;    
                strcpy(cmd_regex, optarg);
                break;
            case 't':
                type_filter = 1;
                strcpy(type_regex, optarg);
                break;
            case 'f':
                file_filter = 1;
                strcpy(file_regex, optarg);
                break;
            case '?':
                puts("Wrong Command.");
                break;
        }
        // For invalid TYPE filter
        if(type_filter){
            if(strcmp(type_regex, "REG") && 
                strcmp(type_regex, "CHR") && 
                strcmp(type_regex, "DIR") && 
                strcmp(type_regex, "FIFO") && 
                strcmp(type_regex, "SOCK") &&
                strcmp(type_regex, "unknown")) {
                printf("Invalid TYPE option.\n");
                return 0;
            }
        }
    }

    DIR *dir = opendir("/proc");
    if (dir == NULL) {
        fprintf(stderr, "------Couldn't open /proc\n");
        return -1;
    }
    
    print_header();

    struct dirent* entry;
    while ((entry = readdir(dir))) {
        // Skip entries '.' and '..' (and any hidden file)
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
            
        // Only inspect directory that are PID numbers
        pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0')
            continue;
        //printf("--------%ld\n", pid);
        lsof_dump(pid);
    }
}
