#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdarg.h>
#include <fcntl.h>

//int stderr_copy;
//void startup (void) __attribute__ ((constructor));
//void startup() {
//	stderr_copy = dup(2);
//}

void *get_filename(int fd, char *filepath)
{
    char procpath[PATH_MAX];

    snprintf(procpath, PATH_MAX, "/proc/self/fd/%d", fd);
    //printf("The path of proc is: %s\n", procpath);
    readlink(procpath, filepath, PATH_MAX);
    //printf("The path of file is: %s\n", filepath);
}

int chmod(const char *pathname, mode_t mode)
{
    static int (*chmod_orig)(const char *, mode_t);
    char path[PATH_MAX];
    
    if(!chmod_orig) {
        chmod_orig = dlsym(RTLD_NEXT, "chmod");
    }
    int ret = chmod_orig(pathname, mode);

    realpath(pathname, path);
    fprintf(stderr, "[logger] chmod(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int chown(const char *pathname, uid_t owner, gid_t group)
{
    static int (*chown_orig)(const char *, uid_t, gid_t);
    char path[PATH_MAX];
    
    if(!chown_orig) {
        chown_orig = dlsym(RTLD_NEXT, "chown");
    }
    int ret = chown_orig(pathname, owner, group);
    
    realpath(pathname, path);
    fprintf(stderr, "[logger] chown(\"%s\", %d, %d) = %d\n", path, owner, group, ret);
    return ret;
}

int close(int fd)
{
    int stderr_copy = dup(2);
    char filepath[PATH_MAX] = {0};
    static int (*close_orig)(int);
    get_filename(fd, filepath);
    
    if(!close_orig) {
        close_orig = dlsym(RTLD_NEXT, "close");
    }
    int ret = close_orig(fd);

    //fprintf(stderr, "[logger] close(\"%s\") = %d\n", filepath, ret);
    dprintf(stderr_copy, "[logger] close(\"%s\") = %d\n", filepath, ret);
    return ret;
}

int creat(const char *pathname, mode_t mode)
{
    static int (*creat_orig)(const char *, mode_t);
    char path[PATH_MAX];
    
    if(!creat_orig) {
        creat_orig = dlsym(RTLD_NEXT, "creat");
    }
    int ret = creat_orig(pathname, mode);

    realpath(pathname, path);
    fprintf(stderr, "[logger] creat(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int creat64(const char *pathname, mode_t mode)
{
    static int (*creat64_orig)(const char *, mode_t);
    char path[PATH_MAX];
    
    if(!creat64_orig) {
        creat64_orig = dlsym(RTLD_NEXT, "creat64");
    }
    int ret = creat64_orig(pathname, mode);

    realpath(pathname, path);
    fprintf(stderr, "[logger] creat(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

FILE *fopen(const char *filename, const char *mode)
{
    static FILE *(*fopen_orig)(const char *, const char *);
    char path[PATH_MAX];
    
    if (!fopen_orig) {
        fopen_orig = dlsym(RTLD_NEXT, "fopen");
    }    
    FILE *ret = fopen_orig(filename, mode);
    
    realpath(filename, path);
    fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, ret);
    return ret;
}

FILE *fopen64(const char *filename, const char *mode)
{
    static FILE *(*fopen64_orig)(const char *, const char *);
    char path[PATH_MAX];
    
    if (!fopen64_orig) {
        fopen64_orig = dlsym(RTLD_NEXT, "fopen64");
    }    
    FILE *ret = fopen64_orig(filename, mode);
    
    realpath(filename, path);
    fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, ret);
    return ret;
}

int fclose(FILE *stream)
{
    int stderr_copy = dup(2);
    //printf("===my fclose===\n");
    static int (*fclose_orig)(FILE *);
    char filepath[PATH_MAX] = {0};
    int fd = fileno(stream);
    get_filename(fd, filepath);
    
    //printf("fd: %d\n", fd);
    //printf("filepath: %s\n", filepath);
    if(!fclose_orig) {
        fclose_orig = dlsym(RTLD_NEXT, "fclose");
    }
    int ret = fclose_orig(stream);
    
    //fprintf(stderr, "[logger] fclose(\"%s\") = %d\n", filepath, ret);
    dprintf(stderr_copy, "[logger] fclose(\"%s\") = %d\n", filepath, ret);
    return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    static size_t (*fread_orig)(void *, size_t, size_t, FILE *);
    char filepath[PATH_MAX] = {0};
    char toStr[32+1];
    int fd = fileno(stream);
    get_filename(fd, filepath);

    if(!fread_orig) {
        fread_orig = dlsym(RTLD_NEXT, "fread");
    }
    int ret = fread_orig(ptr, size, nmemb, stream);
    
    strncpy(toStr, "", sizeof(toStr));
    char *tmp = (char *)ptr;
    for(int i = 0; i < ret && i < 32; i++) {
        char c = tmp[i];

        if(c == '\0') {
            strncat(toStr, &c, 1);
            break;
        }
        if(isprint(c))
            strncat(toStr, &c, 1);
        else
            strcat(toStr, ".");
    }        

    fprintf(stderr, "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %d\n", toStr, size, nmemb, filepath, ret);
    return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    static size_t (*fwrite_orig)(const void *, size_t, size_t, FILE *);
    char filepath[PATH_MAX] = {0};
    char toStr[32+1];
    int fd = fileno(stream);

    if(!fwrite_orig) {
        fwrite_orig = dlsym(RTLD_NEXT, "fwrite");
    }
    int ret = fwrite_orig(ptr, size, nmemb, stream);
    
    strncpy(toStr, "", sizeof(toStr));
    char *tmp = (char *)ptr;
    for(int i = 0; i < ret && i < 32; i++) {
        char c = tmp[i];

        if(c == '\0') {
            strncat(toStr, &c, 1);
            break;
        }
        if(isprint(c))
            strncat(toStr, &c, 1);
        else
            strcat(toStr, ".");
    }        

    get_filename(fd, filepath);
    fprintf(stderr, "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %d\n", toStr, size, nmemb, filepath, ret);
    return ret;
}

int open(const char *filename, int flags, ...)
{
	static int (*open_orig)(const char *, int, mode_t);
    char path[PATH_MAX];
	va_list ap;
	mode_t mode;

    va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);

	if (!open_orig) {
		open_orig = dlsym(RTLD_NEXT, "open");
	}

    if(mode > 0777 || mode < 0) {
        mode = 0;
    }
	int ret = open_orig(filename, flags, mode);

    realpath(filename, path);
	fprintf(stderr, "[logger] open(\"%s\", %o, %o) = %d\n", path, flags, mode, ret);
	return ret;	
}

int open64(const char *filename, int flags, ...)
{
	static int (*open64_orig)(const char *, int, mode_t);
    char path[PATH_MAX];
	va_list ap;
	mode_t mode;
	
    va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	if (!open64_orig) {
		open64_orig = dlsym(RTLD_NEXT, "open64");
	}

    if(mode > 0777 || mode < 0) {
        mode = 0;
    }
	int ret = open64_orig(filename, flags, mode);

    realpath(filename, path);
	fprintf(stderr, "[logger] open(\"%s\", %o, %o) = %d\n", path, flags, mode, ret);
	return ret;	
}

ssize_t read(int fd, void *buf, size_t len)
{
    char filepath[PATH_MAX] = {0};
    char toStr[32+1];
    static ssize_t (*read_orig)(int, void *, size_t);
    get_filename(fd, filepath);
    
    if(!read_orig) {
        read_orig = dlsym(RTLD_NEXT, "read");
    }
    int ret = read_orig(fd, buf, len);
    
    strncpy(toStr, "", sizeof(toStr));
    char *tmp = (char *)buf;
    for(int i = 0; i < ret && i < 32; i++) {
        char c = tmp[i];

        if(c == '\0') {
            strncat(toStr, &c, 1);
            break;
        }
        if(isprint(c))
            strncat(toStr, &c, 1);
        else
            strcat(toStr, ".");
    }        

    fprintf(stderr, "[logger] read(\"%s\", \"%s\", %ld) = %d\n", filepath, toStr, len, ret);
    return ret;
}
    
int remove(const char *pathname)
{
    static int (*remove_orig)(const char *);
    char path[PATH_MAX];
    
    if(!remove_orig) {
        remove_orig = dlsym(RTLD_NEXT, "remove");
    }
    int ret = remove_orig(pathname);

    realpath(pathname, path);
    fprintf(stderr, "[logger] remove(\"%s\") = %d\n", path, ret);
    return ret;
}

int rename(const char *old_filename, const char *new_filename)
{
    static int (*rename_orig)(const char *, const char *);
    char path1[PATH_MAX];
    
    char path2[PATH_MAX];
    if(!rename_orig) {
        rename_orig = dlsym(RTLD_NEXT, "rename");
    }
    int ret = rename_orig(old_filename, new_filename);

    realpath(old_filename, path1);
    realpath(new_filename, path2);
    fprintf(stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", path1, path2, ret);
    return ret;
}

FILE *tmpfile(void)
{
    static FILE *(*tmpfile_orig)(void);

    if(!tmpfile_orig) {
        tmpfile_orig = dlsym(RTLD_NEXT, "tmpfile");
    }
    FILE *ret = tmpfile_orig();
    
    fprintf(stderr, "[logger] tmpfile() = %p\n", ret);
}

FILE *tmpfile64(void)
{
    static FILE *(*tmpfile64_orig)(void);

    if(!tmpfile64_orig) {
        tmpfile64_orig = dlsym(RTLD_NEXT, "tmpfile64");
    }
    FILE *ret = tmpfile64_orig();
    
    fprintf(stderr, "[logger] tmpfile() = %p\n", ret);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    char filepath[PATH_MAX] = {0};
    char toStr[32+1];
    static ssize_t (*write_orig)(int, const void *, size_t);
    
    if(!write_orig) {
        write_orig = dlsym(RTLD_NEXT, "write");
    }
    int ret = write_orig(fd, buf, count);
    
    strncpy(toStr, "", sizeof(toStr));
    char *tmp = (char *)buf;
    for(int i = 0; i < ret && i < 32; i++) {
        char c = tmp[i];

        if(c == '\0') {
            strncat(toStr, &c, 1);
            break;
        }
        if(isprint(c))
            strncat(toStr, &c, 1);
        else
            strcat(toStr, ".");
    }        
    
    get_filename(fd, filepath);
    fprintf(stderr, "[logger] write(\"%s\", \"%s\", %ld) = %d\n", filepath, toStr, count, ret);
    return ret;
}

