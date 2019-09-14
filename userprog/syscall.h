#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/user/syscall.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>

void syscall_init(void);
static void syscall_handler(struct intr_frame *);
/* Argument offsets for syscalls */
// Each argument is a 32 bit integer(4 bytes)
#define SYSCALL_VARIANT 0
#define ARG_0 4
#define ARG_1 8
#define ARG_2 12

#define ERROR_EXIT -1

// File system semaphore. limits the access to file system to one thread at a
// time.
static struct semaphore fs_sem;
struct filemap_t {
  struct list_elem ptr;
  int fd;
  struct file *file;
};

// file descriptors for opened files will start from 2
// Following file descriptors are assigned to different streams by convention:
// 0 - stdin
// 1 - stdout
//
// 3 would normally be stderr on *nix like operating systems, but it is out of
// scope for this project
#define FD_START 2

// Implemented syscalls
// Exits a program with a provided status.
void sys_exit(int status);
int sys_write(int fd, const void *buffer, unsigned int length);

// Opens a file with the given filename and returns a file descriptor to it.
int sys_open(const char *filename);

int sys_read(int fd, void *buffer, unsigned int length);
// Terminates Pintos
void sys_halt(void);
bool sys_create(const char *name, unsigned int size);
unsigned sys_tell(int fd);

void sys_seek(int fd, unsigned pos);

pid_t sys_exec(const char *invocation);
int sys_wait(pid_t pid);
bool sys_remove(const char *filename);
int sys_filesize(int fd);
void sys_close(int fd);
void close_all_files(struct thread *thread);
// Implemented syscalls-end

// Helpers
// Loads a paramters from a interrupt frame's stack.
static uint32_t load_param(struct intr_frame *frame, int offset);
static int get_user(const uint8_t *uaddr);
struct filemap_t *find_filemap(int fd);

static bool put_user(uint8_t *udst, uint8_t byte);

#endif /* userprog/syscall.h */
