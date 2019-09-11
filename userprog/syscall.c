#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <stdio.h>
#include <syscall-nr.h>

static void syscall_handler(struct intr_frame *);

/* Argument offsets for syscalls */
// Each argument is a 32 bit integer(4 bytes)
#define SYSCALL_VARIANT 0
#define ARG_0 4
#define ARG_1 8
#define ARG_2 12

// File system semaphore. limits the access to file system to one thread at a
// time.
static struct semaphore fs_sem;
// TODO: move this somewhere else
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

// Implemented syscalls-end

// Helpers
// Loads a paramters from a interrupt frame's stack.
static uint32_t load_param(struct intr_frame *frame, int offset);
static int get_user(const uint8_t *uaddr);

static bool put_user(uint8_t *udst, uint8_t byte);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  // Initialize file system semaphore
  sema_init(&fs_sem, 1);
}

static void syscall_handler(struct intr_frame *frame UNUSED) {
  // frame is an interrupt stack frame.
  uint32_t syscall_variant = load_param(frame, SYSCALL_VARIANT);
  switch (syscall_variant) {
  // exit syscall
  case SYS_EXIT: {
    sys_exit(load_param(frame, ARG_0));
    return;
  }
  case SYS_WRITE: {
    frame->eax = sys_write((int)load_param(frame, ARG_0),
                           (const void *)load_param(frame, ARG_1),
                           (unsigned int)load_param(frame, ARG_2));
    return;
  }
  }
  // TODO: remove
  printf("error: you did not return within your case statement up there. "
         "Thread is exiting now\n");
  thread_exit();
}

static uint32_t load_param(struct intr_frame *frame, int offset) {
  if (get_user(frame->esp + offset) == -1) {
    sys_exit(-1);
  }
  return *(((uint32_t *)(frame->esp + offset)));
}

// TODO: implement for other files
int sys_write(int fd, const void *buffer, unsigned int length) {
  // TODO: pointer validation
  if (fd == STDOUT_FILENO) {
    putbuf((const char *)buffer, length);
    return length;
  }
  return 0;
}

// Respond to an exit syscall
void sys_exit(int status) {
  struct thread *curr = thread_current();
  curr->exit_code = status;
  thread_exit();
}

int sys_open(const char *filename) {
  // TODO: make sure pointer is safe.

  // Find a number to assign as a file descriptor
  struct thread *thread = thread_current();
  struct list_elem *node;

  int fd = FD_START;

  // Loop over each filemap_t entry we have stored for the thread and find a
  // file descriptor that is not taken.
  for (node = list_begin(&thread->filemap); node != list_end(&thread->filemap);
       node = list_next(node), fd++) {
    struct filemap_t *entry = list_entry(node, struct filemap_t, ptr);
    if (entry->fd > fd) {
      // Select the next node because list_insert requires the which element
      // to insert before.
      node = list_next(node);
      break;
    }
  }

  // This is to handle integer overflows for the file descriptor.  Since a
  // valid file descriptor is >= 2(on pintos), and a file descriptor is an
  // integer, that means any program can theoretically open 2**32-1 files at
  // once. Of course, this is not a case we are planning on seeing often as the
  // os will usually run out of memory before you hit that limit.  Another case
  // is when a program runs for too long, opening and closing files, if you do
  // not reuse file descriptor numbers that have been closed and always start
  // from the maximum file descriptor, you can reach the maximum value for the
  // file descriptor. However, since this specific implementation reuses file
  // descriptors, that is not a possible scenario.
  if (fd < FD_START) {
    // TODO: remove magic number
    sys_exit(-1);
  }

  // Initialize enough memory for the file.
  struct filemap_t *entry = malloc(sizeof(struct filemap_t));

  // Return on failure to acquire enough memory.
  if (entry == NULL) {
    return -1;
  }
  entry->fd = fd;

  // TODO: semaphores
  entry->file = filesys_open(filename);

  // Make sure that the file was opened.
  if (entry->file == NULL) {
    // Release the memory occupied by entry as to not create a memory leak.
    free(entry);
    return -1;
  }

  // Insert it before the node that we found was to be greter than the file
  // descriptor we have
  list_insert(node, &entry->ptr);
  return fd;
}

// Lifted from
// https://web.stanford.edu/~ouster/cgi-bin/cs140-spring18/pintos/pintos_3.html#SEC32
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user(const uint8_t *uaddr) {
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

// Lifted from
// https://web.stanford.edu/~ouster/cgi-bin/cs140-spring18/pintos/pintos_3.html#SEC32
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte) {
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}
