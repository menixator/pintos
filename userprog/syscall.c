#include "userprog/syscall.h"
#include "threads/interrupt.h"
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

// Implemented syscalls
// Exits a program with a provided status.
void sys_exit(int status);
int sys_write(int fd, const void* buffer, unsigned int length);

// Implemented syscalls-end

// Helpers
// Loads a paramters from a interrupt frame's stack.
static uint32_t load_param(struct intr_frame *frame, int offset);
static int get_user(const uint8_t *uaddr);

static bool put_user(uint8_t *udst, uint8_t byte);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *frame UNUSED) {
  // frame is an interrupt stack frame.
  uint32_t syscall_variant = load_param(frame, SYSCALL_VARIANT);
  switch (syscall_variant) {
  // exit syscall
  case SYS_EXIT:{
      sys_exit(load_param(frame, ARG_0));
      return;
    }
  case SYS_WRITE: {
      frame->eax = sys_write(
          (int) load_param(frame, ARG_0),
          (const void*) load_param(frame, ARG_1),
          (unsigned int) load_param(frame, ARG_2)
      );
      return;
    }
  }
  // TODO: remove
  printf("error: you did not return within your case statement up there. Thread is exiting now\n");
  thread_exit();
}

static uint32_t load_param(struct intr_frame *frame, int offset) {
  if (get_user(frame->esp + offset) == -1) {
    sys_exit(-1);
  }
  return *(((uint32_t *)(frame->esp+offset)));
}


// TODO: implement for other files
int sys_write(int fd, const void* buffer, unsigned int length){
  // TODO: pointer validation
  if (fd == STDOUT_FILENO) {
    putbuf((const char*)buffer, length);
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

// Lifted from https://web.stanford.edu/~ouster/cgi-bin/cs140-spring18/pintos/pintos_3.html#SEC32
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user(const uint8_t *uaddr) {
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

// Lifted from https://web.stanford.edu/~ouster/cgi-bin/cs140-spring18/pintos/pintos_3.html#SEC32
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
