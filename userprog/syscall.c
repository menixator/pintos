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

// Implemented syscalls-end

// Helpers
// Loads a paramters from a interrupt frame's stack.
static uint32_t load_param(struct intr_frame *frame, int offset);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *frame UNUSED) {
  // frame is an interrupt stack frame.
  uint32_t syscall_variant = load_param(frame, SYSCALL_VARIANT);
  switch (syscall_variant) {
  // exit syscall
  case SYS_EXIT:
    sys_exit(load_param(frame, ARG_0));
  }
  thread_exit();
}

static uint32_t load_param(struct intr_frame *frame, int offset) {
  return *((uint32_t *)frame->esp + offset);
}

// Respond to an exit syscall
void sys_exit(int status) {
  struct thread *curr = thread_current();
  curr->exit_code = status;
  thread_exit();
}
