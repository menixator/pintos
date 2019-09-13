#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "lib/user/syscall.h"
#include "threads/synch.h"
#include "threads/thread.h"

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

enum pload_status_t { LOADING, SUCCESS, FAIL };

struct process {
  pid_t pid;
  enum pload_status_t load_status;
  struct list_elem ptr;

  // Sempahore to wait for a process
  struct semaphore wait;
  struct semaphore load;
};

#endif /* userprog/process.h */
