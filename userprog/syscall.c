#include "userprog/syscall.h"

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
    sys_exit((int)load_param(frame, ARG_0));
    return;
  }
  case SYS_WRITE: {
    frame->eax = sys_write((int)load_param(frame, ARG_0),
                           (const void *)load_param(frame, ARG_1),
                           (unsigned int)load_param(frame, ARG_2));
    return;
  }
  case SYS_READ: {
    frame->eax = sys_read((int)load_param(frame, ARG_0),
                          (void *)load_param(frame, ARG_1),
                          (unsigned int)load_param(frame, ARG_2));
    return;
  }
  case SYS_OPEN: {
    frame->eax = sys_open((const char *)load_param(frame, ARG_0));
    return;
  }

  case SYS_HALT: {
    sys_halt();
    return;
  }

  case SYS_CREATE: {
    frame->eax = sys_create((const char *)load_param(frame, ARG_0),
                            (unsigned int)load_param(frame, ARG_1));
    return;
  }

  case SYS_TELL: {
    frame->eax = sys_tell((int)load_param(frame, ARG_0));
    return;
  }

  case SYS_SEEK: {
    sys_seek((int)load_param(frame, ARG_0), (unsigned)load_param(frame, ARG_1));
    return;
  }

  case SYS_REMOVE: {
    frame->eax = sys_remove((const char *)load_param(frame, ARG_0));
    return;
  }
  case SYS_FILESIZE: {
    frame->eax = sys_filesize((int)load_param(frame, ARG_0));
    return;
  }

  case SYS_CLOSE: {
    sys_close((int)load_param(frame, ARG_0));
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
    sys_exit(ERROR_EXIT);
  }
  return *(((uint32_t *)(frame->esp + offset)));
}

int sys_write(int fd, const void *buffer, unsigned int length) {
  // TODO: pointer validation
  if (fd == STDOUT_FILENO) {
    putbuf((const char *)buffer, length);
    return length;
  }

  struct filemap_t *entry = find_filemap(fd);

  if (entry == NULL) {
    sys_exit(ERROR_EXIT);
  }

  sema_down(&fs_sem);
  int written = file_write(entry->file, buffer, length);
  sema_up(&fs_sem);
  return written;
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
  // once. Of course, this is not a case we are planning on seeing -- as the
  // os will usually run out of memory before you hit that limit.  Another case
  // is when a program runs for too long, opening and closing files, if you do
  // not reuse file descriptor numbers that have been closed and always start
  // from the maximum file descriptor, you can reach the maximum value for the
  // file descriptor. However, since this specific implementation reuses file
  // descriptors, that is not a possible scenario.
  if (fd < FD_START) {
    sys_exit(ERROR_EXIT);
  }

  // Initialize enough memory for the file.
  struct filemap_t *entry = malloc(sizeof(struct filemap_t));

  // Return on failure to acquire enough memory.
  if (entry == NULL) {
    return -1;
  }
  entry->fd = fd;

  sema_down(&fs_sem);
  entry->file = filesys_open(filename);
  sema_up(&fs_sem);

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

int sys_read(int fd, void *buffer, unsigned int length) {
  if (fd == STDIN_FILENO) {
    unsigned int i;
    for (i = 0; i < length; i++) {
      if (!put_user((uint8_t *)buffer + i, (uint8_t)input_getc())) {
        sys_exit(ERROR_EXIT);
      }
    }
    return i;
  }
  // TODO: validate buffer pointer

  struct filemap_t *entry = find_filemap(fd);

  if (entry == NULL) {
    sys_exit(ERROR_EXIT);
  }

  sema_down(&fs_sem);
  int read = file_read(entry->file, buffer, length);
  sema_up(&fs_sem);
  return read;
}
// Lifted from
// https://web.stanford.edu/~ouster/cgi-bin/cs140-spring18/pintos/pintos_3.html#SEC32
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user(const uint8_t *uaddr) {
  if ((uint32_t)uaddr >= (uint32_t)PHYS_BASE)
    return -1;
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

struct filemap_t *find_filemap(int fd) {
  // Find a number to assign as a file descriptor
  struct thread *thread = thread_current();
  struct list_elem *node;
  // Loop over each filemap_t entry we have stored for the thread and find a
  // file descriptor that is not taken.
  for (node = list_begin(&thread->filemap); node != list_end(&thread->filemap);
       node = list_next(node), fd++) {
    struct filemap_t *entry = list_entry(node, struct filemap_t, ptr);
    if (entry->fd > fd) {
      // The file list is sorted. So if the file descriptor of the entry is
      // greater than the one we are looking for, we can be sure that it does
      // not exist
      break;
    }
    if (entry->fd == fd) {
      return entry;
    }
  }
  return NULL;
}

void sys_halt() { shutdown_power_off(); }

bool sys_create(const char *name, unsigned int size) {
  // If name is null, return false.
  if (name == NULL) {
    sys_exit(ERROR_EXIT);
  }

  // If it is a bad pointer, exit the program
  if (get_user((const uint8_t *)name) == -1) {
    sys_exit(ERROR_EXIT);
  }

  bool status;
  sema_down(&fs_sem);
  status = filesys_create(name, size);
  sema_up(&fs_sem);
  return status;
}

unsigned sys_tell(int fd) {
  // Get the file
  struct filemap_t *entry = find_filemap(fd);
  if (entry == NULL) {
    sys_exit(ERROR_EXIT);
  }

  // Always push down on the semaphore before doing anything with the file
  // system
  sema_down(&fs_sem);
  unsigned int loc = file_tell(entry->file);
  sema_up(&fs_sem);
  return loc;
}

void sys_seek(int fd, unsigned pos) {
  struct filemap_t *entry = find_filemap(fd);
  if (entry == NULL) {
    sys_exit(ERROR_EXIT);
  }

  sema_down(&fs_sem);
  file_seek(entry->file, pos);
  sema_up(&fs_sem);
}

bool sys_remove(const char *filename) {
  sema_down(&fs_sem);
  bool success = filesys_remove(filename);
  sema_up(&fs_sem);

  return success;
}

int sys_filesize(int fd) {
  struct filemap_t *entry = find_filemap(fd);
  if (entry == NULL) {
    sys_exit(ERROR_EXIT);
  }

  sema_down(&fs_sem);
  int length = file_length(entry->file);
  sema_up(&fs_sem);
  return length;
}

void sys_close(int fd) {

  struct filemap_t *entry = find_filemap(fd);
  if (entry == NULL) {
    return;
  }

  sema_down(&fs_sem);
  file_close(entry->file);
  sema_up(&fs_sem);

  list_remove(&entry->ptr);
  // Free the memory
  free(entry);
}

void close_all_files(struct thread *cur) {
  // Freeing up all the files
  for (struct list_elem *node = list_begin(&cur->filemap);
       node != list_end(&cur->filemap); node = list_next(node)) {
    struct filemap_t *filemap = list_entry(node, struct filemap_t, ptr);
    sema_down(&fs_sem);
    file_close(filemap->file);
    sema_up(&fs_sem);
    list_remove(&filemap->ptr);
    // free up the memory
    free(filemap);
  }
}
