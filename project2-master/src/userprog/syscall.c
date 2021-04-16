#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <threads/vaddr.h>
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "lib/syscall-nr.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/inode.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "threads/init.h"


static void syscall_handler (struct intr_frame *);
/* check validity of memory address*/
static bool valid(void *p);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* Sumedh driving */
  uint32_t *p = (uint32_t*)f->esp;
  valid(p);
  int status = *p;
  switch(status) {

    case SYS_HALT:
    {
      sys_halt();
      break;
    }

    case SYS_EXIT:
    {
      valid(p + 1);
      int exit_status = p[1];
      sys_exit (exit_status);
      break;
    }

    case SYS_EXEC:
    { 
      valid(p + 1);
      valid(p[1]);
      const char* cmd_line = p[1];
      f->eax = sys_exec(cmd_line);
      break;
    }
    /* Abinith driving */
    case SYS_WAIT:
    {
      valid(p + 1);
      pid_t child = p[1];
      f->eax = sys_wait(child);
      break;
    }

    case SYS_CREATE:
    {
      valid(p + 1);
      valid(p[1]);
      valid(p + 2);
      const char* file = p[1];
      unsigned initial_size = p[2];
      f->eax = sys_create(file, initial_size);
      break;
    }

    case SYS_REMOVE:
    {
      valid(p + 1);
      valid(p[1]);
      const char* file = p[1];
      f->eax = sys_remove(file);
      break;
    }
    /* Avi driving */
    case SYS_OPEN:
    {
      valid(p + 1);
      valid(p[1]);
      const char* file = p[1];
      f->eax = sys_open(file);
      break;
    }

    case SYS_FILESIZE:
    {
      valid(p + 1);
      int fd = p[1];
      f->eax = sys_filesize(fd);
      break;
    }
    /* Kaushik driving */
    case SYS_READ:
    {
      valid(p + 1);
      valid(p + 2);
      valid(p[2]);
      valid(p + 3);
      int fd = p[1];
      void *buffer = p[2];
      unsigned size = p[3];
      f->eax = sys_read(fd, buffer, size);
      break;
    }

    case SYS_WRITE:
    {
      valid(p + 1);
      valid(p + 2);
      valid(p[2]);
      valid(p + 3);
      int fd = p[1];
      const void *buffer = p[2];
      unsigned size = p[3];
      f->eax = sys_write(fd, buffer, size);
      break;
    }
    /* Avi driving */
    case SYS_SEEK:
    {
      valid(p + 1);
      valid(p + 2);
      int fd = p[1];
      unsigned position = p[2];
      sys_seek(fd, position);
      break;
    }

    case SYS_TELL:
    {
      valid(p + 1);
      int fd = p[1];
      f->eax = sys_tell(fd);
      break;
    }

    case SYS_CLOSE:
    {
      valid(p + 1);
      int fd = p[1];
      sys_close(fd);
      break;
    }
      
    default:
    {
      printf ("system call!\n");
      sys_exit(-1);
      break;
    }
  }
}

bool
valid (void * p)
{
  char * ptr = (char *) p;
  /* Sumedh driving */
  if(ptr == NULL) {
    sys_exit(-1);
    return 0;
  }
  if(!(ptr != NULL && is_user_vaddr(ptr) && 
  pagedir_get_page(thread_current()->pagedir, ptr) != NULL)){
    sys_exit(-1);
    return false;
  }
  else{
    return true;
  }
}

void 
sys_halt (void)
{
  shutdown_power_off ();
  return;
}

void
sys_exit (int status) {
  /* Abinith driving */
  struct thread *curr = thread_current();
  curr->exit_status = status;
  printf ("%s: exit(%d)\n", thread_current ()->name, status);

if(curr->exec_file != NULL){
    sema_down(&sema_file);
    file_close (curr->exec_file);
    sema_up(&sema_file);
  }

  sema_up(&curr->sema_wait);
  sema_down(&curr->sema_free);

  struct list_elem *element;
  for(element = list_begin(&curr->list_child);
    element != list_end(&curr->list_child); element = list_next(element)) {
      struct thread *child = list_entry(element, struct thread, child_elem);
      sema_up(&child->sema_free);
  }
  thread_exit();
}

struct thread*
get_child(tid_t c_tid, struct thread * curr) {
  struct list* cldrn = &curr->list_child;
  if(!list_empty (cldrn)) {
    struct list_elem * last = cldrn->tail.prev;
    struct thread* recent_child = list_entry(last,
      struct thread, child_elem);
    return recent_child;
  }
  return NULL;
}

pid_t
sys_exec (const char *cmd_line) {
  /* Sumedh driving */
  tid_t c_tid = process_execute(cmd_line);
  if(c_tid == TID_ERROR){
    return -1;
  }
  struct thread* child = get_child(c_tid, thread_current());
  if(child == NULL){
    return -1;
  }
  sema_down(&child->sema_load);
  int loaded = child->loaded;
  if(loaded == 0){
    return -1;
  }
  return c_tid;
}  

/* Avi driving */
int
sys_wait (int pid) {
  return process_wait(pid);
}

bool
sys_create (const char* file, unsigned initial_size) {
  sema_down(&sema_file);
  bool val = filesys_create(file, initial_size);
  sema_up(&sema_file);
  return val;
}

/* Kaushik driving */
bool 
sys_remove (const char *file) {
  sema_down (&sema_file);
  bool result = filesys_remove (file);
  sema_up (&sema_file);
  return result;
}

int
sys_open (const char* file) {
  sema_down(&sema_file);
  struct thread *curr = thread_current();
  int value = -1;
  int i = 2;
  for(; i < 128; i++) {
    if(curr->file_d[i] == NULL) {
      struct file *new_f = filesys_open(file);
      if(new_f != NULL) {
        curr->file_d[i] = new_f;
        value = i;
      }
      break;
    }
  }
  sema_up(&sema_file);
  return value;
}

int
sys_filesize (int fd) {
  /* Avi driving */
  if(fd < 1 || fd >= 128) {
    return -1;
  }
  struct thread *curr = thread_current();
  int size = -1;
  struct file *file = curr->file_d[fd];
  sema_down(&sema_file);
  if(file == NULL) {
    size = -1;
  }
  else {
    size = file_length(file);
  }
  sema_up(&sema_file);
  return size;
}

int
sys_read (int fd, void *buffer, unsigned size) {
  if(fd < 1 || fd >= 128) {
    return -1;
  }
  sema_down(&sema_file);
  int val = -1;
  if(fd == STDIN_FILENO) {
    char* buffer_copy = (char *) buffer;
    unsigned i;
    for(i = 0; i < size; i++) {
      buffer_copy[i] = input_getc();
    }
    val = size;
  }
  else if(fd == STDOUT_FILENO){
    val = -1;
  }
  else {
    struct thread *curr = thread_current();
    struct file* file = curr->file_d[fd];
    if(file == NULL) {
      val = -1;
    }
    else {
      int res = file_read(file, (char*) buffer, size);
      val = res;
    }
  }
  sema_up(&sema_file);
  return val;
}

int
sys_write (int fd, const void *buffer, unsigned size) {
  /* Abinith driving */
  if(fd < 1 || fd >= 128){
    return -1;
  }
  sema_down(&sema_file);
  int written = 0;
  if(fd == STDOUT_FILENO) {
    written = size;
    putbuf((const char *) buffer, size);
  }
  else {
    struct thread *curr = thread_current();
    struct file *file = curr->file_d[fd];
    if(file == NULL){
      written = 0;
    }
    else {
      written = file_write(file, buffer, size);
    }
  }
  sema_up(&sema_file);
  return written;
}

void 
sys_seek (int fd, unsigned position) {
  /* Sumedh driving */
  if(fd < 1 || fd >= 128){
    return;
  }
  else{
    sema_down(&sema_file);
    struct thread * curr = thread_current();
    struct file *file = curr->file_d[fd];
    if(file != NULL) {
      file_seek(file, position);
    }
    sema_up(&sema_file);
  }
  return;
}

unsigned
sys_tell (int fd) {
  /* Kaushik driving */
  if(fd < 1 || fd >= 128) {
    return -1;
  }
  unsigned value = -1;
  sema_down(&sema_file);
  struct thread *curr = thread_current();
  struct file *file = curr->file_d[fd];
  if(file != NULL) {
    value = file_tell(file);
    sema_up(&sema_file);
    return value;
  }
  sema_up(&sema_file);
  return value;
}

/* Abinith driving */
void
sys_close (int fd) {
  if(fd < 1 || fd >= 128){
    return;
  }
  sema_down(&sema_file);
  struct thread *curr = thread_current();
  struct file * file = curr->file_d[fd];
  if(file != NULL) {
    file_close(file);
    curr->file_d[fd] = 0;
  }
  sema_up(&sema_file);
}

struct file*
find_file(int fd) {
  struct thread *curr_thread = thread_current();
  struct list_elem *element;
  for(element = list_begin(&curr_thread->open_file_list);
    element != list_end(&curr_thread->open_file_list); 
      element = list_next(element)){
        struct file * file_elem = list_entry(element, struct file, open_elem);
        if(file_elem->fd == fd){
          return file_elem;
        }
  }
    return NULL;
}
