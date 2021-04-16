#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"
#include <stdbool.h>


void syscall_init (void);

/* Sys Calls */

void sys_halt (void);
void sys_exit (int status);
struct thread* get_child(int c_tid, struct thread *curr);
int sys_exec (const char *cmd_line);
struct thread* find_tid (int pid, struct thread *curr);
int sys_wait (int pid);
bool sys_create (const char* file, unsigned initial_size);
bool sys_remove (const char* file);
int sys_open (const char* file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, const void *buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);
struct file* find_file(int fd);
void remove_file (struct list_elem * target);

#endif /* userprog/syscall.h */
