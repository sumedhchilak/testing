#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct process_info{
    // tid_t tid;
    // int exit_status;
    // bool prev_wait;
    // bool exit;
    // struct list_elem child_elem;
    // struct semaphore sema_wait;
    // struct semaphore sema_load;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
// struct process_info* get_child(tid_t child_tid, struct thread *t);

#endif /* userprog/process.h */
