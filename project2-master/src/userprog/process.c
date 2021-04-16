
#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, char* copy, 
  void (**eip) (void), void **esp);
static int MAX_SIZE = 16;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  /* Sumedh driving */
  char *file_copy = palloc_get_page(0);
  if(file_copy == NULL){
    return TID_ERROR;
  }
  strlcpy (file_copy, file_name, PGSIZE);
  char *ptr;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (strtok_r(file_copy, " ", &ptr), 
    PRI_DEFAULT, start_process, fn_copy);
  palloc_free_page(file_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and s it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  /* Abinith Driving*/
  char* fn_cpy = palloc_get_page (0);
  char* _ptr;
  /* get file name from command line */
  strlcpy (fn_cpy, file_name, strlen (file_name) + 1);
  strtok_r (fn_cpy, " ", &_ptr);
  success = load (file_name, fn_cpy, &if_.eip, &if_.esp);
  /*Avi Driving*/
  struct thread* t = thread_current();
  palloc_free_page (file_name);
  palloc_free_page(fn_cpy);
  if (!success){ 
    sema_up(&t->sema_load);
    sys_exit(-1);
  }
  /* signal that thread is loaded and free resources */
  t->loaded = 1;
  sema_up(&t->sema_load);

  /*  Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

struct thread*
find_tid (tid_t pid, struct thread *curr){
  struct list_elem *element;
  for(element = list_begin(&curr->list_child);
    element != list_end(&curr->list_child); element = list_next(element)){
      struct thread *child = list_entry(element, struct thread, child_elem);
      if(child->tid == pid){
        return child;
      }
    }
  return NULL;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  /* Sumedh driving */
  struct thread *curr = thread_current();
  if(list_empty(&curr->list_child)){
    return -1;
  }
  struct thread *child = find_tid(child_tid, curr);
  if(child == NULL){
    return -1;
  }
  sema_down(&child->sema_wait);
  int exit_status = child->exit_status;
  /* Kaushik driving */
  list_remove(&child->child_elem);
  sema_up (&child->sema_free);
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  sema_down (&sema_file);
  
  /* file descriptor numbers 0 and 1 are reserved 
  for file standard input and output*/
  int index = 2;
  /* Abinith driving */
  while(index < 128){
    struct file *f = cur->file_d[index];
    /* if file is open -> close it!*/
    if(f)
      file_close(f);
    index++;
  }

  sema_up(&sema_file);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, ing at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, int argc, 
  int ttl_arg_size,void * pg_ptr, const char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF exec_file from FILE_NAME into the current thread.
   Stores the exec_file's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, char *file_copy, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int num = 0;
  int i;
  sema_down (&sema_file);
  int val = 0;
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  /* Open executable file. */
  /* Avi driving */
  file = filesys_open (file_copy);
  if (file == NULL) 
    {      
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  /* End Avi Driving */
  num = 1;

  /* Read and verify exec_file header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      
      printf ("load: %s: error loading exec_file\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file)) 
        {
          
          goto done;
        }
        
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        {
          
          goto done;
        }
        
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable)) 
                {
                  
                  goto done;
                }
            }
          else 
            {
              
              goto done;
            }
          break;
        }
    }
  val = 1;
  sema_up (&sema_file);
  /* Abinith drving */
  uint32_t stack_size = 0; 

  char *token;
  char *ptr;
  int argc = 0;
  int ttl_arg_size = 0;
  int tok_len;
  
  /* create new copy of file_copy with null terminator */
  char* fn_cpy_2 = palloc_get_page(0);
  strlcpy(fn_cpy_2, file_name, strlen (file_name)+1);
  /* tokenize file name with copy and store argc , 
  argv, total arg size to be passed to setup_stack*/
    for(token = strtok_r(fn_cpy_2, " \n\t", &ptr); token != NULL; 
    token = strtok_r(NULL, " \n\t", &ptr)){
    tok_len = (strlen(token) + 1);
    argc++;
    ttl_arg_size += tok_len;
  }
  palloc_free_page(fn_cpy_2);

  void *pg_ptr = palloc_get_page(0);
  if(pg_ptr != NULL){
    if(!setup_stack(esp, argc, ttl_arg_size, pg_ptr, file_name)){
    goto done;
    }
  }
  else{
    goto done;
  }

  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  if(num){
    thread_current ()->exec_file = file;
    file_deny_write (file);
  }
  if(!val){
    sema_up(&sema_file);
  }
  return success;
  /* End Abinith Driving */
}

uint32_t  get_page_size(int argc, int ttl_arg_size){
  /* calculate total size including padding: argc, 
  argv*, ret Value + num args*4 + total arg size */
  uint32_t cur_pg_size = (1 + 1 + 1)*(4) + ((argc+1)*4) + ttl_arg_size;
  return cur_pg_size;
}

uint32_t  get_padding(uint32_t pg_size){
  /* return padding necesssary*/
  int remainder = pg_size % 4;
  return remainder == 0 ? 0 : (4-remainder);
}

char** get_argv(char* fn_argv_cpy, int argc){
  char* argv[argc];
  char *ptr;
  char *token;
  int index = 0;
  for(token = strtok_r(fn_argv_cpy, " ", &ptr); token != NULL; 
    token = strtok_r(NULL, " ", &ptr)){
      *(argv + index) = token;
      index++;
  }
  *(argv + index) = NULL;
  return argv;
}

static uint32_t
create_page (int argc, int ttl_arg_size, const char * file_name, void * pg_ptr)
{
    /*
    STACK DIAGRAM
    Ret Value - 4 bytes
    Arg Count - 4 bytes
    Argv* - 4 byte
    Argv mem addresses - 4 bytes each
    Null terminator - 4 bytes
    Padding bytes
    Argv actual data - varying bytes
  */

 /* dont want to waste time doing anything until overflow is checked */
  uint32_t pg_size = get_page_size(argc, ttl_arg_size);
  uint32_t pg_pad = get_padding(pg_size);

  pg_size += pg_pad;

  if(pg_size > 4096){
    return NULL;
  }
  /* Kaushik Driving */
  uint32_t pg_start_addr = pg_ptr; 
  

  /* add return value */
  * ((uint32_t *) pg_ptr) = NULL; 
  pg_ptr = ((uint32_t *) pg_ptr) + 1; 

  *((uint32_t *) pg_ptr) = argc; 
  pg_ptr =  (uint32_t *) pg_ptr + 1;

  /* End Sumedh Driving */
  /* Kaushik Driving */
  
  /** ADDING ARGV POINTERS AND STRING DATA TO STACK !!!! ***/

  /* adding argv* into stack */
  *((uint32_t *) pg_ptr) = ((uint32_t)(PHYS_BASE - pg_size)) 
    + ((uint32_t)pg_ptr) + 4 - ((uint32_t) pg_start_addr);
 
  /* point to where argv[0] address located*/
  uint32_t * argv_addr = ((uint32_t *) pg_ptr) + 1; 
  
  /* shift pointer after arguments and argv**/
  pg_ptr = ((uint32_t *) pg_ptr) + argc + 1; 
  /* shift pointer after null terminator*/
  pg_ptr = ((uint32_t *) pg_ptr) + 1; 

  /* End Abinith Driving */
  /* Avi Driving */
  
  /* add padding*/
  pg_ptr = (uint32_t)pg_ptr + pg_pad;
  
  char * argv_fn_cpy = palloc_get_page (0);
  if (argv_fn_cpy == NULL)
    return NULL; 
  /* End Kaushik Driving */
  /* Sumedh Driving */
  strlcpy (argv_fn_cpy, file_name, strlen (file_name) + 1);
  
  char **argv = get_argv(argv_fn_cpy, argc);
  
  int i = 0;
  for(; i < argc; i++){
    int arg_size = sizeof (char) * (strlen(argv[i]) + 1);
    memcpy(pg_ptr, argv[i], arg_size);
    uint32_t start = (uint32_t)(PHYS_BASE - pg_size);
    if(start) {
      *argv_addr = start + ((uint32_t)pg_ptr) - ((uint32_t)pg_start_addr);
    }
    pg_ptr += arg_size;
    argv_addr += 1;
  }
  *argv_addr = NULL;
  int size = (uint32_t) pg_ptr - pg_start_addr;
  return size;
  /* End Avi Driving */
}

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both  and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment ing at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          ing at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, int argc, 
  int ttl_arg_size, void* pg_ptr, const char* file_name) 
{
  uint8_t *kpage;
  bool success = false;

  int size = create_page(argc, ttl_arg_size, file_name, pg_ptr);

  if(size == 0){
    goto done;
  }

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success){
        *esp = (char *) PHYS_BASE;
        *esp -= size;
        memcpy(*esp, pg_ptr, size);
      }
      else
        palloc_free_page (kpage);
    }
  done:
    palloc_free_page(pg_ptr);
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
