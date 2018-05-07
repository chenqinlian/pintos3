#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"


#ifdef DEBUG
#define _DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define _DEBUG_PRINTF(...) /* do nothing */
#endif

static void syscall_handler (struct intr_frame *);

static void check_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int memread_user (void *src, void *des, size_t bytes);

static struct file_descriptor* find_file_desc(struct thread *, int fd);


void sys_exit (int);
pid_t sys_exec (const char *cmdline);
int sys_wait (pid_t pid);

bool sys_create(char *filename, unsigned filesize);
bool sys_remove(char *filename);
int sys_open(const char* filename);
int sys_filesize(int fd);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);

//help function
int sys_badmemory_access(void);


//memory check function
bool check_addr (const uint8_t *uaddr);
bool check_buffer (void* buffer, unsigned size);
static int get_user (const uint8_t *uaddr);




struct lock filesys_lock;

void
syscall_init (void)
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) {
  if (lock_held_by_current_thread(&filesys_lock))
    lock_release (&filesys_lock);

  sys_exit (-1);
  NOT_REACHED();
}

static void
syscall_handler (struct intr_frame *f)
{

    if(!check_addr(f->esp)){
      thread_exit();
    }
  
  
    if(!check_buffer(f->esp,4)){
      sys_badmemory_access();
    }
  

    int syscall_number = *(int *)(f->esp);


  switch (syscall_number) {
  case SYS_HALT: // 0
    {
      shutdown_power_off();
      break;
    }

  case SYS_EXIT: // 1
    {
      int exitcode = *(int *)(f->esp + 4);

      //TODO: need fix
      if(exitcode<-1000){
        sys_badmemory_access();
      }
     

      sys_exit(exitcode);
      break;
    }

  case SYS_EXEC: // 2
    {
      void* cmdline = *(char **)(f->esp+4);



      //check buffer
      check_buffer(f->esp+4, sizeof(cmdline));

      //check cmdline
      if( get_user((const uint8_t *)cmdline)<0){
        sys_badmemory_access();
      }

      //printf("cmdline:%s\n", (const char*) cmdline);

      int return_code = sys_exec((const char*) cmdline);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WAIT: // 3
    {
      if(!check_buffer(f->esp+4, sizeof(pid_t))){
        sys_badmemory_access();
      }    

      pid_t pid = *(int *)(f->esp+4);

      int return_code = sys_wait(pid);

      f->eax = return_code;
      break;
    }

  case SYS_CREATE: // 4
    {
      //check whether pointer is below PHYS_BASE
      if(!check_buffer(f->esp+4, sizeof(char*))){
        sys_badmemory_access();
      } 

      if(!check_buffer(f->esp+8, sizeof(unsigned))){
        sys_badmemory_access();
      } 

      char* filename = *(char **)(f->esp+4);
      unsigned filesize = *(unsigned **)(f->esp+8);
      
      //printf("filename:%s\n",filename);
      //printf("filesize:%d\n",filesize);

      //check valid memory access
      if( get_user((const uint8_t *)filename)<0){
        sys_badmemory_access();
      }

      int return_code = sys_create(filename, filesize);
      f->eax = return_code;
      break;
    }

  case SYS_REMOVE: // 5
    {
      const char* filename;
      bool return_code;

      memread_user(f->esp + 4, &filename, sizeof(filename));

      return_code = sys_remove(filename);
      f->eax = return_code;
      break;
    }

  case SYS_OPEN: // 6
    {
      //check whether pointer is below PHYS_BASE
      if(!check_buffer(f->esp+4, sizeof(char*))){
        sys_badmemory_access();
      } 

      char* filename = *(char **)(f->esp+4);

      //check valid memory access
      if( get_user((const uint8_t *)filename)<0){
        sys_badmemory_access();
      }

      int return_code = sys_open(filename);
      f->eax = return_code;
      
      break;
    }

  case SYS_FILESIZE: // 7
    {
      int fd, return_code;
      memread_user(f->esp + 4, &fd, sizeof(fd));

      return_code = sys_filesize(fd);
      f->eax = return_code;
      break;
    }

  case SYS_READ: // 8
    {
      int fd, return_code;
      void *buffer;
      unsigned size;

      memread_user(f->esp + 4, &fd, sizeof(fd));
      memread_user(f->esp + 8, &buffer, sizeof(buffer));
      memread_user(f->esp + 12, &size, sizeof(size));

      return_code = sys_read(fd, buffer, size);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WRITE: // 9
    {
      int fd, return_code;
      const void *buffer;
      unsigned size;

      memread_user(f->esp + 4, &fd, sizeof(fd));
      memread_user(f->esp + 8, &buffer, sizeof(buffer));
      memread_user(f->esp + 12, &size, sizeof(size));

      return_code = sys_write(fd, buffer, size);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_SEEK: // 10
    {
      int fd;
      unsigned position;

      memread_user(f->esp + 4, &fd, sizeof(fd));
      memread_user(f->esp + 8, &position, sizeof(position));

      sys_seek(fd, position);
      break;
    }

  case SYS_TELL: // 11
    {
      int fd;
      unsigned return_code;

      memread_user(f->esp + 4, &fd, sizeof(fd));

      return_code = sys_tell(fd);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_CLOSE: // 12
    {
      int fd;
      memread_user(f->esp + 4, &fd, sizeof(fd));

      sys_close(fd);
      break;
    }


  /* unhandled case */
  default:
    printf("[ERROR] system call %d is unimplemented!\n", syscall_number);

    // ensure that waiting (parent) process should wake up and terminate.
    sys_exit(-1);
    break;
  }

}

/****************** System Call Implementations ********************/


void sys_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);

  // The process exits.
  // wake up the parent process (if it was sleeping) using semaphore,
  // and pass the return code.
  struct process_control_block *pcb = thread_current()->pcb;
  if(pcb != NULL) {
    pcb->exited = true;
    pcb->exitcode = status;
    sema_up (&pcb->sema_wait);
  }
  else {
    // pcb == NULL probably means that previously
    // page allocation has failed in process_execute()
  }

  thread_exit();
}

pid_t sys_exec(const char *cmdline) {

  tid_t child_tid = process_execute(cmdline);
  return (pid_t)child_tid;
}

int sys_wait(pid_t pid) {

  return process_wait(pid);
}

bool sys_create(char *filename, unsigned filesize){
  bool return_code = false;

  return_code = filesys_create(filename, filesize);

  return return_code;
}

bool sys_remove(char *filename) {
  bool return_code = false;

  return_code = filesys_remove(filename);

  return return_code;

}

int sys_open(const char* filename) {



  struct file *file_toopen = filesys_open(filename);

  if(file_toopen==NULL){
    return -1;
  }

  struct file_descriptor* fd = palloc_get_page(0);
  fd->file = file_toopen; 

  struct thread *t = thread_current();  
  struct list *fd_list = &(t->file_descriptors);

  //TODO: Rewrite
  if (list_empty(fd_list)) {
    
    fd->fd_number = FD_BASE;
    list_push_back(fd_list, &(fd->elem));
    return FD_BASE;
 
  }
  else {
    //form fd to be put in
    struct list_elem *lastelem = list_back(fd_list);
    struct file_descriptor* fdlast = list_entry(lastelem, struct file_descriptor, elem);
    fd->fd_number = fdlast->fd_number + 1;
    list_push_back(fd_list, &(fd->elem));

    //delete old elem
    list_remove(lastelem);// bug may exist, need check

  }
  
  return fd->fd_number;
}

int sys_filesize(int fd) {
  struct file_descriptor* file_d;

  lock_acquire (&filesys_lock);
  file_d = find_file_desc(thread_current(), fd);

  if(file_d == NULL) {
    lock_release (&filesys_lock);
    return -1;
  }

  int ret = file_length(file_d->file);
  lock_release (&filesys_lock);
  return ret;
}

void sys_seek(int fd, unsigned position) {
  lock_acquire (&filesys_lock);
  struct file_descriptor* file_d = find_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    file_seek(file_d->file, position);
  }
  else
    return; // TODO need sys_exit?

  lock_release (&filesys_lock);
}

unsigned sys_tell(int fd) {
  lock_acquire (&filesys_lock);
  struct file_descriptor* file_d = find_file_desc(thread_current(), fd);

  unsigned ret;
  if(file_d && file_d->file) {
    ret = file_tell(file_d->file);
  }
  else
    ret = -1; // TODO need sys_exit?

  lock_release (&filesys_lock);
  return ret;
}

void sys_close(int fd) {
  lock_acquire (&filesys_lock);
  struct file_descriptor* file_d = find_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    file_close(file_d->file);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
  lock_release (&filesys_lock);
}

int sys_read(int fd, void *buffer, unsigned size) {
  // memory validation : [buffer+0, buffer+size) should be all valid
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == 0) { // stdin
    unsigned i;
    for(i = 0; i < size; ++i) {
      if(! put_user(buffer + i, input_getc()) ) {
        lock_release (&filesys_lock);
        sys_exit(-1); // segfault
      }
    }
    ret = size;
  }
  else {
    // read from file
    struct file_descriptor* file_d = find_file_desc(thread_current(), fd);

    if(file_d && file_d->file) {
      ret = file_read(file_d->file, buffer, size);
    }
    else // no such file or can't open
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  // memory validation : [buffer+0, buffer+size) should be all valid
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == 1) { // write to stdout
    putbuf(buffer, size);
    ret = size;
  }
  else {
    // write into file
    struct file_descriptor* file_d = find_file_desc(thread_current(), fd);

    if(file_d && file_d->file) {
      ret = file_write(file_d->file, buffer, size);
    }
    else // no such file or can't open
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}

/****************** Helper Functions on Memory Access ********************/

bool
check_addr(const uint8_t *uaddr){
  if ((void*)uaddr > PHYS_BASE){
    //thread_exit();
    return false;
  }

  return true;
}

bool
check_buffer (void* buffer, unsigned size){

  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    {
      if(!check_addr((const void*) local_buffer) || get_user((const uint8_t *)local_buffer)<0){
        return false;
      }
      local_buffer++;
    }

  return true;
}

static int
get_user (const uint8_t *uaddr) {
   int result;
   asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
   return result;
}


int sys_badmemory_access(void) {
  sys_exit (-1);
  NOT_REACHED();
}























/****************** Helper Functions on Memory Access ********************/

static void
check_user (const uint8_t *uaddr) {
  // check uaddr range or segfaults
  if(get_user (uaddr) == -1)
    fail_invalid_access();
}

/* Writes a single byte (content is 'byte') to user address 'udst'.
 * 'udst' must be below PHYS_BASE.
 *
 * Returns true if successful, false if a segfault occurred.
 */
static bool
put_user (uint8_t *udst, uint8_t byte) {
  // check that a user pointer `udst` points below PHYS_BASE
  if (! ((void*)udst < PHYS_BASE)) {
    return false;
  }

  int error_code;

  // as suggested in the reference manual, see (3.1.5)
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


/**
 * Reads a consecutive `bytes` bytes of user memory with the
 * starting address `src` (uaddr), and writes to dst.
 *
 * Returns the number of bytes read.
 * In case of invalid memory access, exit() is called and consequently
 * the process is terminated with return code -1.
 */
static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i=0; i<bytes; i++) {
    value = get_user(src + i);
    if(value == -1) // segfault or invalid memory access
      fail_invalid_access();

    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}

/****************** Helper Functions on File Access ********************/

static struct file_descriptor*
find_file_desc(struct thread *t, int fd)
{
  ASSERT (t != NULL);

  if (fd < 3) {
    return NULL;
  }

  struct list_elem *e;

  if (! list_empty(&t->file_descriptors)) {
    for(e = list_begin(&t->file_descriptors);
        e != list_end(&t->file_descriptors); e = list_next(e))
    {
      struct file_descriptor *desc = list_entry(e, struct file_descriptor, elem);
      if(desc->fd_number == fd) {
        return desc;
      }
    }
  }

  return NULL; // not found
}
