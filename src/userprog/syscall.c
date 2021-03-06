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



static void syscall_handler (struct intr_frame *);



//funcitons in system calls
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
int sys_write(int fd, void *buffer, unsigned size);

//help function
int sys_badmemory_access(void);
void getfd(struct list *fd_list, struct file_descriptor **mrright, int fd);

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
  case SYS_HALT: 
    {
      shutdown_power_off();
      break;
    }

  case SYS_EXIT: 
    {
      int exitcode = *(int *)(f->esp + 4);

      //TODO: need fix
      if(exitcode<-1000){
        sys_badmemory_access();
      }
     

      sys_exit(exitcode);
      break;
    }

  case SYS_EXEC: 
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

  case SYS_WAIT: 
    {
      if(!check_buffer(f->esp+4, sizeof(pid_t))){
        sys_badmemory_access();
      }    

      pid_t pid = *(int *)(f->esp+4);

      int return_code = sys_wait(pid);

      f->eax = return_code;
      break;
    }

  case SYS_CREATE: 
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

  case SYS_REMOVE:
    {

      char* filename = *(char **)(f->esp+4);
      
      if(!check_buffer(f->esp+4, sizeof(char*))){
        sys_badmemory_access();
      } 


      bool return_code = sys_remove(filename);
      f->eax = return_code;
      break;
    }

  case SYS_OPEN:
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

  case SYS_FILESIZE: 
    {
      int fdnumber = *(int *)(f->esp+4);

      int return_code = sys_filesize(fdnumber);
      f->eax = return_code;
      break;
    }

  case SYS_READ: 
    {
      if(!check_buffer(f->esp+4, sizeof(int))){
        sys_badmemory_access();
      } 
      if(!check_buffer(f->esp+8, sizeof(void*))){
        sys_badmemory_access();
      }
      if(!check_buffer(f->esp+12, sizeof(unsigned))){
        sys_badmemory_access();
      }

      int fd = *(int *)(f->esp+4);
      void *buffer = *(void **)(f->esp+8);
      unsigned size = *(unsigned *)(f->esp+12);

      //TODO:read-bad-ptr
      for(int i=0; i<size; i++){
        if( get_user((const uint8_t *)(buffer+i))<0){
          sys_badmemory_access();
        }
      }


      int return_code = sys_read(fd, buffer, size);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WRITE: 
    {
      if(!check_buffer(f->esp+4, sizeof(int))){
        sys_badmemory_access();
      } 
      if(!check_buffer(f->esp+8, sizeof(void*))){
        sys_badmemory_access();
      }
      if(!check_buffer(f->esp+12, sizeof(unsigned))){
        sys_badmemory_access();
      }

      int fd = *(int *)(f->esp+4);
      void *buffer = *(void **)(f->esp+8);
      unsigned size = *(unsigned *)(f->esp+12);

      if( get_user((const uint8_t *)buffer)<0){
        sys_badmemory_access();
      }

      int return_code = sys_write(fd, buffer, size);
      f->eax = return_code;
      break;
    }

  case SYS_SEEK: 
    {
      int fdnumber = *(int *)(f->esp+4);
      unsigned position = *(unsigned *)(f->esp+8);


      sys_seek(fdnumber, position);
      break;
    }

  case SYS_TELL: 
    {
      int fdnumber = *(int *)(f->esp+4);

      unsigned return_code = sys_tell(fdnumber);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_CLOSE: 
    {
      if(!check_buffer(f->esp+4, sizeof(int))){
        sys_badmemory_access();
      } 

      int fdnumber = *(int *)(f->esp+4);

      //check valid memory access
      if( get_user((const uint8_t *)(f->esp+4))<0){
        sys_badmemory_access();
      }

      //printf("sys_close,fd_number%d\n", fdnumber);
      
      sys_close(fdnumber);

      break;
    }


  /* unhandled case */
  default:
    printf("system call %d is unimplemented!\n", syscall_number);
    sys_exit(-1);
    break;
  }

}

/****************** System Call Implementations ********************/


void sys_exit(int status) {
  char *save_ptr;
  char *token = strtok_r ((char *)thread_current()->name, " ", &save_ptr);
  printf("%s: exit(%d)\n", token, status);

  struct process_control_block *pcb = thread_current()->pcb;
  if(pcb != NULL) {
    pcb->exited = true;
    pcb->exitcode = status;
    sema_up (&pcb->sema_wait);
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

  lock_acquire(&filesys_lock);
  bool return_code = false;

  return_code = filesys_create(filename, filesize);
  lock_release(&filesys_lock);

  return return_code;
}

bool sys_remove(char *filename) {

  lock_acquire(&filesys_lock);
  bool return_code = false;

  return_code = filesys_remove(filename);
  lock_release(&filesys_lock);

  return return_code;

}

int sys_open(const char* filename) {

  lock_acquire(&filesys_lock);

  struct file *file_toopen = filesys_open(filename);

  if(file_toopen==NULL){

  lock_release(&filesys_lock);
    return -1;
  }

  struct file_descriptor* fd = palloc_get_page(0);
  fd->file = file_toopen; 

  struct thread *t = thread_current();  
  struct list *fd_list = &(t->file_descriptors);

  if (list_empty(fd_list)) {
    
    fd->fd_number = FD_BASE;
    list_push_back(fd_list, &(fd->elem));
  lock_release(&filesys_lock);
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

  lock_release(&filesys_lock);
  
  return fd->fd_number;
}

int sys_filesize(int fd) {

  lock_acquire(&filesys_lock);
  struct file_descriptor* file_tosize = NULL;

  struct thread *t = thread_current();  
  struct list *fd_list = &(t->file_descriptors);
  
  getfd(fd_list, &file_tosize,fd);  

  if(!list_empty(fd_list) && file_tosize && file_tosize->file) {
    return file_length(file_tosize->file);
  }

  lock_release(&filesys_lock);
  return -1;

}

void sys_seek(int fd, unsigned position) {

  lock_acquire(&filesys_lock);
  
  struct file_descriptor* file_toseek = NULL;

  struct thread *t = thread_current();  
  struct list *fd_list = &(t->file_descriptors);
  
  getfd(fd_list, &file_toseek,fd);  


  if(!list_empty(fd_list) && file_toseek && file_toseek->file) {
    file_seek(file_toseek->file,position);
  }

  lock_release(&filesys_lock);

  return;

}

unsigned sys_tell(int fd) {

  lock_acquire(&filesys_lock);

  struct file_descriptor* file_totell = NULL;

  struct thread *t = thread_current();  
  struct list *fd_list = &(t->file_descriptors);
  
  getfd(fd_list, &file_totell,fd);  

  if(!list_empty(fd_list) && file_totell && file_totell->file) {
    return file_tell(file_totell->file);
  }

  lock_release(&filesys_lock);

  return -1;

}

void sys_close(int fd) {

  lock_acquire(&filesys_lock);

  struct file_descriptor* file_toclose = NULL;

  struct thread *t = thread_current();  
  struct list *fd_list = &(t->file_descriptors);
  
  getfd(fd_list, &file_toclose,fd);  


  if(!list_empty(fd_list) && file_toclose && file_toclose->file) {
    file_close(file_toclose->file);
    list_remove(&(file_toclose->elem));
  }

  lock_release(&filesys_lock);

  return;
}

void getfd(struct list *fd_list, struct file_descriptor **mrright, int fd)
{

  lock_acquire(&filesys_lock);

  struct list_elem *iter = NULL;

  if(list_empty(fd_list)){
    return;
  }

  //printf("..getfd,list not empty\n");
  for(iter = list_begin(fd_list);iter != list_end(fd_list); iter = list_next(fd_list))
    {
      struct file_descriptor *desc = list_entry(iter, struct file_descriptor, elem);
      if(desc->fd_number == fd) {

        *mrright = desc;
        return;
      }
    }

  lock_release(&filesys_lock);

  return;
}

int sys_read(int fd, void *buffer, unsigned size) {


  int ret;

  lock_acquire(&filesys_lock);

  if(fd == 0) { // stdin
    unsigned i;
    for(i = 0; i < size; ++i) {
      //((uint8_t *)buffer)[i] = input_getc();
     
      (*(int **)buffer)[i] = input_getc();

    }

  lock_release(&filesys_lock);
    return size;
  }
  else {
    // read from file

    struct file_descriptor* file_toread = NULL;

    struct thread *t = thread_current();  
    struct list *fd_list = &(t->file_descriptors);
  
    getfd(fd_list, &file_toread,fd); 
    
    if(file_toread && file_toread->file) {
      return file_read(file_toread->file, buffer, size);
    }

  lock_release(&filesys_lock);
    
    return -1; 
  }
}

int sys_write(int fd, void *buffer, unsigned size) {

  lock_acquire(&filesys_lock);

  int ret;

  if(fd == 1) {
    // output to screem
    putbuf(buffer, size);

  lock_release(&filesys_lock);
    return size;
  }
  else {
    // output to file

    struct file_descriptor* file_towrite = NULL;

    struct thread *t = thread_current();  
    struct list *fd_list = &(t->file_descriptors);
  
    getfd(fd_list, &file_towrite,fd); 
    
    if(file_towrite && file_towrite->file) {
      return file_write(file_towrite->file, buffer, size);
    }
  lock_release(&filesys_lock);
    
    return -1;
  }



}

//Help Functions

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



