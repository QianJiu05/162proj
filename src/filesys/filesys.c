#include <stdlib.h>
#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

#include "userprog/process.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
    write_all2_disk();
    free_map_close(); 
}

/* 
  parameter
  path: 路径
  name: 目录的名字
  cwd: 目录结构，把cwd改成当前要创建的目录的父目录，即a/b/c的b
*/
static bool parse_path (const char* path, char* name, struct dir** cwd) {
    if (path == NULL || path[0] == '\0') {
        return false;
    }

    struct dir* current;
    /* 绝对路径 */
    if (path[0] == '/') {
        current = dir_open_root();
    } else {
        /* 相对路径  a/b/c*/
        struct thread* t = thread_current();
        if (t != NULL && t->pcb != NULL && t->pcb->cwd != NULL) {
            current = t->pcb->cwd;
        } else {
            current = dir_open_root();
        }
    }

    if (current == NULL) return false;

    /* 从current路径开始，一步步打开下级目录 */
    size_t len = strlen(path) + 1;
    char* path_copy = malloc(len);
    if (path_copy == NULL) {
        dir_close(current);
        return false;
    } 

    struct inode* inode;

    strlcpy(path_copy, path, len);
    char *save_ptr;
    char *token, *prev_token = NULL;

    // a/b/c/d
    // 
    // prev_token = d -->要创建的
    // token = null 
    // 此时current = c
    int cnt = 0;
    for (token = strtok_r(path_copy, "/", &save_ptr); token != NULL; 
            token = strtok_r (NULL, "/", &save_ptr)) 
    {
        printf("prevtoken=%s, cnt = %d\n",prev_token,cnt);
        cnt++;

        if (prev_token != NULL) {
            /* 找到子目录,存到inode中 */
            if (!dir_lookup(current, prev_token, &inode)) {
                printf("find no child dir\n");
                free(path_copy);
                return false;
            } 
    
            /* 关掉父目录 */
            dir_close(current);
            /* 打开子目录 */
            current = dir_open(inode);
        }        
        
        prev_token = token;
    }

    if (prev_token == NULL) {
        /* 路径为空或只有 '/' */
        dir_close(current);
        free(path_copy);
        return false;
    }
    strlcpy(name, prev_token, strlen(prev_token)+1);
    *cwd = current;
    free(path_copy);

    return true;
}
/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
    block_sector_t inode_sector = 0;
    struct dir* cwd;
    // struct dir* dir = dir_open_root();
    char child_dir_name[NAME_MAX];
    
    if (!parse_path(name,child_dir_name, &cwd)) 
        return false;

    bool success = (cwd != NULL && free_map_allocate(1, &inode_sector) &&
                    inode_create(inode_sector, initial_size) && dir_add(cwd, child_dir_name, inode_sector));
    if (!success && inode_sector != 0)
      free_map_release(inode_sector, 1);
    dir_close(cwd);

    // bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
    //                 inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector));
    // if (!success && inode_sector != 0)
    //   free_map_release(inode_sector, 1);
    // dir_close(dir);

    return success;
}

/* 打开指定名称的文件。如果成功，则返回新文件；
   否则返回空指针。如果不存在名为 NAME 的文件，
   或者内部内存分配失败，则打开失败。*/
struct file* filesys_open(const char* name) {
  struct dir* dir = dir_open_root();
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
