#include "filesys/filesys.h"
#include <stdlib.h>
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

#include "threads/thread.h"
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
static struct dir* get_start_dir (const char* name) {
    if (name == NULL) return NULL;
  
    struct dir* dir;
    if (name[0] == '/') {
        dir = dir_open_root();
        
    } else {
        struct thread* t = thread_current();
        if (t != NULL && t->pcb != NULL && t->pcb->cwd != NULL) {
              dir = dir_reopen(t->pcb->cwd);
        } else {
              dir = dir_open_root();
        }
    }
    return dir;
}
  // a/b/c/d
  // prev_token = d -->要创建的
  // token = null 
  // 此时current = c
static bool get_directory_and_target (char* path, struct dir** current, char* chdir) {
    char *save_ptr;
    char *token, *prev_token = NULL;
    
    struct inode* inode;
    for (token = strtok_r(path, "/", &save_ptr); token != NULL; 
            token = strtok_r (NULL, "/", &save_ptr)) 
    {
        if (prev_token != NULL) {
            /* 找到子目录,存到inode中 */
            if (!dir_lookup(*current, prev_token, &inode)) {
                printf("find no child dir\n");
                return false;
            } 
    
            /* 关掉父目录 */
            dir_close(*current);
            /* 打开子目录 */
            *current = dir_open(inode);
        }        
        
        prev_token = token;
    }

    strlcpy(chdir, prev_token, strlen(prev_token)+1);
    return true;
}
/* 
  parameter
  name :待解析的path
  current :存dir的二级指针
  chdir :要create/open的 名字
*/
static bool parse_path (const char* name, struct dir** current, char* chdir) {
    if (name == NULL || name[0] == '\0') {
        return false;
    }

    struct dir* cwd = get_start_dir(name);
    if (cwd == NULL) {
        return false;
    }

    size_t len = strlen(name) + 1;
    char* copy = malloc(len);
    strlcpy(copy, name, len);

    /* 跳过开头的 '/' */
    char* path_start = copy;
    while (*path_start == '/') {
        path_start++;
    }
    /* 如果路径为空（只有 '/' 或空字符串） */
    if (*path_start == '\0') {
        free(copy);
        dir_close(cwd);
        return false;
    }

    bool success = get_directory_and_target(copy, &cwd, chdir);

    if (cwd != NULL) {
        *current = cwd;
    }

    free(copy);
    return success;
}
/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
    bool success;

    block_sector_t inode_sector = 0;
    struct dir* dir;
    // char chdir[NAME_MAX];
    char* chdir = malloc(NAME_MAX);
    success = parse_path(name, &dir, chdir);
    
    if (success) {
        success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                      inode_create(inode_sector, initial_size) && dir_add(dir, chdir, inode_sector));
    }

    if (!success && inode_sector != 0)
        free_map_release(inode_sector, 1);
    dir_close(dir);
    free(chdir);

    return success;
}

/* 打开指定名称的文件。如果成功，则返回新文件；
   否则返回空指针。如果不存在名为 NAME 的文件，
   或者内部内存分配失败，则打开失败。*/
struct file* filesys_open(const char* name) {
    // struct dir* dir = dir_open_root();
    struct dir* dir;
    char* file = malloc(NAME_MAX);
    parse_path(name, &dir, file);
    // struct dir* dir = get_start_dir(name);
    struct inode* inode = NULL;

    if (dir != NULL) {
        dir_lookup(dir, file, &inode);
    }
    dir_close(dir);
    free(file);

    return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {

    struct dir* dir;
    char* file = malloc(NAME_MAX);
    parse_path(name, &dir, file);

    bool success = (dir != NULL) && dir_remove(dir, file);
    dir_close(dir);
  // struct dir* dir = dir_open_root();
  // bool success = dir != NULL && dir_remove(dir, name);
  // dir_close(dir);

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
