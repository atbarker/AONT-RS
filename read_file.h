#ifndef READ_FILE_H
#define READ_FILE_H

#include <linux/slab.h>
#include <linux/fs.h>

struct file* file_open(char* path, int flags, int rights);

void file_close(struct file* file);

#endif
