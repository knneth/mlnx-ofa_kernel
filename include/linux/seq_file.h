#ifndef _COMPAT_LINUX_SEQ_FILE_H
#define _COMPAT_LINUX_SEQ_FILE_H

#include "../../compat/config.h"

#include_next <linux/seq_file.h>

#ifndef HAVE_DEFINE_SHOW_ATTRIBUTE
#define DEFINE_SHOW_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}
#endif
#endif /* _COMPAT_LINUX_SEQ_FILE_H */
