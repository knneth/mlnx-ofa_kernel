# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the FUSE filesystem.
#
ccflags-y += -Wframe-larger-than=2048

obj-$(CONFIG_VIRTIO_FS) := virtiofs.o
virtiofs-y := dev.o dir.o file.o inode.o xattr.o acl.o readdir.o ioctl.o iomode.o virtio_fs.o
