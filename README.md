#前言
本项目基于Linux3.7 提炼出了f2fs的第一个提交版本，通过对初始版本进行注释，来逐步学习f2fs的基础原理。
主要包含了如下几个流程的注释：
- f2fs_fill_super
- recover_fsync_data
- start_gc_thread
- f2fs_sync_file
- f2fs_create
- f2fs_mknod
- f2fs_read_data_page
- f2fs_write_data_page
- write_checkpoint

>代码中还有很多没有理解的地方，同样也会有注释错误的地方，欢迎大家批评指正

#patch内容
主要包含了如下的提交：
```
3f6a0150291b    2012-11-27      Jaegeuk Kim     f2fs: update the f2fs document
8377ab02b6a3    2012-11-02      Jaegeuk Kim     f2fs: update Kconfig and Makefile
1c2b6e049f10    2012-11-03      Greg Kroah-Hartman      f2fs: move proc files to debugfs
f23f0a2f65b5    2012-11-02      Jaegeuk Kim     f2fs: add recovery routines for roll-forward
a9b5553371e4    2012-11-02      Jaegeuk Kim     f2fs: add garbage collection functions
f029047fa7ed    2012-11-02      Jaegeuk Kim     f2fs: add xattr and acl functionalities
1f9b35c9b066    2012-11-14      Jaegeuk Kim     f2fs: add core directory operations
3bf7b8e98675    2012-11-02      Jaegeuk Kim     f2fs: add inode operations for special inodes
64c43f6109f7    2012-11-02      Jaegeuk Kim     f2fs: add core inode operations
6b8a900a84a2    2012-11-02      Jaegeuk Kim     f2fs: add address space operations for data
2350d1455a41    2012-11-02      Jaegeuk Kim     f2fs: add file operations
4e4c95127944    2012-11-02      Jaegeuk Kim     f2fs: add segment operations
0ac2640ab9af    2012-11-02      Jaegeuk Kim     f2fs: add node operations
0a507cbdc259    2012-11-02      Jaegeuk Kim     f2fs: add checkpoint operations
b3862b18fe88    2012-11-02      Jaegeuk Kim     f2fs: add super block operations
c9e70d0dae5e    2012-11-28      Jaegeuk Kim     f2fs: add superblock and major in-memory structure
778d9a9c8a2c    2012-11-02      Jaegeuk Kim     f2fs: add on-disk layout
868dfc32edd0    2012-11-02      Jaegeuk Kim     f2fs: add document
```
