/**
 * fs/f2fs/recovery.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include "f2fs.h"
#include "node.h"
#include "segment.h"

static struct kmem_cache *fsync_entry_slab;

bool space_for_roll_forward(struct f2fs_sb_info *sbi)
{
	if (sbi->last_valid_block_count + sbi->alloc_valid_block_count
			> sbi->user_block_count)
		return false;
	return true;
}
/* 遍历fsync_inode_entry链表，找到inode number为ino的fsync_inode_entry */
static struct fsync_inode_entry *get_fsync_inode(struct list_head *head,
								nid_t ino)
{
	struct list_head *this;
	struct fsync_inode_entry *entry;

	list_for_each(this, head) {
		entry = list_entry(this, struct fsync_inode_entry, list);
		if (entry->inode->i_ino == ino)
			return entry;
	}
	return NULL;
}

static int recover_dentry(struct page *ipage, struct inode *inode)
{
	struct f2fs_node *raw_node = (struct f2fs_node *)kmap(ipage);
	struct f2fs_inode *raw_inode = &(raw_node->i);
	struct dentry dent, parent;
	struct f2fs_dir_entry *de;
	struct page *page;
	struct inode *dir;
	int err = 0;

	if (!is_dent_dnode(ipage))
		goto out;

	dir = f2fs_iget(inode->i_sb, le32_to_cpu(raw_inode->i_pino));
	if (IS_ERR(dir)) {
		err = -EINVAL;
		goto out;
	}

	parent.d_inode = dir;
	dent.d_parent = &parent;
	dent.d_name.len = le32_to_cpu(raw_inode->i_namelen);
	dent.d_name.name = raw_inode->i_name;

	de = f2fs_find_entry(dir, &dent.d_name, &page);
	if (de) {
		kunmap(page);
		f2fs_put_page(page, 0);
	} else {
		f2fs_add_link(&dent, inode);
	}
	iput(dir);
out:
	kunmap(ipage);
	return err;
}

static int recover_inode(struct inode *inode, struct page *node_page)
{
	void *kaddr = page_address(node_page);
	struct f2fs_node *raw_node = (struct f2fs_node *)kaddr;
	struct f2fs_inode *raw_inode = &(raw_node->i);

	inode->i_mode = le32_to_cpu(raw_inode->i_mode);
	i_size_write(inode, le64_to_cpu(raw_inode->i_size));
	inode->i_atime.tv_sec = le64_to_cpu(raw_inode->i_mtime);
	inode->i_ctime.tv_sec = le64_to_cpu(raw_inode->i_ctime);
	inode->i_mtime.tv_sec = le64_to_cpu(raw_inode->i_mtime);
	inode->i_atime.tv_nsec = le32_to_cpu(raw_inode->i_mtime_nsec);
	inode->i_ctime.tv_nsec = le32_to_cpu(raw_inode->i_ctime_nsec);
	inode->i_mtime.tv_nsec = le32_to_cpu(raw_inode->i_mtime_nsec);

	return recover_dentry(node_page, inode);
}
/* 
 * 通过遍历CURSEG_WARM_NODE的segment中每一个dnode block, 
 * 初始化每一个dnode block对应的fsync_inode_entry，并将fsync_inode_entry链接起来
 * note: 1.每个node都有唯一的inode对应，但一个inode可对应多个node
 *       2.CURSEG_WARM_NODE用于存放direct node blocks of normal files
 */
static int find_fsync_dnodes(struct f2fs_sb_info *sbi, struct list_head *head)
{
	unsigned long long cp_ver = le64_to_cpu(sbi->ckpt->checkpoint_ver);
	struct curseg_info *curseg;
	struct page *page;
	block_t blkaddr;
	int err = 0;

	/* get node pages in the current segment */
	/* CURSEG_WARM_NODE用于存放direct node blocks of normal files */
	curseg = CURSEG_I(sbi, CURSEG_WARM_NODE);
	/*获取当前有效node segment的下一个要写入的dnode block地址, 这个就是fsync标记的新的dnode block*/
	blkaddr = START_BLOCK(sbi, curseg->segno) + curseg->next_blkoff;

	/* read node page */
	page = alloc_page(GFP_F2FS_ZERO);
	if (IS_ERR(page))
		return PTR_ERR(page);
	lock_page(page);

	/*遍历next_blkoff组成的node list*/
	while (1) {
		struct fsync_inode_entry *entry;
		/* 读取dnode block */
		if (f2fs_readpage(sbi, page, blkaddr, READ_SYNC))
			goto out;
		/* 比较cpver的版本与rn->footer.cp_ver是否相同 */
		if (cp_ver != cpver_of_node(page))
			goto out;
		/*前滚恢复只能恢复fsync标记的dnode*/
		if (!is_fsync_dnode(page))
			goto next;
		/*遍历fsync_inode_entry链表，找到inode number为ino的fsync_inode_entry*/
		entry = get_fsync_inode(head, ino_of_node(page));
		/* 表示f2fs_inode_entry已经在inode list */
		if (entry) {
			entry->blkaddr = blkaddr;
			/* 如果是dentry的inode */
			if (IS_INODE(page) && is_dent_dnode(page))
				set_inode_flag(F2FS_I(entry->inode),
							FI_INC_LINK);
		/* 表示f2fs_inode_entry不在inode list, 则将其加入到inode list */
		} else {
			if (IS_INODE(page) && is_dent_dnode(page)) {
				if (recover_inode_page(sbi, page)) {
					err = -ENOMEM;
					goto out;
				}
			}

			/* add this fsync inode to the list */
			entry = kmem_cache_alloc(fsync_entry_slab, GFP_NOFS);
			if (!entry) {
				err = -ENOMEM;
				goto out;
			}

			INIT_LIST_HEAD(&entry->list);
			list_add_tail(&entry->list, head);
			/* 
			 * dnode block的ino没有改变, 因此ino对应的inode也没有改变
			 * 因此f2fs_inode也是旧的，f2fs_inode->i_nids也是旧的，例证未找到
			 */
			entry->inode = f2fs_iget(sbi->sb, ino_of_node(page));
			if (IS_ERR(entry->inode)) {
				err = PTR_ERR(entry->inode);
				goto out;
			}
			entry->blkaddr = blkaddr;
		}
		/* 如果dnode本身就是inode，则恢复inode的信息 */
		if (IS_INODE(page)) {
			err = recover_inode(entry->inode, page);
			if (err)
				goto out;
		}
next:
		/* check next segment */
		/* 
		 * F2FS分配f2fs_node物理地址的时候，会将本次分配的blkaddr和下一次分配的blkaddr，
		 * 通过f2fs_node->node_footer->blk_addr连接成一个list
		 * 前滚恢复通过这个list找到下一个被分配的blkaddr，直到没有分配为止
		 */
		blkaddr = next_blkaddr_of_node(page);
		ClearPageUptodate(page);
	}
out:
	unlock_page(page);
	__free_pages(page, 0);
	return err;
}

static void destroy_fsync_dnodes(struct f2fs_sb_info *sbi,
					struct list_head *head)
{
	struct list_head *this;
	struct fsync_inode_entry *entry;
	list_for_each(this, head) {
		entry = list_entry(this, struct fsync_inode_entry, list);
		iput(entry->inode);
		list_del(&entry->list);
		kmem_cache_free(fsync_entry_slab, entry);
	}
}
/*
 * 根据新的blkaddr找到先前对应的node block
 * 通过blkaddr获取在node中的索引号，并通过索引号找到旧的block，将其设为无效
 */
static void check_index_in_prev_nodes(struct f2fs_sb_info *sbi,
						block_t blkaddr)
{
	struct seg_entry *sentry;
	/* 以main区域blk0为起始地址(main所在seg为起始seg)，计算blkaddr所处的segment */
	unsigned int segno = GET_SEGNO(sbi, blkaddr);
	/* 计算blkaddr在segment的偏移 */
	unsigned short blkoff = GET_SEGOFF_FROM_SEG0(sbi, blkaddr) &
					(sbi->blocks_per_seg - 1);
	struct f2fs_summary sum;
	nid_t ino;
	void *kaddr;
	struct inode *inode;
	struct page *node_page;
	block_t bidx;
	int i;

	sentry = get_seg_entry(sbi, segno);
	if (!f2fs_test_bit(blkoff, sentry->cur_valid_map))
		return;

	/* Get the previous summary */
	for (i = CURSEG_WARM_DATA; i <= CURSEG_COLD_DATA; i++) {
		struct curseg_info *curseg = CURSEG_I(sbi, i);
		if (curseg->segno == segno) {
			sum = curseg->sum_blk->entries[blkoff];
			break;
		}
	}
	if (i > CURSEG_COLD_DATA) {
		struct page *sum_page = get_sum_page(sbi, segno);
		struct f2fs_summary_block *sum_node;
		kaddr = page_address(sum_page);
		sum_node = (struct f2fs_summary_block *)kaddr;
		sum = sum_node->entries[blkoff];
		f2fs_put_page(sum_page, 1);
	}

	/* Get the node page */
	node_page = get_node_page(sbi, le32_to_cpu(sum.nid));
	/* 获取blkaddr对应先前的node page的索引 */
	bidx = start_bidx_of_node(ofs_of_node(node_page)) +
				le16_to_cpu(sum.ofs_in_node);
	/* 获取blkaddr对应的先前的dnode page的所属的ino*/
	ino = ino_of_node(node_page);
	f2fs_put_page(node_page, 1);

	/* Deallocate previous index in the node page */
	inode = f2fs_iget_nowait(sbi->sb, ino);
	/* 
	 * 将旧的dnode block中索引号为bidx的block设为无效
	 * note: 此处的inode（inode对于新旧node没有变化）中bidx索引所在的node为旧的node
	 * 	 因此通过bidx索引找到的block块号也为旧的
	 */
	truncate_hole(inode, bidx, bidx + 1);
	iput(inode);
}
/*
 * @inode: fsync标记的新的dnode block的inode
 * 	   NOTE:它与旧的dnode block的inode是同一个, 因此获取的f2fs_inode为旧的
 * @page:  fsync标记的新的dnode block对应的page 
 * @blkaddr: fsync标记的新的dnode block的地址
 * note: 新块：具有fsync标记的dnode中索引指向的data block
 * 	 旧块：先前的dnode中相同索引指向的data block
 *
 * 1.如果新的dnode block索引的data block与先前的dnode索引的data block不一致,
 * 则将先前的dnode block索引的block设置为无效,即清零sit entry相应的bit map
 * 2.就地修改nat entry
 */
static void do_recover_data(struct f2fs_sb_info *sbi, struct inode *inode,
					struct page *page, block_t blkaddr)
{
	unsigned int start, end;
	struct dnode_of_data dn;
	struct f2fs_summary sum;
	struct node_info ni;
	
	/* 
	 * 获取fsync标记的dnode page中存放的首个block地址的索引
	 *
	 * note:
	 * 假设fsync的dnode page为2nd dnode page,nid位于f2fs_inode->i_nid[1]
	 * fsync的dnode的起始block地址索引start为: 923+1018=1941(2nd dnode page的开始索引号)
	 * fsync的dnode的结束block地址索引end为: 923+1018+1018=2959（2nd dnode page的结束索引号）
	 */
	start = start_bidx_of_node(ofs_of_node(page));
	if (IS_INODE(page))
		end = start + ADDRS_PER_INODE;
	else
		end = start + ADDRS_PER_BLOCK;
	
	/* 初始化dnode, 0表示不清楚nid */
	set_new_dnode(&dn, inode, NULL, NULL, 0);
	/* 
	 * 通过dnode中index索引查找到对应的block地址，保存在dn->data_blkaddr中
	 * note:dn保存的是旧的dnode page的数据,`
	 * 
	 * note:
	 * 假设fsync的dnode page为2nd dnode page,start为1941为例,dn被初始化为：
	 * dn->nid=nids[1],2nd dnode对应的nid,它来自于f2fs_inode.i_nid[1],是先前的2nd dnode的nid
	 * dn->ofs_in_node=offset[1]=0, start索引在2nd dnode的偏移，start=1941时为0
	 * dn->node_page=npage[1]，2nd dnode对应的page, 来自于inode.i_nid[1],是先前的2nd dnode
	 * dn->data_blkaddr=先前的2nd dnode中偏移为0的block块号，也就是旧block块号
	 */
	if (get_dnode_of_data(&dn, start, 0))
		return;

	wait_on_page_writeback(dn.node_page);

	/*
	 * note:
	 * 假设fsync的dnode page为2nd dnode page,start为1941为例:
	 * 获取先前的2nd dnode的node info
	 */
	get_node_info(sbi, dn.nid, &ni);
	BUG_ON(ni.ino != ino_of_node(page));
	BUG_ON(ofs_of_node(dn.node_page) != ofs_of_node(page));
	/* 遍历新旧dnode中索引的block，对其执行恢复操作 */
	for (; start < end; start++) {
		block_t src, dest;
		/*
		 * src保存了先前的dnode中的索引为ofs_in_node的块号
		 * dest保存了新的做了fsync标记的dnode中索引为ofs_in_node的块号
		 * note: dn中保存的是先前的dnode数据
		 */
		src = datablock_addr(dn.node_page, dn.ofs_in_node);
		dest = datablock_addr(page, dn.ofs_in_node);

		if (src != dest && dest != NEW_ADDR && dest != NULL_ADDR) {
			if (src == NULL_ADDR) {
				int err = reserve_new_block(&dn);
				/* We should not get -ENOSPC */
				BUG_ON(err);
			}

			/* Check the previous node page having this index */
			/* 根据新块号dest找到先前的dnode，根据索引号找到旧块block, 将其设为无效 */
			check_index_in_prev_nodes(sbi, dest);
			/* 用先前的dnode初始化summary */
			set_summary(&sum, dn.nid, dn.ofs_in_node, ni.version);

			/* write dummy data page */
			/*实际是只更新了sit entry部分*/
			recover_data_page(sbi, NULL, &sum, src, dest);
			update_extent_cache(dest, &dn);
		}
		dn.ofs_in_node++;
	}

	/* write node page in place */
	set_summary(&sum, dn.nid, 0, 0);
	if (IS_INODE(dn.node_page))
		sync_inode_page(&dn);
	/*将fsync的dnode page的node footer信息拷贝给先前的dnode*/
	copy_node_footer(dn.node_page, page);
	fill_node_footer(dn.node_page, dn.nid, ni.ino,
					ofs_of_node(page), false);
	/*就地修改先前的dnode*/
	set_page_dirty(dn.node_page);
	/*就地修改nat_entry*/
	recover_node_page(sbi, dn.node_page, &sum, &ni, blkaddr);
	f2fs_put_dnode(&dn);
}
/*
 * @head: fsync标记的dnode所在的inode组成的链表
 *
 * 遍历inode链表的每一个fsync的dnode，对其索引的data block执行恢复操作
 */
static void recover_data(struct f2fs_sb_info *sbi,
				struct list_head *head, int type)
{
	unsigned long long cp_ver = le64_to_cpu(sbi->ckpt->checkpoint_ver);
	struct curseg_info *curseg;
	struct page *page;
	block_t blkaddr;

	/* get node pages in the current segment */
	curseg = CURSEG_I(sbi, type);
	/* 获取当前有效node segment的下一个要写入的block地址, 这个就是fsync标记的新的dnode block*/
	blkaddr = NEXT_FREE_BLKADDR(sbi, curseg);

	/* read node page */
	page = alloc_page(GFP_NOFS | __GFP_ZERO);
	if (IS_ERR(page))
		return;
	lock_page(page);

	while (1) {
		struct fsync_inode_entry *entry;
		/* 读取fsync标记的dnode block */
		if (f2fs_readpage(sbi, page, blkaddr, READ_SYNC))
			goto out;

		if (cp_ver != cpver_of_node(page))
			goto out;
		/* 找到与dnode page的ino号一致的fsync_inode_entry */
		entry = get_fsync_inode(head, ino_of_node(page));
		if (!entry)
			goto next;
		/* 对fsync标记的dnode执行数据恢复 */
		do_recover_data(sbi, entry->inode, page, blkaddr);

		if (entry->blkaddr == blkaddr) {
			iput(entry->inode);
			list_del(&entry->list);
			kmem_cache_free(fsync_entry_slab, entry);
		}
next:
		/* check next segment */
		/* 获取下一个dnode block的地址保存在blkaddr */
		blkaddr = next_blkaddr_of_node(page);
		ClearPageUptodate(page);
	}
out:
	unlock_page(page);
	__free_pages(page, 0);

	allocate_new_segments(sbi);
}
/*
 * 当data block已经修改，并在dnode中已经做了fsync标记，但是还没有同步修改元数据时发生掉电
 * 此时需要修复元数据，包括：NAT, SIT, SSA, CP? 使得与数据一致
 */
void recover_fsync_data(struct f2fs_sb_info *sbi)
{
	struct list_head inode_list;

	fsync_entry_slab = f2fs_kmem_cache_create("f2fs_fsync_inode_entry",
			sizeof(struct fsync_inode_entry), NULL);
	if (unlikely(!fsync_entry_slab))
		return;

	INIT_LIST_HEAD(&inode_list);

	/* step #1: find fsynced inode numbers */
	/* 
	 * 遍历CURSEG_WARM_NODE的segment中每一个dnode block
	 * 找到符合条件的dnode block(dnode可能就是inode本身)对应的inode，链入inode_list链表 
	 * note: dnode恢复需要满足条件：
	 * 	 1.有fsync标记；
	 * 	 2.cp version与checkpoint的cp version相同
	 */
	if (find_fsync_dnodes(sbi, &inode_list))
		goto out;

	if (list_empty(&inode_list))
		goto out;

	/* step #2: recover data */
	sbi->por_doing = 1;
	/* 遍历inode链表的每一个fsync的dnode，对其索引的data block执行恢复操作 */
	recover_data(sbi, &inode_list, CURSEG_WARM_NODE);
	sbi->por_doing = 0;
	BUG_ON(!list_empty(&inode_list));
out:
	destroy_fsync_dnodes(sbi, &inode_list);
	kmem_cache_destroy(fsync_entry_slab);
	write_checkpoint(sbi, false, false);
}
