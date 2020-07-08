/**
 * fs/f2fs/node.c
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
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/blkdev.h>
#include <linux/pagevec.h>
#include <linux/swap.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"

static struct kmem_cache *nat_entry_slab;
static struct kmem_cache *free_nid_slab;

static void clear_node_page_dirty(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct f2fs_sb_info *sbi = F2FS_SB(mapping->host->i_sb);
	unsigned int long flags;

	if (PageDirty(page)) {
		spin_lock_irqsave(&mapping->tree_lock, flags);
		radix_tree_tag_clear(&mapping->page_tree,
				page_index(page),
				PAGECACHE_TAG_DIRTY);
		spin_unlock_irqrestore(&mapping->tree_lock, flags);

		clear_page_dirty_for_io(page);
		dec_page_count(sbi, F2FS_DIRTY_NODES);
	}
	ClearPageUptodate(page);
}
/*获取nid对应的nat entry所在的nat entry block*/
static struct page *get_current_nat_page(struct f2fs_sb_info *sbi, nid_t nid)
{
	pgoff_t index = current_nat_addr(sbi, nid);
	return get_meta_page(sbi, index);
}
/*此函数是如何选择下一个nat block的？*/
static struct page *get_next_nat_page(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct page *src_page;
	struct page *dst_page;
	pgoff_t src_off;
	pgoff_t dst_off;
	void *src_addr;
	void *dst_addr;
	struct f2fs_nm_info *nm_i = NM_I(sbi);

	/*获取nid对应的nat entry所在磁盘的block地址*/
	src_off = current_nat_addr(sbi, nid);
	/*获取nat entry block地址为src_off的下一个nat entry block的地址*/
	dst_off = next_nat_addr(sbi, src_off);

	/* get current nat block page with lock */
	src_page = get_meta_page(sbi, src_off);

	/* Dirty src_page means that it is already the new target NAT page. */
	if (PageDirty(src_page))
		return src_page;

	dst_page = grab_meta_page(sbi, dst_off);

	src_addr = page_address(src_page);
	dst_addr = page_address(dst_page);
	memcpy(dst_addr, src_addr, PAGE_CACHE_SIZE);
	set_page_dirty(dst_page);
	f2fs_put_page(src_page, 1);

	set_to_next_nat(nm_i, nid);

	return dst_page;
}

/**
 * Readahead NAT pages
 */
static void ra_nat_pages(struct f2fs_sb_info *sbi, int nid)
{
	struct address_space *mapping = sbi->meta_inode->i_mapping;
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct page *page;
	pgoff_t index;
	int i;

	for (i = 0; i < FREE_NID_PAGES; i++, nid += NAT_ENTRY_PER_BLOCK) {
		if (nid >= nm_i->max_nid)
			nid = 0;
		/* 获取nid对应的nat entry所在的block地址  */
		index = current_nat_addr(sbi, nid);

		page = grab_cache_page(mapping, index);
		if (!page)
			continue;
		if (f2fs_readpage(sbi, page, index, READ)) {
			f2fs_put_page(page, 1);
			continue;
		}
		page_cache_release(page);
	}
}

static struct nat_entry *__lookup_nat_cache(struct f2fs_nm_info *nm_i, nid_t n)
{
	return radix_tree_lookup(&nm_i->nat_root, n);
}

static unsigned int __gang_lookup_nat_cache(struct f2fs_nm_info *nm_i,
		nid_t start, unsigned int nr, struct nat_entry **ep)
{
	return radix_tree_gang_lookup(&nm_i->nat_root, (void **)ep, start, nr);
}

static void __del_from_nat_cache(struct f2fs_nm_info *nm_i, struct nat_entry *e)
{
	list_del(&e->list);
	radix_tree_delete(&nm_i->nat_root, nat_get_nid(e));
	nm_i->nat_cnt--;
	kmem_cache_free(nat_entry_slab, e);
}

int is_checkpointed_node(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *e;
	int is_cp = 1;

	read_lock(&nm_i->nat_tree_lock);
	e = __lookup_nat_cache(nm_i, nid);
	if (e && !e->checkpointed)
		is_cp = 0;
	read_unlock(&nm_i->nat_tree_lock);
	return is_cp;
}

static struct nat_entry *grab_nat_entry(struct f2fs_nm_info *nm_i, nid_t nid)
{
	struct nat_entry *new;

	new = kmem_cache_alloc(nat_entry_slab, GFP_ATOMIC);
	if (!new)
		return NULL;
	if (radix_tree_insert(&nm_i->nat_root, nid, new)) {
		kmem_cache_free(nat_entry_slab, new);
		return NULL;
	}
	memset(new, 0, sizeof(struct nat_entry));
	nat_set_nid(new, nid);
	list_add_tail(&new->list, &nm_i->nat_entries);
	nm_i->nat_cnt++;
	return new;
}

static void cache_nat_entry(struct f2fs_nm_info *nm_i, nid_t nid,
						struct f2fs_nat_entry *ne)
{
	struct nat_entry *e;
retry:
	write_lock(&nm_i->nat_tree_lock);
	e = __lookup_nat_cache(nm_i, nid);
	if (!e) {
		e = grab_nat_entry(nm_i, nid);
		if (!e) {
			write_unlock(&nm_i->nat_tree_lock);
			goto retry;
		}
		nat_set_blkaddr(e, le32_to_cpu(ne->block_addr));
		nat_set_ino(e, le32_to_cpu(ne->ino));
		nat_set_version(e, ne->version);
		e->checkpointed = true;
	}
	write_unlock(&nm_i->nat_tree_lock);
}

static void set_node_addr(struct f2fs_sb_info *sbi, struct node_info *ni,
			block_t new_blkaddr)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *e;
retry:
	write_lock(&nm_i->nat_tree_lock);
	e = __lookup_nat_cache(nm_i, ni->nid);
	if (!e) {
		e = grab_nat_entry(nm_i, ni->nid);
		if (!e) {
			write_unlock(&nm_i->nat_tree_lock);
			goto retry;
		}
		e->ni = *ni;
		e->checkpointed = true;
		BUG_ON(ni->blk_addr == NEW_ADDR);
	} else if (new_blkaddr == NEW_ADDR) {
		/*
		 * when nid is reallocated,
		 * previous nat entry can be remained in nat cache.
		 * So, reinitialize it with new information.
		 */
		e->ni = *ni;
		BUG_ON(ni->blk_addr != NULL_ADDR);
	}

	if (new_blkaddr == NEW_ADDR)
		e->checkpointed = false;

	/* sanity check */
	BUG_ON(nat_get_blkaddr(e) != ni->blk_addr);
	BUG_ON(nat_get_blkaddr(e) == NULL_ADDR &&
			new_blkaddr == NULL_ADDR);
	BUG_ON(nat_get_blkaddr(e) == NEW_ADDR &&
			new_blkaddr == NEW_ADDR);
	BUG_ON(nat_get_blkaddr(e) != NEW_ADDR &&
			nat_get_blkaddr(e) != NULL_ADDR &&
			new_blkaddr == NEW_ADDR);

	/* increament version no as node is removed */
	if (nat_get_blkaddr(e) != NEW_ADDR && new_blkaddr == NULL_ADDR) {
		unsigned char version = nat_get_version(e);
		nat_set_version(e, inc_node_version(version));
	}

	/* change address */
	nat_set_blkaddr(e, new_blkaddr);
	__set_nat_cache_dirty(nm_i, e);
	write_unlock(&nm_i->nat_tree_lock);
}

static int try_to_free_nats(struct f2fs_sb_info *sbi, int nr_shrink)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);

	if (nm_i->nat_cnt < 2 * NM_WOUT_THRESHOLD)
		return 0;

	write_lock(&nm_i->nat_tree_lock);
	while (nr_shrink && !list_empty(&nm_i->nat_entries)) {
		struct nat_entry *ne;
		ne = list_first_entry(&nm_i->nat_entries,
					struct nat_entry, list);
		__del_from_nat_cache(nm_i, ne);
		nr_shrink--;
	}
	write_unlock(&nm_i->nat_tree_lock);
	return nr_shrink;
}

/**
 * This function returns always success
 */
/*获取nid对应的node info*/
void get_node_info(struct f2fs_sb_info *sbi, nid_t nid, struct node_info *ni)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_summary_block *sum = curseg->sum_blk;
	nid_t start_nid = START_NID(nid);
	struct f2fs_nat_block *nat_blk;
	struct page *page = NULL;
	struct f2fs_nat_entry ne;
	struct nat_entry *e;
	int i;

	ni->nid = nid;

	/* Check nat cache */
	/*首先，从nat cache中查找是否有nid对应的f2fs nat enry,如果找到则初始化ni返回*/
	read_lock(&nm_i->nat_tree_lock);
	e = __lookup_nat_cache(nm_i, nid);
	if (e) {
		ni->ino = nat_get_ino(e);
		ni->blk_addr = nat_get_blkaddr(e);
		ni->version = nat_get_version(e);
	}
	read_unlock(&nm_i->nat_tree_lock);
	if (e)
		return;

	/* Check current segment summary */
	mutex_lock(&curseg->curseg_mutex);
	/*其次，根据nid查询current segment的nat journey，获取f2fs nat entry, 如果找到则初始化ni返回*/
	i = lookup_journal_in_cursum(sum, NAT_JOURNAL, nid, 0);
	if (i >= 0) {
		/*获取索引对应的f2fs nat entry*/
		ne = nat_in_journal(sum, i);
		/*用获取的f2fs nat entry初始化node info*/
		node_info_from_raw_nat(ni, &ne);
	}
	mutex_unlock(&curseg->curseg_mutex);
	if (i >= 0)
		goto cache;

	/* Fill node_info from nat page */
	/*再次，如果从current segment的summary中无法查找到nat entry，则从f2fs nat entry block中查找,如果找到则初始化ni返回*/
	page = get_current_nat_page(sbi, start_nid);
	nat_blk = (struct f2fs_nat_block *)page_address(page);
	ne = nat_blk->entries[nid - start_nid];
	node_info_from_raw_nat(ni, &ne);
	f2fs_put_page(page, 1);
cache:
	/* cache nat entry */
	cache_nat_entry(NM_I(sbi), nid, &ne);
}

/**
 * The maximum depth is four.
 * Offset[0] will have raw inode offset.
 */
/*
 * @block ：data block地址所在dnode page中的索引
 * @offset：保存了data block的各级索引,假设一个data block有四级索引则：
 *	　　offset[0]保存data block地址在inode中的索引
 * 	    offset[1]保存data block地址在dindnode中的索引
 *          offset[2]保存data block地址在indnode中的索引
 *          offset[3]保存data block地址在dnode中的索引
 * @noffset: 一共有多少个索引(index) block(在当前检索到的结点处)
 * @return: 返回block偏移地址所处的level,如在inode为0，在direct block为1，indirect block为2，dindirect block为3
 */
static int get_node_path(long block, int offset[4], unsigned int noffset[4])
{
	const long direct_index = ADDRS_PER_INODE;
	const long direct_blks = ADDRS_PER_BLOCK;
	const long dptrs_per_blk = NIDS_PER_BLOCK;
	const long indirect_blks = ADDRS_PER_BLOCK * NIDS_PER_BLOCK;
	const long dindirect_blks = indirect_blks * NIDS_PER_BLOCK;
	int n = 0;
	int level = 0;

	noffset[0] = 0;
	/*
	 * 从inode block开始检索, inode中共有direct_index个地址
	 *
	 * 如果block < direct_index，说明此地址存在于inode本身
	 *
	 * offset[0]=block: 在第0层（inode）中的索引为block
	 * noffset[0]=0   ：在第0层（inode）中index block的个数为0
	 *	 
	 * level=0        : 在inode包含此地址，则level = 0
	 */	
	if (block < direct_index) {
		offset[n++] = block;
		level = 0;
		goto got;
	}
	/*
    	 * 如果direct_index < block < direct_blks, 说明此地址存在于第一个direct block中。
    	 
	 * offset[0] = NODE_DIR1_BLOCKs, 在第0层（inode）中的索引为NODE_DIR1_BLOCKs
	 * noffset[0] = 0, 在第0层（inode）中index block的个数为0
	 *    
	 * offset[1] = block, 在第1层（1st dnode）中的索引为block
	 * noffset[1] = 1, 在第1层（1st dnode）中index block的个数为1:inode
	 *
	 * level = 1，在1st dnode包含此地址，则level = 1
	 * 
	 * note:其实此block已经为原block - direct_index后剩下的值 即其在第一层index block中的索引
         */
	block -= direct_index;
	if (block < direct_blks) {
		offset[n++] = NODE_DIR1_BLOCK;
		noffset[n] = 1;
		offset[n++] = block;
		level = 1;
		goto got;
	}
	
	/*
	 * 如果 direct_bllks < block < 2 * direct_blks, 说明inode 中不包含此地址，第一个direct block也不包含此
	 * 地址，而第二个direct index block中包含此地址。
	 *	 
	 * offset[0] = NODE_DIR2_BLOCK, 在第0层（inode）中的索引为NODE_DIR2_BLOCKs
	 * noffset[0] = 0, 在第0层（inode）中index block的个数为0
	 *
	 * offset[1] = block，第1层（2nd dnode）中的索引为block
	 * noffset[1] = 2, 在第1层（2nd dnode）中index block的个数为1：inode, 1st dnode
	 
	 * level = 1, 在2nd dnode包含此地址，则level = 1
         */
	block -= direct_blks;
	if (block < direct_blks) {
		offset[n++] = NODE_DIR2_BLOCK;
		noffset[n] = 2;
		offset[n++] = block;
		level = 1;
		goto got;
	}
	/*   
         * 如果 2 * direct_bllks < block < indirect_blks, 说明inode,2个direct block也不包含此
         * 地址，indirect block中包含此地址。
	 *
         * offset[0] = NODE_IND1_BLOCK, 在第0层（inode）中的索引为NODE_IND1_BLOCK
         * noffset[0] = 0, 在第0层（inode）中index block的个数为0
	 *
	 * offset[1] = block / direct_blks,在第1层（1st indnode）中的索引，为其在indirect block中的索引相当于段地址
	 * noffset[1] = 3, 在第1层（1st indnode）中index block的个数为3:inode+2*dnode 
	 *
	 * offset[2] = block % direct_blks, 在第2层（dnode）中的索引, 为其在dnode中的索引相当于段内偏移 
	 * noffset[2] = 4+offset[1]=4+block/direct_blks,第2层（dnode）中index block的个数: inode+2*dnode+indnode+block/direct_blks
	 *
	 * level = 2, 在1st indirect block包含此地址，则level = 2
         *  _________________ 
         * |                 |
         * |                 |
         * |_________________|      indirect block
         * |NODE_IND1_BLOCK  |-----> _________
         * |_________________|      |         |
         * |_________________|      |         |     dirict block
         * |_________________|      |offset[1]|----> _________
         *                          |_________|     |_________|
         *                          |         |     |offset[2]|---->addr
         *                          |_________|     |_________|
         *                                          |_________|
	 */
	block -= direct_blks;
	if (block < indirect_blks) {
		offset[n++] = NODE_IND1_BLOCK;
		noffset[n] = 3;
		offset[n++] = block / direct_blks;
		noffset[n] = 4 + offset[n - 1];
		offset[n++] = block % direct_blks;
		level = 2;
		goto got;
	}
  	/*
    	 * 如果indirect_blks < block < 2 * indirect_blks， 说明inode block中不包含，两个direct index block, 第1个indirect block也不包含
    	 * 而是在2个indirect block中，
	 *
	 * offset[0] = NODE_IND2_BLOCK, 在第0层（inode）中的索引为NODE_IND2_BLOCK
         * noffset[0] = 0, 在第0层（inode）中index block的个数为0
         *
         * offset[1] = block / direct_blks,在第1层（2nd indnode）中的索引，为其在indirect block中的索引相当于段地址
         * noffset[1] = 4 + dptrs_per_blk, 在第1层（2nd indnode）中index block的个数为:inode+2*dnode+indnode+dptrs_per_blk
         *
         * offset[2] = block % direct_blks, 在第2层（dnode）中的索引, 为其在dnode中的索引相当于段内偏移 
         * noffset[2] = 5+dptrs_per_blk+offset[n - 1]=5+dptrs_per_blk+block/direct_blks,在第2层（dnode）中index block的个数: 
	 *							inode+2*dnode+indnode+dptrs_per_blk+indnode+block/direct_blks
         *
         * level = 2, 在2st indirect block包含此地址，则level = 2
	 *
	 *  inode block
    	 *  _________________ 
    	 * |                 |
    	 * |                 |
    	 * |_________________|       indirect block
    	 * |NODE_IND2_BLOCK  |-----> _________
    	 * |_________________|      |         |
    	 * |_________________|      |         |     dirict block
    	 * |_________________|      |         |      _________
    	 *                          |_________|     |_________|
    	 *                          |offset[2]|---->|offset[2]|---->addr
    	 *                          |_________|     |_________|
    	 *                                          |_________|
    	 */
	block -= indirect_blks;
	if (block < indirect_blks) {
		offset[n++] = NODE_IND2_BLOCK;
		noffset[n] = 4 + dptrs_per_blk;
		offset[n++] = block / direct_blks;
		noffset[n] = 5 + dptrs_per_blk + offset[n - 1];
		offset[n++] = block % direct_blks;
		level = 2;
		goto got;
	}
	/*
         * 如果2*indirect_blks < block < dindirect_blks， 说明inode block中不包含，2个direct index block, 2个indirect block也不包含
         * 而是在dindirect block中，
         * offset[0] = NODE_DIND_BLOCK, 在第0层（inode）中的索引为NODE_DIND_BLOCK
	 * noffset[0] = 0, 在第0层（inode）中index block的个数为0	

         * offset[1] = block / indirect_blks, 在第1层（dindnode）中的索引,相当于dindirect block的索引
	 * noffset[1] = 5+(dptrs_per_blk*2);在第1层（dindnode）中index block的个数:inode+2*dnode+2*indnode+

         * offset[2] = (block / direct_blks) % dptrs_per_blk, 相当于indierct block的索引
	 * noffset[2] = 6 + (dptrs_per_blk * 2) + offset[n - 1] * (dptrs_per_blk + 1); ???

	 * offset[3] = block % direct_blks, 相当于direct block的索引 
	 * noffset[3] = 7 + (dptrs_per_blk * 2) + offset[n - 2] * (dptrs_per_blk + 1) + offset[n - 1];???
	 *
	 * level = 3, 在dindirect block包含此地址，则level = 3
	 */
	block -= indirect_blks;
	if (block < dindirect_blks) {
		offset[n++] = NODE_DIND_BLOCK;
		noffset[n] = 5 + (dptrs_per_blk * 2);
		offset[n++] = block / indirect_blks;
		noffset[n] = 6 + (dptrs_per_blk * 2) +
			      offset[n - 1] * (dptrs_per_blk + 1);
		offset[n++] = (block / direct_blks) % dptrs_per_blk;
		noffset[n] = 7 + (dptrs_per_blk * 2) +
			      offset[n - 2] * (dptrs_per_blk + 1) +
			      offset[n - 1];
		offset[n++] = block % direct_blks;
		level = 3;

		goto got;
	} else {
		BUG();
	}
got:
	return level;
}

/*
 * Caller should call f2fs_put_dnode(dn).
 */
/*
 * @index: dnode page中的存放的block地址的索引 
 * 本函数以index = 1941(2nd dnode的第一个index)为例进行说明
 * 通过dnode中index索引查找到对应的block地址，保存在dn->data_blkaddr中
 *
 * note:对于fsync恢复，dn中保存的均为旧的dnode page的内容
 */
int get_dnode_of_data(struct dnode_of_data *dn, pgoff_t index, int ro)
{
	struct f2fs_sb_info *sbi = F2FS_SB(dn->inode->i_sb);
	struct page *npage[4];
	struct page *parent;
	int offset[4];
	unsigned int noffset[4];
	nid_t nids[4];
	int level, i;
	int err = 0;
	/* 
	 * 根据node page的block地址的索引index，获取所处的node level
	 * 其中offset用于存放index在各级索引中的偏移，通过offset和noffset可以找到index对应的block地址
	 * (inode:0, dnode:1, indnode:2, dindnode:3)
	 *
	 * 以index = 1941为例:
	 * 则level=1
	 * offset[0] = NODE_DIR2_BLOCK
	 * offset[1] = 0
	 * noffset[0] = 0
	 * noffset[1] = 2
	 */
	level = get_node_path(index, offset, noffset);

	/* 获取index所在的dnode所属的inode的ino */
	nids[0] = dn->inode->i_ino;
	/* 
	 * 获取index所在的dnode所属的f2fs_inode的block page
	 */
	npage[0] = get_node_page(sbi, nids[0]);
	if (IS_ERR(npage[0]))
		return PTR_ERR(npage[0]);

	parent = npage[0];
	/* 
	 * 获取offset[0]对应的nid
	 *
	 * 以index=1941为例：
	 * offset[0]=NODE_DIR2_BLOCK
	 * nids[1]=f2fs_node->inode.i_nid[NODE_DIR2_BLOCK]=f2fs_node->inode.i_nid[1]
	 *
	 * note:对于fsync恢复，f2fs_node->inode.i_nid[1]保存的是旧的dnode的nid
	 */
	nids[1] = get_nid(parent, offset[0], true);
	dn->inode_page = npage[0];
	dn->inode_page_locked = true;

	/* get indirect or direct nodes */
	for (i = 1; i <= level; i++) {
		bool done = false;

		if (!nids[i] && !ro) {
			mutex_lock_op(sbi, NODE_NEW);

			/* alloc new node */
			if (!alloc_nid(sbi, &(nids[i]))) {
				mutex_unlock_op(sbi, NODE_NEW);
				err = -ENOSPC;
				goto release_pages;
			}

			dn->nid = nids[i];
			npage[i] = new_node_page(dn, noffset[i]);
			if (IS_ERR(npage[i])) {
				alloc_nid_failed(sbi, nids[i]);
				mutex_unlock_op(sbi, NODE_NEW);
				err = PTR_ERR(npage[i]);
				goto release_pages;
			}

			set_nid(parent, offset[i - 1], nids[i], i == 1);
			alloc_nid_done(sbi, nids[i]);
			mutex_unlock_op(sbi, NODE_NEW);
			done = true;
		} else if (ro && i == level && level > 1) {
			npage[i] = get_node_page_ra(parent, offset[i - 1]);
			if (IS_ERR(npage[i])) {
				err = PTR_ERR(npage[i]);
				goto release_pages;
			}
			done = true;
		}
		/*index = 1941为例*/
		if (i == 1) {
			dn->inode_page_locked = false;
			unlock_page(parent);
		} else {
			f2fs_put_page(parent, 1);
		}
		/*
		 * index = 1941为例,npage[1]保存nids[1]对应的node block page
		 * 
		 * note:对于fsync恢复，npage[1]保存的是旧的dnode page
		 */
		if (!done) {
			npage[i] = get_node_page(sbi, nids[i]);
			if (IS_ERR(npage[i])) {
				err = PTR_ERR(npage[i]);
				f2fs_put_page(npage[0], 0);
				goto release_out;
			}
		}
		if (i < level) {
			parent = npage[i];
			nids[i + 1] = get_nid(parent, offset[i], false);
		}
	}
	/* 
	 * index = 1941为例:
	 * dn->nid=nids[1],2nd dnode对应的nid
	 * dn->ofs_in_node=offset[1]=0, 在2nd dnode的偏移
	 * dn->node_page=npage[1]，2nd dnode对应的page
	 * dn->data_blkaddr=2nd dnode中偏移为0的block块号
	 */
	dn->nid = nids[level];
	dn->ofs_in_node = offset[level];
	dn->node_page = npage[level];
	dn->data_blkaddr = datablock_addr(dn->node_page, dn->ofs_in_node);
	return 0;

release_pages:
	f2fs_put_page(parent, 1);
	if (i > 1)
		f2fs_put_page(npage[0], 0);
release_out:
	dn->inode_page = NULL;
	dn->node_page = NULL;
	return err;
}

static void truncate_node(struct dnode_of_data *dn)
{
	struct f2fs_sb_info *sbi = F2FS_SB(dn->inode->i_sb);
	struct node_info ni;

	get_node_info(sbi, dn->nid, &ni);
	BUG_ON(ni.blk_addr == NULL_ADDR);

	if (ni.blk_addr != NULL_ADDR)
		invalidate_blocks(sbi, ni.blk_addr);

	/* Deallocate node address */
	dec_valid_node_count(sbi, dn->inode, 1);
	set_node_addr(sbi, &ni, NULL_ADDR);

	if (dn->nid == dn->inode->i_ino) {
		remove_orphan_inode(sbi, dn->nid);
		dec_valid_inode_count(sbi);
	} else {
		sync_inode_page(dn);
	}

	clear_node_page_dirty(dn->node_page);
	F2FS_SET_SB_DIRT(sbi);

	f2fs_put_page(dn->node_page, 1);
	dn->node_page = NULL;
}

static int truncate_dnode(struct dnode_of_data *dn)
{
	struct f2fs_sb_info *sbi = F2FS_SB(dn->inode->i_sb);
	struct page *page;

	if (dn->nid == 0)
		return 1;

	/* get direct node */
	page = get_node_page(sbi, dn->nid);
	if (IS_ERR(page) && PTR_ERR(page) == -ENOENT)
		return 1;
	else if (IS_ERR(page))
		return PTR_ERR(page);

	/* Make dnode_of_data for parameter */
	dn->node_page = page;
	dn->ofs_in_node = 0;
	truncate_data_blocks(dn);
	truncate_node(dn);
	return 1;
}

static int truncate_nodes(struct dnode_of_data *dn, unsigned int nofs,
						int ofs, int depth)
{
	struct f2fs_sb_info *sbi = F2FS_SB(dn->inode->i_sb);
	struct dnode_of_data rdn = *dn;
	struct page *page;
	struct f2fs_node *rn;
	nid_t child_nid;
	unsigned int child_nofs;
	int freed = 0;
	int i, ret;

	if (dn->nid == 0)
		return NIDS_PER_BLOCK + 1;

	page = get_node_page(sbi, dn->nid);
	if (IS_ERR(page))
		return PTR_ERR(page);

	rn = (struct f2fs_node *)page_address(page);
	if (depth < 3) {
		for (i = ofs; i < NIDS_PER_BLOCK; i++, freed++) {
			child_nid = le32_to_cpu(rn->in.nid[i]);
			if (child_nid == 0)
				continue;
			rdn.nid = child_nid;
			ret = truncate_dnode(&rdn);
			if (ret < 0)
				goto out_err;
			set_nid(page, i, 0, false);
		}
	} else {
		child_nofs = nofs + ofs * (NIDS_PER_BLOCK + 1) + 1;
		for (i = ofs; i < NIDS_PER_BLOCK; i++) {
			child_nid = le32_to_cpu(rn->in.nid[i]);
			if (child_nid == 0) {
				child_nofs += NIDS_PER_BLOCK + 1;
				continue;
			}
			rdn.nid = child_nid;
			ret = truncate_nodes(&rdn, child_nofs, 0, depth - 1);
			if (ret == (NIDS_PER_BLOCK + 1)) {
				set_nid(page, i, 0, false);
				child_nofs += ret;
			} else if (ret < 0 && ret != -ENOENT) {
				goto out_err;
			}
		}
		freed = child_nofs;
	}

	if (!ofs) {
		/* remove current indirect node */
		dn->node_page = page;
		truncate_node(dn);
		freed++;
	} else {
		f2fs_put_page(page, 1);
	}
	return freed;

out_err:
	f2fs_put_page(page, 1);
	return ret;
}

static int truncate_partial_nodes(struct dnode_of_data *dn,
			struct f2fs_inode *ri, int *offset, int depth)
{
	struct f2fs_sb_info *sbi = F2FS_SB(dn->inode->i_sb);
	struct page *pages[2];
	nid_t nid[3];
	nid_t child_nid;
	int err = 0;
	int i;
	int idx = depth - 2;

	nid[0] = le32_to_cpu(ri->i_nid[offset[0] - NODE_DIR1_BLOCK]);
	if (!nid[0])
		return 0;

	/* get indirect nodes in the path */
	for (i = 0; i < depth - 1; i++) {
		/* refernece count'll be increased */
		pages[i] = get_node_page(sbi, nid[i]);
		if (IS_ERR(pages[i])) {
			depth = i + 1;
			err = PTR_ERR(pages[i]);
			goto fail;
		}
		nid[i + 1] = get_nid(pages[i], offset[i + 1], false);
	}

	/* free direct nodes linked to a partial indirect node */
	for (i = offset[depth - 1]; i < NIDS_PER_BLOCK; i++) {
		child_nid = get_nid(pages[idx], i, false);
		if (!child_nid)
			continue;
		dn->nid = child_nid;
		err = truncate_dnode(dn);
		if (err < 0)
			goto fail;
		set_nid(pages[idx], i, 0, false);
	}

	if (offset[depth - 1] == 0) {
		dn->node_page = pages[idx];
		dn->nid = nid[idx];
		truncate_node(dn);
	} else {
		f2fs_put_page(pages[idx], 1);
	}
	offset[idx]++;
	offset[depth - 1] = 0;
fail:
	for (i = depth - 3; i >= 0; i--)
		f2fs_put_page(pages[i], 1);
	return err;
}

/**
 * All the block addresses of data and nodes should be nullified.
 */
int truncate_inode_blocks(struct inode *inode, pgoff_t from)
{
	struct f2fs_sb_info *sbi = F2FS_SB(inode->i_sb);
	int err = 0, cont = 1;
	int level, offset[4], noffset[4];
	unsigned int nofs;
	struct f2fs_node *rn;
	struct dnode_of_data dn;
	struct page *page;

	level = get_node_path(from, offset, noffset);

	page = get_node_page(sbi, inode->i_ino);
	if (IS_ERR(page))
		return PTR_ERR(page);

	set_new_dnode(&dn, inode, page, NULL, 0);
	unlock_page(page);

	rn = page_address(page);
	switch (level) {
	case 0:
	case 1:
		nofs = noffset[1];
		break;
	case 2:
		nofs = noffset[1];
		if (!offset[level - 1])
			goto skip_partial;
		err = truncate_partial_nodes(&dn, &rn->i, offset, level);
		if (err < 0 && err != -ENOENT)
			goto fail;
		nofs += 1 + NIDS_PER_BLOCK;
		break;
	case 3:
		nofs = 5 + 2 * NIDS_PER_BLOCK;
		if (!offset[level - 1])
			goto skip_partial;
		err = truncate_partial_nodes(&dn, &rn->i, offset, level);
		if (err < 0 && err != -ENOENT)
			goto fail;
		break;
	default:
		BUG();
	}

skip_partial:
	while (cont) {
		dn.nid = le32_to_cpu(rn->i.i_nid[offset[0] - NODE_DIR1_BLOCK]);
		switch (offset[0]) {
		case NODE_DIR1_BLOCK:
		case NODE_DIR2_BLOCK:
			err = truncate_dnode(&dn);
			break;

		case NODE_IND1_BLOCK:
		case NODE_IND2_BLOCK:
			err = truncate_nodes(&dn, nofs, offset[1], 2);
			break;

		case NODE_DIND_BLOCK:
			err = truncate_nodes(&dn, nofs, offset[1], 3);
			cont = 0;
			break;

		default:
			BUG();
		}
		if (err < 0 && err != -ENOENT)
			goto fail;
		if (offset[1] == 0 &&
				rn->i.i_nid[offset[0] - NODE_DIR1_BLOCK]) {
			lock_page(page);
			wait_on_page_writeback(page);
			rn->i.i_nid[offset[0] - NODE_DIR1_BLOCK] = 0;
			set_page_dirty(page);
			unlock_page(page);
		}
		offset[1] = 0;
		offset[0]++;
		nofs += err;
	}
fail:
	f2fs_put_page(page, 0);
	return err > 0 ? 0 : err;
}

int remove_inode_page(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_SB(inode->i_sb);
	struct page *page;
	nid_t ino = inode->i_ino;
	struct dnode_of_data dn;

	mutex_lock_op(sbi, NODE_TRUNC);
	page = get_node_page(sbi, ino);
	if (IS_ERR(page)) {
		mutex_unlock_op(sbi, NODE_TRUNC);
		return PTR_ERR(page);
	}

	if (F2FS_I(inode)->i_xattr_nid) {
		nid_t nid = F2FS_I(inode)->i_xattr_nid;
		struct page *npage = get_node_page(sbi, nid);

		if (IS_ERR(npage)) {
			mutex_unlock_op(sbi, NODE_TRUNC);
			return PTR_ERR(npage);
		}

		F2FS_I(inode)->i_xattr_nid = 0;
		set_new_dnode(&dn, inode, page, npage, nid);
		dn.inode_page_locked = 1;
		truncate_node(&dn);
	}
	if (inode->i_blocks == 1) {
		/* inernally call f2fs_put_page() */
		set_new_dnode(&dn, inode, page, page, ino);
		truncate_node(&dn);
	} else if (inode->i_blocks == 0) {
		struct node_info ni;
		get_node_info(sbi, inode->i_ino, &ni);

		/* called after f2fs_new_inode() is failed */
		BUG_ON(ni.blk_addr != NULL_ADDR);
		f2fs_put_page(page, 1);
	} else {
		BUG();
	}
	mutex_unlock_op(sbi, NODE_TRUNC);
	return 0;
}

int new_inode_page(struct inode *inode, struct dentry *dentry)
{
	struct f2fs_sb_info *sbi = F2FS_SB(inode->i_sb);
	struct page *page;
	struct dnode_of_data dn;

	/* allocate inode page for new inode */
	set_new_dnode(&dn, inode, NULL, NULL, inode->i_ino);
	mutex_lock_op(sbi, NODE_NEW);
	page = new_node_page(&dn, 0);
	init_dent_inode(dentry, page);
	mutex_unlock_op(sbi, NODE_NEW);
	if (IS_ERR(page))
		return PTR_ERR(page);
	f2fs_put_page(page, 1);
	return 0;
}

struct page *new_node_page(struct dnode_of_data *dn, unsigned int ofs)
{
	struct f2fs_sb_info *sbi = F2FS_SB(dn->inode->i_sb);
	struct address_space *mapping = sbi->node_inode->i_mapping;
	struct node_info old_ni, new_ni;
	struct page *page;
	int err;

	if (is_inode_flag_set(F2FS_I(dn->inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	page = grab_cache_page(mapping, dn->nid);
	if (!page)
		return ERR_PTR(-ENOMEM);

	get_node_info(sbi, dn->nid, &old_ni);

	SetPageUptodate(page);
	fill_node_footer(page, dn->nid, dn->inode->i_ino, ofs, true);

	/* Reinitialize old_ni with new node page */
	BUG_ON(old_ni.blk_addr != NULL_ADDR);
	new_ni = old_ni;
	new_ni.ino = dn->inode->i_ino;

	if (!inc_valid_node_count(sbi, dn->inode, 1)) {
		err = -ENOSPC;
		goto fail;
	}
	set_node_addr(sbi, &new_ni, NEW_ADDR);

	dn->node_page = page;
	sync_inode_page(dn);
	set_page_dirty(page);
	set_cold_node(dn->inode, page);
	if (ofs == 0)
		inc_valid_inode_count(sbi);

	return page;

fail:
	f2fs_put_page(page, 1);
	return ERR_PTR(err);
}
/*以page->index为nid获取对应的node block page*/
static int read_node_page(struct page *page, int type)
{
	struct f2fs_sb_info *sbi = F2FS_SB(page->mapping->host->i_sb);
	struct node_info ni;
	/*获取nid(page->index)对应的f2fs nat entry,用于初始化ni*/
	get_node_info(sbi, page->index, &ni);

	if (ni.blk_addr == NULL_ADDR)
		return -ENOENT;
	/*读取ni对应的node block page*/
	return f2fs_readpage(sbi, page, ni.blk_addr, type);
}

/**
 * Readahead a node page
 */
void ra_node_page(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct address_space *mapping = sbi->node_inode->i_mapping;
	struct page *apage;

	apage = find_get_page(mapping, nid);
	if (apage && PageUptodate(apage))
		goto release_out;
	f2fs_put_page(apage, 0);

	apage = grab_cache_page(mapping, nid);
	if (!apage)
		return;

	if (read_node_page(apage, READA))
		goto unlock_out;

	page_cache_release(apage);
	return;

unlock_out:
	unlock_page(apage);
release_out:
	page_cache_release(apage);
}
/*获取nid对应的node block page*/
struct page *get_node_page(struct f2fs_sb_info *sbi, pgoff_t nid)
{
	int err;
	struct page *page;
	struct address_space *mapping = sbi->node_inode->i_mapping;

	page = grab_cache_page(mapping, nid);
	if (!page)
		return ERR_PTR(-ENOMEM);

	/*以page->index为nid获取对应node block page*/
	err = read_node_page(page, READ_SYNC);
	if (err) {
		f2fs_put_page(page, 1);
		return ERR_PTR(err);
	}

	BUG_ON(nid != nid_of_node(page));
	mark_page_accessed(page);
	return page;
}

/**
 * Return a locked page for the desired node page.
 * And, readahead MAX_RA_NODE number of node pages.
 */
struct page *get_node_page_ra(struct page *parent, int start)
{
	struct f2fs_sb_info *sbi = F2FS_SB(parent->mapping->host->i_sb);
	struct address_space *mapping = sbi->node_inode->i_mapping;
	int i, end;
	int err = 0;
	nid_t nid;
	struct page *page;

	/* First, try getting the desired direct node. */
	nid = get_nid(parent, start, false);
	if (!nid)
		return ERR_PTR(-ENOENT);

	page = find_get_page(mapping, nid);
	if (page && PageUptodate(page))
		goto page_hit;
	f2fs_put_page(page, 0);

repeat:
	page = grab_cache_page(mapping, nid);
	if (!page)
		return ERR_PTR(-ENOMEM);

	err = read_node_page(page, READA);
	if (err) {
		f2fs_put_page(page, 1);
		return ERR_PTR(err);
	}

	/* Then, try readahead for siblings of the desired node */
	end = start + MAX_RA_NODE;
	end = min(end, NIDS_PER_BLOCK);
	for (i = start + 1; i < end; i++) {
		nid = get_nid(parent, i, false);
		if (!nid)
			continue;
		ra_node_page(sbi, nid);
	}

page_hit:
	lock_page(page);
	if (PageError(page)) {
		f2fs_put_page(page, 1);
		return ERR_PTR(-EIO);
	}

	/* Has the page been truncated? */
	if (page->mapping != mapping) {
		f2fs_put_page(page, 1);
		goto repeat;
	}
	return page;
}

void sync_inode_page(struct dnode_of_data *dn)
{
	if (IS_INODE(dn->node_page) || dn->inode_page == dn->node_page) {
		update_inode(dn->inode, dn->node_page);
	} else if (dn->inode_page) {
		if (!dn->inode_page_locked)
			lock_page(dn->inode_page);
		update_inode(dn->inode, dn->inode_page);
		if (!dn->inode_page_locked)
			unlock_page(dn->inode_page);
	} else {
		f2fs_write_inode(dn->inode, NULL);
	}
}

int sync_node_pages(struct f2fs_sb_info *sbi, nid_t ino,
					struct writeback_control *wbc)
{
	struct address_space *mapping = sbi->node_inode->i_mapping;
	pgoff_t index, end;
	struct pagevec pvec;
	int step = ino ? 2 : 0;
	int nwritten = 0, wrote = 0;

	pagevec_init(&pvec, 0);

next_step:
	index = 0;
	end = LONG_MAX;

	while (index <= end) {
		int i, nr_pages;
		nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
				PAGECACHE_TAG_DIRTY,
				min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/*
			 * flushing sequence with step:
			 * 0. indirect nodes
			 * 1. dentry dnodes
			 * 2. file dnodes
			 */
			if (step == 0 && IS_DNODE(page))
				continue;
			if (step == 1 && (!IS_DNODE(page) ||
						is_cold_node(page)))
				continue;
			if (step == 2 && (!IS_DNODE(page) ||
						!is_cold_node(page)))
				continue;

			/*
			 * If an fsync mode,
			 * we should not skip writing node pages.
			 */
			if (ino && ino_of_node(page) == ino)
				lock_page(page);
			else if (!trylock_page(page))
				continue;

			if (unlikely(page->mapping != mapping)) {
continue_unlock:
				unlock_page(page);
				continue;
			}
			if (ino && ino_of_node(page) != ino)
				goto continue_unlock;

			if (!PageDirty(page)) {
				/* someone wrote it for us */
				goto continue_unlock;
			}

			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			/* called by fsync() */
			if (ino && IS_DNODE(page)) {
				int mark = !is_checkpointed_node(sbi, ino);
				set_fsync_mark(page, 1);
				if (IS_INODE(page))
					set_dentry_mark(page, mark);
				nwritten++;
			} else {
				set_fsync_mark(page, 0);
				set_dentry_mark(page, 0);
			}
			mapping->a_ops->writepage(page, wbc);
			wrote++;

			if (--wbc->nr_to_write == 0)
				break;
		}
		pagevec_release(&pvec);
		cond_resched();

		if (wbc->nr_to_write == 0) {
			step = 2;
			break;
		}
	}

	if (step < 2) {
		step++;
		goto next_step;
	}

	if (wrote)
		f2fs_submit_bio(sbi, NODE, wbc->sync_mode == WB_SYNC_ALL);

	return nwritten;
}

static int f2fs_write_node_page(struct page *page,
				struct writeback_control *wbc)
{
	struct f2fs_sb_info *sbi = F2FS_SB(page->mapping->host->i_sb);
	nid_t nid;
	unsigned int nofs;
	block_t new_addr;
	struct node_info ni;

	if (wbc->for_reclaim) {
		dec_page_count(sbi, F2FS_DIRTY_NODES);
		wbc->pages_skipped++;
		set_page_dirty(page);
		return AOP_WRITEPAGE_ACTIVATE;
	}

	wait_on_page_writeback(page);

	mutex_lock_op(sbi, NODE_WRITE);

	/* get old block addr of this node page */
	nid = nid_of_node(page);
	nofs = ofs_of_node(page);
	BUG_ON(page->index != nid);

	get_node_info(sbi, nid, &ni);

	/* This page is already truncated */
	if (ni.blk_addr == NULL_ADDR)
		return 0;

	set_page_writeback(page);

	/* insert node offset */
	write_node_page(sbi, page, nid, ni.blk_addr, &new_addr);
	set_node_addr(sbi, &ni, new_addr);
	dec_page_count(sbi, F2FS_DIRTY_NODES);

	mutex_unlock_op(sbi, NODE_WRITE);
	unlock_page(page);
	return 0;
}

static int f2fs_write_node_pages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct f2fs_sb_info *sbi = F2FS_SB(mapping->host->i_sb);
	struct block_device *bdev = sbi->sb->s_bdev;
	long nr_to_write = wbc->nr_to_write;

	if (wbc->for_kupdate)
		return 0;

	if (get_pages(sbi, F2FS_DIRTY_NODES) == 0)
		return 0;

	if (try_to_free_nats(sbi, NAT_ENTRY_PER_BLOCK)) {
		write_checkpoint(sbi, false, false);
		return 0;
	}

	/* if mounting is failed, skip writing node pages */
	wbc->nr_to_write = bio_get_nr_vecs(bdev);
	sync_node_pages(sbi, 0, wbc);
	wbc->nr_to_write = nr_to_write -
		(bio_get_nr_vecs(bdev) - wbc->nr_to_write);
	return 0;
}

static int f2fs_set_node_page_dirty(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct f2fs_sb_info *sbi = F2FS_SB(mapping->host->i_sb);

	SetPageUptodate(page);
	if (!PageDirty(page)) {
		__set_page_dirty_nobuffers(page);
		inc_page_count(sbi, F2FS_DIRTY_NODES);
		SetPagePrivate(page);
		return 1;
	}
	return 0;
}

static void f2fs_invalidate_node_page(struct page *page, unsigned long offset)
{
	struct inode *inode = page->mapping->host;
	struct f2fs_sb_info *sbi = F2FS_SB(inode->i_sb);
	if (PageDirty(page))
		dec_page_count(sbi, F2FS_DIRTY_NODES);
	ClearPagePrivate(page);
}

static int f2fs_release_node_page(struct page *page, gfp_t wait)
{
	ClearPagePrivate(page);
	return 0;
}

/**
 * Structure of the f2fs node operations
 */
const struct address_space_operations f2fs_node_aops = {
	.writepage	= f2fs_write_node_page,
	.writepages	= f2fs_write_node_pages,
	.set_page_dirty	= f2fs_set_node_page_dirty,
	.invalidatepage	= f2fs_invalidate_node_page,
	.releasepage	= f2fs_release_node_page,
};

static struct free_nid *__lookup_free_nid_list(nid_t n, struct list_head *head)
{
	struct list_head *this;
	struct free_nid *i = NULL;
	list_for_each(this, head) {
		i = list_entry(this, struct free_nid, list);
		if (i->nid == n)
			break;
		i = NULL;
	}
	return i;
}

static void __del_from_free_nid_list(struct free_nid *i)
{
	list_del(&i->list);
	kmem_cache_free(free_nid_slab, i);
}

static int add_free_nid(struct f2fs_nm_info *nm_i, nid_t nid)
{
	struct free_nid *i;

	if (nm_i->fcnt > 2 * MAX_FREE_NIDS)
		return 0;
retry:
	i = kmem_cache_alloc(free_nid_slab, GFP_NOFS);
	if (!i) {
		cond_resched();
		goto retry;
	}
	i->nid = nid;
	i->state = NID_NEW;

	spin_lock(&nm_i->free_nid_list_lock);
	if (__lookup_free_nid_list(nid, &nm_i->free_nid_list)) {
		spin_unlock(&nm_i->free_nid_list_lock);
		kmem_cache_free(free_nid_slab, i);
		return 0;
	}
	list_add_tail(&i->list, &nm_i->free_nid_list);
	nm_i->fcnt++;
	spin_unlock(&nm_i->free_nid_list_lock);
	return 1;
}

static void remove_free_nid(struct f2fs_nm_info *nm_i, nid_t nid)
{
	struct free_nid *i;
	spin_lock(&nm_i->free_nid_list_lock);
	i = __lookup_free_nid_list(nid, &nm_i->free_nid_list);
	if (i && i->state == NID_NEW) {
		__del_from_free_nid_list(i);
		nm_i->fcnt--;
	}
	spin_unlock(&nm_i->free_nid_list_lock);
}
/**
 * 从nat entry block的nid的nat entry开始扫描,将block_addr为空的nat entry的nid加入到free nid list
 */ 
static int scan_nat_page(struct f2fs_nm_info *nm_i,
			struct page *nat_page, nid_t start_nid)
{
	struct f2fs_nat_block *nat_blk = page_address(nat_page);
	block_t blk_addr;
	int fcnt = 0;
	int i;

	/* 0 nid should not be used */
	if (start_nid == 0)
		++start_nid;

	i = start_nid % NAT_ENTRY_PER_BLOCK;

	for (; i < NAT_ENTRY_PER_BLOCK; i++, start_nid++) {
		blk_addr  = le32_to_cpu(nat_blk->entries[i].block_addr);
		BUG_ON(blk_addr == NEW_ADDR);
		if (blk_addr == NULL_ADDR)
			fcnt += add_free_nid(nm_i, start_nid);
	}
	return fcnt;
}
/* 扫描nat entries，将free nid加入到free nid链表 */
static void build_free_nids(struct f2fs_sb_info *sbi)
{
	struct free_nid *fnid, *next_fnid;
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_summary_block *sum = curseg->sum_blk;
	nid_t nid = 0;
	bool is_cycled = false;
	int fcnt = 0;
	int i;

	nid = nm_i->next_scan_nid;
	nm_i->init_scan_nid = nid;
	/* 
	 * 从nid所在的nat entry block预读FREE_NID_PAGES个block page
	 * 这样后面直接可以读page，不用再读磁盘
	 */
	ra_nat_pages(sbi, nid);

	while (1) {
		struct page *page = get_current_nat_page(sbi, nid);
		/* 扫描一个nat entry block page,累加free nids */
		fcnt += scan_nat_page(nm_i, page, nid);
		f2fs_put_page(page, 1);

		nid += (NAT_ENTRY_PER_BLOCK - (nid % NAT_ENTRY_PER_BLOCK));

		if (nid >= nm_i->max_nid) {
			nid = 0;
			is_cycled = true;
		}
		if (fcnt > MAX_FREE_NIDS)
			break;
		if (is_cycled && nm_i->init_scan_nid <= nid)
			break;
	}

	nm_i->next_scan_nid = nid;

	/* find free nids from current sum_pages */
	mutex_lock(&curseg->curseg_mutex);
	for (i = 0; i < nats_in_cursum(sum); i++) {
		block_t addr = le32_to_cpu(nat_in_journal(sum, i).block_addr);
		nid = le32_to_cpu(nid_in_journal(sum, i));
		if (addr == NULL_ADDR)
			add_free_nid(nm_i, nid);
		else
			remove_free_nid(nm_i, nid);
	}
	mutex_unlock(&curseg->curseg_mutex);

	/* remove the free nids from current allocated nids */
	list_for_each_entry_safe(fnid, next_fnid, &nm_i->free_nid_list, list) {
		struct nat_entry *ne;

		read_lock(&nm_i->nat_tree_lock);
		ne = __lookup_nat_cache(nm_i, fnid->nid);
		if (ne && nat_get_blkaddr(ne) != NULL_ADDR)
			remove_free_nid(nm_i, fnid->nid);
		read_unlock(&nm_i->nat_tree_lock);
	}
}

/*
 * If this function returns success, caller can obtain a new nid
 * from second parameter of this function.
 * The returned nid could be used ino as well as nid when inode is created.
 */
/* 遍历free_nid_list找到空闲的nid */
bool alloc_nid(struct f2fs_sb_info *sbi, nid_t *nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i = NULL;
	struct list_head *this;
retry:
	mutex_lock(&nm_i->build_lock);
	if (!nm_i->fcnt) {
		/* scan NAT in order to build free nid list */
		build_free_nids(sbi);
		if (!nm_i->fcnt) {
			mutex_unlock(&nm_i->build_lock);
			return false;
		}
	}
	mutex_unlock(&nm_i->build_lock);

	/*
	 * We check fcnt again since previous check is racy as
	 * we didn't hold free_nid_list_lock. So other thread
	 * could consume all of free nids.
	 */
	spin_lock(&nm_i->free_nid_list_lock);
	if (!nm_i->fcnt) {
		spin_unlock(&nm_i->free_nid_list_lock);
		goto retry;
	}

	BUG_ON(list_empty(&nm_i->free_nid_list));
	list_for_each(this, &nm_i->free_nid_list) {
		i = list_entry(this, struct free_nid, list);
		if (i->state == NID_NEW)
			break;
	}

	BUG_ON(i->state != NID_NEW);
	*nid = i->nid;
	i->state = NID_ALLOC;
	nm_i->fcnt--;
	spin_unlock(&nm_i->free_nid_list_lock);
	return true;
}

/**
 * alloc_nid() should be called prior to this function.
 */
void alloc_nid_done(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i;

	spin_lock(&nm_i->free_nid_list_lock);
	i = __lookup_free_nid_list(nid, &nm_i->free_nid_list);
	if (i) {
		BUG_ON(i->state != NID_ALLOC);
		__del_from_free_nid_list(i);
	}
	spin_unlock(&nm_i->free_nid_list_lock);
}

/**
 * alloc_nid() should be called prior to this function.
 */
void alloc_nid_failed(struct f2fs_sb_info *sbi, nid_t nid)
{
	alloc_nid_done(sbi, nid);
	add_free_nid(NM_I(sbi), nid);
}
/*
 * @new_blkaddr: fysnc的dnone block
 * 就地修改nat_entry
 */
void recover_node_page(struct f2fs_sb_info *sbi, struct page *page,
		struct f2fs_summary *sum, struct node_info *ni,
		block_t new_blkaddr)
{
	rewrite_node_page(sbi, page, sum, ni->blk_addr, new_blkaddr);
	set_node_addr(sbi, ni, new_blkaddr);
	clear_node_page_dirty(page);
}

int recover_inode_page(struct f2fs_sb_info *sbi, struct page *page)
{
	struct address_space *mapping = sbi->node_inode->i_mapping;
	struct f2fs_node *src, *dst;
	nid_t ino = ino_of_node(page);
	struct node_info old_ni, new_ni;
	struct page *ipage;

	ipage = grab_cache_page(mapping, ino);
	if (!ipage)
		return -ENOMEM;

	/* Should not use this inode  from free nid list */
	remove_free_nid(NM_I(sbi), ino);

	get_node_info(sbi, ino, &old_ni);
	SetPageUptodate(ipage);
	fill_node_footer(ipage, ino, ino, 0, true);

	src = (struct f2fs_node *)page_address(page);
	dst = (struct f2fs_node *)page_address(ipage);

	memcpy(dst, src, (unsigned long)&src->i.i_ext - (unsigned long)&src->i);
	dst->i.i_size = 0;
	dst->i.i_blocks = 1;
	dst->i.i_links = 1;
	dst->i.i_xattr_nid = 0;

	new_ni = old_ni;
	new_ni.ino = ino;

	set_node_addr(sbi, &new_ni, NEW_ADDR);
	inc_valid_inode_count(sbi);

	f2fs_put_page(ipage, 1);
	return 0;
}

int restore_node_summary(struct f2fs_sb_info *sbi,
			unsigned int segno, struct f2fs_summary_block *sum)
{
	struct f2fs_node *rn;
	struct f2fs_summary *sum_entry;
	struct page *page;
	block_t addr;
	int i, last_offset;

	/* alloc temporal page for read node */
	page = alloc_page(GFP_NOFS | __GFP_ZERO);
	if (IS_ERR(page))
		return PTR_ERR(page);
	lock_page(page);

	/* scan the node segment */
	last_offset = sbi->blocks_per_seg;
	addr = START_BLOCK(sbi, segno);
	sum_entry = &sum->entries[0];

	for (i = 0; i < last_offset; i++, sum_entry++) {
		if (f2fs_readpage(sbi, page, addr, READ_SYNC))
			goto out;

		rn = (struct f2fs_node *)page_address(page);
		sum_entry->nid = rn->footer.nid;
		sum_entry->version = 0;
		sum_entry->ofs_in_node = 0;
		addr++;

		/*
		 * In order to read next node page,
		 * we must clear PageUptodate flag.
		 */
		ClearPageUptodate(page);
	}
out:
	unlock_page(page);
	__free_pages(page, 0);
	return 0;
}
/*遍历current segment的summary nat journal，将dirty nat entry加入nm_i->dirty_nat_entries链表*/
static bool flush_nats_in_journal(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_summary_block *sum = curseg->sum_blk;
	int i;

	mutex_lock(&curseg->curseg_mutex);
	/*返回false表示没有flush*/
	if (nats_in_cursum(sum) < NAT_JOURNAL_ENTRIES) {
		mutex_unlock(&curseg->curseg_mutex);
		return false;
	}
	/*遍历current segment的summary nat journal，将dirty nat entry加入nm_i->dirty_nat_entries链表*/
	for (i = 0; i < nats_in_cursum(sum); i++) {
		struct nat_entry *ne;
		struct f2fs_nat_entry raw_ne;
		nid_t nid = le32_to_cpu(nid_in_journal(sum, i));

		raw_ne = nat_in_journal(sum, i);
retry:
		write_lock(&nm_i->nat_tree_lock);
		/*首先从nat cache中查找, 如果查找到则转移到nm_i->dirty_nat_entries*/
		ne = __lookup_nat_cache(nm_i, nid);
		if (ne) {
			__set_nat_cache_dirty(nm_i, ne);
			write_unlock(&nm_i->nat_tree_lock);
			continue;
		}
		/*其次如果在nat cache中没有查找到，则创建新的nat entry并加入到nm_i->dirty_nat_entries*/
		ne = grab_nat_entry(nm_i, nid);
		if (!ne) {
			write_unlock(&nm_i->nat_tree_lock);
			goto retry;
		}
		nat_set_blkaddr(ne, le32_to_cpu(raw_ne.block_addr));
		nat_set_ino(ne, le32_to_cpu(raw_ne.ino));
		nat_set_version(ne, raw_ne.version);
		__set_nat_cache_dirty(nm_i, ne);
		write_unlock(&nm_i->nat_tree_lock);
	}
	update_nats_in_cursum(sum, -i);
	mutex_unlock(&curseg->curseg_mutex);
	return true;
}

/**
 * This function is called during the checkpointing process.
 */
/*flush dirty的nat entry，如果current segment的summary有空间则更新到此，否则更新到nat区*/
void flush_nat_entries(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_summary_block *sum = curseg->sum_blk;
	struct list_head *cur, *n;
	struct page *page = NULL;
	struct f2fs_nat_block *nat_blk = NULL;
	nid_t start_nid = 0, end_nid = 0;
	bool flushed;

	/*遍历current segment的summary nat journal，将dirty nat entry加入nm_i->dirty_nat_entries链表*/
	flushed = flush_nats_in_journal(sbi);

	if (!flushed)
		mutex_lock(&curseg->curseg_mutex);

	/* 1) flush dirty nat caches */
	list_for_each_safe(cur, n, &nm_i->dirty_nat_entries) {
		struct nat_entry *ne;
		nid_t nid;
		struct f2fs_nat_entry raw_ne;
		int offset = -1;
		block_t old_blkaddr, new_blkaddr;

		ne = list_entry(cur, struct nat_entry, list);
		nid = nat_get_nid(ne);

		if (nat_get_blkaddr(ne) == NEW_ADDR)
			continue;
		if (flushed)
			goto to_nat_page;

		/* if there is room for nat enries in curseg->sumpage */
		/*如果current segment  sum block的nat journal有空间，则更新到此*/
		offset = lookup_journal_in_cursum(sum, NAT_JOURNAL, nid, 1);
		if (offset >= 0) {
			raw_ne = nat_in_journal(sum, offset);
			old_blkaddr = le32_to_cpu(raw_ne.block_addr);
			goto flush_now;
		}
		/*如果current segment sum block的nat journal没有空间，则更新到nat page*/
to_nat_page:
		if (!page || (start_nid > nid || nid > end_nid)) {
			if (page) {
				f2fs_put_page(page, 1);
				page = NULL;
			}
			start_nid = START_NID(nid);
			end_nid = start_nid + NAT_ENTRY_PER_BLOCK - 1;

			/*
			 * get nat block with dirty flag, increased reference
			 * count, mapped and lock
			 */
			page = get_next_nat_page(sbi, start_nid);
			nat_blk = page_address(page);
		}

		BUG_ON(!nat_blk);
		raw_ne = nat_blk->entries[nid - start_nid];
		old_blkaddr = le32_to_cpu(raw_ne.block_addr);
flush_now:
		new_blkaddr = nat_get_blkaddr(ne);

		raw_ne.ino = cpu_to_le32(nat_get_ino(ne));
		raw_ne.block_addr = cpu_to_le32(new_blkaddr);
		raw_ne.version = nat_get_version(ne);

		if (offset < 0) {
			nat_blk->entries[nid - start_nid] = raw_ne;
		} else {
			nat_in_journal(sum, offset) = raw_ne;
			nid_in_journal(sum, offset) = cpu_to_le32(nid);
		}

		if (nat_get_blkaddr(ne) == NULL_ADDR) {
			write_lock(&nm_i->nat_tree_lock);
			__del_from_nat_cache(nm_i, ne);
			write_unlock(&nm_i->nat_tree_lock);

			/* We can reuse this freed nid at this point */
			add_free_nid(NM_I(sbi), nid);
		} else {
			write_lock(&nm_i->nat_tree_lock);
			__clear_nat_cache_dirty(nm_i, ne);
			ne->checkpointed = true;
			write_unlock(&nm_i->nat_tree_lock);
		}
	}
	if (!flushed)
		mutex_unlock(&curseg->curseg_mutex);
	f2fs_put_page(page, 1);

	/* 2) shrink nat caches if necessary */
	try_to_free_nats(sbi, nm_i->nat_cnt - NM_WOUT_THRESHOLD);
}
/* 初始化node manager info, 重点初始化了nat_bitmap, 它来源于cp  */
static int init_node_manager(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *sb_raw = F2FS_RAW_SUPER(sbi);
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned char *version_bitmap;
	unsigned int nat_segs, nat_blocks;

	nm_i->nat_blkaddr = le32_to_cpu(sb_raw->nat_blkaddr);

	/* segment_count_nat includes pair segment so divide to 2. */
	nat_segs = le32_to_cpu(sb_raw->segment_count_nat) >> 1;
	nat_blocks = nat_segs << le32_to_cpu(sb_raw->log_blocks_per_seg);
	nm_i->max_nid = NAT_ENTRY_PER_BLOCK * nat_blocks;
	nm_i->fcnt = 0;
	nm_i->nat_cnt = 0;

	INIT_LIST_HEAD(&nm_i->free_nid_list);
	INIT_RADIX_TREE(&nm_i->nat_root, GFP_ATOMIC);
	INIT_LIST_HEAD(&nm_i->nat_entries);
	INIT_LIST_HEAD(&nm_i->dirty_nat_entries);

	mutex_init(&nm_i->build_lock);
	spin_lock_init(&nm_i->free_nid_list_lock);
	rwlock_init(&nm_i->nat_tree_lock);

	nm_i->bitmap_size = __bitmap_size(sbi, NAT_BITMAP);
	nm_i->init_scan_nid = le32_to_cpu(sbi->ckpt->next_free_nid);
	nm_i->next_scan_nid = le32_to_cpu(sbi->ckpt->next_free_nid);
	/* 来源于cp区域的nat version bitmap*/
	nm_i->nat_bitmap = kzalloc(nm_i->bitmap_size, GFP_KERNEL);
	if (!nm_i->nat_bitmap)
		return -ENOMEM;
	version_bitmap = __bitmap_ptr(sbi, NAT_BITMAP);
	if (!version_bitmap)
		return -EFAULT;

	/* copy version bitmap */
	memcpy(nm_i->nat_bitmap, version_bitmap, nm_i->bitmap_size);
	return 0;
}

int build_node_manager(struct f2fs_sb_info *sbi)
{
	int err;

	sbi->nm_info = kzalloc(sizeof(struct f2fs_nm_info), GFP_KERNEL);
	if (!sbi->nm_info)
		return -ENOMEM;

	err = init_node_manager(sbi);
	if (err)
		return err;

	build_free_nids(sbi);
	return 0;
}

void destroy_node_manager(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *i, *next_i;
	struct nat_entry *natvec[NATVEC_SIZE];
	nid_t nid = 0;
	unsigned int found;

	if (!nm_i)
		return;

	/* destroy free nid list */
	spin_lock(&nm_i->free_nid_list_lock);
	list_for_each_entry_safe(i, next_i, &nm_i->free_nid_list, list) {
		BUG_ON(i->state == NID_ALLOC);
		__del_from_free_nid_list(i);
		nm_i->fcnt--;
	}
	BUG_ON(nm_i->fcnt);
	spin_unlock(&nm_i->free_nid_list_lock);

	/* destroy nat cache */
	write_lock(&nm_i->nat_tree_lock);
	while ((found = __gang_lookup_nat_cache(nm_i,
					nid, NATVEC_SIZE, natvec))) {
		unsigned idx;
		for (idx = 0; idx < found; idx++) {
			struct nat_entry *e = natvec[idx];
			nid = nat_get_nid(e) + 1;
			__del_from_nat_cache(nm_i, e);
		}
	}
	BUG_ON(nm_i->nat_cnt);
	write_unlock(&nm_i->nat_tree_lock);

	kfree(nm_i->nat_bitmap);
	sbi->nm_info = NULL;
	kfree(nm_i);
}

int create_node_manager_caches(void)
{
	nat_entry_slab = f2fs_kmem_cache_create("nat_entry",
			sizeof(struct nat_entry), NULL);
	if (!nat_entry_slab)
		return -ENOMEM;

	free_nid_slab = f2fs_kmem_cache_create("free_nid",
			sizeof(struct free_nid), NULL);
	if (!free_nid_slab) {
		kmem_cache_destroy(nat_entry_slab);
		return -ENOMEM;
	}
	return 0;
}

void destroy_node_manager_caches(void)
{
	kmem_cache_destroy(free_nid_slab);
	kmem_cache_destroy(nat_entry_slab);
}
