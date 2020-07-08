/**
 * fs/f2fs/gc.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/f2fs_fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/blkdev.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "gc.h"

static struct kmem_cache *winode_slab;

static int gc_thread_func(void *data)
{
	struct f2fs_sb_info *sbi = data;
	wait_queue_head_t *wq = &sbi->gc_thread->gc_wait_queue_head;
	long wait_ms;

	wait_ms = GC_THREAD_MIN_SLEEP_TIME;

	do {
		if (try_to_freeze())
			continue;
		else
			wait_event_interruptible_timeout(*wq,
						kthread_should_stop(),
						msecs_to_jiffies(wait_ms));
		if (kthread_should_stop())
			break;

		f2fs_balance_fs(sbi);

		if (!test_opt(sbi, BG_GC))
			continue;

		/*
		 * [GC triggering condition]
		 * 0. GC is not conducted currently.
		 * 1. There are enough dirty segments.
		 * 2. IO subsystem is idle by checking the # of writeback pages.
		 * 3. IO subsystem is idle by checking the # of requests in
		 *    bdev's request list.
		 *
		 * Note) We have to avoid triggering GCs too much frequently.
		 * Because it is possible that some segments can be
		 * invalidated soon after by user update or deletion.
		 * So, I'd like to wait some time to collect dirty segments.
		 */
		if (!mutex_trylock(&sbi->gc_mutex))
			continue;

		if (!is_idle(sbi)) {
			wait_ms = increase_sleep_time(wait_ms);
			mutex_unlock(&sbi->gc_mutex);
			continue;
		}

		if (has_enough_invalid_blocks(sbi))
			wait_ms = decrease_sleep_time(wait_ms);
		else
			wait_ms = increase_sleep_time(wait_ms);

		sbi->bg_gc++;

		if (f2fs_gc(sbi, 1) == GC_NONE)
			wait_ms = GC_THREAD_NOGC_SLEEP_TIME;
		else if (wait_ms == GC_THREAD_NOGC_SLEEP_TIME)
			wait_ms = GC_THREAD_MAX_SLEEP_TIME;

	} while (!kthread_should_stop());
	return 0;
}

int start_gc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_gc_kthread *gc_th = NULL;

	gc_th = kmalloc(sizeof(struct f2fs_gc_kthread), GFP_KERNEL);
	if (!gc_th)
		return -ENOMEM;

	sbi->gc_thread = gc_th;
	init_waitqueue_head(&sbi->gc_thread->gc_wait_queue_head);
	sbi->gc_thread->f2fs_gc_task = kthread_run(gc_thread_func, sbi,
				GC_THREAD_NAME);
	if (IS_ERR(gc_th->f2fs_gc_task)) {
		kfree(gc_th);
		return -ENOMEM;
	}
	return 0;
}

void stop_gc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_gc_kthread *gc_th = sbi->gc_thread;
	if (!gc_th)
		return;
	kthread_stop(gc_th->f2fs_gc_task);
	kfree(gc_th);
	sbi->gc_thread = NULL;
}
/* @type: GC_CB or GC_GREEDY  */
static int select_gc_type(int gc_type)
{
	return (gc_type == BG_GC) ? GC_CB : GC_GREEDY;
}

static void select_policy(struct f2fs_sb_info *sbi, int gc_type,
			int type, struct victim_sel_policy *p)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	if (p->alloc_mode) {/* SSR MODE*/
		p->gc_mode = GC_GREEDY;
		p->dirty_segmap = dirty_i->dirty_segmap[type];
		p->ofs_unit = 1;
	} else { /* LFS MODE*/
		p->gc_mode = select_gc_type(gc_type);
		p->dirty_segmap = dirty_i->dirty_segmap[DIRTY];
		p->ofs_unit = sbi->segs_per_sec;
	}
	p->offset = sbi->last_victim[p->gc_mode];
}

static unsigned int get_max_cost(struct f2fs_sb_info *sbi,
				struct victim_sel_policy *p)
{
	if (p->gc_mode == GC_GREEDY)
		return (1 << sbi->log_blocks_per_seg) * p->ofs_unit;
	else if (p->gc_mode == GC_CB)
		return UINT_MAX;
	else /* No other gc_mode */
		return 0;
}

static unsigned int check_bg_victims(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int segno;

	/*
	 * If the gc_type is FG_GC, we can select victim segments
	 * selected by background GC before.
	 * Those segments guarantee they have small valid blocks.
	 */
	segno = find_next_bit(dirty_i->victim_segmap[BG_GC],
						TOTAL_SEGS(sbi), 0);
	if (segno < TOTAL_SEGS(sbi)) {
		clear_bit(segno, dirty_i->victim_segmap[BG_GC]);
		return segno;
	}
	return NULL_SEGNO;
}
/*
 * Cost-Benefit算法 Cost-Benefit算法是一个同时考虑最近一次修改时间以及invalid block个数的算法。
 * 因为相当于频繁修改的数据而言，不值得进行GC，因为GC完很快就修改了，同时由于异地更新的特性，导致继续产生invalid block。
 * 较长时间未作修改的数据，可以认为迁移以后也相对没那么频繁继续产生invalid block。Cost-Benefit算法的核心是:
 *
 * cost = (1 - u) / 2u * age
 * 其中
 * u: 表示valid block在该section中的比例
 * 1-u: 表示对这个section进行gc后的收益
 * 2u:  表示对这个section的GC的开销，读取Valid block（1个u）然后写入到到新的segment（再1个u）
 * age: 表示上一次修改时间
 */
static unsigned int get_cb_cost(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int secno = GET_SECNO(sbi, segno);
	unsigned int start = secno * sbi->segs_per_sec;
	unsigned long long mtime = 0;
	unsigned int vblocks;
	unsigned char age = 0;
	unsigned char u;
	unsigned int i;
	/* 计算section里面的每一个segment最近一次访问时间 */
	for (i = 0; i < sbi->segs_per_sec; i++)
		mtime += get_seg_entry(sbi, start + i)->mtime;
	/* 获取当前的section有多少个valid block */
	vblocks = get_valid_blocks(sbi, segno, sbi->segs_per_sec);
	/* 计算平均每一segment的最近一次访问时间 */
	mtime = div_u64(mtime, sbi->segs_per_sec);
	/* 计算平均每一个segment的valid block个数 */
	vblocks = div_u64(vblocks, sbi->segs_per_sec);
	/* 百分比计算所以乘以100，然后计算得到了valid block的比例 */
	u = (vblocks * 100) >> sbi->log_blocks_per_seg;

	/* Handle if the system time is changed by user */
	if (mtime < sit_i->min_mtime)
		sit_i->min_mtime = mtime;
	if (mtime > sit_i->max_mtime)
		sit_i->max_mtime = mtime;
	if (sit_i->max_mtime != sit_i->min_mtime)
		age = 100 - div64_u64(100 * (mtime - sit_i->min_mtime),
				sit_i->max_mtime - sit_i->min_mtime);
	
	/*
	 * 公式((100 * (100 - u) * age) / (100 + u))即对应(1 - u) / 2u * age,做了一些变换
	 * 使用UINT_MAX减去这个值的原因是f2fs要维持cost越高，越不值得被gc的特征  
	 */
	return UINT_MAX - ((100 * (100 - u) * age) / (100 + u));
}

static unsigned int get_gc_cost(struct f2fs_sb_info *sbi, unsigned int segno,
					struct victim_sel_policy *p)
{
	if (p->alloc_mode == SSR)
		return get_seg_entry(sbi, segno)->ckpt_valid_blocks;

	/* alloc_mode == LFS */
	if (p->gc_mode == GC_GREEDY)
		/* Greedy算法，valid block越多表示cost越大，越不值得gc  */
		return get_valid_blocks(sbi, segno, sbi->segs_per_sec);
	else
		/* Cost-Benefit算法，这个是考虑了访问时间和valid block开销的算法  */
		return get_cb_cost(sbi, segno);
}

/**
 * This function is called from two pathes.
 * One is garbage collection and the other is SSR segment selection.
 * When it is called during GC, it just gets a victim segment
 * and it does not remove it from dirty seglist.
 * When it is called from SSR segment selection, it finds a segment
 * which has minimum valid blocks and removes it from dirty seglist.
 *
 * @gc_type: BG_GC or FG_GC
 * @type: GC_CB or GC_GREEDY
 * @alloc_mode: LFS or SSA
 * @result: 存放选取的section no
 * return: 返回是否找到cost最小的segment
 */
static int get_victim_by_default(struct f2fs_sb_info *sbi,
		unsigned int *result, int gc_type, int type, char alloc_mode)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct victim_sel_policy p;
	unsigned int segno;
	int nsearched = 0;

	p.alloc_mode = alloc_mode;
	select_policy(sbi, gc_type, type, &p);

	p.min_segno = NULL_SEGNO;
	/*
	 * get_victim_by_default函数目的是找到一个cost最低的segment进行回收
	 * 因此在找到之前需要设定一个最大cost，用于一步步遍历降低cost
	 */
	p.min_cost = get_max_cost(sbi, &p);

	mutex_lock(&dirty_i->seglist_lock);
	/* 
	 * 前台gc模式要求快速释放空间，因此不做循环寻找，
	 * 直接找到之前BG GC的时候所记录下来适合gc的的segment进行gc  
	 */
	if (p.alloc_mode == LFS && gc_type == FG_GC) {
		p.min_segno = check_bg_victims(sbi);
		if (p.min_segno != NULL_SEGNO)
			goto got_it;
	}

	while (1) {
		unsigned long cost;
		/* 从p.offset开始，查找p.dirty_segmap中第一个置位的bit的位索引,它对应segno */
		segno = find_next_bit(p.dirty_segmap,
						TOTAL_SEGS(sbi), p.offset);
		if (segno >= TOTAL_SEGS(sbi)) {
			if (sbi->last_victim[p.gc_mode]) {
				sbi->last_victim[p.gc_mode] = 0;
				p.offset = 0;
				continue;
			}
			break;
		}
		p.offset = ((segno / p.ofs_unit) * p.ofs_unit) + p.ofs_unit;

		if (test_bit(segno, dirty_i->victim_segmap[FG_GC]))
			continue;
		if (gc_type == BG_GC &&
				test_bit(segno, dirty_i->victim_segmap[BG_GC]))
			continue;
		if (IS_CURSEC(sbi, GET_SECNO(sbi, segno)))
			continue;
		/* 计算选中的segment的cost */
		cost = get_gc_cost(sbi, segno, &p);
		/* 判断更新最小cost */
		if (p.min_cost > cost) {
			p.min_segno = segno;
			p.min_cost = cost;
		}

		if (cost == get_max_cost(sbi, &p))
			continue;
		/* 达到了最大搜索次数即退出 */
		if (nsearched++ >= MAX_VICTIM_SEARCH) {
			sbi->last_victim[p.gc_mode] = segno;
			break;
		}
	}
got_it:
	if (p.min_segno != NULL_SEGNO) {
		*result = (p.min_segno / p.ofs_unit) * p.ofs_unit;
		if (p.alloc_mode == LFS) {
			int i;
			/* 在dirty_i->victim_segmap中置位选取的segment */
			for (i = 0; i < p.ofs_unit; i++)
				set_bit(*result + i,
					dirty_i->victim_segmap[gc_type]);
		}
	}
	mutex_unlock(&dirty_i->seglist_lock);

	return (p.min_segno == NULL_SEGNO) ? 0 : 1;
}

static const struct victim_selection default_v_ops = {
	.get_victim = get_victim_by_default,
};

static struct inode *find_gc_inode(nid_t ino, struct list_head *ilist)
{
	struct list_head *this;
	struct inode_entry *ie;

	list_for_each(this, ilist) {
		ie = list_entry(this, struct inode_entry, list);
		if (ie->inode->i_ino == ino)
			return ie->inode;
	}
	return NULL;
}

static void add_gc_inode(struct inode *inode, struct list_head *ilist)
{
	struct list_head *this;
	struct inode_entry *new_ie, *ie;

	list_for_each(this, ilist) {
		ie = list_entry(this, struct inode_entry, list);
		if (ie->inode == inode) {
			iput(inode);
			return;
		}
	}
repeat:
	new_ie = kmem_cache_alloc(winode_slab, GFP_NOFS);
	if (!new_ie) {
		cond_resched();
		goto repeat;
	}
	new_ie->inode = inode;
	list_add_tail(&new_ie->list, ilist);
}

static void put_gc_inode(struct list_head *ilist)
{
	struct inode_entry *ie, *next_ie;
	list_for_each_entry_safe(ie, next_ie, ilist, list) {
		iput(ie->inode);
		list_del(&ie->list);
		kmem_cache_free(winode_slab, ie);
	}
}

static int check_valid_map(struct f2fs_sb_info *sbi,
				unsigned int segno, int offset)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct seg_entry *sentry;
	int ret;

	mutex_lock(&sit_i->sentry_lock);
	sentry = get_seg_entry(sbi, segno);
	ret = f2fs_test_bit(offset, sentry->cur_valid_map);
	mutex_unlock(&sit_i->sentry_lock);
	return ret ? GC_OK : GC_NEXT;
}

/**
 * This function compares node address got in summary with that in NAT.
 * On validity, copy that node with cold status, otherwise (invalid node)
 * ignore that.
 */
/*对选定的segment，根据其summary执行GC, 将valid block回写*/
static int gc_node_segment(struct f2fs_sb_info *sbi,
		struct f2fs_summary *sum, unsigned int segno, int gc_type)
{
	bool initial = true;
	struct f2fs_summary *entry;
	int off;

next_step:
	entry = sum;
	for (off = 0; off < sbi->blocks_per_seg; off++, entry++) {
		nid_t nid = le32_to_cpu(entry->nid);
		struct page *node_page;
		int err;

		/*
		 * It makes sure that free segments are able to write
		 * all the dirty node pages before CP after this CP.
		 * So let's check the space of dirty node pages.
		 */
		if (should_do_checkpoint(sbi)) {
			mutex_lock(&sbi->cp_mutex);
			block_operations(sbi);
			return GC_BLOCKED;
		}

		err = check_valid_map(sbi, segno, off);
		if (err == GC_ERROR)
			return err;
		else if (err == GC_NEXT)
			continue;
		/*预读需要gc的section中的所有的segment的f2fs_summary*/
		if (initial) {
			ra_node_page(sbi, nid);
			continue;
		}
		node_page = get_node_page(sbi, nid);
		if (IS_ERR(node_page))
			continue;

		/* set page dirty and write it */
		if (!PageWriteback(node_page))
			set_page_dirty(node_page);
		f2fs_put_page(node_page, 1);
		stat_inc_node_blk_count(sbi, 1);
	}
	if (initial) {
		initial = false;
		goto next_step;
	}
	/*如果是前台GC则需要手动执行sync，如果是后台回收则通过swap线程周期性刷新page cache*/
	if (gc_type == FG_GC) {
		struct writeback_control wbc = {
			.sync_mode = WB_SYNC_ALL,
			.nr_to_write = LONG_MAX,
			.for_reclaim = 0,
		};
		sync_node_pages(sbi, 0, &wbc);
	}
	return GC_DONE;
}

/**
 * Calculate start block index that this node page contains
 */
/* 返回node page的首个block地址的索引 */
block_t start_bidx_of_node(unsigned int node_ofs)
{
	block_t start_bidx;
	unsigned int bidx, indirect_blks;
	int dec;

	indirect_blks = 2 * NIDS_PER_BLOCK + 4;

	start_bidx = 1;
	if (node_ofs == 0) {
		start_bidx = 0;
	} else if (node_ofs <= 2) {
		bidx = node_ofs - 1;
	} else if (node_ofs <= indirect_blks) {
		dec = (node_ofs - 4) / (NIDS_PER_BLOCK + 1);
		bidx = node_ofs - 2 - dec;
	} else {
		dec = (node_ofs - indirect_blks - 3) / (NIDS_PER_BLOCK + 1);
		bidx = node_ofs - 5 - dec;
	}

	if (start_bidx)
		start_bidx = bidx * ADDRS_PER_BLOCK + ADDRS_PER_INODE;
	return start_bidx;
}

static int check_dnode(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
		struct node_info *dni, block_t blkaddr, unsigned int *nofs)
{
	struct page *node_page;
	nid_t nid;
	unsigned int ofs_in_node;
	block_t source_blkaddr;

	nid = le32_to_cpu(sum->nid);
	ofs_in_node = le16_to_cpu(sum->ofs_in_node);

	node_page = get_node_page(sbi, nid);
	if (IS_ERR(node_page))
		return GC_NEXT;

	get_node_info(sbi, nid, dni);

	if (sum->version != dni->version) {
		f2fs_put_page(node_page, 1);
		return GC_NEXT;
	}

	*nofs = ofs_of_node(node_page);
	source_blkaddr = datablock_addr(node_page, ofs_in_node);
	f2fs_put_page(node_page, 1);

	if (source_blkaddr != blkaddr)
		return GC_NEXT;
	return GC_OK;
}

static void move_data_page(struct inode *inode, struct page *page, int gc_type)
{
	if (page->mapping != inode->i_mapping)
		goto out;

	if (inode != page->mapping->host)
		goto out;

	if (PageWriteback(page))
		goto out;

	if (gc_type == BG_GC) {
		set_page_dirty(page);
		set_cold_data(page);
	} else {
		struct f2fs_sb_info *sbi = F2FS_SB(inode->i_sb);
		mutex_lock_op(sbi, DATA_WRITE);
		if (clear_page_dirty_for_io(page) &&
			S_ISDIR(inode->i_mode)) {
			dec_page_count(sbi, F2FS_DIRTY_DENTS);
			inode_dec_dirty_dents(inode);
		}
		set_cold_data(page);
		do_write_data_page(page);
		mutex_unlock_op(sbi, DATA_WRITE);
		clear_cold_data(page);
	}
out:
	f2fs_put_page(page, 1);
}

/**
 * This function tries to get parent node of victim data block, and identifies
 * data block validity. If the block is valid, copy that with cold status and
 * modify parent node.
 * If the parent node is not valid or the data block address is different,
 * the victim data block is ignored.
 */
static int gc_data_segment(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
		struct list_head *ilist, unsigned int segno, int gc_type)
{
	struct super_block *sb = sbi->sb;
	struct f2fs_summary *entry;
	block_t start_addr;
	int err, off;
	int phase = 0;

	start_addr = START_BLOCK(sbi, segno);

next_step:
	entry = sum;
	for (off = 0; off < sbi->blocks_per_seg; off++, entry++) {
		struct page *data_page;
		struct inode *inode;
		struct node_info dni; /* dnode info for the data */
		unsigned int ofs_in_node, nofs;
		block_t start_bidx;

		/*
		 * It makes sure that free segments are able to write
		 * all the dirty node pages before CP after this CP.
		 * So let's check the space of dirty node pages.
		 */
		if (should_do_checkpoint(sbi)) {
			mutex_lock(&sbi->cp_mutex);
			block_operations(sbi);
			err = GC_BLOCKED;
			goto stop;
		}

		err = check_valid_map(sbi, segno, off);
		if (err == GC_ERROR)
			goto stop;
		else if (err == GC_NEXT)
			continue;

		if (phase == 0) {
			ra_node_page(sbi, le32_to_cpu(entry->nid));
			continue;
		}

		/* Get an inode by ino with checking validity */
		err = check_dnode(sbi, entry, &dni, start_addr + off, &nofs);
		if (err == GC_ERROR)
			goto stop;
		else if (err == GC_NEXT)
			continue;

		if (phase == 1) {
			ra_node_page(sbi, dni.ino);
			continue;
		}

		start_bidx = start_bidx_of_node(nofs);
		ofs_in_node = le16_to_cpu(entry->ofs_in_node);

		if (phase == 2) {
			inode = f2fs_iget_nowait(sb, dni.ino);
			if (IS_ERR(inode))
				continue;

			data_page = find_data_page(inode,
					start_bidx + ofs_in_node);
			if (IS_ERR(data_page))
				goto next_iput;

			f2fs_put_page(data_page, 0);
			add_gc_inode(inode, ilist);
		} else {
			inode = find_gc_inode(dni.ino, ilist);
			if (inode) {
				data_page = get_lock_data_page(inode,
						start_bidx + ofs_in_node);
				if (IS_ERR(data_page))
					continue;
				move_data_page(inode, data_page, gc_type);
				stat_inc_data_blk_count(sbi, 1);
			}
		}
		continue;
next_iput:
		iput(inode);
	}
	if (++phase < 4)
		goto next_step;
	err = GC_DONE;
stop:
	if (gc_type == FG_GC)
		f2fs_submit_bio(sbi, DATA, true);
	return err;
}

static int __get_victim(struct f2fs_sb_info *sbi, unsigned int *victim,
						int gc_type, int type)
{
	struct sit_info *sit_i = SIT_I(sbi);
	int ret;
	mutex_lock(&sit_i->sentry_lock);
	ret = DIRTY_I(sbi)->v_ops->get_victim(sbi, victim, gc_type, type, LFS);
	mutex_unlock(&sit_i->sentry_lock);
	return ret;
}

static int do_garbage_collect(struct f2fs_sb_info *sbi, unsigned int segno,
				struct list_head *ilist, int gc_type)
{
	struct page *sum_page;
	struct f2fs_summary_block *sum;
	int ret = GC_DONE;

	/* read segment summary of victim */
	sum_page = get_sum_page(sbi, segno);
	if (IS_ERR(sum_page))
		return GC_ERROR;

	/*
	 * CP needs to lock sum_page. In this time, we don't need
	 * to lock this page, because this summary page is not gone anywhere.
	 * Also, this page is not gonna be updated before GC is done.
	 */
	unlock_page(sum_page);
	sum = page_address(sum_page);

	switch (GET_SUM_TYPE((&sum->footer))) {
	case SUM_TYPE_NODE:
		ret = gc_node_segment(sbi, sum->entries, segno, gc_type);
		break;
	case SUM_TYPE_DATA:
		ret = gc_data_segment(sbi, sum->entries, ilist, segno, gc_type);
		break;
	}
	stat_inc_seg_count(sbi, GET_SUM_TYPE((&sum->footer)));
	stat_inc_call_count(sbi->stat_info);

	f2fs_put_page(sum_page, 0);
	return ret;
}

int f2fs_gc(struct f2fs_sb_info *sbi, int nGC)
{
	unsigned int segno;
	int old_free_secs, cur_free_secs;
	int gc_status, nfree;
	struct list_head ilist;
	int gc_type = BG_GC;

	INIT_LIST_HEAD(&ilist);
gc_more:
	nfree = 0;
	gc_status = GC_NONE;

	if (has_not_enough_free_secs(sbi))
		old_free_secs = reserved_sections(sbi);
	else
		old_free_secs = free_sections(sbi);

	while (sbi->sb->s_flags & MS_ACTIVE) {
		int i;
		if (has_not_enough_free_secs(sbi))
			gc_type = FG_GC;

		cur_free_secs = free_sections(sbi) + nfree;

		/* We got free space successfully. */
		if (nGC < cur_free_secs - old_free_secs)
			break;

		if (!__get_victim(sbi, &segno, gc_type, NO_CHECK_TYPE))
			break;

		for (i = 0; i < sbi->segs_per_sec; i++) {
			/*
			 * do_garbage_collect will give us three gc_status:
			 * GC_ERROR, GC_DONE, and GC_BLOCKED.
			 * If GC is finished uncleanly, we have to return
			 * the victim to dirty segment list.
			 */
			gc_status = do_garbage_collect(sbi, segno + i,
					&ilist, gc_type);
			if (gc_status != GC_DONE)
				goto stop;
			nfree++;
		}
	}
stop:
	if (has_not_enough_free_secs(sbi) || gc_status == GC_BLOCKED) {
		write_checkpoint(sbi, (gc_status == GC_BLOCKED), false);
		if (nfree)
			goto gc_more;
	}
	mutex_unlock(&sbi->gc_mutex);

	put_gc_inode(&ilist);
	BUG_ON(!list_empty(&ilist));
	return gc_status;
}

void build_gc_manager(struct f2fs_sb_info *sbi)
{
	DIRTY_I(sbi)->v_ops = &default_v_ops;
}

int create_gc_caches(void)
{
	winode_slab = f2fs_kmem_cache_create("f2fs_gc_inodes",
			sizeof(struct inode_entry), NULL);
	if (!winode_slab)
		return -ENOMEM;
	return 0;
}

void destroy_gc_caches(void)
{
	kmem_cache_destroy(winode_slab);
}
