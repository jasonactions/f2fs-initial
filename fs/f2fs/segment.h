/**
 * fs/f2fs/segment.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
/* constant macro */
#define NULL_SEGNO			((unsigned int)(~0))

/* V: Logical segment # in volume, R: Relative segment # in main area */
/*
 * Logical segment no:表示以sb区域所在的首个segment(0x0)为起始segment
 * Relate segment no:表示以main区域的首个segment作为起始segment
 * free_i->start_segno表示main区域首个segment的Logical segmentno
 */
/*将Logical segno转换为Relative segno, 此处segno为Logical seg no(以sb所在segment为首个seg no)*/
#define GET_L2R_SEGNO(free_i, segno)	(segno - free_i->start_segno)
/*将Relative segno转换为Logical segno, 此处segno为Relative seg no(以main所在segment为首个seg no)*/
#define GET_R2L_SEGNO(free_i, segno)	(segno + free_i->start_segno)

#define IS_DATASEG(t)							\
	((t == CURSEG_HOT_DATA) || (t == CURSEG_COLD_DATA) ||		\
	(t == CURSEG_WARM_DATA))

#define IS_NODESEG(t)							\
	((t == CURSEG_HOT_NODE) || (t == CURSEG_COLD_NODE) ||		\
	(t == CURSEG_WARM_NODE))

#define IS_CURSEG(sbi, segno)						\
	((segno == CURSEG_I(sbi, CURSEG_HOT_DATA)->segno) ||	\
	 (segno == CURSEG_I(sbi, CURSEG_WARM_DATA)->segno) ||	\
	 (segno == CURSEG_I(sbi, CURSEG_COLD_DATA)->segno) ||	\
	 (segno == CURSEG_I(sbi, CURSEG_HOT_NODE)->segno) ||	\
	 (segno == CURSEG_I(sbi, CURSEG_WARM_NODE)->segno) ||	\
	 (segno == CURSEG_I(sbi, CURSEG_COLD_NODE)->segno))

#define IS_CURSEC(sbi, secno)						\
	((secno == CURSEG_I(sbi, CURSEG_HOT_DATA)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_WARM_DATA)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_COLD_DATA)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_HOT_NODE)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_WARM_NODE)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_COLD_NODE)->segno /		\
	  sbi->segs_per_sec))	\
/*获取segno的首个block的Logical block no*/
#define START_BLOCK(sbi, segno)						\
	(SM_I(sbi)->seg0_blkaddr +					\
	 (GET_R2L_SEGNO(FREE_I(sbi), segno) << sbi->log_blocks_per_seg))
/*获取curget的下一个将要写入的block的Logcical block no*/
#define NEXT_FREE_BLKADDR(sbi, curseg)					\
	(START_BLOCK(sbi, curseg->segno) + curseg->next_blkoff)

#define MAIN_BASE_BLOCK(sbi)	(SM_I(sbi)->main_blkaddr)

/* 将blk_addr转换为以cp区域的第0个block地址为起始地址 */
#define GET_SEGOFF_FROM_SEG0(sbi, blk_addr)				\
	((blk_addr) - SM_I(sbi)->seg0_blkaddr)
/* 以cp区域blk0为起始地址(cp所在seg为起始seg)，计算blk_addr所处的segment*/
#define GET_SEGNO_FROM_SEG0(sbi, blk_addr)				\
	(GET_SEGOFF_FROM_SEG0(sbi, blk_addr) >> sbi->log_blocks_per_seg)
/* 以main区域blk0为起始地址(main所在seg为起始seg)，计算blk_addr所处的segment */
#define GET_SEGNO(sbi, blk_addr)					\
	(((blk_addr == NULL_ADDR) || (blk_addr == NEW_ADDR)) ?		\
	NULL_SEGNO : GET_L2R_SEGNO(FREE_I(sbi),			\
		GET_SEGNO_FROM_SEG0(sbi, blk_addr)))

#define GET_SECNO(sbi, segno)					\
	((segno) / sbi->segs_per_sec)
#define GET_ZONENO_FROM_SEGNO(sbi, segno)				\
	((segno / sbi->segs_per_sec) / sbi->secs_per_zone)

#define GET_SUM_BLOCK(sbi, segno)				\
	((sbi->sm_info->ssa_blkaddr) + segno)

#define GET_SUM_TYPE(footer) ((footer)->entry_type)
#define SET_SUM_TYPE(footer, type) ((footer)->entry_type = type)
/* segno对应的seg entry在其seg entry block的偏移  */
#define SIT_ENTRY_OFFSET(sit_i, segno)					\
	(segno % sit_i->sents_per_block)
/* 根据segno获取sit entry 所在sit entry block号 */
#define SIT_BLOCK_OFFSET(sit_i, segno)					\
	(segno / SIT_ENTRY_PER_BLOCK)
/* 根据segno找到所处sit entry block的起始sit entry的索引号 */
#define	START_SEGNO(sit_i, segno)		\
	(SIT_BLOCK_OFFSET(sit_i, segno) * SIT_ENTRY_PER_BLOCK)
#define f2fs_bitmap_size(nr)			\
	(BITS_TO_LONGS(nr) * sizeof(unsigned long))
#define TOTAL_SEGS(sbi)	(SM_I(sbi)->main_segments)

/* during checkpoint, bio_private is used to synchronize the last bio */
struct bio_private {
	struct f2fs_sb_info *sbi;
	bool is_sync;
	void *wait;
};

/*
 * indicate a block allocation direction: RIGHT and LEFT.
 * RIGHT means allocating new sections towards the end of volume.
 * LEFT means the opposite direction.
 */
enum {
	ALLOC_RIGHT = 0,
	ALLOC_LEFT
};

/*
 * In the victim_sel_policy->alloc_mode, there are two block allocation modes.
 * LFS writes data sequentially with cleaning operations.
 * SSR (Slack Space Recycle) reuses obsolete space without cleaning operations.
 */
enum {
	LFS = 0,
	SSR
};

/*
 * In the victim_sel_policy->gc_mode, there are two gc, aka cleaning, modes.
 * GC_CB is based on cost-benefit algorithm.
 * GC_GREEDY is based on greedy algorithm.
 */
enum {
	GC_CB = 0,
	GC_GREEDY
};

/*
 * BG_GC means the background cleaning job.
 * FG_GC means the on-demand cleaning job.
 */
enum {
	BG_GC = 0,
	FG_GC
};

/* for a function parameter to select a victim segment */
struct victim_sel_policy {
	int alloc_mode;			/* LFS or SSR */
	int gc_mode;			/* GC_CB or GC_GREEDY */
	unsigned long *dirty_segmap;	/* dirty segment bitmap */
	/*遍历过程中当前的查找偏移*/
	unsigned int offset;		/* last scanned bitmap offset */
	/*表示在查找过程中每次查找跨越的单元，SSR是以1个segment为单元，LFS是以1个section为单元*/
	unsigned int ofs_unit;		/* bitmap search unit */
	/*记录查找过程中的最小cost*/
	unsigned int min_cost;		/* minimum cost */
	/*记录的是查找过程中最小cost所对应的segno*/
	unsigned int min_segno;		/* segment # having min. cost */
};

struct seg_entry {
	unsigned short valid_blocks;	/* # of valid blocks */
	unsigned char *cur_valid_map;	/* validity bitmap of blocks */
	/*
	 * # of valid blocks and the validity bitmap stored in the the last
	 * checkpoint pack. This information is used by the SSR mode.
	 */
	unsigned short ckpt_valid_blocks;
	unsigned char *ckpt_valid_map;
	unsigned char type;		/* segment type like CURSEG_XXX_TYPE */
	/* segment最近一次的修改时间 */
	unsigned long long mtime;	/* modification time of the segment */
};

struct sec_entry {
	unsigned int valid_blocks;	/* # of valid blocks in a section */
};

struct segment_allocation {
	void (*allocate_segment)(struct f2fs_sb_info *, int, bool);
};

struct sit_info {
	const struct segment_allocation *s_ops;
	/* SIT area的起始块地址 */
	block_t sit_base_addr;		/* start block address of SIT area */
	/* sit area的block块数 */
	block_t sit_blocks;		/* # of blocks used by SIT area */
	/* main area的有效的block块数 */
	block_t written_valid_blocks;	/* # of valid blocks in main area */
	char *sit_bitmap;		/* SIT bitmap pointer */
	unsigned int bitmap_size;	/* SIT bitmap size */

	unsigned long *dirty_sentries_bitmap;	/* bitmap for dirty sentries */
	unsigned int dirty_sentries;		/* # of dirty sentries */
	unsigned int sents_per_block;		/* # of SIT entries per block */
	struct mutex sentry_lock;		/* to protect SIT cache */
	/*指向为main area分配的seg_entry区域*/
	struct seg_entry *sentries;		/* SIT segment-level cache */
	struct sec_entry *sec_entries;		/* SIT section-level cache */

	/* for cost-benefit algorithm in cleaning procedure */
	unsigned long long elapsed_time;	/* elapsed time after mount */
	unsigned long long mounted_time;	/* mount time */
	unsigned long long min_mtime;		/* min. modification time */
	unsigned long long max_mtime;		/* max. modification time */
};

struct free_segmap_info {
	/*以cp区域的seg no(0x1)作为起始seg no,main区域的第一个segment*/
	unsigned int start_segno;	/* start segment number logically */
	unsigned int free_segments;	/* # of free segments */
	unsigned int free_sections;	/* # of free sections */
	rwlock_t segmap_lock;		/* free segmap lock */
	/* bit置1表示此segment dirty, bit清0表示此segment clean  */
	unsigned long *free_segmap;	/* free segment bitmap */
	unsigned long *free_secmap;	/* free section bitmap */
};

/* Notice: The order of dirty type is same with CURSEG_XXX in f2fs.h */
enum dirty_type {
	DIRTY_HOT_DATA,		/* dirty segments assigned as hot data logs */
	DIRTY_WARM_DATA,	/* dirty segments assigned as warm data logs */
	DIRTY_COLD_DATA,	/* dirty segments assigned as cold data logs */
	DIRTY_HOT_NODE,		/* dirty segments assigned as hot node logs */
	DIRTY_WARM_NODE,	/* dirty segments assigned as warm node logs */
	DIRTY_COLD_NODE,	/* dirty segments assigned as cold node logs */
	DIRTY,			/* to count # of dirty segments */
	PRE,			/* to count # of entirely obsolete segments */
	NR_DIRTY_TYPE
};

struct dirty_seglist_info {
	const struct victim_selection *v_ops;	/* victim selction operation */
	unsigned long *dirty_segmap[NR_DIRTY_TYPE];
	struct mutex seglist_lock;		/* lock for segment bitmaps */
	int nr_dirty[NR_DIRTY_TYPE];		/* # of dirty segments */
	/* 由于gc以section为单位，此处置位gc选取的section的所有segment */
	unsigned long *victim_segmap[2];	/* BG_GC, FG_GC */
};

/* victim selection function for cleaning and SSR */
struct victim_selection {
	int (*get_victim)(struct f2fs_sb_info *, unsigned int *,
							int, int, char);
};

/* for active log information */
struct curseg_info {
	struct mutex curseg_mutex;		/* lock for consistency */
	/* 每个有效的segment有对应一个summary block，它描述了当前segment的blocks状态 */
	struct f2fs_summary_block *sum_blk;	/* cached summary block */
	unsigned char alloc_type;		/* current allocation type */
	/* 当前有效的segment number */
	unsigned int segno;			/* current segment number */
	/* 当前有效的segment的下一个将要写入的block在current segment的偏移地址 */
	unsigned short next_blkoff;		/* next block offset to write */
	unsigned int zone;			/* current zone number */
	/* 将要写入的下一个segment number */
	unsigned int next_segno;		/* preallocated segment */
};

/*
 * inline functions
 */
static inline struct curseg_info *CURSEG_I(struct f2fs_sb_info *sbi, int type)
{
	return (struct curseg_info *)(SM_I(sbi)->curseg_array + type);
}

static inline struct seg_entry *get_seg_entry(struct f2fs_sb_info *sbi,
						unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	return &sit_i->sentries[segno];
}

static inline struct sec_entry *get_sec_entry(struct f2fs_sb_info *sbi,
						unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	return &sit_i->sec_entries[GET_SECNO(sbi, segno)];
}

static inline unsigned int get_valid_blocks(struct f2fs_sb_info *sbi,
				unsigned int segno, int section)
{
	/*
	 * In order to get # of valid blocks in a section instantly from many
	 * segments, f2fs manages two counting structures separately.
	 */
	if (section > 1)
		return get_sec_entry(sbi, segno)->valid_blocks;
	else
		return get_seg_entry(sbi, segno)->valid_blocks;
}

static inline void seg_info_from_raw_sit(struct seg_entry *se,
					struct f2fs_sit_entry *rs)
{
	se->valid_blocks = GET_SIT_VBLOCKS(rs);
	se->ckpt_valid_blocks = GET_SIT_VBLOCKS(rs);
	memcpy(se->cur_valid_map, rs->valid_map, SIT_VBLOCK_MAP_SIZE);
	memcpy(se->ckpt_valid_map, rs->valid_map, SIT_VBLOCK_MAP_SIZE);
	se->type = GET_SIT_TYPE(rs);
	se->mtime = le64_to_cpu(rs->mtime);
}

static inline void seg_info_to_raw_sit(struct seg_entry *se,
					struct f2fs_sit_entry *rs)
{
	unsigned short raw_vblocks = (se->type << SIT_VBLOCKS_SHIFT) |
					se->valid_blocks;
	rs->vblocks = cpu_to_le16(raw_vblocks);
	memcpy(rs->valid_map, se->cur_valid_map, SIT_VBLOCK_MAP_SIZE);
	memcpy(se->ckpt_valid_map, rs->valid_map, SIT_VBLOCK_MAP_SIZE);
	se->ckpt_valid_blocks = se->valid_blocks;
	rs->mtime = cpu_to_le64(se->mtime);
}

static inline unsigned int find_next_inuse(struct free_segmap_info *free_i,
		unsigned int max, unsigned int segno)
{
	unsigned int ret;
	read_lock(&free_i->segmap_lock);
	ret = find_next_bit(free_i->free_segmap, max, segno);
	read_unlock(&free_i->segmap_lock);
	return ret;
}
/* 清零segment bitmap/section bit map表示空闲的segment/section */
static inline void __set_free(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno = segno / sbi->segs_per_sec;
	unsigned int start_segno = secno * sbi->segs_per_sec;
	unsigned int next;

	write_lock(&free_i->segmap_lock);
	clear_bit(segno, free_i->free_segmap);
	free_i->free_segments++;
	
	/* 如果next>=start_segno+sbi->segs_per_sec条件满足，
	 * 表示当前segment所在的section也是空闲的,对section bitmap清0
	 * 假设segno=1,secno=0,next=3,start_segno=0,因此3>=0+2
	 *
	 * |seg0|seg1|seg2|seg3|seg4|seg5|seg6|seg7|
	 * +----+----+----+----+----+----+----+----+
	 * |    | 1  |    | 1  |    |    |    |    | 
	 * +----+----+----+----+----+----+----+----+
	 * |  sec0   |  sec1   |  sec2   |  sec3   |
	 */
	next = find_next_bit(free_i->free_segmap, TOTAL_SEGS(sbi), start_segno);
	if (next >= start_segno + sbi->segs_per_sec) {
		clear_bit(secno, free_i->free_secmap);
		free_i->free_sections++;
	}
	write_unlock(&free_i->segmap_lock);
}

static inline void __set_inuse(struct f2fs_sb_info *sbi,
		unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno = segno / sbi->segs_per_sec;
	set_bit(segno, free_i->free_segmap);
	free_i->free_segments--;
	if (!test_and_set_bit(secno, free_i->free_secmap))
		free_i->free_sections--;
}

static inline void __set_test_and_free(struct f2fs_sb_info *sbi,
		unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno = segno / sbi->segs_per_sec;
	unsigned int start_segno = secno * sbi->segs_per_sec;
	unsigned int next;

	write_lock(&free_i->segmap_lock);
	/* free_i->free_segmap清零表示segment free */
	if (test_and_clear_bit(segno, free_i->free_segmap)) {
		free_i->free_segments++;

		next = find_next_bit(free_i->free_segmap, TOTAL_SEGS(sbi),
								start_segno);
		if (next >= start_segno + sbi->segs_per_sec) {
			if (test_and_clear_bit(secno, free_i->free_secmap))
				free_i->free_sections++;
		}
	}
	write_unlock(&free_i->segmap_lock);
}
/* 置位segno/secno对应的free_segmap/free_secmap，表示segment/section非空闲 */
static inline void __set_test_and_inuse(struct f2fs_sb_info *sbi,
		unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno = segno / sbi->segs_per_sec;
	write_lock(&free_i->segmap_lock);
	if (!test_and_set_bit(segno, free_i->free_segmap)) {
		free_i->free_segments--;
		if (!test_and_set_bit(secno, free_i->free_secmap))
			free_i->free_sections--;
	}
	write_unlock(&free_i->segmap_lock);
}

static inline void get_sit_bitmap(struct f2fs_sb_info *sbi,
		void *dst_addr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	memcpy(dst_addr, sit_i->sit_bitmap, sit_i->bitmap_size);
}

static inline block_t written_block_count(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	block_t vblocks;

	mutex_lock(&sit_i->sentry_lock);
	vblocks = sit_i->written_valid_blocks;
	mutex_unlock(&sit_i->sentry_lock);

	return vblocks;
}

static inline unsigned int free_segments(struct f2fs_sb_info *sbi)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int free_segs;

	read_lock(&free_i->segmap_lock);
	free_segs = free_i->free_segments;
	read_unlock(&free_i->segmap_lock);

	return free_segs;
}

static inline int reserved_segments(struct f2fs_sb_info *sbi)
{
	return SM_I(sbi)->reserved_segments;
}

static inline unsigned int free_sections(struct f2fs_sb_info *sbi)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int free_secs;

	read_lock(&free_i->segmap_lock);
	free_secs = free_i->free_sections;
	read_unlock(&free_i->segmap_lock);

	return free_secs;
}

static inline unsigned int prefree_segments(struct f2fs_sb_info *sbi)
{
	return DIRTY_I(sbi)->nr_dirty[PRE];
}

static inline unsigned int dirty_segments(struct f2fs_sb_info *sbi)
{
	return DIRTY_I(sbi)->nr_dirty[DIRTY_HOT_DATA] +
		DIRTY_I(sbi)->nr_dirty[DIRTY_WARM_DATA] +
		DIRTY_I(sbi)->nr_dirty[DIRTY_COLD_DATA] +
		DIRTY_I(sbi)->nr_dirty[DIRTY_HOT_NODE] +
		DIRTY_I(sbi)->nr_dirty[DIRTY_WARM_NODE] +
		DIRTY_I(sbi)->nr_dirty[DIRTY_COLD_NODE];
}

static inline int overprovision_segments(struct f2fs_sb_info *sbi)
{
	return SM_I(sbi)->ovp_segments;
}

static inline int overprovision_sections(struct f2fs_sb_info *sbi)
{
	return ((unsigned int) overprovision_segments(sbi)) / sbi->segs_per_sec;
}

static inline int reserved_sections(struct f2fs_sb_info *sbi)
{
	return ((unsigned int) reserved_segments(sbi)) / sbi->segs_per_sec;
}

static inline bool need_SSR(struct f2fs_sb_info *sbi)
{
	return (free_sections(sbi) < overprovision_sections(sbi));
}

static inline int get_ssr_segment(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	return DIRTY_I(sbi)->v_ops->get_victim(sbi,
				&(curseg)->next_segno, BG_GC, type, SSR);
}

static inline bool has_not_enough_free_secs(struct f2fs_sb_info *sbi)
{
	return free_sections(sbi) <= reserved_sections(sbi);
}

static inline int utilization(struct f2fs_sb_info *sbi)
{
	return (long int)valid_user_blocks(sbi) * 100 /
			(long int)sbi->user_block_count;
}

/*
 * Sometimes f2fs may be better to drop out-of-place update policy.
 * So, if fs utilization is over MIN_IPU_UTIL, then f2fs tries to write
 * data in the original place likewise other traditional file systems.
 * But, currently set 100 in percentage, which means it is disabled.
 * See below need_inplace_update().
 */
#define MIN_IPU_UTIL		100
static inline bool need_inplace_update(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_SB(inode->i_sb);
	if (S_ISDIR(inode->i_mode))
		return false;
	if (need_SSR(sbi) && utilization(sbi) > MIN_IPU_UTIL)
		return true;
	return false;
}

static inline unsigned int curseg_segno(struct f2fs_sb_info *sbi,
		int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	return curseg->segno;
}

static inline unsigned char curseg_alloc_type(struct f2fs_sb_info *sbi,
		int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	return curseg->alloc_type;
}

static inline unsigned short curseg_blkoff(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	return curseg->next_blkoff;
}

static inline void check_seg_range(struct f2fs_sb_info *sbi, unsigned int segno)
{
	unsigned int end_segno = SM_I(sbi)->segment_count - 1;
	BUG_ON(segno > end_segno);
}

/*
 * This function is used for only debugging.
 * NOTE: In future, we have to remove this function.
 */
static inline void verify_block_addr(struct f2fs_sb_info *sbi, block_t blk_addr)
{
	struct f2fs_sm_info *sm_info = SM_I(sbi);
	block_t total_blks = sm_info->segment_count << sbi->log_blocks_per_seg;
	block_t start_addr = sm_info->seg0_blkaddr;
	block_t end_addr = start_addr + total_blks - 1;
	BUG_ON(blk_addr < start_addr);
	BUG_ON(blk_addr > end_addr);
}

/*
 * Summary block is always treated as invalid block
 */
/* 检查raw_sit所描述的valid blocks */
static inline void check_block_count(struct f2fs_sb_info *sbi,
		int segno, struct f2fs_sit_entry *raw_sit)
{
	struct f2fs_sm_info *sm_info = SM_I(sbi);
	unsigned int end_segno = sm_info->segment_count - 1;
	int valid_blocks = 0;
	int i;

	/* check segment usage */
	BUG_ON(GET_SIT_VBLOCKS(raw_sit) > sbi->blocks_per_seg);

	/* check boundary of a given segment number */
	BUG_ON(segno > end_segno);

	/* check bitmap with valid block count */
	for (i = 0; i < sbi->blocks_per_seg; i++)
		if (f2fs_test_bit(i, raw_sit->valid_map))
			valid_blocks++;
	BUG_ON(GET_SIT_VBLOCKS(raw_sit) != valid_blocks);
}

static inline pgoff_t current_sit_addr(struct f2fs_sb_info *sbi,
						unsigned int start)
{
	struct sit_info *sit_i = SIT_I(sbi);
	/*获取segno为start的sit entry所在的sit entry block地址*/
	unsigned int offset = SIT_BLOCK_OFFSET(sit_i, start);
	/*获取sit entry block的logical block地址*/
	block_t blk_addr = sit_i->sit_base_addr + offset;

	check_seg_range(sbi, start);

	/* calculate sit block address */
	if (f2fs_test_bit(offset, sit_i->sit_bitmap))
		blk_addr += sit_i->sit_blocks;

	return blk_addr;
}

/*
 * 获取sit entry所在block_addr的下一个block地址,由于sit area如下图排列，因此下个block地址循环在两个sit area区域存放
 * +---o sit_base_addr
 * |
 * |<------------------sit area------------------------------->|<------------------backup sit area------------------------>|                                                        
 * +-----------------------------------------------------------+-----------------------------------------------------------+                                                       
 * |  0  |  1  |  2  |  3  |  4  |  5  | ... | SEG |  N-1|  N  |  0  |  1  |  2  |  3  |  4  |  5  | ... | SEG |  N-1|  N  |                                                          * +-----------------------------------------------------------+-----------------------------------------------------------+                                                          *                                   .        .
 *                         .                          .
 *                 .                                          .                                                                                                                      
 *                 +-------------------------------------------+                                                         
 *                 | 0 | 1 | 2 | 3 | block |...|...|...|510|511|                                                                                                                     
 *                 +-------------------------------------------+                                                                                                                     
 *                                .         .
 *                              .             .                                                                                                                                      
 *                            .                 .                                                                                                                                    
 *                          .                     .
 *                         +-----------------------+                                                                                                                                 
 *                         | se | se | se |...| se |                                                                                                                                 
 *                         +-----------------------+                                                                                                                                 
 *      
 */
static inline pgoff_t next_sit_addr(struct f2fs_sb_info *sbi,
						pgoff_t block_addr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	block_addr -= sit_i->sit_base_addr;
	if (block_addr < sit_i->sit_blocks)
		block_addr += sit_i->sit_blocks;
	else
		block_addr -= sit_i->sit_blocks;

	return block_addr + sit_i->sit_base_addr;
}

static inline void set_to_next_sit(struct sit_info *sit_i, unsigned int start)
{
	unsigned int block_off = SIT_BLOCK_OFFSET(sit_i, start);

	if (f2fs_test_bit(block_off, sit_i->sit_bitmap))
		f2fs_clear_bit(block_off, sit_i->sit_bitmap);
	else
		f2fs_set_bit(block_off, sit_i->sit_bitmap);
}

static inline unsigned long long get_mtime(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	return sit_i->elapsed_time + CURRENT_TIME_SEC.tv_sec -
						sit_i->mounted_time;
}

static inline void set_summary(struct f2fs_summary *sum, nid_t nid,
			unsigned int ofs_in_node, unsigned char version)
{
	sum->nid = cpu_to_le32(nid);
	sum->ofs_in_node = cpu_to_le16(ofs_in_node);
	sum->version = version;
}
/**
 * 获取cp area真正数据开始存放的block地址
 */
static inline block_t start_sum_block(struct f2fs_sb_info *sbi)
{
	return __start_cp_addr(sbi) +
		le32_to_cpu(F2FS_CKPT(sbi)->cp_pack_start_sum);
}
/* 
 * 在cp区域存放了当前有效segment的summary block
 * 以128M镜像为例，cp_pack_total_block_count为8：
 * cp第0个block放空,第1个block存放cp pack数据，第2到第7个block存放当前有效segment的summary block
 * cp区域的布局如下：
 *            +---------------------------------------------------------------------------------------------------+
 *            | f2fs_checkpoint | data summaries | hot node summaries | warm node summaries | cold node summaries |
 *            +---------------------------------------------------------------------------------------------------+
 *                             .                 .             
 *                      .                                   .               
 *                .                 compacted summaries                 .        
 *                +----------------+-------------------+----------------+
 *                |  nat journal   |    sit journal    | data summaries |
 *                +----------------+-------------------+----------------+
 *
 *                .                  normal summaries                   .        
 *                +----------------+-------------------+----------------+
 *                |                    data summaries                   |
 *                +----------------+-------------------+----------------+
 *
 */
static inline block_t sum_blk_addr(struct f2fs_sb_info *sbi, int base, int type)
{
	return __start_cp_addr(sbi) +
		le32_to_cpu(F2FS_CKPT(sbi)->cp_pack_total_block_count)
				- (base + 1) + type;
}
