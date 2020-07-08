#include <linux/f2fs_fs.h>

void f2fs_dump_raw_sb(struct f2fs_super_block *raw_super)
{
	int i;

	printk(KERN_ERR "======information of raw super block=====\n");
	printk(KERN_ERR "magic:0x%x\n", raw_super->magic);
	printk(KERN_ERR "major_ver:0x%x\n", raw_super->major_ver);
	printk(KERN_ERR "minor_ver:0x%x\n", raw_super->minor_ver);
	printk(KERN_ERR "log_sectorsize:0x%x\n", raw_super->log_sectorsize);
	printk(KERN_ERR "log_sectors_per_block:0x%x\n", raw_super->log_sectors_per_block);
	printk(KERN_ERR "log_blocksize:0x%x\n", raw_super->log_blocksize);
	printk(KERN_ERR "log_blocks_per_seg:0x%x\n", raw_super->log_blocks_per_seg);
	printk(KERN_ERR "segs_per_sec:0x%x\n", raw_super->segs_per_sec);
	printk(KERN_ERR "secs_per_zone:0x%x\n", raw_super->secs_per_zone);
	printk(KERN_ERR "checksum_offset:0x%x\n", raw_super->checksum_offset);
	printk(KERN_ERR "block_count:%llu\n", raw_super->block_count);
	printk(KERN_ERR "section_count:0x%x\n", raw_super->section_count);
	printk(KERN_ERR "segment_count:0x%x\n", raw_super->segment_count);
	printk(KERN_ERR "segment_count_ckpt:0x%x\n", raw_super->segment_count_ckpt);
	printk(KERN_ERR "segment_count_sit:0x%x\n", raw_super->segment_count_sit);
	printk(KERN_ERR "segment_count_nat:0x%x\n", raw_super->segment_count_nat);
	printk(KERN_ERR "segment_count_ssa:0x%x\n", raw_super->segment_count_ssa);
	printk(KERN_ERR "segment_count_main:0x%x\n", raw_super->segment_count_main);
	printk(KERN_ERR "segment0_blkaddr:0x%x\n", raw_super->segment0_blkaddr);
	printk(KERN_ERR "cp_blkaddr:0x%x\n", raw_super->cp_blkaddr);
	printk(KERN_ERR "sit_blkaddr:0x%x\n", raw_super->sit_blkaddr);
	printk(KERN_ERR "nat_blkaddr:0x%x\n", raw_super->nat_blkaddr);
	printk(KERN_ERR "ssa_blkaddr:0x%x\n", raw_super->ssa_blkaddr);
	printk(KERN_ERR "main_blkaddr:0x%x\n", raw_super->main_blkaddr);
	printk(KERN_ERR "root_ino:0x%x\n", raw_super->root_ino);
	printk(KERN_ERR "node_ino:0x%x\n", raw_super->node_ino);
	printk(KERN_ERR "meta_ino:0x%x\n", raw_super->meta_ino);
	printk(KERN_ERR "uuid:");
	for (i = 0; i < sizeof(raw_super->uuid) / sizeof(char); i++) 
		printk(KERN_ERR "%02x ", *(raw_super->uuid + i));
	printk(KERN_ERR "\n");
	printk(KERN_ERR "volume_name:");
	for (i = 0; i < sizeof(raw_super->volume_name) / sizeof(__le16); i++)
		printk(KERN_ERR "%04x ", *(raw_super->volume_name + i));
	printk(KERN_ERR "\n");
	printk(KERN_ERR "extension_count:0x%x\n", raw_super->extension_count);
	printk(KERN_ERR "\n\n\n"); 
}

void f2fs_dump_raw_cp(struct f2fs_checkpoint *cp_block)
{
	int i;

	printk(KERN_ERR "=======information of raw checkpoint=====\n"); 
	printk(KERN_ERR "checkpoint_ver:%llu\n", cp_block->checkpoint_ver);
	printk(KERN_ERR "user_block_count:%llu\n", cp_block->user_block_count);	
	printk(KERN_ERR "valid_block_count:%llu\n", cp_block->valid_block_count); 
	printk(KERN_ERR "rsvd_segment_count:0x%x\n", cp_block->rsvd_segment_count); 
	printk(KERN_ERR "overprov_segment_count:0x%x\n", cp_block->overprov_segment_count); 
	printk(KERN_ERR "free_segment_count:0x%x\n", cp_block->free_segment_count); 
	
	printk(KERN_ERR "****information of current node segments****\n");
	printk(KERN_ERR "----cur_node_segno----\n");
	for (i = 0; i < 8; i++)
		printk(KERN_ERR "0x%08x|", cp_block->cur_node_segno[i]); 
	printk(KERN_ERR "\n"); 

	printk(KERN_ERR "----cur_node_blkoff----\n");
	for (i = 0; i < 8; i++)
		printk(KERN_ERR "0x%08x|", cp_block->cur_node_blkoff[i]); 
	printk(KERN_ERR "\n"); 

	printk(KERN_ERR "****information of current data segments****\n");
	printk(KERN_ERR "----cur_data_segno----\n");
	for (i = 0; i < 8; i++)
		printk(KERN_ERR "0x%08x|", cp_block->cur_data_segno[i]); 
	printk(KERN_ERR "\n"); 

	printk(KERN_ERR "----cur_data_blkoff----\n");
	for (i = 0; i < 8; i++)
		printk(KERN_ERR "0x%08x|", cp_block->cur_data_blkoff[i]); 
	printk(KERN_ERR "\n"); 

	printk(KERN_ERR "ckpt_flags:0x%x\n", cp_block->ckpt_flags); 
	printk(KERN_ERR "cp_pack_total_block_count:0x%x\n", cp_block->cp_pack_total_block_count); 
	printk(KERN_ERR "cp_pack_start_sum:0x%x\n", cp_block->cp_pack_start_sum); 
	printk(KERN_ERR "valid_node_count:0x%x\n", cp_block->valid_node_count); 
	printk(KERN_ERR "valid_inode_count:0x%x\n", cp_block->valid_inode_count); 
	printk(KERN_ERR "next_free_nid:0x%x\n", cp_block->next_free_nid); 
	printk(KERN_ERR "sit_ver_bitmap_bytesize:0x%x\n", cp_block->sit_ver_bitmap_bytesize); 
	printk(KERN_ERR "nat_ver_bitmap_bytesize:0x%x\n", cp_block->nat_ver_bitmap_bytesize); 
	printk(KERN_ERR "checksum_offset:0x%x\n", cp_block->checksum_offset); 
	printk(KERN_ERR "elapsed_time:%llu\n", cp_block->elapsed_time); 
	
	printk(KERN_ERR "****allocation type of current segment****\n");
	for (i = 0; i < 16; i++)
		printk(KERN_ERR "0x%08x|", cp_block->alloc_type[i]); 
	printk(KERN_ERR "\n"); 
	
	printk(KERN_ERR "sit_nat_version_bitmap:0x%x\n", cp_block->sit_nat_version_bitmap[0]); 
	printk(KERN_ERR "\n\n\n");
}
