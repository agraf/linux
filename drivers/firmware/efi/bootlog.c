// SPDX-License-Identifier: GPL-2.0
/*
 * bootlog.c
 *
 * Copyright (c) 2023 Amazon Development Center Germany GmbH
 * Author: Alexander Graf <graf@amazon.com>
 *
 * based on bootlog-table.c which is
 *
 * Copyright (c) 2020 Red Hat
 * Author: Lenny Szubowicz <lszubowi@redhat.com>
 *
 * /sys/firmware/efi/bootlog/
 *
 */
#define pr_fmt(fmt) "bootlog: " fmt

#include <linux/capability.h>
#include <linux/efi.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/slab.h>

#include <asm/early_ioremap.h>

/*
 * The LINUX_EFI_MOK_VARIABLE_TABLE_GUID config table is a packed
 * sequence of struct efi_bootlog_entry, one for each named
 * MOK variable. The sequence is terminated by an entry with a
 * completely NULL name and 0 data size.
 *
 * efi_bootlog_table_size is set to the computed size of the Boot log by
 * efi_bootlog_init(). This will be non-zero if the table is present.
 */
static size_t efi_bootlog_table_size;

/*
 * Each /sys/firmware/efi/bootlog/ sysfs file is represented by
 * an instance of struct efi_bootlog_sysfs_attr on efi_bootlog_sysfs_list.
 * bin_attr.private points to the associated EFI MOK config table entry.
 *
 * This list is created during boot and then remains unchanged.
 * So no synchronization is currently required to walk the list.
 */
struct efi_bootlog_sysfs_attr {
	struct bin_attribute bin_attr;
	struct list_head node;
	uint8_t name[16];
	struct bootlog *bootlog;
	u32 bootlog_size;
};

struct bootlog_table {
	u32 signature;
	u16 max_logs;
	u16 nr_logs;
	u64 log_address[];
};

struct bootlog {
	u32 signature;
	uint8_t producer[4];
	uint16_t extra_header_type;
	uint8_t extra_header_size;
	uint8_t msg_extra_header_size;
	uint32_t last_byte;
};

static LIST_HEAD(efi_bootlog_sysfs_list);
static struct kobject *bootlog_kobj;

/*
 * efi_bootlog_init() - Reserve Bootlog memory
 *
 * If present, reserve Bootlog table memory for later consumption.
 *
 * This routine must be called before efi_free_boot_services() in order
 * to guarantee that it can mark the table as reserved.
 *
 * Implicit inputs:
 * efi.bootlog:	Physical address of Bootlog config table
 *		or special value that indicates no such table.
 *
 * Implicit outputs:
 * efi_bootlog_table_size: Computed size of Bootlog config table.
 *			   The table is considered present if this is non-zero.
 */
void __init efi_bootlog_init(void)
{
	efi_memory_desc_t md;
	unsigned long offset_limit;
	unsigned long bootlog_table_size = 0;
	unsigned long map_size = 0;
	unsigned int i;
	struct bootlog_table *bootlog_table = NULL;
	int err;

	if (!efi_enabled(EFI_MEMMAP))
		return;

	if (efi.bootlog == EFI_INVALID_TABLE_ADDR)
		return;

	/*
	 * The Bootlog config table must fit within a single EFI memory
	 * descriptor range.
	 */
	err = efi_mem_desc_lookup(efi.bootlog, &md);
	if (err) {
		pr_warn("Bootlog config table is not within the EFI memory map\n");
		return;
	}

	offset_limit = efi_mem_desc_end(&md) - efi.bootlog;
	if (sizeof(*bootlog_table) > offset_limit) {
		pr_warn("Bootlog config table spans multiple memory maps (%lx - %lx)\n",
			efi.bootlog + sizeof(*bootlog_table), offset_limit);
		return;
	}

	bootlog_table = early_memremap(efi.bootlog, sizeof(*bootlog_table));
	bootlog_table_size = sizeof(*bootlog_table) + bootlog_table->nr_logs *
			     sizeof(bootlog_table->log_address[0]);
	early_memunmap(bootlog_table, sizeof(*bootlog_table));

	if (bootlog_table_size > offset_limit) {
		pr_warn("Bootlog config table spans multiple memory maps\n");
		return;
	}

	efi_mem_reserve(efi.bootlog, bootlog_table_size);
	bootlog_table = early_memremap(efi.bootlog, bootlog_table_size);

	for (i = 0; i < bootlog_table->nr_logs; i++) {
		u64 addr = bootlog_table[i].log_address[i];
		struct bootlog *bootlog = NULL;

		bootlog = early_memremap(addr, sizeof(*bootlog));
		pr_info("Bootlog %s: %llx - %llx\n", bootlog->producer, addr,
						     addr + bootlog->last_byte);
		map_size = bootlog->last_byte;
		early_memunmap(bootlog, sizeof(*bootlog));
		efi_mem_reserve(addr, map_size);
	}

	early_memunmap(bootlog_table, bootlog_table_size);
	efi_bootlog_table_size = bootlog_table_size;
}

/*
 * efi_bootlog_sysfs_read() - sysfs binary file read routine
 *
 * Returns:	Count of bytes read.
 *
 * Copy EFI MOK config table entry data for this bootlog sysfs binary file
 * to the supplied buffer, starting at the specified offset into bootlog table
 * entry data, for the specified count bytes. The copy is limited by the
 * amount of data in this bootlog config table entry.
 */
static ssize_t efi_bootlog_sysfs_read(struct file *file, struct kobject *kobj,
				 struct bin_attribute *bin_attr, char *buf,
				 loff_t off, size_t count)
{
	struct efi_bootlog_sysfs_attr *bootlog_entry =
		container_of(bin_attr, struct efi_bootlog_sysfs_attr, bin_attr);

	if (!capable(CAP_SYS_ADMIN))
		return 0;

	if (off >= bootlog_entry->bootlog_size)
		return 0;
	if (count >  bootlog_entry->bootlog_size - off)
		count = bootlog_entry->bootlog_size - off;

	memcpy(buf, (void*)bootlog_entry->bootlog + off, count);
	return count;
}

/*
 * efi_bootlog_sysfs_init() - Map EFI MOK config table and create sysfs
 *
 * Map the EFI MOK variable config table for run-time use by the kernel
 * and create the sysfs entries in /sys/firmware/efi/bootlog/
 *
 * This routine just returns if a valid EFI MOK variable config table
 * was not found earlier during boot.
 *
 * This routine must be called during a "middle" initcall phase, i.e.
 * after efi_bootlog_init() but before UEFI certs are loaded
 * during late init.
 *
 * Implicit inputs:
 * efi.bootlog:	Physical address of EFI MOK variable config table
 *			or special value that indicates no such table.
 *
 * efi_bootlog_table_size: Computed size of Bootlog config table.
 *			   The table is considered present if this is non-zero.
 *
 * Implicit outputs:
 * efi_bootlog_va:	Start virtual address of the EFI MOK config table.
 */
static int __init efi_bootlog_sysfs_init(void)
{
	struct bootlog_table *bootlog_table;
	struct bootlog *bootlog = NULL;
	struct efi_bootlog_sysfs_attr *bootlog_sysfs = NULL;
	unsigned int i;
	int err = 0;

	if (efi_bootlog_table_size == 0)
		return -ENOENT;

	bootlog_table = memremap(efi.bootlog, efi_bootlog_table_size,
			     MEMREMAP_WB);
	if (!bootlog_table) {
		pr_err("Failed to map EFI Bootlog config table\n");
		return -ENOMEM;
	}

	bootlog_kobj = kobject_create_and_add("bootlog", efi_kobj);
	if (!bootlog_kobj) {
		pr_err("Failed to create EFI bootlog sysfs entry\n");
		return -ENOMEM;
	}

	for (i = 0; i < bootlog_table->nr_logs; i++) {
		u64 addr = bootlog_table[i].log_address[i];

		bootlog_sysfs = kzalloc(sizeof(*bootlog_sysfs), GFP_KERNEL);
		if (!bootlog_sysfs) {
			err = -ENOMEM;
			break;
		}

		bootlog_sysfs->bootlog = memremap(addr, sizeof(*bootlog), MEMREMAP_WB);
		bootlog_sysfs->bootlog_size = bootlog_sysfs->bootlog->last_byte;
		memunmap(bootlog_sysfs->bootlog);
		bootlog_sysfs->bootlog = memremap(addr, bootlog_sysfs->bootlog_size,
						  MEMREMAP_WB);
		memcpy(bootlog_sysfs->name, bootlog_sysfs->bootlog->producer,
		       sizeof(bootlog_sysfs->bootlog->producer));

		sysfs_bin_attr_init(&bootlog_sysfs->bin_attr);
		bootlog_sysfs->bin_attr.private = bootlog_sysfs;
		bootlog_sysfs->bin_attr.attr.name = bootlog_sysfs->name;
		bootlog_sysfs->bin_attr.attr.mode = 0400;
		bootlog_sysfs->bin_attr.size = bootlog_sysfs->bootlog_size;
		bootlog_sysfs->bin_attr.read = efi_bootlog_sysfs_read;

		err = sysfs_create_bin_file(bootlog_kobj,
					   &bootlog_sysfs->bin_attr);
		if (err)
			break;

		list_add_tail(&bootlog_sysfs->node, &efi_bootlog_sysfs_list);
	}

	if (err) {
		pr_err("Failed to create some bootlog sysfs entries\n");
		kfree(bootlog_sysfs);
	}
	return err;
}
device_initcall(efi_bootlog_sysfs_init);
