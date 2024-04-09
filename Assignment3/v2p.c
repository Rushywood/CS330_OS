//210676_Nitesh Kaushal
#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/*
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables
 * */

struct vm_area *make_new_node(long start, long end, int prot)
{
    struct vm_area *new = os_alloc(sizeof(struct vm_area));
    new->access_flags = prot;
    new->vm_start = start;
    new->vm_end = end;
    stats->num_vm_area++;
    new->vm_next = NULL;
    return new;
}

int change_pfn(struct exec_context *current, long address, int prot, int type)
{

    // u64 part_5_12 = address & 0xFFF;
    // u64 part_4_9 = address & 0x1FF000;
    // part_4_9 = part_4_9 >> 12;
    // u64 part_3_9 = address & 0x3FE00000;
    // part_3_9 = part_3_9 >> 21;
    // u64 part_2_9 = address & 0x7FC0000000;
    // part_2_9 = part_2_9 >> 30;
    // u64 part_1_9 = address & 0xFF8000000000;
    // part_1_9 = part_1_9 >> 39;
    long pfn = current->pgd;
    long *addr_ptr;
    int off;
    for (int i = 0; i < 4; i++)
    {
        addr_ptr = osmap(pfn);
        off = (address >> (39 - 9 * i)) % 512;
        pfn = (addr_ptr[off] >> 12);
    }

    if (addr_ptr[off] % 2 == 1)
    {
        if (type == 1)
        {
            if (!get_pfn_refcount(pfn))
            {
                if (prot == PROT_READ)
                {
                    addr_ptr[off] = addr_ptr[off] & (-9);
                }
            }
            else
            {
                if ((prot & PROT_WRITE) == PROT_WRITE)
                {
                    addr_ptr[off] = addr_ptr[off] | 8;
                }
                else
                {
                    addr_ptr[off] = addr_ptr[off] & (-9);
                }
            }
        }
        else
        {
            if (!get_pfn_refcount(pfn))
            {
                put_pfn(pfn);
                addr_ptr[off] = 0;
                // printk("inside pfref\n");
            }
            else
            {
                put_pfn(pfn);
                os_pfn_free(USER_REG, pfn);
                addr_ptr[off] = 0;
            }
        }
    }

    asm volatile("invlpg (%0)" ::"r"(address): "memory");
    return 0;
}

//We copy the memory between the parent and child by this function

int copy_mem(long start, long end, long pgd_old, long pgd_new)
{
    long *ptr_p1 = osmap(pgd_old);
    long *ptr_p2 = osmap(pgd_new);

    start = start - start % 4096;

    long pfn1, pfn2;
    long *ptr_1, *ptr_2;
    for (long addr = start; addr < end; addr += 4096)
    {

        ptr_1 = ptr_p1;
        ptr_2 = ptr_p2;
        int off;

        for (int i = 1; i <= 4; i++)
        {
            off = (addr >> (48 - 9 * i)) % 512;

            if (ptr_1[off] % 2 == 0)
            {
                ptr_2[off] = 0;
                break;
            }
            else if (i <= 3)
            {
                if (ptr_2[off] % 2 == 0)
                {

                    long main_pfn = os_pfn_alloc(OS_PT_REG);

                    if (main_pfn == 0)
                    {
                        return -1;
                    }

                    ptr_2[off] = (main_pfn << 12) + (ptr_1[off] % 4096);
                }
                ptr_1 = osmap(ptr_1[off] >> 12);
                ptr_2 = osmap(ptr_2[off] >> 12);
            }
            else
            {
                ptr_1[off] = ptr_1[off] & (-9);
                ptr_2[off] = ptr_1[off];
                get_pfn(ptr_1[off] >> 12);
                asm volatile("invlpg (%0)" ::"r"(addr): "memory");
            }
        }
    }
    return 0;
}

long alloc_PTE(long pfn, long us, long rw, long bit)
{
    return ((pfn << 12) + (us << 4) + (rw << 3) + bit);
}

/**
 * mprotect System call Implementation.
 */

long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{

    // printk("mprotect start\n");
    if (length % 4096 != 0)
    {
        length = length + (4096 - length % 4096);
    }

   if (current == NULL)
        return -EINVAL;

    int length_valid = (length >= 0) && (length <= 0x200000);

    int addr_valid = (addr >= MMAP_AREA_START) && (addr < MMAP_AREA_END);

    int prot_valid = (prot > 0) && (prot < 4);
    
    if (!prot_valid)
        return -EINVAL;
    if (!length_valid)
        return -EINVAL;
    if (!addr_valid)
        return -EINVAL;
    if (length==0)
        return 0;

    if (current->vm_area == NULL)
    {
        current->vm_area = make_new_node(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        stats->num_vm_area = 1;
    }

    struct vm_area *prev = current->vm_area;

    struct vm_area *curr = prev->vm_next;

    while (curr->vm_start < addr + length && curr != NULL)
    {
        long start_add, end_add;

        if (curr->access_flags == prot || curr->vm_end <= addr)
        {
            prev = curr;
            curr = curr->vm_next;
            continue;
        }
        else
        {
            if (addr + length < curr->vm_end && curr->vm_start < addr)
            {
                end_add = addr + length;
                start_add = addr;

                struct vm_area *node1 = make_new_node(curr->vm_start, addr, curr->access_flags);
                struct vm_area *node2 = make_new_node(addr, addr + length, prot);

                curr->vm_start = addr + length;
                prev->vm_next = node1;
                node1->vm_next = node2;
                node2->vm_next = curr;

                for (long adrs = start_add; adrs < end_add; adrs += 4096)
                {
                    change_pfn(current, adrs, prot, 1);
                }
            }
            else if (addr + length < curr->vm_end && curr->vm_start >= addr)
            {
                end_add = addr + length;
                start_add = curr->vm_start;
                
                if (prev->vm_end == curr->vm_start && prev->access_flags == prot && prev != current->vm_area)
                {
                    prev->vm_end = addr + length;
                    curr->vm_start = addr + length;
                }
                else
                {
                    struct vm_area *new = make_new_node(curr->vm_start, addr + length, prot);
                    curr->vm_start = addr + length;
                    new->vm_next = curr;
                    prev->vm_next = new;
                }
                for (long adrs = start_add; adrs < end_add; adrs += 4096)
                {
                    change_pfn(current, adrs, prot, 1);
                }
            }
            else if (addr > curr->vm_start && addr + length >= curr->vm_end)
            {
                end_add = curr->vm_end;
                struct vm_area *next = curr->vm_next;
                start_add = addr;
                if (next != NULL && next->vm_start == curr->vm_end && next->access_flags == prot)
                {
                    next->vm_start = addr;
                    curr->vm_end = addr;
                }
                else
                {
                    struct vm_area *new = make_new_node(addr, curr->vm_end, prot);
                    curr->vm_end = addr;
                    new->vm_next = curr->vm_next;
                    curr->vm_next = new;
                }
                for (long adrs = start_add; adrs < end_add; adrs += 4096)
                {
                    change_pfn(current, adrs, prot, 1);
                }
            }
            else if (addr + length >= curr->vm_end && addr <= curr->vm_start)
            {
                end_add = curr->vm_end;
                struct vm_area *next = curr->vm_next;
                start_add = curr->vm_start;
                if (prev->access_flags == prot && prev != current->vm_area && prev->vm_end == curr->vm_start)
                {
                    if (next != NULL && next->vm_start == curr->vm_end && next->access_flags == prot)
                    {
                        prev->vm_end = next->vm_end;
                        prev->vm_next = next->vm_next;

                        os_free(curr, sizeof(struct vm_area));
                        os_free(next, sizeof(struct vm_area));

                        stats->num_vm_area -= 2;
                        curr = prev;
                    }
                    else
                    {
                        prev->vm_end = curr->vm_end;
                        prev->vm_next = next;

                        os_free(curr, sizeof(struct vm_area));
                        stats->num_vm_area--;
                        curr = prev;
                    }
                }
                else
                {
                    if (next->access_flags == prot && next != NULL && next->vm_start == curr->vm_end)
                    {
                        curr->vm_end = next->vm_end;
                        curr->vm_next = next->vm_next;
                        curr->access_flags = prot;
                        os_free(next, sizeof(struct vm_area));
                        stats->num_vm_area--;
                    }
                    else
                    {
                        curr->access_flags = prot;
                    }
                }
                for (long adrs = start_add; adrs < end_add; adrs += 4096)
                {
                    change_pfn(current, adrs, prot, 1);
                }
            }
        }
        prev = curr;
        curr = curr->vm_next;
    }
    return 0;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    if (length % 4096 != 0)
    {
        length = length + (4096 - length%4096);
    }
    int flag_valid = (flags == 0) || (flags == MAP_FIXED);

    int addr_invalid = addr != NULL && (addr < MMAP_AREA_START + 0x1000 || addr >= MMAP_AREA_END);

    int prot_valid = prot == PROT_READ || prot == (PROT_READ | PROT_WRITE);

    int length_valid = (length >= 0) && (length <= 0x200000);

    int addr_valid = !addr_invalid;

    if (!(flag_valid && addr_valid && prot_valid && length_valid))
        return -1;
    if (length == 0)
    {
        return 0;
    }

    if (current->vm_area == NULL)
    {
        current->vm_area = make_new_node(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        stats->num_vm_area = 1;
    }

    if (addr < MMAP_AREA_END && addr != NULL && addr >= MMAP_AREA_START + 4096)
    {

        struct vm_area *prev = current->vm_area;
        struct vm_area *curr = prev->vm_next;

        while (prev->vm_end <= addr && curr != NULL)
        {
            if (addr + length <= curr->vm_start)
            {
                if (prev->access_flags == prot && addr == prev->vm_end)
                {
                    if (!(addr + length == curr->vm_start && curr->access_flags == prot))
                    {
                        prev->vm_end += length;
                    }
                    else
                    {
                        prev->vm_end = curr->vm_end;
                        prev->vm_next = curr->vm_next;

                        os_free(curr, sizeof(struct vm_area));
                        stats->num_vm_area--;
                    }
                }

                else
                {
                    if (!(prot == curr->access_flags && addr + length == curr->vm_start))
                    {
                        struct vm_area *new = make_new_node(addr, addr + length, prot);
                        prev->vm_next = new;
                        new->vm_next = curr;
                    }
                    else
                    {
                        curr->vm_start -= length;
                    }
                }
                return addr;
            }
            else if (addr <= curr->vm_start)
            {
                if (flags == MAP_FIXED)
                {
                    return -1;
                }
                else
                {
                    break;
                }
            }
            else
            {
                prev = curr;
                curr = curr->vm_next;
            }
        }
        if (curr == NULL)
        {
            
            if (flags == MAP_FIXED)
            {
                return -EINVAL;
            }
            else if (prev->access_flags == prot && addr == prev->vm_end)
            {
                prev->vm_end += length;
                return addr;
            }
            else if (addr > prev->vm_end)
            {
                struct vm_area *new = make_new_node(addr, addr + length, prot);
                prev->vm_next = new;
                new->vm_next = NULL;
                return addr;
            }
        }
    }

    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;

    while (curr != NULL)
    {
        if (curr->vm_start - prev->vm_end >= length)
        {
            long retval = prev->vm_end;
            if (prev->access_flags != prot)
            {
                if (prev->vm_end + length == curr->vm_start && prot == curr->access_flags)
                {
                    curr->vm_start -= length;
                }
                else
                {
                    struct vm_area *new = make_new_node(prev->vm_end, prev->vm_end + length, prot);
                    prev->vm_next = new;
                    new->vm_next = curr;
                }
            }
            else
            {
                if (!(prev->vm_end + length == curr->vm_start && prot == curr->access_flags))
                {
                    prev->vm_end += length;
                }
                else
                {
                    prev->vm_end = curr->vm_end;
                    prev->vm_next = curr->vm_next;
                    os_free(curr, sizeof(struct vm_area));
                    stats->num_vm_area--;
                }
            }
            return retval;
        }
        else
        {
            prev = curr;
            curr = curr->vm_next;
        }
    }
    if (curr == NULL)
    {
        long retval = prev->vm_end;
        if (prev->access_flags != prot)
        {
            struct vm_area *new = make_new_node(prev->vm_end, prev->vm_end + length, prot);
            prev->vm_next = new;
            new->vm_next = NULL;
        }
        else
        {
            prev->vm_end += length;
        }
        return retval;
    }
    return -EINVAL;
}


/**
 * munmap system call implemenations
 */

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    // printk("unmap\n");
    if (length > 2097152 || current == NULL || addr < MMAP_AREA_START || addr >= MMAP_AREA_END)
    {
        return -EINVAL;
    }
    if (length < 0)
    {
        return -EINVAL;
    }
    if (length == 0)
    {
        return 0;
    }
    if (length % 4096 != 0)
    {
        length = length + (4096 - length % 4096);
    }

    if (current->vm_area == NULL)
    {
        current->vm_area = make_new_node(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        stats->num_vm_area = 1;
    }

    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;

    while (curr != NULL && curr->vm_start < addr + length)
    {
        if (curr->vm_end > addr)
        {
            long beginning, finish;
            if (curr->vm_start < addr && addr + length < curr->vm_end)
            {
                finish = addr + length;
                beginning = addr;
                struct vm_area *new = make_new_node(curr->vm_start, addr, curr->access_flags);
                prev->vm_next = new;
                new->vm_next = curr;
                curr->vm_start = addr + length;
            }
            else if (curr->vm_start >= addr && addr + length < curr->vm_end)
            {
                finish = addr + length;
                beginning = curr->vm_start;
                curr->vm_start = addr + length;
            }
        
        
            else if (addr <= curr->vm_start && addr + length >= curr->vm_end)
            {
                finish = curr->vm_end;
                beginning = curr->vm_start;
                prev->vm_next = curr->vm_next;
                os_free(curr, sizeof(struct vm_area));
                stats->num_vm_area--;
                curr = prev;
            }
            else if (addr > curr->vm_start && addr + length >= curr->vm_end)
            {
                finish = curr->vm_end;
                beginning = addr;
                curr->vm_end = addr;
            }
            for (long ptr = beginning; ptr < finish; ptr += 4096)
            {
                change_pfn(current, ptr, -1, 0);
            }
        }
        prev = curr;
        curr = curr->vm_next;
    }

    return 0;
}


/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    // printk("fault start\n");
    if (addr<MMAP_AREA_START || current == NULL ||  addr>=MMAP_AREA_END) 
    {
        return -EINVAL;
    }

    if (addr == NULL)
    return -1;

    if (error_code!=6 && error_code!=7 && error_code!=4) 
    {
        return -1;
    }

    struct vm_area* curr = current->vm_area;
    if (curr == NULL)
    {
        current->vm_area = make_new_node(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        stats->num_vm_area = 1;
        curr = current->vm_area;
    }
    struct vm_area* next = current->vm_area->vm_next;;

    struct vm_area* node = NULL;

    int flag=0;

    //calculating req bits
    u64 part_5_12 = addr & 0xFFF;
    u64 part_4_9 = addr & 0x1FF000;
    part_4_9 = part_4_9 >> 12;
    u64 part_3_9 = addr & 0x3FE00000;
    part_3_9 = part_3_9 >> 21;
    u64 part_2_9 = addr & 0x7FC0000000;
    part_2_9 = part_2_9 >> 30;
    u64 part_1_9 = addr & 0xFF8000000000;
    part_1_9 = part_1_9 >> 39;

    while (next != NULL)
    {
        if (addr >= next->vm_start && addr < next->vm_end)
        {
            if(error_code == 0x4 || error_code == 0x6)
            {
                if (next->access_flags == PROT_READ && error_code == 6)
                {
                    return -1;
                    // printk("In excep\n");
                    //check of exception
                }
                long* ptr_add = osmap(current->pgd);
                for (int i=0;i<3;i++)
                {
                    int offs = (addr>>(48 - 9*(i+1)))%512;
                    if (ptr_add[offs]%2 == 0)
                    {
                        long pfn = os_pfn_alloc(OS_PT_REG);

                        if (pfn == 0)
                        return -1;

                        ptr_add[offs] = alloc_PTE(pfn,1,1,1);
                    }
                    long vir_add = ptr_add[offs]>>12;
                    ptr_add = osmap(vir_add);
                }
                int offs = (addr>>12)%512;
                if (ptr_add[offs]%2 == 0)
                {
                    int rwbit = 0;
                    if ((next->access_flags&PROT_WRITE)==PROT_WRITE)
                    rwbit=1;
                    long pfn = os_pfn_alloc(USER_REG);

                    if (pfn==0)
                    return -1;

                    ptr_add[offs] = alloc_PTE(pfn,1,rwbit,1);
                }
                return 0;
            }
            else if (error_code == 0x7)
            {
                // printk("In con of 7\n");
                if ((next->access_flags&PROT_WRITE) != PROT_WRITE )
                {
                    return -1;
                    // printk("In excep22\n");
                    //check of exception
                }
                else
                {
                    // printk("In con of 7 in else before cow\n");
                    handle_cow_fault(current,addr,next->access_flags);
                    return 1;
                }
            }
            break;
        }
        next = next->vm_next;
    }
    return -1;
}

long do_cfork()
{
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
    /* Do not modify above lines
     *
     * */
    //--------------------- Your code [start]---------------//

    pid = new_ctx->pid;

    new_ctx->ppid = ctx->pid;

    new_ctx->type = ctx->type;

    new_ctx->used_mem = ctx->used_mem;

    new_ctx->state = ctx->state;

    new_ctx->regs = ctx->regs;

    new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;

    new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;

    new_ctx->alarm_config_time = ctx->alarm_config_time;

    new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;

    new_ctx->ctx_threads = ctx->ctx_threads;

    for (int i = 0; i < CNAME_MAX; i++)
    {
        new_ctx->name[i] = ctx->name[i];
    }
    for (int i = 0; i < MAX_SIGNALS; i++)
    {
        new_ctx->sighandlers[i] = ctx->sighandlers[i];
    }
    for (int i = 0; i < MAX_MM_SEGS; i++)
    {
        new_ctx->mms[i] = ctx->mms[i];
    }
    for (int i = 0; i < MAX_OPEN_FILES; i++)
    {
        new_ctx->files[i] = ctx->files[i];
    }
    
    if (ctx->vm_area == NULL)
    {
        new_ctx->vm_area = NULL;
    }
    else
    {
        struct vm_area *new = ctx->vm_area->vm_next;
        struct vm_area *pfn_ptr1 = ctx->vm_area->vm_next;
        struct vm_area *pfn_ptr2 = ctx->vm_area->vm_next;

        new_ctx->vm_area = make_new_node(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        pfn_ptr2 = new_ctx->vm_area;
        while (pfn_ptr1 != NULL)
        {
            new = make_new_node(pfn_ptr1->vm_start, pfn_ptr1->vm_end, pfn_ptr1->access_flags);
            pfn_ptr2->vm_next = new;
            pfn_ptr2 = new;
            pfn_ptr1 = pfn_ptr1->vm_next;
        }
        pfn_ptr2->vm_next = NULL;
    }


    new_ctx->pgd = os_pfn_alloc(OS_PT_REG);

    if (new_ctx->pgd == 0)
    {
        return -1;
    }
    int retval;
    for (int i = 0; i <= 2; i++)
    {
        retval = copy_mem(ctx->mms[i].start, ctx->mms[i].next_free, ctx->pgd, new_ctx->pgd);
        if (retval == -1)
        {
            return -1;
        }
    }
    retval = copy_mem(ctx->mms[3].start, ctx->mms[3].end, ctx->pgd, new_ctx->pgd);
    if (retval == -1)
    {
        return -1;
    }

    if (ctx->vm_area != NULL)
    {
        for (struct vm_area *ptr = ctx->vm_area->vm_next; ptr != NULL; ptr = ptr->vm_next)
        {
            retval = copy_mem(ptr->vm_start, ptr->vm_end, ctx->pgd, new_ctx->pgd);

            if (retval == -1)
            {
                return -1;
            }
        }
    }
    //--------------------- Your code [end] ----------------//

    /*
     * The remaining part must not be changed
     */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}

/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data)
 * it is called when there is a CoW violation in these areas.
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    // printk("in cow\n");
    long main_pfn = current->pgd;
    int offs;
    long *ptr;
    for (int j = 1; j <= 4; j++)
    {
        ptr = osmap(main_pfn);
        offs = (vaddr >> (48 - 9 * j)) % 512;
        main_pfn = (ptr[offs] >> 12);
    }

    int cnt = get_pfn_refcount(main_pfn);

    if (cnt > 1)
    {
        long addr_pt = os_pfn_alloc(USER_REG);
        if (addr_pt == 0)
            return -1;
        ptr[offs] = (addr_pt << 12) + (ptr[offs] % 4096);
        ptr[offs] = ptr[offs] | 8;
        put_pfn(main_pfn);

        long *pfn_t1 = osmap(main_pfn);
        long *pfn_t2 = osmap(addr_pt);
        for (int i = 0; i < 512; i++)
        {
            pfn_t2[i] = pfn_t1[i];
        }
    }
    else
    {
        ptr[offs] = ptr[offs] | 8;
    }

    asm volatile("invlpg (%0)" ::"r"(vaddr): "memory");
    return 0;
}