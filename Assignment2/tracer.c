//Nitesh Kaushal______210676

#include<context.h>
#include<memory.h>
#include<lib.h>
#include<entry.h>
#include<file.h>
#include<tracer.h>


///////////////////////////////////////////////////////////////////////////
//// 		Start of Trace buffer functionality 		      /////
///////////////////////////////////////////////////////////////////////////


u32 min(u32 a, u32 b)
{
	if (a>b)
	return b;

	return a;
}

int is_valid_mem_range(unsigned long buff, u32 count, int access_bit) 
{
	struct exec_context* ctx = get_current_ctx();

	if (buff >= ctx->mms[MM_SEG_CODE].start && buff < ctx->mms[MM_SEG_CODE].next_free)
	{
		if (access_bit & 1)
		return 0;
	}
	else if (buff >= ctx->mms[MM_SEG_RODATA].start && buff<ctx->mms[MM_SEG_RODATA].next_free)
	{
		if (access_bit & 1)
		return 0;
	}
	else if (buff >= ctx->mms[MM_SEG_DATA].start && buff < ctx->mms[MM_SEG_DATA].next_free)
	{
		if (access_bit & 3)
		return 0;
	}
	else if (buff >= ctx->mms[MM_SEG_STACK].start && buff < ctx->mms[MM_SEG_STACK].end)
	{
		if (access_bit & 3)
		return 0;
	}
	struct vm_area* my_area = ctx->vm_area;
	while (my_area!=NULL)
	{
		if (buff>=my_area->vm_start && buff < my_area->vm_end)
		{
			if (access_bit & my_area->access_flags)
			{
				return 0;
			}
		}
		my_area = my_area->vm_next;
	}
	return 1;
}

long trace_buffer_close(struct file *filep)
{
	os_free(filep->fops,sizeof(struct fileops));
	os_page_free(USER_REG,filep->trace_buffer->arr);
	os_free(filep->trace_buffer,sizeof(struct trace_buffer_info));
	os_page_free(USER_REG,filep);
	return 0;	
}


int trace_buffer_read(struct file *filep, char *buff, u32 count)
{

	if (is_valid_mem_range((unsigned long)buff,count,2))
	return -EBADMEM;
	
	struct trace_buffer_info* my_buffer = filep->trace_buffer;

	if (my_buffer->mode == O_WRITE) return -EINVAL;

	u32 read_off = my_buffer->read_offset;
	u32 write_off = my_buffer->write_offset;

	u32 bytes_re;

	if(my_buffer->empty)
	return 0;

	int i;
	if (read_off < write_off)
	{
		bytes_re = min(count, write_off-read_off);
		if(write_off-read_off == bytes_re) 
		my_buffer->empty = 1;

		for (i=0;i<bytes_re;i++)
		{
			buff[i] = my_buffer->arr[i+read_off];
		}
		my_buffer->read_offset =bytes_re + read_off;
	}
	else
	{
		if(count > 4096 - read_off)
		{
			bytes_re = min(count,4096 - read_off + write_off);
			if(4096+write_off-read_off == bytes_re) 
			my_buffer->empty = 1;

			for (i=0;i<4096 - read_off;i++)
			{
				buff[i] = my_buffer->arr[i+read_off];
			}
			for (i = 0 ;i<bytes_re - (4096-read_off);i++)
			{
				buff[i + 4096 - read_off] = my_buffer->arr[i];
			}
			my_buffer->read_offset=i;
		}
		else
		{
			bytes_re = min(count,4096 - read_off);
			for (i=0;i<bytes_re;i++)
			{
				buff[i] = my_buffer->arr[i+read_off];
			}
			my_buffer->read_offset = bytes_re + read_off;
		}
	}
	return bytes_re;
}

int trace_buffer_read_2(struct file *filep, char *buff, u32 count)
{
	
	struct trace_buffer_info* my_buffer = filep->trace_buffer;

	if (my_buffer->mode == O_WRITE) return -EINVAL;

	u32 read_off = my_buffer->read_offset;
	u32 write_off = my_buffer->write_offset;

	u32 bytes_re;

	if(my_buffer->empty)
	return 0;

	int i;
	if (read_off < write_off)
	{
		bytes_re = min(count, write_off-read_off);
		if(write_off-read_off == bytes_re) 
		my_buffer->empty = 1;

		for (i=0;i<bytes_re;i++)
		{
			buff[i] = my_buffer->arr[i+read_off];
		}
		my_buffer->read_offset =bytes_re + read_off;
	}
	else
	{
		if(count > 4096 - read_off)
		{
			bytes_re = min(count,4096 - read_off + write_off);
			if(4096+write_off-read_off == bytes_re) 
			my_buffer->empty = 1;

			for (i=0;i<4096 - read_off;i++)
			{
				buff[i] = my_buffer->arr[i+read_off];
			}
			for (i = 0 ;i<bytes_re - (4096-read_off);i++)
			{
				buff[i + 4096 - read_off] = my_buffer->arr[i];
			}
			my_buffer->read_offset=i;
		}
		else
		{
			bytes_re = min(count,4096 - read_off);
			for (i=0;i<bytes_re;i++)
			{
				buff[i] = my_buffer->arr[i+read_off];
			}
			my_buffer->read_offset = bytes_re + read_off;
		}
	}
	return bytes_re;
}


int trace_buffer_write(struct file *filep, char *buff, u32 count)
{

	if (is_valid_mem_range((unsigned long)buff,count,1))
	return -EBADMEM;

	struct trace_buffer_info* my_buffer = filep->trace_buffer;

	if (my_buffer->mode==O_READ) 
	return -EINVAL;

	u32 read_off = my_buffer->read_offset;
	u32 write_off = my_buffer->write_offset;

	u32 byt_rem;

	if(count) my_buffer->empty =0;
	
	int i;
	if (read_off>write_off)
	{
		byt_rem = min(count,read_off-write_off);
		for (i = 0;i<byt_rem;i++)
		{
			my_buffer->arr[i + write_off] = buff[i];
		}
		my_buffer->write_offset = i + write_off;
	}
	else
	{

		if (count <= 4096 - write_off)
		{
			byt_rem= min(count,4096 - write_off);
			for (i = 0;i<byt_rem;i++)
			{
				my_buffer->arr[i + write_off] = buff[i];
			}
			my_buffer->write_offset = byt_rem + write_off;
		}
		else
		{
			byt_rem= min(count,4096 - write_off + read_off);
			
				for (i = 0;i<4096-write_off;i++)
				{
					my_buffer->arr[i + write_off] = buff[i];
				}
				for (i=0;i<byt_rem - (4096-write_off);i++)
				{
					my_buffer->arr[i] = buff[i + 4096 - write_off];
				}
				my_buffer->write_offset = i;
		}

	}
		return byt_rem;
}

int trace_buffer_write_2(struct file *filep, char *buff, u32 count)
{

	struct trace_buffer_info* my_buffer = filep->trace_buffer;

	if (my_buffer->mode==O_READ) 
	return -EINVAL;

	u32 read_off = my_buffer->read_offset;
	u32 write_off = my_buffer->write_offset;
	u32 byt_rem;


	if(count) my_buffer->empty =0;
	
	int i;
	if (read_off>write_off)
	{
		byt_rem = min(count,read_off-write_off);
		for (i = 0;i<byt_rem;i++)
		{
			my_buffer->arr[i + write_off] = buff[i];
		}
		my_buffer->write_offset = i + write_off;
	}
	else
	{

		if (count <= 4096 - write_off)
		{
			byt_rem= min(count,4096 - write_off);
			for (i = 0;i<byt_rem;i++)
			{
				my_buffer->arr[i + write_off] = buff[i];
			}
			my_buffer->write_offset = byt_rem + write_off;
		}
		else
		{
			byt_rem= min(count,4096 - write_off + read_off);
			
				for (i = 0;i<4096-write_off;i++)
				{
					my_buffer->arr[i + write_off] = buff[i];
				}
				for (i=0;i<byt_rem - (4096-write_off);i++)
				{
					my_buffer->arr[i] = buff[i + 4096 - write_off];
				}
				my_buffer->write_offset = i;
		}

	}
		return byt_rem;
}

int sys_create_trace_buffer(struct exec_context *current, int mode)
{
	int file_fd;
	int flag = 0;

	int ff = 0;
	if (mode == O_RDWR || mode == O_READ || mode == O_WRITE)
	{
		ff = 1;
	}
	if (ff==0)
	return -EINVAL;

	for (int i=0;i<MAX_OPEN_FILES;i++)
	{
		if (current->files[i]==NULL)
		{
			flag=1;
			file_fd = i;
			break;
		}

	}
	if (flag=0)
	return -EINVAL;

	struct file* myfile = (struct file*)os_page_alloc(USER_REG);

	
	if (myfile==NULL)return -ENOMEM;

	myfile->offp=0;
	myfile->ref_count=1;
	myfile->type = 1; 
	myfile->mode = mode;
	
	myfile->inode = NULL;

	current->files[file_fd]=myfile;

	struct trace_buffer_info* mybuff = (struct trace_buffer_info*)os_alloc(sizeof(struct trace_buffer_info));
	if (mybuff==NULL)
	return -ENOMEM;

	mybuff->arr = (char*)os_page_alloc(USER_REG);

	mybuff->mode=mode;
	mybuff->read_offset=0;
	mybuff->write_offset=0;
	mybuff->empty=1;
	myfile->trace_buffer = mybuff;

	
	struct fileops* file_op = (struct fileops*)os_alloc(sizeof(struct fileops));
	if (file_op==NULL)
	return -ENOMEM;
	

	file_op->close=&(trace_buffer_close);
	file_op->read=&(trace_buffer_read);
	file_op->write=&(trace_buffer_write);
	myfile->fops = file_op;


	return file_fd;
}


///////////////////////////////////////////////////////////////////////////
//// 		Start of strace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

int get_no_arguments(u64 syscall_num)
{
	int arg=0;
	if (syscall_num == 2 || syscall_num == 10 || syscall_num == 11 || syscall_num == 13 || syscall_num == 15 || syscall_num == 20 || syscall_num == 21 || syscall_num == 22 || syscall_num == 38)
	{
		arg=0;
	}
	else if (syscall_num == 1 || syscall_num == 6 || syscall_num == 7 || syscall_num == 12 || syscall_num == 14 || syscall_num == 19 || syscall_num == 27 || syscall_num == 29)
	{
		arg=1;
	}
	else if (syscall_num == 4 || syscall_num == 8 || syscall_num == 9 || syscall_num == 17 || syscall_num == 23 || syscall_num == 28 || syscall_num == 37 || syscall_num == 40)
	{
		arg=2;
	}
	else if (syscall_num == 5 || syscall_num == 18 || syscall_num == 24 || syscall_num == 25 || syscall_num == 30 || syscall_num == 39 || syscall_num == 41)
	{
		arg=3;
	}
	else if (syscall_num == 16 || syscall_num == 35)
	{
		arg=4;
	}
	else
	{
		return -1;
	}
	return arg;
}


int perform_tracing(u64 syscall_num, u64 param1, u64 param2, u64 param3, u64 param4)
{
	if (syscall_num == SYSCALL_START_STRACE || syscall_num == SYSCALL_END_STRACE || syscall_num == 39 || syscall_num == 40 )
	{
		return 0;
	}
	int no_arguments; 
	struct exec_context* current = get_current_ctx();

	if (current == NULL){
		return -EINVAL;
	}

	struct strace_head* list_head=current->st_md_base;
	int fd = list_head->strace_fd;
	struct file *trace_buffer_file = current->files[fd];
	struct trace_buffer_info *my_buffer_ = trace_buffer_file->trace_buffer;
	
	if (list_head->is_traced == 0)
	{
		return 0;   
	}

	if(list_head->tracing_mode == FILTERED_TRACING)
	{
		struct strace_info* curr=list_head->next;
		int flag=0;
		while(curr!= NULL)
		{
			if(curr->syscall_num == syscall_num)
			{
				flag=1;
				break;
			}
			curr=curr->next;
		}
		if(flag==0) 
		return 0; 
	}

	no_arguments=get_no_arguments(syscall_num);
	
	u64 array[]={syscall_num,param1,param2,param3,param4};
	
	trace_buffer_write_2(trace_buffer_file,(char*)array,8*(no_arguments+1));
	
	return 0;
}


int sys_strace(struct exec_context *current, int syscall_num, int action)
{
	if(current == NULL)
	{
		return -EINVAL;
	}

	if (current->st_md_base != NULL)
	{
		struct strace_head* head = current -> st_md_base;
		
		if (action == ADD_STRACE)
		{
			if (head->count >= MAX_STRACE)
			return -EINVAL;
			
			struct strace_info* meno = head->next;
			while (meno != NULL)
			{
				if (meno->syscall_num == syscall_num)
				return -EINVAL;
			}
			

			if (head->next != NULL)
			{
				struct strace_info* node = (struct strace_info*)os_alloc(sizeof(struct strace_info));
				node->syscall_num = syscall_num;
				node->next = NULL;

				head->last->next = node;
				head->count = head->count + 1;
			}
			else
			{
				struct strace_info* node = (struct strace_info*)os_alloc(sizeof(struct strace_info));
				node->syscall_num = syscall_num;
				node->next = NULL;

				head->count = head->count + 1;
				head->next = node;
				head->last = node;
			}
		}
		else if (action == REMOVE_STRACE)
		{
			if (head->next == NULL)
			return -EINVAL;

			struct strace_info* list_node = head->next;
			struct strace_info* temp;
			int flag = 0;

			while (head->next!=NULL && list_node->syscall_num==syscall_num )
			{
				flag=1;
				head->count = head->count - 1;
				head->next = list_node->next;

				os_free(list_node,sizeof(struct strace_info));
				list_node = head->next;
			}

			while (list_node->next != NULL)
			{
				if (list_node->next->syscall_num == syscall_num)
				{
					temp = list_node->next->next;
					flag=1;
					head->count = head->count - 1;

					os_free(list_node->next,sizeof(struct strace_info));
					list_node->next = temp;
				}
				else
				list_node = list_node->next;
			}

			if (flag==0)
			return -EINVAL;
		}

	}
	else
	{
		if (action == REMOVE_STRACE)
		return -EINVAL;

		else
		{
			struct strace_head* head = (struct strace_head*)os_alloc(sizeof(struct strace_head));
			head->count = 0;
			head->is_traced = 0;
			head->next = NULL;
			head->last = NULL;

			current->st_md_base = head;

			struct strace_info* node = (struct strace_info*)os_alloc(sizeof(struct strace_info));
			node->syscall_num = syscall_num;
			node->next = NULL;

			head->count = head->count + 1;
			head->next = node;
			head->last = node;
		}

	}
	return 0;
}

int sys_read_strace(struct file *filep, char *buff, u64 count)
{
	
	if (filep == NULL)
	{
		return -EINVAL;
	}

	int no_arguments; 
	int new_count=0;
	struct trace_buffer_info *my_buffer_ = filep->trace_buffer;
	if(my_buffer_ == NULL) return -EINVAL;
	
	int read_off=my_buffer_->read_offset;
	int write_off=my_buffer_->write_offset;


	if(my_buffer_->empty) return 0;

	while(count--)
	{
		u64 syscall_num=*(u64*)(my_buffer_->arr+read_off);

		int arg=get_no_arguments(syscall_num);

		new_count += (arg+1)*8;
		
		read_off =(read_off+(arg+1)*8)%4096;

		if(read_off==write_off)break;
	}
	
	return trace_buffer_read_2(filep,buff,new_count);
}

int sys_start_strace(struct exec_context *current, int fd, int tracing_mode)
{
	if (current == NULL || fd <0)
	return -EINVAL;

	if (current->st_md_base ==NULL)
	{	
	struct strace_head* head = (struct strace_head*)os_alloc(sizeof(struct strace_head));
	head->count = 0;
	head->is_traced = 1;
	head->strace_fd = fd;
	head->tracing_mode = tracing_mode;
	head->next = NULL;
	head->last = NULL;

	current->st_md_base = head;
	}
	else
	{
		current->st_md_base->is_traced = 1;
		current->st_md_base->strace_fd = fd;
		current->st_md_base->tracing_mode = tracing_mode;
	}
	return 0;
}

int sys_end_strace(struct exec_context *current)
{

	if (current == NULL)
	return -EINVAL;

	struct strace_head* head = current->st_md_base;

	if (head==NULL)
	return -EINVAL;

	struct strace_info* node = head->next;
	struct strace_info* next_node;
	while (node!=NULL)
	{
		next_node = node->next;
		os_free(node,sizeof(struct strace_info));
		node = next_node;
	}
	os_free(head,sizeof(struct strace_head));
	return 0;
}

///////////////////////////////////////////////////////////////////////////
//// 		Start of ftrace functionality 		      	      /////
///////////////////////////////////////////////////////////////////////////

void con_to_char(u64 value, char* char_array,u32 read_off) {
    for (int i = 0; i < 8; i++) {
        char_array[i+read_off] = value%256;
		value /= 256;
    }
}


long do_ftrace(struct exec_context *ctx, unsigned long faddr, long action, long nargs, int fd_trace_buffer)
{
	if(action == ADD_FTRACE)
	{
		if(ctx->ft_md_base->count >= FTRACE_MAX) 
		return -EINVAL;

		struct ftrace_info* node = ctx->ft_md_base->next;
		while(node)
		{
			if(node->faddr==faddr) 
			return -EINVAL;

			node = node->next;
		}
		
		struct ftrace_info* new_node = (struct ftrace_info*)os_alloc(sizeof(struct ftrace_info));

		new_node->faddr=faddr;
		new_node->fd = fd_trace_buffer;
		new_node->num_args = nargs;
		new_node->next = NULL;
		
		if(ctx->ft_md_base->last != NULL)
		{
			ctx->ft_md_base->last->next = new_node;
			ctx->ft_md_base->last = new_node;
		}
		else
		{
			ctx->ft_md_base->next=new_node;
			ctx->ft_md_base->last=new_node;
		}
	}
	else if(action == REMOVE_FTRACE)
	{
		struct ftrace_head* head = ctx->ft_md_base;

		if(head->next==NULL && head->last == NULL)
		{
			return -EINVAL;
		}

		struct ftrace_info* node = head->next;
		struct ftrace_info* prev = head->next;
		int flag=0;
		while(node)
		{
			if(node->faddr == faddr)
			{
				prev->next = node->next;
				os_free(node,sizeof(struct strace_info));
				flag=1;
			}
			node = node->next;
		}

		if(flag == 0) 
		return -EINVAL;
	}
	else if(action == ENABLE_FTRACE)
	{
		struct ftrace_info* node = ctx->ft_md_base->next;
		int flag=0;
		while(node!=NULL)
		{
			if(node->faddr==faddr)
			{
				u8* fad = (u8*)node->faddr;

				if (*fad == INV_OPCODE)
				return 0;

				for(int i=0;i<4;i++)
				{
					node->code_backup[i] = *(u8*)(fad+i);
					*(u8*)(fad+i) = INV_OPCODE;
				}
				flag=1;
				break;
			}
			node = node->next;
		}
		if(flag==0)
		{
			return -EINVAL;
		}
	}
	else if(action == DISABLE_FTRACE)
	{
		struct ftrace_info* node = ctx->ft_md_base->next;

		int flag=0;
		while(node){
			if(node->faddr==faddr)
			{
				u8* fad = (u8*)node->faddr;
				for(int i=0;i<4;i++)
				{
					*(u8*)(fad+i) = node->code_backup[i];
				}
				flag=1;
				break;
			}
			node = node->next;
		}
		if(flag==0)
		{
			return -EINVAL;
		}
	}
	else if(action == ENABLE_BACKTRACE)
	{
		struct ftrace_info* node = ctx->ft_md_base->next;
		int flag=0;

		while(node){
			if(node->faddr==faddr)
			{
				char * fad = (char*)node->faddr;
				for(int i=0;i<4;i++)
				{
					node->code_backup[i] = *(u8*)(fad+i);
					*(u8*)(fad+i) = INV_OPCODE;
				}
				node->capture_backtrace=1;
				flag=1;
				break;
			}
			node = node->next;
		}
		if(flag==0)
		{
			return -EINVAL;
		}
	}
	else if(action == DISABLE_BACKTRACE)
	{
		struct ftrace_info* node = ctx->ft_md_base->next;

		int flag=0;
		while(node){
			if(node->faddr==faddr)
			{
				char * fad = (char*)node->faddr;
				for(int i=0;i<4;i++)
				{
					*(u8*)(fad+i) = node->code_backup[i];
				}
				node->capture_backtrace=0;
				flag=1;
				break;
			}
			node = node->next;
		}
		if(flag==0)
		{
			return -EINVAL;
		}
	}
	else
	{
		return -EINVAL;
	}
    return 0;
}

//Fault handler
long handle_ftrace_fault(struct user_regs *regs)
{
	int flag=0;

	struct exec_context* curr = get_current_ctx();
	if (curr == NULL)
	return -EINVAL;
	
	struct ftrace_info* node = curr->ft_md_base->next;
	
	while(node){
		if(node->faddr==regs->entry_rip)
		{
			unsigned long faddr=node->faddr;
			int n=node->num_args;
			int k=5;	
			
			char* temp=(char*)(&node->faddr);
			
			trace_buffer_write_2(curr->files[node->fd],(char*)(&faddr),8);

			temp=(char*)(&regs->rdi);

			if(n>=1) trace_buffer_write_2(curr->files[node->fd],temp,8);

			temp=(char*)(&regs->rsi);

			if(n>=2) trace_buffer_write_2(curr->files[node->fd],temp,8);

			temp=(char*)(&regs->rdx);

			if(n>=3) trace_buffer_write_2(curr->files[node->fd],temp,8);

			temp=(char*)(&regs->rcx);

			if(n>=4) trace_buffer_write_2(curr->files[node->fd],temp,8);

			temp=(char*)(&regs->r8);

			if(n>=5) trace_buffer_write_2(curr->files[node->fd],temp,8);
			
			temp=(char*)(&regs->r9);

			if(n>=6) trace_buffer_write_2(curr->files[node->fd],temp,8);
		
			u64 erro_code = INV_OPCODE;

			trace_buffer_write_2(curr->files[node->fd],(char*)(&erro_code),8);

			regs->entry_rsp -= 8;

			(*(u64*)regs->entry_rsp) = regs->rbp;

			regs->rbp = regs->entry_rsp;

			regs->entry_rip += 4;

			flag=1;
			if(node->capture_backtrace==1)
			{
				trace_buffer_write_2(curr->files[node->fd],(char*)(&faddr),8);
				u64 ptr = regs->rbp;
				while(*(u64*)(ptr+8) != END_ADDR)
				{
					char buf_arr[8];
					con_to_char(*(u64*)(ptr+8),buf_arr,0);

					trace_buffer_write_2(curr->files[node->fd],buf_arr,8);
					ptr = *(u64*)(ptr);
				}
			}

			break;
		}
		node = node->next;
	}
	if(flag==0)
	{
		return -EINVAL;
	}
    return 0;
}

int sys_read_ftrace(struct file *filep, char *buff, u64 count)
{
	struct exec_context* current = get_current_ctx();
	
	struct strace_head* head_ls=current->st_md_base;

	struct trace_buffer_info *my_bufferr = filep->trace_buffer;

	char *buffer= my_bufferr->arr;

	if(my_bufferr == NULL) 
	return -EINVAL;

	int bytes=0;
	int write_off=my_bufferr->write_offset;	

	char my_arrr[8];

	while(count--)
	{
		while(*(u64*)(buffer+my_bufferr->read_offset)!=INV_OPCODE && my_bufferr->empty==0)
		{
			bytes+=trace_buffer_read_2(filep,buff+bytes,8);
		}
		if (my_bufferr->empty==0)
		trace_buffer_read_2(filep,my_arrr,8);
	}
	return bytes;
	return 0;
}