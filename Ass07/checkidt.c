/*
 * CheckIDT V1.1
 * Play with IDT from userland
 * It's a tripwire kind for IDT
 * kad 2002
 * 
 * gcc -Wall -o checkidt checkidt.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm/segment.h>
#include <string.h>

#define NORMAL          "\033[0m"
#define NOIR            "\033[30m"
#define ROUGE           "\033[31m"
#define VERT            "\033[32m"
#define JAUNE           "\033[33m"
#define BLEU            "\033[34m"
#define MAUVE           "\033[35m"
#define BLEU_CLAIR      "\033[36m"
#define SYSTEM          "System gate"
#define INTERRUPT       "Interrupt gate"
#define TRAP            "Trap gate"
#define DEFAULT_FILE    "Safe_idt"
#define DEFAULT_MAP		"/boot/System.map"

/***********GLOBAL**************/
int fd_kmem;
unsigned long ptr_idt;
/******************************/


struct descriptor_idt
{
	unsigned short offset_low,seg_selector;
	unsigned char reserved,flag;
	unsigned short offset_high;
};

struct Mode
{
	int show_idt_addr;
	int show_all_info;
	int read_file_archive;
	int create_file_archive;
	char out_filename[20];
	int compare_idt;
	int restore_idt;
	char in_filename[20];
	int show_all_descriptor;
	int resolve;
	char map_filename[40];   
};

unsigned long get_addr_idt (void)
{
	unsigned char idtr[6];
	unsigned long idt;
	__asm__ volatile ("sidt %0": "=m" (idtr));
	idt = *((unsigned long *) &idtr[2]);
	return(idt);
}

unsigned short get_size_idt(void)
{
	unsigned idtr[6];
	unsigned short size;
	__asm__ volatile ("sidt %0": "=m" (idtr));
	size=*((unsigned short *) &idtr[0]);
	return(size);
}

char * get_segment(unsigned short selecteur)
{
	if(selecteur == __KERNEL_CS)
	{
		return("KERNEL_CS");
	}
	if(selecteur == __KERNEL_DS)
	{
		return("KERNEL_DS");
	}
	if(selecteur == __USER_CS)
	{
		return("USER_CS");
	}
	if(selecteur == __USER_DS)
	{
		return("USER_DS");
	}
	else
	{
		printf("UNKNOW\n");
	}
}


void readkmem(void *m,unsigned off,int size)
{
	if(lseek(fd_kmem,off,SEEK_SET) != off)
	{
		fprintf(stderr,"Error lseek. Are you root? \n");
		exit(-1);
	}
	if(read(fd_kmem,m,size)!= size)
	{
		fprintf(stderr,"Error read kmem\n");
		exit(-1);
	}
}

void writekmem(void *m,unsigned off,int size)
{
	if(lseek(fd_kmem,off,SEEK_SET) != off)
	{
		fprintf(stderr,"Error lseek. Are you root? \n");
		exit(-1);
	}
	if(write(fd_kmem,m,size)!= size)
	{
		fprintf(stderr,"Error read kmem\n");
		exit(-1);
	}
}

void resolv(char *file,unsigned long stub_addr,char *name)
{
	FILE *fd;
	char buf[100],addr[30];
	int ptr,ptr_begin,ptr_end;
	snprintf(addr,30,"%x",(char *)stub_addr);
	if(!(fd=fopen(file,"r")))
	{
		fprintf(stderr,"Can't open map file. You can specify a map file -S option or change #define in source\n");
		exit(-1);
	}
	while(fgets(buf,100,fd) != NULL)
	{	
		ptr=strstr(buf,addr);
		if(ptr)
		{
			bzero(name,30);
			ptr_begin=strstr(buf," ");
			ptr_begin=strstr(ptr_begin+1," ");
			ptr_end=strstr(ptr_begin+1,"\n");
			strncpy(name,ptr_begin+1,ptr_end-ptr_begin-1);
			break;
		}
	}
	if(strlen(name)==0)strcpy(name,ROUGE"can't resolve"NORMAL); 
	fclose(fd);
}

void show_all_info(int interrupt,int all_descriptor,char *file,int resolve)
{
	struct descriptor_idt *descriptor;
	unsigned long stub_addr;
	unsigned short selecteur;
	char type[15];
	char segment[15];
	char name[30];
	int x;
	int dpl;
	bzero(name,strlen(name));
	descriptor=(struct descriptor_idt *)malloc(sizeof(struct descriptor_idt));
	printf("Int *** Stub Address *** Segment *** DPL *** Type ");
	if(resolve >= 0) 
	{
		printf("            Handler Name\n");
		printf("--------------------------------------------------------------------------\n");
	}
	else
	{
		printf("\n");
		printf("---------------------------------------------------\n");
	}

	if(interrupt >= 0)
	{
		readkmem(descriptor,ptr_idt+8*interrupt,sizeof(struct descriptor_idt));
		stub_addr=(unsigned long)(descriptor->offset_high << 16) + descriptor->offset_low;
		selecteur=(unsigned short) descriptor->seg_selector;
		if(descriptor->flag & 64) dpl=3;
		else dpl = 0;
		if(descriptor->flag & 1)
		{
			if(dpl)
				strncpy(type,SYSTEM,sizeof(SYSTEM));
			else strncpy(type,TRAP,sizeof(TRAP));
		}
		else strncpy(type,INTERRUPT,sizeof(INTERRUPT));
		strcpy(segment,get_segment(selecteur));

		if(resolve >= 0) 
		{
			resolv(file,stub_addr,name); 
			printf("%-7i 0x%-14.8x %-12s%-8i%-16s %s\n",interrupt,stub_addr,segment,dpl,type,name);
		}
		else 
		{
			printf("%-7i 0x%-14.8x %-12s %-7i%s\n",interrupt,stub_addr,segment,dpl,type);
		}   
	}
	if(all_descriptor >= 0 )
	{
		for (x=0;x<(get_size_idt()+1)/8;x++)
		{
			readkmem(descriptor,ptr_idt+8*x,sizeof(struct descriptor_idt));
			stub_addr=(unsigned long)(descriptor->offset_high << 16) + descriptor->offset_low;
			if(stub_addr != 0)
			{
				selecteur=(unsigned short) descriptor->seg_selector;
				if(descriptor->flag & 64) dpl=3;
				else dpl = 0;
				if(descriptor->flag & 1)
				{
					if(dpl)
						strncpy(type,SYSTEM,sizeof(SYSTEM));
					else strncpy(type,TRAP,sizeof(TRAP));
				}
				else strncpy(type,INTERRUPT,sizeof(INTERRUPT));
				strcpy(segment,get_segment(selecteur));
				if(resolve >= 0) 
				{
					bzero(name,strlen(name));
					resolv(file,stub_addr,name);
					printf("%-7i 0x%-14.8x %-12s%-8i%-16s %s\n",x,stub_addr,segment,dpl,type,name);
				}
				else
				{ 
					printf("%-7i 0x%-14.8x %-12s %-7i%s\n",x,stub_addr,segment,dpl,type);
				}
			}
		}
	}
	free(descriptor);
}

void create_archive(char *file)
{
	FILE *file_idt;
	struct descriptor_idt *descriptor;
	int x;
	descriptor=(struct descriptor_idt *)malloc(sizeof(struct descriptor_idt));
	if(!(file_idt=fopen(file,"w")))
	{
		fprintf(stderr,"Error while opening file\n");
		exit(-1);
	}
	for(x=0;x<(get_size_idt()+1)/8;x++)
	{
		readkmem(descriptor,ptr_idt+8*x,sizeof(struct descriptor_idt));
		fwrite(descriptor,sizeof(struct descriptor_idt),1,file_idt);
	}
	free(descriptor);
	fclose(file_idt);
	fprintf(stderr,"Creating file archive idt done \n");
}

void read_archive(char *file)
{
	FILE *file_idt;
	int x;
	struct descriptor_idt *descriptor;
	unsigned long stub_addr;
	descriptor=(struct descriptor_idt *)malloc(sizeof(struct descriptor_idt));
	if(!(file_idt=fopen(file,"r")))
	{
		fprintf(stderr,"Error, check if the file exist\n");
		exit(-1);
	}
	for(x=0;x<(get_size_idt()+1)/8;x++)
	{
		fread(descriptor,sizeof(struct descriptor_idt),1,file_idt);
		stub_addr=(unsigned long)(descriptor->offset_high << 16) + descriptor->offset_low;
		printf("Interruption : %i  -- Stub addresse : 0x%.8x\n",x,stub_addr);
	}
	free(descriptor);
	fclose(file_idt);
}

void compare_idt(char *file,int restore_idt)
{
	FILE *file_idt;
	int x,change=0;
	int result;
	struct descriptor_idt *save_descriptor,*actual_descriptor;
	unsigned long save_stub_addr,actual_stub_addr;
	unsigned short *offset;
	save_descriptor=(struct descriptor_idt *)malloc(sizeof(struct descriptor_idt));
	actual_descriptor=(struct descriptor_idt *)malloc(sizeof(struct descriptor_idt));
	file_idt=fopen(file,"r");
	for(x=0;x<(get_size_idt()+1)/8;x++)
	{
		fread(save_descriptor,sizeof(struct descriptor_idt),1,file_idt);
		save_stub_addr=(unsigned long)(save_descriptor->offset_high << 16) + save_descriptor->offset_low;
		readkmem(actual_descriptor,ptr_idt+8*x,sizeof(struct descriptor_idt));
		actual_stub_addr=(unsigned long)(actual_descriptor->offset_high << 16) + actual_descriptor->offset_low;
		if(actual_stub_addr != save_stub_addr)
		{
			if(restore_idt < 1)
			{
				fprintf(stderr,VERT"Hey stub address of interrupt %i has changed!!!\n"NORMAL,x);
				fprintf(stderr,"Old Value : 0x%.8x\n",save_stub_addr);
				fprintf(stderr,"New Value : 0x%.8x\n",actual_stub_addr);
				change=1;
			}
			else
			{
				fprintf(stderr,VERT"Restore old stub address of interrupt %i\n"NORMAL,x);
				actual_descriptor->offset_high = (unsigned short) (save_stub_addr >> 16);
				actual_descriptor->offset_low  = (unsigned short) (save_stub_addr & 0x0000FFFF);
				writekmem(actual_descriptor,ptr_idt+8*x,sizeof(struct descriptor_idt));
				change=1;
			}
		}
	}
	if(!change)
		fprintf(stderr,VERT"All values are same\n"NORMAL);
}

void initialize_value(struct Mode *mode)
{
	mode->show_idt_addr=-1;
	mode->show_all_info=-1;
	mode->show_all_descriptor=-1;
	mode->create_file_archive=-1;
	mode->read_file_archive=-1;
	strncpy(mode->out_filename,DEFAULT_FILE,strlen(DEFAULT_FILE));
	mode->compare_idt=-1;
	mode->restore_idt=-1;
	strncpy(mode->in_filename,DEFAULT_FILE,strlen(DEFAULT_FILE));
	strncpy(mode->map_filename,DEFAULT_MAP,strlen(DEFAULT_MAP));
	mode->resolve=-1;
}

void usage()
{
	fprintf(stderr,"CheckIDT V 1.1 by kad\n");
	fprintf(stderr,"---------------------\n");
	fprintf(stderr,"Option : \n");
	fprintf(stderr,"       -a nb    show all info about one interrupt\n");
	fprintf(stderr,"       -A       showw all info about all interrupt\n");
	fprintf(stderr,"       -I       show IDT address \n");
	fprintf(stderr,"       -c       create file archive\n");
	fprintf(stderr,"       -r       read file archive\n");
	fprintf(stderr,"       -o file  output filename (for creating file archive)\n");
	fprintf(stderr,"       -C       compare save idt & new idt\n");
	fprintf(stderr,"       -R       restore IDT\n");
	fprintf(stderr,"       -i file  input filename to compare or read\n");
	fprintf(stderr,"       -s		resolve symbol thanks to /boot/System.map\n");
	fprintf(stderr,"       -S file	specify a map file\n\n"); 
	exit(1);
}

int main(int argc, char ** argv)
{
	int option;
	struct Mode *mode;
	if (argc < 2)
	{
		usage();
	}

	mode=(struct Mode *) malloc(sizeof(struct Mode));
	initialize_value(mode);

	while((option=getopt(argc,argv,"hIa:Aco:Ci:rRsS:"))!=-1)
	{
		switch(option)
		{
			case 'h': usage();
					  exit(1);
			case 'I': mode->show_idt_addr=1;
					  break;
			case 'a': mode->show_all_info=atoi(optarg);
					  break;
			case 'A': mode->show_all_descriptor=1;
					  break;
			case 'c': mode->create_file_archive=1;
					  break;
			case 'r': mode->read_file_archive=1;
					  break;
			case 'R': mode->restore_idt=1;
					  break;
			case 'o': bzero(mode->out_filename,sizeof(mode->out_filename));
					  if(strlen(optarg) > 20)
					  {
						  fprintf(stderr,"Filename too long\n");
						  exit(-1);
					  }
					  strncpy(mode->out_filename,optarg,strlen(optarg));
					  break;
			case 'C': mode->compare_idt=1;
					  break;
			case 'i': bzero(mode->in_filename,sizeof(mode->in_filename));
					  if(strlen(optarg) > 20)
					  {
						  fprintf(stderr,"Filename too long\n");
						  exit(-1);
					  }
					  strncpy(mode->in_filename,optarg,strlen(optarg));
					  break;
			case 's': mode->resolve=1;
					  break;
			case 'S': bzero(mode->map_filename,sizeof(mode->map_filename));
					  if(strlen(optarg) > 40)
					  {
						  fprintf(stderr,"Filename too long\n");
						  exit(-1);
					  }
					  if(optarg)strncpy(mode->map_filename,optarg,strlen(optarg));
					  break;
		}
	}
	printf("\n");
	ptr_idt=get_addr_idt();
	if(mode->show_idt_addr >= 0)
	{
		fprintf(stdout,"Addresse IDT : 0x%x\n",ptr_idt);
	}
	fd_kmem=open("/dev/kmem",O_RDWR);
	if(mode->show_all_info >= 0 || mode->show_all_descriptor >= 0)
	{
		show_all_info(mode->show_all_info,mode->show_all_descriptor,mode->map_filename,mode->resolve);
	}
	if(mode->create_file_archive >= 0)
	{
		create_archive(mode->out_filename);
	}
	if(mode->read_file_archive >= 0)
	{
		read_archive(mode->in_filename);
	}
	if(mode->compare_idt >= 0)
	{
		compare_idt(mode->in_filename,mode->restore_idt);
	}
	if(mode->restore_idt >= 0)
	{
		compare_idt(mode->in_filename,mode->restore_idt);
	}
	printf(JAUNE"\nThanks for choosing kad's products :-)\n"NORMAL);

	free(mode);
	return 0;
}

