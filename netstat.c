#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <inttypes.h>
#include <getopt.h>

#define  TEMP_BUFFER_SIZE 0x10000

typedef struct filterStr{
	char str[20];
	struct filterStr *next;
} FilterStr;


typedef struct filterList{
	FilterStr *head;
	FilterStr *tail;
	int num;
} FilterList;

typedef struct ipv4info{
	char local_address_ip[32];
	char rem_address_ip[32];
	char local_address_port[8];
	char rem_address_port[8];
	int inode;
	char pid[200];
	char print_line[2000];
	struct ipv4info *next;
} Ipv4Info;

typedef struct ipv4InfoList{
	Ipv4Info *head;
	Ipv4Info *tail;
	int num;	
} Ipv4InfoList;


typedef struct ipv6info{
        char local_address_ip[128];
        char rem_address_ip[128];
        char local_address_port[8];
        char rem_address_port[8];
        int inode;
	char pid[200];
	char print_line[2000];
        struct ipv6info *next;
} Ipv6Info;

typedef struct ipv6InfoList{
        Ipv6Info *head;
        Ipv6Info *tail;
        int num;
} Ipv6InfoList;
 


void trans_ipv4_address(char *hex){
        struct in_addr sa;
        sa.s_addr = strtoull(hex, NULL, 16);
	inet_ntop(AF_INET, (void *)&sa, hex, INET_ADDRSTRLEN);
        //fprintf(stderr, "%s\n", hex);
}


void trans_ipv6_address(char *hex){
        struct in6_addr sa;
	//char buf[] = "BACD0120000000000000000052965732"; //"0000000000000000FFFF0000BF00A8C0";
	sscanf(hex, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
		&sa.s6_addr[3], &sa.s6_addr[2], &sa.s6_addr[1], &sa.s6_addr[0],
                &sa.s6_addr[7], &sa.s6_addr[6], &sa.s6_addr[5], &sa.s6_addr[4],
                &sa.s6_addr[11], &sa.s6_addr[10], &sa.s6_addr[9], &sa.s6_addr[8],
                &sa.s6_addr[15], &sa.s6_addr[14], &sa.s6_addr[13], &sa.s6_addr[12]);	
	
	inet_ntop(AF_INET6, (void *)&sa, hex, INET6_ADDRSTRLEN);
        //fprintf(stderr, "%s\n", hex);
}

int filter_print(char *source, FilterList *filter_list, char *type, int first){
	int printable = -1;
	if(filter_list->num != 0){
		FilterStr *ptr = filter_list->head;
		for(int i=0; i<filter_list->num; i++){
			char *loc = strstr(source, ptr->str);
			if(loc != NULL) {
        			printable ++;
    			}
		}
	}else{printable = 0;}

	if((printable == 0) || ((printable > 0) && (printable == filter_list->num) )){
		if(first == 0){
			if (strcmp(type, "tcp") == 0)
                                fprintf(stderr, "\nList of TCP connections:\n");
                        if (strcmp(type, "udp") == 0)
                                fprintf(stderr, "\nList of UDP connections:\n");
                        fprintf(stderr, "%-15s %-25s %-25s %-35s\n", "Protocol", "Local Address", "Foreign Address", "PID/Program name and arguments");
                        first = 1;
                }
               fprintf(stderr, "%s\n", source);
	}
	return first;
}

void print_tcp_stat(Ipv4InfoList *tcp_list, Ipv6InfoList *tcp6_list, FilterList *filter_list){
	//fprintf(stderr, "\nList of TCP connections:\n");
	//fprintf(stderr, "%-15s %-25s %-25s %-35s\n", "Protocol", "Local Address", "Foreign Address", "PID");
	int first = 0;
	if(tcp_list->num != 0){
		Ipv4Info *ptr = tcp_list->head;
		for(int i=0; i<tcp_list->num; i++){
			char local[30];
                	char remote[30];
                	sprintf(local, "%s:%s", ptr->local_address_ip, ptr->local_address_port);
                	sprintf(remote, "%s:%s", ptr->rem_address_ip, ptr->rem_address_port);
			sprintf(ptr->print_line, "%-15s %-25s %-25s %-40s", "tcp", local, remote, ptr->pid);
                        first = filter_print(ptr->print_line, filter_list, "tcp", first);
			//fprintf(stderr, "%s\n", ptr->print_line);
			ptr = ptr->next;
		}
	}
	if(tcp6_list->num != 0){
                Ipv6Info *ptr = tcp6_list->head;
                for(int i=0; i<tcp6_list->num; i++){
                        char local[30];
                        char remote[30];
                        sprintf(local, "%s:%s", ptr->local_address_ip, ptr->local_address_port);
                        sprintf(remote, "%s:%s", ptr->rem_address_ip, ptr->rem_address_port);
                        sprintf(ptr->print_line, "%-15s %-25s %-25s %-40s", "tcp6", local, remote, ptr->pid);
                        first = filter_print(ptr->print_line, filter_list, "tcp", first);
			//fprintf(stderr, "%s\n", ptr->print_line);
                        ptr = ptr->next;
                }
        }
}
void print_udp_stat(Ipv4InfoList *udp_list, Ipv6InfoList *udp6_list, FilterList *filter_list){
	//fprintf(stderr, "\nList of UDP connections:\n");
	//fprintf(stderr, "%-15s %-25s %-25s %-35s\n", "Protocol", "Local Address", "Foreign Address", "PID");
        int first = 0;
	if(udp_list->num != 0){
                Ipv4Info *ptr = udp_list->head;
                for(int i=0; i<udp_list->num; i++){
                        char local[30];
                        char remote[30];
                        sprintf(local, "%s:%s", ptr->local_address_ip, ptr->local_address_port);
                        sprintf(remote, "%s:%s", ptr->rem_address_ip, ptr->rem_address_port);
                        sprintf(ptr->print_line, "%-15s %-25s %-25s %-40s", "udp", local, remote, ptr->pid);
			first = filter_print(ptr->print_line, filter_list, "udp", first);
                        //fprintf(stderr, "%s\n", ptr->print_line);
                        ptr = ptr->next;
                }
        }
        if(udp6_list->num != 0){
                Ipv6Info *ptr = udp6_list->head;
                for(int i=0; i<udp6_list->num; i++){
                        char local[30];
                        char remote[30];
                        sprintf(local, "%s:%s", ptr->local_address_ip, ptr->local_address_port);
                        sprintf(remote, "%s:%s", ptr->rem_address_ip, ptr->rem_address_port);
                        sprintf(ptr->print_line, "%-15s %-25s %-25s %-40s", "udp6", local, remote, ptr->pid);
			first = filter_print(ptr->print_line, filter_list, "udp", first);
			//fprintf(stderr, "%s\n", ptr->print_line);
                        ptr = ptr->next;
                }
        }

}

void print_tcp(){
	char ptr1[32] = "0100007F";
	char ptr2[128] = "0000000000000000FFFF0000BF00A8C0";
	char addr1[32];
	char addr2[128];
	trans_ipv4_address(ptr1);
	trans_ipv6_address(ptr2);
}

	
char *list_dir(int inode, char *pid_buffer){
	
	char dirpath[] = "/proc/";
	char path[50];
	DIR *mydir;
    	struct dirent *myfile;
	char pid[6];
	FILE *fp;
        char cmd[50];
        char fdpath[50];
	char pstatus[50];
	char pname[50];
        char line_buffer[ TEMP_BUFFER_SIZE ];
	DIR *fddir;
	struct dirent *fdfile;	
	char linkpath[50];
	char name[100];
	int ino = 0;
	ssize_t nbytes;
	char cmd_buffer[100];
	int found_pid = 0;
	
    	mydir = opendir(dirpath);
    	while((myfile = readdir(mydir)) != NULL){
		sscanf(myfile->d_name, "%[0-9]*", pid);
		if(atoi(pid) > 0){
			snprintf(fdpath, sizeof(fdpath), "/proc/%s/fd", pid);
			fddir = opendir(fdpath);
			if(fddir){
				while((fdfile = readdir(fddir)) != NULL){
					ino = 0;
					snprintf(linkpath, sizeof(linkpath), "%s/%s", fdpath, fdfile->d_name);
					nbytes = readlink(linkpath, name, sizeof(name));
					sscanf(name, "socket:[%d]", &ino);
					if(ino == 0)
						sscanf(name, "[0000]:%d", &ino);
					if (inode == ino){
						snprintf(pstatus, sizeof(pstatus), "/proc/%s/status", pid);
			                        fp = fopen(pstatus, "r");
                        			if(fp){
                                			//fprintf(stderr, "pid: %s\n", pid);
                                			fgets( line_buffer, TEMP_BUFFER_SIZE-1, fp );
                                			sscanf(line_buffer, "Name:\t%s", &pname);
                                			//fprintf(stderr, "pname: %s\n", pname);
                                			fclose(fp);
                        			}

                        			snprintf(cmd, sizeof(cmd), "/proc/%s/cmdline", pid);
                        			fp = fopen(cmd, "r");
                        			if(fp){
							char c;
							int count=0;
							int zerocount=0;
                                			while((c = getc(fp))!=EOF){
								if(c == '\0')
									zerocount = 1;
								if(zerocount == 1){
									if(c == '\0')
                                        					cmd_buffer[count++] = ' '; 
									else
										cmd_buffer[count++] = c;
								}
                                			}
                                			fclose(fp);
                        			}
						
						//fprintf(stderr, "cmd_buf: %s\n", cmd_buffer);
						/*
						fprintf(stderr, "pname: %s\n", pname);
						fprintf(stderr, "pid: %s\n", pid);
						fprintf(stderr, "%s\n", name);
						fprintf(stderr, "read: %s\n", linkpath);
						fprintf(stderr, "ino: %d\n", ino);
						*/
						sprintf(pid_buffer, "%s/%s %s", pid, pname, cmd_buffer);
						found_pid = 1;
					}
				}
			}
			closedir(fddir);
			
		}
    	}
    	closedir(mydir);
	if (found_pid == 0){
		sprintf(pid_buffer, "-", pid, pname);
	}
}


Ipv4InfoList *get_ipv4_info(char *fdpath){
	Ipv4InfoList *ipv4_info_list = malloc(sizeof(Ipv4InfoList));
	ipv4_info_list->num = 0;
	FILE *fp;
	char line_buffer[ TEMP_BUFFER_SIZE ];
	int num;
	int line_num = 0;	

	if((fp=fopen(fdpath, "r" )) == NULL){
                return NULL;
        }
        if(fgets( line_buffer, TEMP_BUFFER_SIZE-1, fp ) == NULL){
                fclose(fp);
                return NULL;
        }
        while( fgets( line_buffer, TEMP_BUFFER_SIZE-1, fp ) ){
		unsigned int local_address_port;
		unsigned int rem_address_port;
		Ipv4Info *ipv4_info = malloc(sizeof(Ipv4Info));
		char delim[] = " ";

		char *ptr = strtok(line_buffer, delim);
		
		int ptr_cnt = 0;
		while(ptr != NULL)
		{
			//printf("'%s'\n", ptr);
			if(ptr_cnt==1)
				sscanf(ptr, "%[^:]:%X", &ipv4_info->local_address_ip, &local_address_port);
			if(ptr_cnt==2)
				sscanf(ptr, "%[^:]:%X", &ipv4_info->rem_address_ip, &rem_address_port);
			if(ptr_cnt==9){
				sscanf(ptr, "%d", &ipv4_info->inode);
				list_dir(ipv4_info->inode, ipv4_info->pid);
				if (ipv4_info->pid == NULL)
					strcpy(ipv4_info->pid ,"-");
			}
			ptr = strtok(NULL, delim);
			ptr_cnt++;
		}
		
		line_num++;                
		trans_ipv4_address(ipv4_info->local_address_ip);
		trans_ipv4_address(ipv4_info->rem_address_ip);
		
		if ((int) local_address_port == 0)
			sprintf(ipv4_info->local_address_port, "*");
		else
			sprintf(ipv4_info->local_address_port, "%d", (int) local_address_port);
		
		if ((int) rem_address_port == 0)
                        sprintf(ipv4_info->rem_address_port, "*");
                else
			sprintf(ipv4_info->rem_address_port, "%d", (int) rem_address_port);

		if(line_num == 1){
			ipv4_info_list->head = ipv4_info;
			ipv4_info_list->tail = ipv4_info;
			ipv4_info->next = NULL;
		}else{
			ipv4_info_list->tail->next = ipv4_info;
			ipv4_info_list->tail = ipv4_info;
			ipv4_info->next = NULL;
		}
        }
	ipv4_info_list->num = line_num;
	return ipv4_info_list;

}

Ipv6InfoList *get_ipv6_info(char *fdpath){
        Ipv6InfoList *ipv6_info_list = malloc(sizeof(Ipv6InfoList));
        ipv6_info_list->num = 0;
        FILE *fp;
        char line_buffer[ TEMP_BUFFER_SIZE ];
        int num;
        int line_num = 0;

        if((fp=fopen(fdpath, "r" )) == NULL){
                return NULL;
        }
        if(fgets( line_buffer, TEMP_BUFFER_SIZE-1, fp ) == NULL){
                fclose(fp);
                return NULL;
        }
        while( fgets( line_buffer, TEMP_BUFFER_SIZE-1, fp ) ){
                unsigned int local_address_port;
                unsigned int rem_address_port;
                Ipv6Info *ipv6_info = malloc(sizeof(Ipv6Info));
                char delim[] = " ";

                char *ptr = strtok(line_buffer, delim);

                int ptr_cnt = 0;
                while(ptr != NULL)
                {
                        //printf("'%s'\n", ptr);
                        if(ptr_cnt==1)
                                sscanf(ptr, "%[^:]:%X", &ipv6_info->local_address_ip, &local_address_port);
                        if(ptr_cnt==2)
                                sscanf(ptr, "%[^:]:%X", &ipv6_info->rem_address_ip, &rem_address_port);
                        if(ptr_cnt==9){
                                sscanf(ptr, "%d", &ipv6_info->inode);
                                list_dir(ipv6_info->inode, ipv6_info->pid);
				if (ipv6_info->pid == NULL)
                                        strcpy(ipv6_info->pid ,"-");
                        }

                        ptr = strtok(NULL, delim);
                        ptr_cnt++;
                }

		line_num++;
                trans_ipv6_address(ipv6_info->local_address_ip);
                trans_ipv6_address(ipv6_info->rem_address_ip);
                
		if ((int) local_address_port == 0)
                        sprintf(ipv6_info->local_address_port, "*");
                else
                        sprintf(ipv6_info->local_address_port, "%d", (int) local_address_port);

                if ((int) rem_address_port == 0)
                        sprintf(ipv6_info->rem_address_port, "*");
                else
                        sprintf(ipv6_info->rem_address_port, "%d", (int) rem_address_port);
                
                if(line_num == 1){
                        ipv6_info_list->head = ipv6_info;
                        ipv6_info_list->tail = ipv6_info;
                        ipv6_info->next = NULL;
                }else{
                        ipv6_info_list->tail->next = ipv6_info;
                        ipv6_info_list->tail = ipv6_info;
                        ipv6_info->next = NULL;
                }
        }
        ipv6_info_list->num = line_num;
        return ipv6_info_list;

}


int main(int argc, char *argv[]) {
	int i;
	char tcp_path[] = "/proc/net/tcp";
	char udp_path[] = "/proc/net/udp";
	char tcp6_path[] = "/proc/net/tcp6";
        char udp6_path[] = "/proc/net/udp6";
		
	Ipv4InfoList *tcp_info_list = NULL;
	Ipv4InfoList *udp_info_list = NULL;
	Ipv6InfoList *tcp6_info_list = NULL;
        Ipv6InfoList *udp6_info_list = NULL;
		

	int print_tcp = 0;
	int print_udp = 0;
	int print_mode = 3;
	int print_search = NULL;

	FilterList *filter_list = malloc(sizeof(filter_list));
	int opt;
   	int digit_optind = 0;
   	int option_index = 0;
   	char *optstring = "tu";
   	static struct option long_options[] = {
      	 	{"tcp", no_argument, NULL, 't'},
       		{"udp", no_argument, NULL, 'u'},
       		{0, 0, 0, 0}
   	};
 
   	while ( (opt = getopt_long(argc, argv, optstring, long_options, &option_index)) != -1)
   	{
        	//printf("opt = %c\n", opt);
        	//printf("optarg = %s\n", optarg);
        	//printf("optind = %d\n", optind);
        	//printf("argv[optind - 1] = %s\n",  argv[optind - 1]);
        	//printf("option_index = %d\n", option_index);
		
		switch(opt){
			case 't':
				print_tcp = 1;
				break;
			case 'u':
				print_udp = 1;
				break;
		}
			
	}

	filter_list->num=0;
	if (optind < argc){
      		while (optind < argc){
			FilterStr *filter_str = malloc(sizeof(FilterStr));
        		strcpy(filter_str, argv[optind++]);
			filter_str->next = NULL;
			if (filter_list->num==0){
				filter_list->head = filter_str;
				filter_list->tail = filter_str;
			}else{
				filter_list->tail->next = filter_str;
				filter_list->tail = filter_str;
			}
			filter_list->num++;
      		}
    	}
	

	print_mode = print_tcp*1 + print_udp*2; 
	if (print_mode == 0)
		print_mode = 3;

	if ((print_mode & 1) == 1){
		tcp_info_list = get_ipv4_info(tcp_path);
        	tcp6_info_list = get_ipv6_info(tcp6_path);
		print_tcp_stat(tcp_info_list, tcp6_info_list, filter_list);
	}
	if ((print_mode & 2) == 2){
		udp_info_list = get_ipv4_info(udp_path);
                udp6_info_list = get_ipv6_info(udp6_path);
		print_udp_stat(udp_info_list, udp6_info_list, filter_list);
	}

	return 0;
}

