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

#define  TEMP_BUFFER_SIZE 0x10000



typedef struct netInfo{
	unsigned int local_address_ip;
	unsigned int rem_address_ip;
	unsigned int local_address_port;
	unsigned int rem_address_port;
	unsigned int line_id;
	unsigned int conn_state;
	struct netInfo *next;
} NetInfo;

typedef struct netInfoList{
	NetInfo *head;
	NetInfo *tail;
	int num;	
} NetInfoList;



void convertStrToUnChar(const char* str, unsigned char* UnChar)  
{  
    int i = strlen(str), j = 0, counter = 0;  
    char c[2];  
    unsigned int bytes[2];  
 
    for (j = 0; j < i; j += 2)   
    {  
        if(0 == j % 2)  
        {  
            c[0] = str[j];  
            c[1] = str[j + 1];  
            sscanf(c, "%02x" , &bytes[0]);  
            UnChar[counter] = bytes[0];  
            counter++;  
        }  
    }  
    return;  
}  


void print_ipv4_address(const char *hex){
        char addr[20];
        struct in_addr sa;
        sa.s_addr = strtoull(hex, NULL, 16);
        inet_ntop(AF_INET, (void *)&sa, addr, INET_ADDRSTRLEN);
        fprintf(stderr, "%s\n", addr);
}

void print_ipv6_address(const char *hex){
        char addr[20];
        struct in6_addr sa;
        //convertStrToUnChar(hex, sa.s6_addr);
        inet_pton(AF_INET6, "::ffff:192.168.0.191", &sa);
	fprintf(stderr, "%X\n", sa.s6_addr);
	inet_ntop(AF_INET6, (void *)&sa, addr, INET6_ADDRSTRLEN);
        fprintf(stderr, "%s\n", addr);
}



void print_stat(NetInfoList *tcp_list, NetInfoList *udp_list){
	fprintf(stderr, "\nList of TCP connections:\n");
	fprintf(stderr, "%10s %20s %20s %15s\n", "Protocol", "Local Address", "Foreign Address", "PID");
	if(tcp_list->num != 0){
		NetInfo *ptr = tcp_list->head;
		for(int i=0; i<tcp_list->num; i++){
			fprintf(stderr, "%10s %20X:%X %20s %15s\n", "tcp", ptr->local_address_ip, ptr->local_address_port , "0.0.0.0:78", "9257");
			ptr = ptr->next;
		}
	}
	
	fprintf(stderr, "\nList of UDP connections:\n");
	fprintf(stderr, "%10s %20s %20s %15s\n", "Protocol", "Local Address", "Foreign Address", "PID");
        if(udp_list->num != 0){
                for(int i=0; i<udp_list->num; i++){
                        fprintf(stderr, "%10s %20s %20s %15s\n", "udp", "127.0.0.1:8888" , "0.0.0.0:78", "9257");
                }
        }

}

void print_tcp(){
	const char *ptr1 = "0100007F";
	const char *ptr2 = "0000000000000000FFFF0000BF00A8C0";
	fprintf(stderr, "List of TCP connections:\n");
	print_ipv4_address(ptr1);
	print_ipv6_address(ptr2);
}

	

void get_pid_status(int pid){
	FILE *fp;
	char fdpath[16];
	char filec;
	snprintf(fdpath, sizeof(fdpath), "/proc/%d/cmd", pid);
	fp = fopen(fdpath, "r");
	while((filec = fgetc(fp)) != EOF){
                printf("%c", filec);
        }
}

void list_dir(){
	DIR *mydir;
    	struct dirent *myfile;

    	mydir = opendir("/proc/");
    	while((myfile = readdir(mydir)) != NULL){
        	printf(" %s\n", myfile->d_name);
    	}
    	closedir(mydir);
}


NetInfoList *get_net_info(char *fdpath){
	NetInfoList *net_info_list = malloc(sizeof(NetInfoList));
	net_info_list->num = 0;
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
		
		NetInfo *net_info = malloc(sizeof(NetInfo));
                num = sscanf(line_buffer,"%d: %X:%X %X:%X %X", &net_info->line_id, &net_info->local_address_ip, &net_info->local_address_port, &net_info->rem_address_ip, &net_info->rem_address_port, &net_info->conn_state);
		line_num++;                
		if(num < 6){
			free(net_info);
                        fclose(fp);
                        return NULL;
                }
		if(net_info->local_address_port == "0xAB19"){
                        free(net_info);
			fclose( fp );
                        return NULL;
                }
		if(line_num == 1){
			net_info_list->head = net_info;
			net_info_list->tail = net_info;
			net_info->next = NULL;
		}else{
			net_info_list->tail->next = net_info;
			net_info_list->tail = net_info;
			net_info->next = NULL;
		}
        }
	fprintf(stderr, "%s line_num:%d\n", fdpath, line_num);
	net_info_list->num = line_num;
	return net_info_list;

}

int main(int argc, char *argv[]) {
	int i;
	char tcp_path[14] = "/proc/net/tcp";
	char udp_path[14] = "/proc/net/udp";
	char name[16];
	char fdpath[16];	
	FILE *fp;
	char filec;
	int line_counter = 0;
	int pid = getpid();	
	NetInfoList *tcp_info_list = NULL;
	NetInfoList *udp_info_list = NULL;	

	/*
	for(i = 0; i < argc; i++)
		printf("'%s' ", argv[i]);
	printf("\n");
	*/
	snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
	readlink(fdpath, name, sizeof(name));
	fprintf(stderr, "%s\n", fdpath);
	fprintf(stderr, "%s\n", name);
	

	print_tcp();
	//get_pid_status(5916);
	
	tcp_info_list = get_net_info(tcp_path);
	udp_info_list = get_net_info(udp_path);
	fprintf(stderr, "0x%X\n", tcp_info_list->head->local_address_ip);
	fprintf(stderr, "0x%X\n", udp_info_list->head->local_address_ip);
	//list_dir();
	print_stat(tcp_info_list, udp_info_list);

	return 0;
}

