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

#define TEMP_BUFFER_SIZE 1024

int main()

{

    char line_buffer[ TEMP_BUFFER_SIZE ];

    FILE *fp;

    int num;

    unsigned int local_address_ip;

    unsigned int rem_address_ip;

    unsigned int local_address_port;

    unsigned int rem_address_port;

    unsigned int line_id;

    unsigned int conn_state;



    /* Open the mtd file */

    if((fp=fopen( "/proc/net/tcp", "r" )) == NULL)

    {

        return 0;

    }



    /* Read first line of titles - ignored*/

    if (fgets( line_buffer, TEMP_BUFFER_SIZE-1, fp ) == NULL)

    {

        fclose( fp );

        return 0;

    }



    /* Read the file line by line*/

    while ( fgets( line_buffer, TEMP_BUFFER_SIZE-1, fp ) )

    {

        num = sscanf(line_buffer,"%d: %X:%X %X:%X %X",&line_id,&local_address_ip,&local_address_port,&rem_address_ip,&rem_address_port,&conn_state);



        printf("num (%d) line_buffer = %s\n",num,line_buffer);

        printf("line_id (0x%X),  local_address_ip (0x%X) ,  local_address_port (0x%X),   rem_address_ip (0x%X),  rem_address_port (0x%X),   conn_state (0x%X)\n\n",line_id,  local_address_ip,  local_address_port,   rem_address_ip,  rem_address_port,   conn_state);



        if (num < 6)

        {

            fclose( fp );

            return -1;

        }

        if (local_address_port == "0xAB19")

        {

            fclose( fp );

            return 1;

        }

    }



    /* close '/proc' file */

    fclose( fp );



    return 0;

}
