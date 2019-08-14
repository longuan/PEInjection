#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define oops(msg,code) {perror(msg);exit(code);}

long get_address(char *first_line)
{
    int length = strchr(first_line, '-') - first_line;
    char address[16]={0};
    strncpy(address, first_line, length);
    unsigned long a;
    sscanf(address, "%lx", &a);
    return a;
}

int find_str(char *buffer, int buf_size, char *str, int str_size)
{
    if(buffer == NULL || str == NULL || str_size > buf_size)
        return -1;

    for(int i=0; i<buf_size-str_size; i++)
    {
        int j = 0;
        for(; j<str_size; j++)
        {
            if(str[j] != buffer[i+j])
                break;
        }
        if(j==str_size)
            return i;
    }
    return -1;
}


int main(int argc, char *argv[])
{
    if(argc != 2)
        oops("Wrong usage\n", 1);
    int target_pid = atoi(argv[1]);
    char map_filename[16];
    char mem_filename[16];
    unsigned n = snprintf(map_filename,sizeof(map_filename),"/proc/%d/maps",target_pid);
    if(n >= sizeof(map_filename) || (access(map_filename, F_OK)==-1))
        oops("wrong pid\n", 2);
    n = snprintf(mem_filename, sizeof(mem_filename), "/proc/%d/mem", target_pid);
    if(n >= sizeof(mem_filename) || (access(mem_filename, F_OK)==-1))
        oops("wrong pid\n", 2);

    FILE *mapfile_fd = fopen(map_filename, "r");
    char buffer[BUFSIZ];
    fgets(buffer, BUFSIZ, mapfile_fd);
    unsigned long address = get_address(buffer);

    int mem_fd = open(mem_filename, O_RDWR|O_SYNC);
    if(mem_fd == -1)
        oops("failed to open mem file\n", 3);
    
    // char *mmap_base = (char *)mmap(NULL, MAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, mem_fd, address);
    // if(mmap_base == (void *)-1)
    //     oops("mmap failed \n", 4);
    // munmap(mmap_base, MAP_SIZE);
    
    lseek(mem_fd, address, SEEK_SET);
    n = read(mem_fd, buffer, sizeof(buffer));
      
    int hello_pos = find_str(buffer,BUFSIZ, "Hello World", 11);
    if(hello_pos == -1)
        oops("Hello World not found\n", 4);
    printf("find %s at %lx\n",buffer+hello_pos, address+hello_pos);

    lseek(mem_fd, address+hello_pos, SEEK_SET);
    write(mem_fd,"DEAD BEEF!\0", 11); 
    printf("Hello World -> DEAD BEEF\n");
    close(mem_fd);
    fclose(mapfile_fd);
    return 0;
}
