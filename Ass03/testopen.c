/*

Simple C program to open a test file and generating a symbolic link in the /proc
file system that can be hidden by the rootkit

*/



#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]){

FILE* fp = fopen("/root/git/Ass03/rootkit_testfile","r+");
printf("file opend\n");

//sleep(30);
getchar();

fclose(fp);

}
