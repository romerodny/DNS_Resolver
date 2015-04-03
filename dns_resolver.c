#include "dns_resolver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#define MAXSIZE 512

ssize_t writen(int sd, char *vptr, ssize_t size);
ssize_t readline(int fd, void *vptr, size_t maxlen);
void DNSQuery(char *root, char *name);
void DNSFormat(unsigned char *dns,char *name);
char* getHost(unsigned char* reader,unsigned char* buffer,int* count);

void syserr(char* msg)
{
    perror(msg);
    exit(-1);
}

/*
 *  Written by David Romero. This program will call the DNSQuery function which behaves much like gethostbyname. Will convert the domain name (say cnn.com) to its IP.
 *
 * @param argv Will take two terminal inputs, root server and domain name
 */
int main(int argc, char* argv[])
{
    //Checking to see if there are two inputs, else terminate the program
    if(argc != 3)
    {
        fprintf(stderr, "Usage: %s <root server> <domain name>\n", argv[0]);
        return 1;
    }
    
    DNSQuery(argv[1], argv[2]);
    
    return 0;
}

/*
 * gethostbyname implementation written by David Romero. This function will obtain the IPv4 IP of the domain. It does this by going between intermediate servers.
 *
 * @param root  dns server IP
 * @param name domain name
 */
void DNSQuery(char *root, char *name)
{
    int sockfd, portno, i, qtype, done, j;
    struct sockaddr_in serv_addr;
    unsigned char buffer[MAXSIZE], *qname, *read;
    struct RES_RECORD answers[20],auth[20],additional[20];
    struct HEADER *header = NULL;
    struct QUESTION *question = NULL;
    
    qtype = 1;
    portno = 53;
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    if(sockfd < 0)
    {
        syserr("can't open socket");
    }
    
    bzero((char *) &serv_addr, sizeof(serv_addr));
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(root);
    serv_addr.sin_port = htons(portno);
    
    header = (struct HEADER *)&buffer;
    
    //The function will continuously loop, going from server to server
    while(1)
    {
        //Initializing the DNS Header
        header->id = (unsigned short) htons(32);
        header->qr = 0;
        header->opcode = 0;
        header->aa = 0;
        header->tc = 0;
        header->rd = 0;
        header->ra = 0;
        header->z = 0;
        header->ad = 0;
        header->cd = 0;
        header->rcode = 0;
        header->q_count = htons(1);
        header->ans_count = 0;
        header->auth_count = 0;
        header->add_count = 0;
    
        //Placing domain name represented as a sequence of labels
        qname =(unsigned char*)&buffer[sizeof(struct HEADER)];
    
        //getting the header and converting it into a format readable by the DNS server.
        DNSFormat(qname, name);
   
        //Getting the question section from the buffer
        question =(struct QUESTION*)&buffer[sizeof(struct HEADER) + (strlen((const char*)qname) + 1)];
    
        //Setting the qtype and qclass
        question->qtype = htons(1);
        question->qclass = htons(1);
        
        //Sending the information through the stream
        if( sendto(sockfd,(char*)buffer,sizeof(struct HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        {
            syserr("Error with sending, exiting");
        }

        i = sizeof(serv_addr);
        
        //Recieving message from stream
        if(recvfrom (sockfd, buffer , MAXSIZE, 0 , (struct sockaddr*)&serv_addr , (socklen_t *)&i) < 0)
        {
            syserr("Error with recieving, exiting");
        }
    
        header = (struct HEADER*) buffer;
    
        
        read = &buffer[sizeof(struct HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
        
        printf("\n----------------------------------------\n");
        printf("DNS server to query: %s \n", inet_ntoa(serv_addr.sin_addr) );
        printf("Reply received. Content overview: ");
        printf("\t\n %d Answers.",ntohs(header->ans_count));
        printf("\t\n %d Authoritative Servers.",ntohs(header->auth_count));
        printf("\t\n %d Additional records.\n\n",ntohs(header->add_count));
    
        done = 0;
        
        //Reading the answers from the DNS server
        for(i=0;i<ntohs(header->ans_count);i++)
        {
            answers[i].name=getHost(read,buffer,&done);
            read = read + done;
            
            answers[i].resource = (struct R_DATA*)(read);
            read = read + sizeof(struct R_DATA);
            
            if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
            {
                answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
                
                for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
                {
                    answers[i].rdata[j]=read[j];
                }
                
                answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
                
                read = read + ntohs(answers[i].resource->data_len);
            }
            else
            {
                answers[i].rdata = getHost(read,buffer,&done);
                read = read + done;
            }
        }
        
        //Reading the authorities
        for(i=0;i<ntohs(header->auth_count);i++)
        {
            auth[i].name=getHost(read,buffer,&done);
            read+=done;
            
            auth[i].resource=(struct R_DATA*)(read);
            read+=sizeof(struct R_DATA);
            
            auth[i].rdata=getHost(read,buffer,&done);
            read+=done;
        }
        
        //Reading the Additional information
        for(i=0;i<ntohs(header->add_count);i++)
        {
            additional[i].name=getHost(read,buffer,&done);
            read+=done;
            
            additional[i].resource=(struct R_DATA*)(read);
            read+=sizeof(struct R_DATA);
            
            if(ntohs(additional[i].resource->type)==1)
            {
                additional[i].rdata = (unsigned char*)malloc(ntohs(additional[i].resource->data_len));
                for(j=0;j<ntohs(additional[i].resource->data_len);j++)
                    additional[i].rdata[j]=read[j];
                
                additional[i].rdata[ntohs(additional[i].resource->data_len)]='\0';
                read+=ntohs(additional[i].resource->data_len);
            }
            else
            {
                additional[i].rdata=getHost(read,buffer,&done);
                read+=done;
            }
        }
        
        //Printing the previously read information
        printf("Answer Section:\n");
        for(i=0 ; i < ntohs(header->ans_count) ; i++)
        {
            printf("\tName: %s ",answers[i].name);
            
            long *p;
            p=(long*)answers[i].rdata;
            serv_addr.sin_addr.s_addr=(*p); //working without ntohl
            printf("\tIP: %s",inet_ntoa(serv_addr.sin_addr));
            
            
            printf("\n");
        }
        
        printf("\nAuthoritive Section:\n");
        for( i=0 ; i < ntohs(header->auth_count) ; i++)
        {
            
            printf("\tName: %s ",auth[i].name);
            if(ntohs(auth[i].resource->type)==2)
            {
                printf("\tName Server: %s",auth[i].rdata);
            }
            printf("\n");
        }
        
        printf("\nAdditional Section:\n");
        for(i=0; i < ntohs(header->add_count) ; i++)
        {
            printf("\tName: %s ",additional[i].name);
            if(ntohs(additional[i].resource->type)==1)
            {
                long *p;
                p=(long*)additional[i].rdata;
                serv_addr.sin_addr.s_addr=(*p);
                printf("\tIP: %s",inet_ntoa(serv_addr.sin_addr));
            }
            printf("\n");
        }
        
        //If we have an answer, exit
        if(header->ans_count > 0)
        {
            break;
        }
    }
}

/*
 * Source: http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/ this function converts the domain name from the formatted version to a readable one.
 *
 */

char* getHost(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
    
    *count = 1;
    name = (unsigned char*)malloc(256);
    
    name[0]='\0';
    
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        else
        {
            name[p++]=*reader;
        }
        
        reader = reader+1;
        
        if(jumped==0)
        {
            *count = *count + 1;
        }
    }
    
    name[p]='\0';
    if(jumped==1)
    {
        *count = *count + 1;
    }
    
    for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0';
    return name;
}

/*
 * Converts the url users input to a format recognizable by the DNS server.
 *
 *@param header the header section of the packet
 *@param name hostname
 */
void DNSFormat(unsigned char* header,char* name)
{
    int count = 0 , i;
    strcat((char*)name,".");
    
    for(i = 0 ; i < strlen((char*)name) ; i++)
    {
        if(name[i]=='.')
        {
            *header++ = i-count;
            for(;count<i;count++)
            {
                *header++=name[count];
            }
            count++;
        }
    }
    *header++='\0';
}