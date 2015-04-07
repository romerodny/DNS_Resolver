struct HEADER
{
  unsigned short id; 
 
  //3rd byte
  unsigned char rd :1; 
  unsigned char tc :1; 
  unsigned char aa :1; 
  unsigned char opcode :4;
  unsigned char qr :1; 
 
  //4th byte
  unsigned char rcode :4;
  unsigned char cd :1; 
  unsigned char ad :1; 
  unsigned char z :1; 
  unsigned char ra :1; 
 
  unsigned short q_count;
  unsigned short ans_count;
  unsigned short auth_count;
  unsigned short add_count; 
};
 

struct QUESTION
{
  unsigned short qtype;
  unsigned short qclass;
};
 
//make sure the alighment matches the DNS message format specification
//i.e., there should not be any padding.
//(by default, C struct aligment is based on the "widest" field
#pragma pack(push, 1)
struct R_DATA
{
  unsigned short type;
  unsigned short class;
  unsigned int ttl;
  unsigned short data_len;
};
#pragma pack(pop)
 
struct RES_RECORD
{
  unsigned char *name;
  struct R_DATA *resource;
  unsigned char *rdata;
};
 
typedef struct
{
  unsigned char *name;
  struct QUESTION *ques;
} QUERY;
