#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <endian.h>
#include <ctype.h>

#define MAXDATASIZE 10000000

/***** Helper functions used in main *****/
uint16_t calculateChecksum(uint8_t* buf, size_t len);
void *get_in_addr(struct sockaddr *sa);
ssize_t rio_readn(int fd, void *usrbuf, size_t n);
ssize_t rio_writen(int fd, void *usrbuf, size_t n);
uint64_t alphaCounter(uint8_t *buf, uint64_t remainder, uint64_t data_len);
void shiftKeyword(char *keyword, char *default_key, int shift);
/*****************************************/


// Function to calculate TCP checksum
// Reference: https://www.winpcap.org/pipermail/winpcap-users/2007-July/001984.html
uint16_t calculateChecksum(uint8_t* buf, size_t len)
{
  if (len % 2 == 1)
    len++;

  uint64_t cksum = 0;

  for (int i = 0; i < (len/2); i++) {
    cksum += (((uint64_t)buf[2*i+1]) << 8) & 0xFF00;
    cksum += (uint64_t)buf[(2*i)] & 0xFF;
  }

  cksum = (cksum & 0xFFFF) + ((cksum>>16) & 0xFFFF) 
            + ((cksum>>32) & 0xFFFF) + ((cksum>>48) & 0xFFFF);
  cksum = (cksum & 0xFFFF) + (cksum >>16);

  return (uint16_t)(~cksum);
}


// Function to get sockaddr, IPv4 or IPv6
// Reference: https://beej.us/guide/bgnet/html/single/bgnet.html
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int main(int argc, char **argv) {
  struct addrinfo hints, *servinfo, *p;
  uint64_t numalpha = 0;   // number of alphabets in data field
  int sockfd, numbytes, recv_numbytes, rv;
  int32_t opt;
  uint16_t optype;    // 0: encrypt, 1: decrypt
  uint8_t *buf = (uint8_t *)malloc(MAXDATASIZE * sizeof(uint8_t));
  uint8_t *recv_buf = (uint8_t *)malloc(MAXDATASIZE * sizeof(uint8_t));
  char s[INET6_ADDRSTRLEN];
  char keyword[4];
  char default_key[4];
  char host[16];
  char *port;
  uint8_t is_h=0, is_p=0, is_o=0, is_k=0;  // variable for checking existence of each argument

  // Check the number of arguments
  if (argc != 9) {
    fprintf(stderr, "Wrong number of arguments\n");
    exit(1);
  }

  /*****************************************************/
  /********** parsing command line arguments ***********/
  while((opt = getopt(argc, argv, "h:p:o:k:")) != EOF) {
    switch(opt)
    {
      case 'h':
        strcpy(host, optarg);
        is_h = 1;
        break;
      case 'p':
        port = optarg;
        is_p = 1;
        break;
      case 'o':
        optype = (uint8_t)atoi(optarg);
        is_o = 1;
        if (optype != 0 && optype != 1) {
          fprintf(stderr, "wrong operation type\n");
          exit(1);
        }
        break;
      case 'k':
        strcpy(keyword, optarg);
        strcpy(default_key, optarg);
        is_k = 1;
        break;
    }
  }

  if (!(is_h & is_p & is_o & is_k)) {
    fprintf(stderr, "Command line argument is not enough");
    exit(1);
  }
  /*******************************************************/
  
  
  /*******************************************************/
  /*************** open socket and connect ***************/
  /* Reference: https://beej.us/guide/bgnet/html/single/bgnet.html */
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
      p->ai_protocol)) == -1) {  // socket
        perror("client: socket");
        continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {  // connect
      close(sockfd);
      perror("client: connect");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "client: failed to connect\n");
    return 2;
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);

  freeaddrinfo(servinfo);
  /*********************************************************/
  /*********************************************************/


  /* While loop does below things
   * 1. Read stdin
   *    1-1 calculate checksum and set header following protocol
   * 2. Send data to server
   * 3. Receive data from server
   *    3-1 validate checksum and length
   * 4. Write stout
  */
  ///////////////// 1. Read stdin
  while (numbytes = read(0, buf+16, MAXDATASIZE-16)) {   // 16 is offset for op, checksum, keyword, length field
    /////////////////////////////////////////////////
    // 1-1. set header of buf & calculate checksum //
    uint16_t checksum;
    uint16_t optypeBigEndian = htobe16(optype);
    uint64_t len = numbytes+16;
    uint64_t lenBigEndian = htobe64(len);

    // shift keyword if the number of alphabets that is read before is not multiple of 4
    if (numalpha % 4 != 0)
      shiftKeyword(keyword, default_key, (numalpha % 4));

    memcpy(buf, &optypeBigEndian, 2);
    memcpy(buf+4, &keyword, 4);
    memcpy(buf+8, &lenBigEndian, 8);
    buf[2] = 0;
    buf[3] = 0;
    checksum = calculateChecksum(buf, numbytes+16);
    memcpy(buf+2, &checksum, 2);
    /////////////////////////////////////////////////
    /////////////////////////////////////////////////
    
    buf[numbytes+16] = '\0';

    // 2. Send data to server
    if (rio_writen(sockfd, buf, numbytes+16) == -1)
      perror("send");
    
    // 3. Receive data from server
    if ((recv_numbytes = rio_readn(sockfd, recv_buf, numbytes+16)) == -1) {
      perror("recv");
      exit(1);
    }

    // 3-1. Validate checksum and length received from the server
    if (calculateChecksum(recv_buf, recv_numbytes) != 0)
      fprintf(stderr, "client: Wrong checksum received\n");
    if (recv_numbytes != be64toh(*((uint64_t*)(recv_buf+8))))
      fprintf(stderr, "client: Data length is wrong\n");

    write(1, recv_buf+16, recv_numbytes - 16);  // 4. Write stdout
    numalpha = alphaCounter(buf+16, numalpha, numbytes);
  }

  close(sockfd);
  exit(0);

  return 0;
}


/***** Robust I/O (rio) Reading *****/
/* Reference: computer systems a programmar's perspective 2nd edition page 869 */
ssize_t rio_readn(int fd, void *usrbuf, size_t n)
{
  size_t nleft = n;
  ssize_t nread;
  char *bufp = usrbuf;

  while (nleft > 0){
    if ((nread = read(fd, bufp, nleft)) < 0) {
      if (errno = EINTR)  /* Interrupted by sig handler return */
        nread = 0;        /* and call read() again */
      else
        return -1;        /* errno set by read() */
    }
    else if (nread == 0)
      break;              /* EOF */
    
    nleft -= nread;
    bufp += nread;
  }
  return (n - nleft);     /* Return >= 0 */ 
}


/***** Robust I/O(Rio) Writing *****/
/* Reference: computer systems a programmar's perspective 2nd edition page 869 */
ssize_t rio_writen(int fd, void *usrbuf, size_t n) 
{
  size_t nleft = n;
  ssize_t nwritten;
  char *bufp = usrbuf;

  while (nleft > 0) {
    if ((nwritten = write(fd, bufp, nleft)) <= 0) {
      if (errno == EINTR)   /* Interrupted by sig handler return */
        nwritten = 0;       /* and call write() again */
      else
        return -1;          /* errno set by write() */
    }

    nleft -= nwritten;
    bufp += nwritten;
  }

  return n;
}


// Function to counter number of alphabets in data field
uint64_t alphaCounter(uint8_t *buf, uint64_t remainder, uint64_t data_len)
{
  uint64_t count = 0;
  for (int i=0; i<data_len; i++) {
    if (isalpha(buf[i]))
      count++;
  }

  return (remainder + count);
}


// Function to shift keyword
// if the number of alphabets that are already read is not multiple of 4
void shiftKeyword(char *keyword, char *default_key, int shift)
{
  switch (shift)
  {
  case 1:  // ex. cake -> akec
    keyword[0] = default_key[1];
    keyword[1] = default_key[2];
    keyword[2] = default_key[3];
    keyword[3] = default_key[0];
    break;
  
  case 2:  // ex. cake -> keca
    keyword[0] = default_key[2];
    keyword[1] = default_key[3];
    keyword[2] = default_key[0];
    keyword[3] = default_key[1];
    break;

  case 3:  // ex. cake -> ecak
    keyword[3] = default_key[2];
    keyword[2] = default_key[1];
    keyword[1] = default_key[0];
    keyword[0] = default_key[3];
    break;
  }
}
