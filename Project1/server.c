#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>

#define BACKLOG 10 // how many pending connections queue will hold
#define MAXDATASIZE 10000000

/***** Helper functions used in main *****/
void sigchld_handler(int s);
uint16_t calculateChecksum(uint8_t* buf, size_t len);
void *get_in_addr(struct sockaddr *sa);
ssize_t rio_readn(int fd, void *usrbuf, size_t n);
ssize_t rio_writen(int fd, void *usrbuf, size_t n);
void cipherEncrypt(uint8_t *send_buf, uint8_t *buf, int *keyword, uint64_t len);
void cipherDecrypt(uint8_t *send_buf, uint8_t *buf, int *keyword, uint64_t len);
/*****************************************/


// Signal handler
// Reference: https://beej.us/guide/bgnet/html/single/bgnet.html
void sigchld_handler(int s)
{
  int saved_errno = errno;

  while(waitpid(-1, NULL, WNOHANG) > 0);

  errno = saved_errno;
}


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
  return  &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int main(int argc, char** argv) {
  struct sigaction sa;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr; // connector's address information
  socklen_t sin_size;
  int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
  int yes=1;
  int rv;
  int32_t opt;
  char *port;
  char s[INET6_ADDRSTRLEN];
  uint8_t is_p = 0;
  

  // Check the number of arguments
  if (argc != 3) {
    fprintf(stderr, "Wrong number of arguments\n");
    exit(1);
  }

  /********* parsing command line arguments **********/
  while((opt = getopt(argc, argv, "p:")) != EOF) {
    switch(opt)
    {
      case 'p':
        port = optarg;
        is_p =1;
        break;
    }
  }

  if (!is_p) {
    fprintf(stderr, "Command line argument is not enough");
    exit(1);
  }
  /*************************************************/

  /************************************************************/
  /*************** open socket and bind, listen ***************/
  /* Reference: https://beej.us/guide/bgnet/html/single/bgnet.html */
  memset(&hints, 0,  sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  for (p = servinfo; p != NULL; p = p->ai_next) {
    if (( sockfd = socket(p->ai_family, p->ai_socktype,
      p->ai_protocol)) == -1) {   // 1. socket
        perror("server: socket");
        continue;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
      sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {   // 2. bind
      close(sockfd);
      perror("server: bind");
      continue;
    }

    break;
  }

  freeaddrinfo(servinfo);

  if (p == NULL) {
    fprintf(stderr, "server: failed to bind\n");
    exit(1);
  }

  if (listen(sockfd, BACKLOG) == -1) {  // 3. listen
    perror("listen");
    exit(1);
  }

  sa.sa_handler = sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }

  fprintf(stderr, "server: waiting for connections... \n");
  /************************************************************/
  /************************************************************/


  /******** main accept() loop ********/
  /*
   * 1. Parent process just close new_fd file descriptor
   * 2. What child process does is the followings
   *    - close socket used for listen()
   *    - Receive data from the client and parse the header
   *    - Encrypt or decrypt received data
   *    - Send data to the client
   */
  while(1) {
    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
      perror("accept");
      continue;
    }

    inet_ntop(their_addr.ss_family,
      get_in_addr((struct sockaddr *)&their_addr),
      s, sizeof s);
    fprintf(stderr, "server: got connection from %s\n", s);

    if (!fork()) {  // this is the child process
      close(sockfd);
      
      uint64_t len, data_len;
      int keyword[4];
      int numbytes;
      uint16_t optype, checksum;
      uint8_t *buf = (uint8_t *)malloc(MAXDATASIZE * sizeof(uint8_t));
      uint8_t *send_buf = (uint8_t *)malloc(MAXDATASIZE * sizeof(uint8_t));

      while (1) {
        /* First read header */
        if (read(new_fd, buf, 16) == -1) {
          perror("recv");
          exit(1);
        }

        /* Parse the contents of the protocol from the client */
        optype = buf[1];
        keyword[0] = tolower(buf[4]) - 'a';
        keyword[1] = tolower(buf[5]) - 'a';
        keyword[2] = tolower(buf[6]) - 'a';
        keyword[3] = tolower(buf[7]) - 'a';
        len = be64toh(*((uint64_t*)(buf+8)));
        data_len = len - 16;

        /* Reject connections if clients violate protocol */
        if (optype != 0 && optype != 1)
          break;
        if (!isalpha(buf[4]) || !isalpha(buf[5]) || !isalpha(buf[6]) || !isalpha(buf[7]))
          break;
        if (len > MAXDATASIZE)
          break;

        /* Now read data field */
        if ((numbytes = rio_readn(new_fd, buf+16, data_len)) == -1) {
          perror("recv");
          exit(1);
        }
        numbytes += 16;

        if (numbytes <= 16)
          break;
        
        buf[numbytes] = '\0';

        // validate checksum received from the client
        if (calculateChecksum(buf, numbytes) != 0) {
          fprintf(stderr, "server: Wrong checksum received\n");
          break;
        }
        
        /* Encrypt or decrypt the received data */
        if (optype == 0)
          cipherEncrypt(send_buf+16, buf+16, keyword, data_len);
        else if (optype == 1)
          cipherDecrypt(send_buf+16, buf+16, keyword, data_len);

        /* set header of send_buf */
        send_buf[2] = 0;
        send_buf[3] = 0;
        memcpy(send_buf, buf, 2);       // copy operation type field
        memcpy(send_buf+4, buf+4, 12);  // copy keyword and length field
        checksum = calculateChecksum(send_buf, numbytes);
        memcpy(send_buf+2, &checksum, 2);  // set checksum in header
        
        if (rio_writen(new_fd, send_buf, numbytes) == -1)
          perror("send");
      }
      close(new_fd);
      exit(0);
    }
    close(new_fd);  // parent doesn't need this
  }
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

// Function to encrypt the data field with keyword
void cipherEncrypt(uint8_t *send_buf, uint8_t *buf, int *keyword, uint64_t len)
{
  int key_idx = 0;
  uint8_t temp;
  for (int i = 0; i < len; i++) {
    if (isalpha(buf[i])) {
      temp = (tolower(buf[i]) + keyword[key_idx]);
      if (temp > 'z')
        send_buf[i] = temp - 26;
      else
        send_buf[i] = temp;
      
      key_idx = (key_idx+1)%4;
    }
    else
      send_buf[i] = buf[i];
  }
}

// Function to decrypt the data field with keyword
void cipherDecrypt(uint8_t *send_buf, uint8_t *buf, int *keyword, uint64_t len)
{
  int key_idx = 0;
  uint8_t temp;
  for (int i = 0; i < len; i++) {
    if (isalpha(buf[i])) {
      temp = (tolower(buf[i]) - keyword[key_idx]);
      if (temp < 'a')
        send_buf[i] = temp + 26;
      else
        send_buf[i] = temp;
      
      key_idx = (key_idx+1)%4;
    }
    else
      send_buf[i] = buf[i];
  }
}
