#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>

#define MAXDATASIZE 10000000


/***** Helper functions used in main *****/
uint16_t calculateChecksum(uint8_t* buf, size_t len);
void *get_in_addr(struct sockaddr *sa);
ssize_t rio_readn(int fd, void *usrbuf, size_t n);
ssize_t rio_writen(int fd, void *usrbuf, size_t n);
void cipherEncrypt(uint8_t *send_buf, uint8_t *buf, int *keyword, uint64_t len);
void cipherDecrypt(uint8_t *send_buf, uint8_t *buf, int *keyword, uint64_t len);
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
  return  &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int main (int argc, char** argv) {
  fd_set master;
  fd_set read_fds;
  struct sockaddr_storage remoteaddr;
  struct addrinfo hints, *ai, *p;
  socklen_t addrlen;
  int fdmax, listener, newfd, i, rv; 
  int yes = 1;
  int32_t opt;
  char remoteIP[INET6_ADDRSTRLEN];
  char *port;
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

  // clear the master and temp sets
  FD_ZERO(&master);   
  FD_ZERO(&read_fds);

  /************************************************************/
  /*************** open socket and bind, listen ***************/
  /* Reference: https://beej.us/guide/bgnet/html/single/bgnet.html */
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if ((rv = getaddrinfo(NULL, port, &hints, &ai)) != 0) {
    fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
    exit(1);
  }

  for (p = ai; p != NULL; p = p->ai_next) {
    // 1. socket
    listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (listener < 0) {
      continue;
    }

    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    // 2. bind
    if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
      close(listener);
      continue;
    }
    break;
  }

  if (p == NULL) {
    fprintf(stderr, "selectserver: failed to bind\n");
    exit(2);
  }

  freeaddrinfo(ai);

  // 3. listen
  if (listen(listener, 10) == -1) {
    perror("listen");
    exit(3);
  }
  /************************************************************/
  /************************************************************/

  FD_SET(listener, &master);
  fdmax = listener; 

  /***** main loop *****/
  /* Reference: https://beej.us/guide/bgnet/html/single/bgnet.html */
  for(;;) {
    read_fds = master;
    // select
    if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
      perror("select");
      exit(4);
    }

    for (i = 0; i <= fdmax; i++) {
      if (FD_ISSET(i, &read_fds)) {
        if (i == listener) {
          addrlen = sizeof remoteaddr;
          // accept
          newfd = accept(listener,
              (struct sockaddr *)&remoteaddr,
              &addrlen);
          
          if (newfd == -1) {
            perror("accept");
          } else {
            FD_SET(newfd, &master);
            if (newfd > fdmax) {
              fdmax = newfd;
            }
            fprintf(stderr, "selectserver: new connection from %s on "
                "socket %d\n",
                inet_ntop(remoteaddr.ss_family,
                    get_in_addr((struct sockaddr*)&remoteaddr),
                    remoteIP, INET6_ADDRSTRLEN),
                newfd);
          }
        } else {  // if i is not listener
          uint64_t len, data_len;
          uint8_t *buf = (uint8_t *)malloc(MAXDATASIZE * sizeof(uint8_t));
          uint8_t *send_buf = (uint8_t *)malloc(MAXDATASIZE * sizeof(uint8_t));
          int keyword[4];
          int nbytes, numbytes;
          uint16_t optype, checksum;
    
          /* First read header */
          if ((nbytes = read(i, buf, 16)) <= 0) {
            if (nbytes == 0)
              fprintf(stderr, "selectserver: socket %d hung up\n", i);
            else
              perror("recv");

            close(i);
            FD_CLR(i, &master);
          } else {
            if (FD_ISSET(i, &master)) {
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
              if ((numbytes = rio_readn(i, buf+16, data_len)) == -1) {
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
                  
              if (rio_writen(i, send_buf, numbytes) == -1)
                perror("send");
            }
          }
        }
      }
    }
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
