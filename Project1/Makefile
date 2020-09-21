CC = gcc
OBJS = client.o server.o server_select.o
TARGET = client server server_select

.SUFFIXES : .c .o

# all : $(TARGET)

# $(TARGET): $(OBJS)
# 		 $(CC) -o client client.o
# 		 $(CC) -o server server.o
#      $(CC) -o server_select server_select.o

all: client server server_select

client: client.c
	$(CC) -o client client.c

server: server.c
	$(CC) -o server server.c

server_select: server_select.c
	$(CC) -o server_select server_select.c

clean:
		 rm -rf $(OBJS) $(TARGET)
