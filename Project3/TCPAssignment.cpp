/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_RoutingInfo.hpp>
#include <E/E_System.hpp>
#include "TCPAssignment.hpp"
#include <unistd.h>

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{
	
}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
	this->clientSeq = 4294966500;
}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	// src is dst of new packet, dst is src of new packet
	uint32_t src_ip, dst_ip, big_src_ip, big_dst_ip, receivedSeq;
	uint16_t src_port, dst_port, big_src_port, big_dst_port;
	uint8_t flags, newFlags;
	packet->readData(14+12, &big_src_ip, 4); 
	packet->readData(14+16, &big_dst_ip, 4);
	packet->readData(34, &big_src_port, 2);
	packet->readData(36, &big_dst_port, 2);
	packet->readData(47, &flags, 1);
	packet->readData(38, &receivedSeq, 4);
	src_ip = ntohl(big_src_ip);
	dst_ip = ntohl(big_dst_ip);
	src_port = ntohs(big_src_port);
	dst_port = ntohs(big_dst_port);
	receivedSeq = ntohl(receivedSeq);

	int sockfd;
	uint64_t sockKey1;

	/*** Find socket with src and dst address of packet ***/
	auto iterAddr = this->fdToAddr.begin();
	// IF flag is not SYN, find sockfd with TCP context
	if (flags != SYN) {
		while (iterAddr != this->fdToAddr.end()) {
			if ((std::get<1>(iterAddr->second) == dst_port) 
					&& (std::get<2>(iterAddr->second) == dst_ip || std::get<2>(iterAddr->second) == 0)
					&& (std::get<3>(iterAddr->second) == src_port)
					&& (std::get<4>(iterAddr->second) == src_ip)) {
				sockfd = (int)((iterAddr->first)&0xFFFFFFFF);
				sockKey1 = iterAddr->first;
				break;
			}
			iterAddr++;
		}
	}
	else {  // IF flag is SYN, find listening socket
		while (iterAddr != this->fdToAddr.end()) {
			if ((std::get<1>(iterAddr->second) == dst_port) 
					&& (std::get<2>(iterAddr->second) == dst_ip || std::get<2>(iterAddr->second) == 0)
					&& (std::get<3>(iterAddr->second) == 0)) {
				sockfd = (int)((iterAddr->first)&0xFFFFFFFF);
				sockKey1 = iterAddr->first;
				break;
			}
			iterAddr++;
		}
		// if statement is for TestConnect_SimultanouesConnect
		if (iterAddr == this->fdToAddr.end()) {
			iterAddr = this->fdToAddr.begin();
			while (iterAddr != this->fdToAddr.end()) {
				if ((std::get<1>(iterAddr->second) == dst_port) 
						&& (std::get<2>(iterAddr->second) == dst_ip || std::get<2>(iterAddr->second) == 0)) {
					sockfd = (int)((iterAddr->first)&0xFFFFFFFF);
					sockKey1 = iterAddr->first;
					break;
				}
				iterAddr++;
			}
		}
	}
	
	bool isServer;
	auto iterMapS = this->serverMap.begin();
	auto iterMapC = this->clientMap.begin();
	if ((iterMapS = this->serverMap.find(sockKey1)) == this->serverMap.end()) {
		iterMapC = this->clientMap.find(sockfd);
		isServer = false;
	}
	else {
		isServer = true;
	}

	/***** FINITE STATE MACHINE *****/
	switch (isServer? (std::get<2>(iterMapS->second)) : (std::get<0>(iterMapC->second)) ) {
		case SOC_LISTEN: // when server socket gets SYN
		{	
			// If the pending queue is full, send packet with RST flag
			if (std::get<7>(iterMapS->second) >= std::get<1>(iterMapS->second)) {
				newFlags = RST;
			}
			else {
				newFlags = SYNACK;
				int pid = std::get<4>(iterMapS->second);

				// create new fd for accept socket and insert it into fdToAddr&serverMap
				int newfd = this->createFileDescriptor(std::get<4>(iterMapS->second));
				uint64_t sockKey = getPidSocketKey(pid, newfd);
				this->fdToAddr.insert(std::pair<uint64_t, Namespace>(sockKey, Namespace(AF_INET, dst_port, dst_ip, src_port, src_ip, std::get<4>(iterMapS->second))));
				std::queue <struct sockaddr *> pendingQueue;
				this->serverMap.insert(std::pair<uint64_t, serverNamespace>(sockKey, serverNamespace(pendingQueue, 0, SYN_RCVD, std::get<3>(iterMapS->second), std::get<4>(iterMapS->second), sockfd, NULL, 0, std::get<8>(iterMapS->second)+1)));

				std::get<7>(iterMapS->second)++;
			}
			sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &std::get<8>(iterMapS->second), receivedSeq, 0, 0);
			break;
		}
		case SYN_SENT:  // when client socket gets ACK and SYN
		{	
			// if received flag is RST, return -1
			if (flags == RST) {
				this->returnSystemCall(std::get<2>(iterMapC->second), -1);
				break;
			}

			if (flags != SYN)
				std::get<0>(iterMapC->second) = ESTAB;
			else
				this->clientSeq = this->clientSeq -1;
			
			newFlags = (flags!=SYN) ? ACK : SYNACK;
			sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 0);
			
			if (flags == SYN)
				this->clientSeq = this->clientSeq+1;
			else
				this->returnSystemCall(std::get<2>(iterMapC->second), 0);

			break;
		}
		case SYN_RCVD:  // when server socket gets ACK
		{
			// change state to ESTAB
			std::get<2>(iterMapS->second) = ESTAB;
			// find the information about parent
			int parentFd = std::get<5>(iterMapS->second);
			int parentPid = std::get<4>(iterMapS->second);
			uint64_t parentKey = getPidSocketKey(parentPid, parentFd);;
			auto iterParent = this->serverMap.begin();
			iterParent = this->serverMap.find(parentKey);

			// if accept() is not called yet, push address to pending queue
			if (std::get<6>(iterParent->second) == NULL) {  
				struct sockaddr_in* pendingAddr;
				pendingAddr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
				pendingAddr->sin_family = AF_INET;
				pendingAddr->sin_port = src_port;
				pendingAddr->sin_addr.s_addr = src_ip;
				memset(pendingAddr->sin_zero, 0, 8);
				std::get<0>(iterParent->second).push((struct sockaddr *)pendingAddr);
				std::get<7>(iterParent->second)--;
			}
			else {  // if accept() is already called, finish what should be done at accept() function
				((struct sockaddr_in*)std::get<6>(iterParent->second))->sin_family = AF_INET;
				((struct sockaddr_in*)std::get<6>(iterParent->second))->sin_port = src_port;
				((struct sockaddr_in*)std::get<6>(iterParent->second))->sin_addr.s_addr = src_ip;

				std::get<6>(iterParent->second) = NULL;
				std::get<7>(iterParent->second)--;
				this->returnSystemCall(std::get<3>(iterParent->second), sockfd);
			}
			break;
		}
		case ESTAB: 
		{
			newFlags = ACK; 
			if (isServer) {
				// change state to CLOSE_WAIT
				std::get<2>(iterMapS->second) = CLOSE_WAIT;
				sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &std::get<8>(iterMapS->second), receivedSeq, 0, 0);
			}
			else { // if client, change state to TIMED_WAIT and then start a new timer
				std::get<0>(iterMapC->second) = TIMED_WAIT;
				int * sockfdPtr;
				sockfdPtr = (int *)malloc(sizeof(int));
				*sockfdPtr = sockfd;
				UUID timerID = addTimer(sockfdPtr, 60);
				std::get<3>(iterMapC->second) = timerID;

				sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 0);
			}
			break;
		}
		case CLOSE_WAIT:
		{
			break;
		}
		case LAST_ACK:
		{
			// change state to CLOSED
			std::get<2>(iterMapS->second) = CLOSED;
			newFlags = ACK;
			if (flags == FIN) {
				sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &std::get<8>(iterMapS->second), receivedSeq, 1, 0);
			}
			break;
		}
		case FIN_WAIT_1:
		{
			if (flags == ACK) {
				std::get<0>(iterMapC->second) = FIN_WAIT_2; /// change state to FIN_WAIT_2
				break;
			}

			/****** Fall through!!!! *******/
			/****** Don't write anything *****/
		}
		case FIN_WAIT_2:
		{
			if (flags == ACK) {
				break;
			}
			// change state to TIMED_WAIT
			std::get<0>(iterMapC->second) = TIMED_WAIT;
			newFlags = ACK;
			int * sockfdPtr;
			sockfdPtr = (int *)malloc(sizeof(int));
			*sockfdPtr = sockfd;
			UUID timerID = addTimer(sockfdPtr, 60);
			std::get<3>(iterMapC->second) = timerID;
			sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 1);
			break; 
		}
		case TIMED_WAIT:
		{
			// If FIN packet is arrived, retransmit the ACK packet
			if (flags == FIN) {
				newFlags = ACK;
				sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &(this->clientSeq), receivedSeq, 0, 1);
			}
			break;
		}
		case CLOSED:
		{
			if (flags == FIN) {
				newFlags = ACK;
				sendPacketHeader(big_dst_ip, big_src_ip, big_dst_port, big_src_port, newFlags, &std::get<8>(iterMapS->second), receivedSeq, 1, 0);
			}
			break;
		}
	}

	// given packet is my responsibility
	this->freePacket(packet);
}

void TCPAssignment::timerCallback(void* payload)
{
	auto iterMapC = this->clientMap.begin();
	iterMapC = this->clientMap.find(*((int *)payload));

	UUID timerID = std::get<3>(iterMapC->second);
	cancelTimer(timerID);
	free(payload);
	std::get<0>(iterMapC->second) = CLOSED;
	return;
}

/* socket() system call */
void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
	// create file descriptor and return the result
	int sockfd = this->createFileDescriptor(pid);
	this->returnSystemCall(syscallUUID, sockfd);
}

/* close() system call */
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{	
	bool isServer;
	uint64_t sockKey = getPidSocketKey(pid, sockfd);
	auto iter = this->fdToAddr.begin();
	iter = this->fdToAddr.find(sockKey);
	auto iterMapS = this->serverMap.begin();
	auto iterMapC = this->clientMap.begin();
	if ((iterMapS = this->serverMap.find(sockKey)) == this->serverMap.end()) {
		iterMapC = this->clientMap.find(sockfd);
		isServer = false;
		// If neither server nor client
		if (iterMapC == this->clientMap.end()) {  
			// if the sockfd is bound, remove it from fdToAddr
			if (iter != this->fdToAddr.end()) {
				this->fdToAddr.erase(sockKey);
			}
			this->removeFileDescriptor(pid, sockfd);
			this->returnSystemCall(syscallUUID, 0); 
			return;
		}
	}
	else {
		isServer = true;
	}

	// If the socket is listening socket, just remove the socket
	if (isServer && std::get<3>(iter->second) == 0) {
		this->removeFileDescriptor(pid, sockfd);
		this->returnSystemCall(syscallUUID, 0);
		return;
	}

	uint32_t src_ip = htonl(std::get<2>(iter->second));
	uint32_t dst_ip = htonl(std::get<4>(iter->second));
	uint16_t src_port = htons(std::get<1>(iter->second));
	uint16_t dst_port = htons(std::get<3>(iter->second));
	uint8_t newFlags = FIN;

	if (!isServer) {
		/**** syscall_close for client socket ****/
		/*** Change State ***/
		std::get<0>(iterMapC->second) = FIN_WAIT_1;

		sendPacketHeader(src_ip, dst_ip, src_port, dst_port, newFlags, &(this->clientSeq), -1, 0, 1);
	}
	else {
		/**** syscall_close for server socket ****/
		// change state to LAST_ACK
		std::get<2>(iterMapS->second) = LAST_ACK;

		sendPacketHeader(src_ip, dst_ip, src_port, dst_port, newFlags, &std::get<8>(iterMapS->second), -1, 0, 0);
	}
 
	// remove file descriptor
	this->removeFileDescriptor(pid, sockfd);
	this->returnSystemCall(syscallUUID, 0);
}

/* bind() system call */
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd,
				struct sockaddr *my_addr, socklen_t addrlen)
{
	uint8_t family;
	uint16_t port;
	uint32_t ipAddr;
	uint16_t portBigEndian;
	uint32_t ipBigEndian;

	uint64_t sockKey = getPidSocketKey(pid, sockfd);
	// if the socket is already bound, return -1
	if (this->fdToAddr.find(sockKey) != this->fdToAddr.end())
		this->returnSystemCall(syscallUUID, -1);

	// copy and change the endian of address
	memcpy(&portBigEndian, my_addr->sa_data, 2);
	port = ntohs(portBigEndian);
	memcpy(&ipBigEndian, my_addr->sa_data+2, 4);
	ipAddr = ntohl(ipBigEndian);
	family = my_addr->sa_family;

	// check whether the overlapped address is already bound or not
	for (auto iter = this->fdToAddr.begin(); iter != this->fdToAddr.end(); iter++) {
		if (std::get<1>(iter->second) == port) {
			if ((std::get<2>(iter->second) == ipAddr) || (std::get<2>(iter->second) == INADDR_ANY) || (ipAddr == INADDR_ANY))
				this->returnSystemCall(syscallUUID, -1);
		}
	}

	// insert the address into fdToAddr and return 0
	this->fdToAddr.insert(std::pair<uint64_t, Namespace>(sockKey, Namespace(family, port, ipAddr, NULL, NULL, pid)));
	this->returnSystemCall(syscallUUID, 0);
}

/* getsockname() system call */
void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
				struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in * addr2 = (struct sockaddr_in*)malloc(*addrlen);
	uint64_t sockKey = getPidSocketKey(pid, sockfd);
	// Find the address matched to sockfd in the fdToAddr
	// If the socket is not bound, just return 0
	auto iter = this->fdToAddr.begin();
	if ((iter = this->fdToAddr.find(sockKey)) == this->fdToAddr.end()) {
		this->returnSystemCall(syscallUUID, 0);
		return;
	}

	// Copy the address to * addr
	memset(addr2, 0, *addrlen);
	addr2->sin_family = std::get<0>(iter->second);
	addr2->sin_port = htons(std::get<1>(iter->second));
	addr2->sin_addr.s_addr = htonl(std::get<2>(iter->second));
	memcpy(addr, addr2, *addrlen);

	free(addr2);
	this->returnSystemCall(syscallUUID, 0);
}

/* connect() system call */
void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, 
				struct sockaddr* serv_addr, socklen_t addrlen) 
{
	uint32_t big_src_ip, big_dst_ip;
	uint16_t big_src_port, big_dst_port;
	uint64_t sockKey = getPidSocketKey(pid, sockfd);

	// Find the address matched to sockfd in the fdToAddr
	auto iter = this->fdToAddr.begin();
	if ((iter = this->fdToAddr.find(sockKey)) == this->fdToAddr.end()) {
		// bind implicitly
		uint16_t port = (uint16_t)rand();
		uint8_t ip_addr[4];
		memset(ip_addr, 0, 4);
		uint32_t ipAddr;
		this->getHost()->getIPAddr(ip_addr,
			  this->getHost()->getRoutingTable(ip_addr));
		memcpy(&ipAddr, ip_addr, 4);
		ipAddr = ntohl(ipAddr);
		this->fdToAddr.insert(std::pair<uint64_t, Namespace>(sockKey, Namespace(AF_INET, port, ipAddr, NULL, NULL, pid)));
		iter = this->fdToAddr.find(sockKey);
	}
		
	big_src_port = htons(std::get<1>(iter->second));
	big_src_ip = htonl(std::get<2>(iter->second));
	struct sockaddr_in* serv_addr_in = (struct sockaddr_in*)(serv_addr);
	big_dst_port = serv_addr_in->sin_port;
	big_dst_ip = serv_addr_in->sin_addr.s_addr;

	std::get<3>(iter->second) = ntohs(big_dst_port);
	std::get<4>(iter->second) = ntohl(big_dst_ip);

	this->clientMap.insert(std::pair<int, clientNamespace>(sockfd, clientNamespace(SOC_LISTEN, this->clientSeq, syscallUUID, -1)));
	uint8_t newFlags = SYN;
	sendPacketHeader(big_src_ip, big_dst_ip, big_src_port, big_dst_port, newFlags, &(this->clientSeq), -1, 0, 1);
	
	/*** Change State ***/
	auto iter_client = this->clientMap.begin();
	iter_client = this->clientMap.find(sockfd);
	std::get<0>(iter_client->second) = SYN_SENT;
}

/* listen() system call */
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	// Insert the information to serverMap
	std::queue <struct sockaddr *> pendingQueue;
	uint64_t sockKey = getPidSocketKey(pid, sockfd);
	this->serverMap.insert(std::pair<uint64_t, serverNamespace>(sockKey, serverNamespace(pendingQueue , backlog, SOC_LISTEN, syscallUUID, pid, 0, 0, 0, 3321757695)));
	this->returnSystemCall(syscallUUID, 0);
}

/* accept() system call */
void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, 
				struct sockaddr* addr, socklen_t* addrlen)
{
	socklen_t clientLen;
	memcpy(&clientLen, addrlen, sizeof(socklen_t));
	uint64_t sockKey = getPidSocketKey(pid, sockfd);

	auto iter = this->serverMap.begin();
	if ((iter = this->serverMap.find(sockKey)) == this->serverMap.end())
		this->returnSystemCall(syscallUUID, -1);

	auto iterAddr = this->fdToAddr.begin();
	if ((iterAddr = this->fdToAddr.find(sockKey)) == this->fdToAddr.end())
		this->returnSystemCall(syscallUUID, -1);

	// If queue is not empty, pop one element in the queue
	if ((std::get<0>(iter->second)).size() > 0) {
		struct sockaddr* clientAddr = (std::get<0>(iter->second)).front();
		memcpy(addr, clientAddr, 16);
		(std::get<0>(iter->second)).pop();

		int newfd;
		auto iterSock = this->fdToAddr.begin();
		while (iterSock != this->fdToAddr.end()) {
			if ((std::get<1>(iterSock->second) == std::get<1>(iterAddr->second)) 
					&& (std::get<2>(iterSock->second) == std::get<2>(iterAddr->second) || std::get<2>(iterSock->second) == 0 || std::get<2>(iterAddr->second) == 0)
					&& (std::get<3>(iterSock->second) == ((sockaddr_in*)clientAddr)->sin_port)
					&& (std::get<4>(iterSock->second) == ((sockaddr_in*)clientAddr)->sin_addr.s_addr)) {
				newfd = (int)((iterSock->first)&0xFFFFFFFF);

				break;
			}
			iterSock++;
		}

		free(clientAddr);
		this->returnSystemCall(syscallUUID, newfd);
	}
	else {  // if queue is empty, store UUID and addr to copy
		std::get<3>(iter->second) = syscallUUID;
		std::get<6>(iter->second) = addr;
	}

	return;
}

/* getpeername() system call */
void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
				struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in * addr2 = (struct sockaddr_in*)malloc(*addrlen);
	uint64_t sockKey = getPidSocketKey(pid, sockfd);

	// Find the address matched to sockfd in the fdToAddr
	// If the socket is not bound, just return 0
	auto iter = this->fdToAddr.begin();
	if ((iter = this->fdToAddr.find(sockKey)) == this->fdToAddr.end())
		this->returnSystemCall(syscallUUID, 0);

	// Copy the address to * addr
	memset(addr2, 0, *addrlen);
	addr2->sin_family = std::get<0>(iter->second);
	addr2->sin_port = htons(std::get<3>(iter->second));
	addr2->sin_addr.s_addr = htonl(std::get<4>(iter->second));
	memcpy(addr, addr2, *addrlen);

	free(addr2);
	this->returnSystemCall(syscallUUID, 0);
}

// Function to make Key which is concatenation of pid and sockfd
uint64_t TCPAssignment::getPidSocketKey(int pid, int sockfd) 
{
	return ((((uint64_t)pid)<<32) & 0xFFFFFFFF00000000) + sockfd;
}

// Function to make packet header
void TCPAssignment::sendPacketHeader(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t flag,
				int* seqNum, int rcvNum, int seqNumBeforeIncr, int seqNumAfterIncr)
{
	Packet* myPacket = this->allocatePacket(54);

	myPacket->writeData(14+12, &src_ip, 4);
	myPacket->writeData(14+16, &dst_ip, 4);
	myPacket->writeData(34, &src_port, 2);
	myPacket->writeData(36, &dst_port, 2);
					
	// write sequence number
	*seqNum += seqNumBeforeIncr;
	uint32_t bigSeqNum = htonl(*seqNum);
	myPacket->writeData(38, &bigSeqNum, 4);
	*seqNum += seqNumAfterIncr;

	// write flag
	myPacket->writeData(47, &flag, 1);

	// write acknowledge number
	rcvNum++;
	rcvNum = htonl(rcvNum);
	myPacket->writeData(42, &rcvNum, 4);
	
	// length and unused field
	uint8_t lengthAndUnused = (5 << 4) & 0xF0;
	myPacket->writeData(46, &lengthAndUnused, 1);

	// window size
	uint16_t windowSize = htons(51200);
	myPacket->writeData(48, &windowSize, 2);

	// zero cksum field, calculate cksum, and set cksum
	uint16_t zero16 = 0;
	myPacket->writeData(50, &zero16, 2);
	uint8_t packetHeader[20];
	myPacket->readData(34, packetHeader, 20);
	uint16_t sendChecksum = ~NetworkUtil::tcp_sum(src_ip, dst_ip, packetHeader, 20);
	sendChecksum = htons(sendChecksum);
	myPacket->writeData(50, &sendChecksum, 2);

	// IP module will fill rest of IP header, send it to correct network interface 
	this->sendPacket("IPv4", myPacket);
}

}
