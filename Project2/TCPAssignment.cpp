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
#include <E/E_System.hpp>
#include "TCPAssignment.hpp"

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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

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
	// remove file descriptor
	this->removeFileDescriptor(pid, sockfd);

	// if the sockfd is bound, remove it from fdToAddr
	auto iter = this->fdToAddr.begin();
	if ((iter = this->fdToAddr.find(sockfd)) != this->fdToAddr.end()) {
		this->fdToAddr.erase(sockfd);
	}

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

	// if the socket is already bound, return -1
	if (this->fdToAddr.find(sockfd) != this->fdToAddr.end())
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
	this->fdToAddr.insert(std::pair<int, Namespace>(sockfd, Namespace(family, port, ipAddr)));
	this->returnSystemCall(syscallUUID, 0);
}

/* getsockname() system call */
void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
				struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in * addr2 = (struct sockaddr_in*)malloc(*addrlen);

	// Find the address matched to sockfd in the fdToAddr
	// If the socket is not bound, just return 0
	auto iter = this->fdToAddr.begin();
	if ((iter = this->fdToAddr.find(sockfd)) == this->fdToAddr.end())
		this->returnSystemCall(syscallUUID, 0);

	// Copy the address to * addr
	memset(addr2, 0, *addrlen);
	addr2->sin_family = std::get<0>(iter->second);
	addr2->sin_port = htons(std::get<1>(iter->second));
	addr2->sin_addr.s_addr = htonl(std::get<2>(iter->second));
	memcpy(addr, addr2, *addrlen);

	free(addr2);
	this->returnSystemCall(syscallUUID, 0);
}

}
