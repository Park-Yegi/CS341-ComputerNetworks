/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/E_Common.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <queue>


#include <E/E_TimerModule.hpp>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
public:
	enum socketState { SOC_LISTEN, SYN_RCVD, ESTAB, CLOSE_WAIT, LAST_ACK, CLOSED, SYN_SENT, FIN_WAIT_1, FIN_WAIT_2, TIMED_WAIT };
	enum packetFlag { FIN=1, SYN=2, RST=4, ACK=16, SYNACK=18 };

	int clientSeq;

	typedef uint8_t Family;
	typedef uint16_t Port;
	typedef uint32_t IPAddr;
	typedef int PID;
	typedef std::tuple<Family, Port, IPAddr, Port, IPAddr, PID> Namespace;
	std::unordered_map<uint64_t, Namespace> fdToAddr;

	typedef std::queue <struct sockaddr*> Pendings; // 0
	typedef int Backlog;                            // 1
	typedef socketState sState;                     // 2
	typedef int parentFd;                           // 5
	typedef struct sockaddr * acceptAddr;           // 6
	typedef int pendingCount;                       // 7
	typedef int seqNum;                             // 8
	typedef std::tuple<Pendings, Backlog, sState, UUID, PID, parentFd, acceptAddr, pendingCount, seqNum> serverNamespace;
	std::unordered_map<uint64_t, serverNamespace> serverMap;

	typedef socketState cState; // 0
	typedef uint32_t cSeq;      // 1
	typedef UUID TimerID;       // 3
	typedef std::tuple<cState, cSeq, UUID, TimerID> clientNamespace;
	std::unordered_map<int, clientNamespace> clientMap;


private:

private:
	virtual void timerCallback(void* payload) final;

	/***** KENS#1: Requirement2 *****/
	void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
	void syscall_close(UUID syscallUUID, int pid, int sockfd);
	void syscall_bind(UUID syscallUUID, int pid, int sockfd,	struct sockaddr *my_addr, socklen_t addrlen);
	void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	/********************************/

	/***** KENS#2: Requirements *****/
	void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr* serv_addr, socklen_t addrlen);
	void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrlen);
	void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	/********************************/
	
	/***** Helper functions *****/
	uint64_t getPidSocketKey(int pid, int sockfd);
	void sendPacketHeader(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t flag, int* seqNum, int rcvNum, int seqNumBeforeIncr, int seqNumAfterIncr);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
