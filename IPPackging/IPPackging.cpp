// IPDataPackaging.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdio.h"
#include <iostream>
#include <string>
//#include <Windows.h>
#include "pcap.h"
#include <math.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
using namespace std;


struct ipInputAddress{
	int sectiona;
	int sectionb;
	int sectionc;
	int sectiond;
};
struct ipSendAddress{
	u_char section1;
	u_char section2;
	u_char section3;
	u_char section4;
};


struct ipHead{
	u_char ipVersion_HeadLength;
	u_char ipServiceType;
	u_short ipTotalLength;//最后算
	u_short ipIdentification;//发一个加一个
	u_short ipFlags_FragmentOffset;//010还有分片 000没有分片
	u_char TimeToLive;
	u_char ipProtocal;
	u_short ipHeaderCheckSum;//后面得算
	in_addr ipSorceAddress;
	in_addr ipDestinationAddress;
};
	//define ipVersion
	#define IPV4 0x04;
	#define IPV6 0x06;
	//define ipProtocal
    #define IPProtocal 0x04;
    #define ICMPProtocal 0x01;
    #define IGMPProtocal 0x02;
    #define TCPProtocal 0x06;
    #define EGPProtocal 0x08;
    #define IGPProtocal 0x09;
    #define UDPProtocal 0x11;
    #define IPV6Protocal 0x29;
    #define ESPProtocal 0x32;
    #define OSPFProtocal 0x59;
int lengthofData(u_char *achar);

int _tmain(int argc, _TCHAR* argv[])
{
	unsigned char data[100000]; //Data length is less than 1500 bytes in IP Package, the longest IP head permitted is 60 bytes.
	for (int i = 0; i < 100000; i++)
	{
		data[i] = '\0';
	}
	
	u_short countPackge=1;
	
	ipHead head;//defult defination
	head.ipVersion_HeadLength = 0x45;
	head.ipServiceType = 0x00;
	head.TimeToLive = 0xff;
	head.ipProtocal = ICMPProtocal;
	head.ipIdentification = 0x0001;

	//find net device
	pcap_if_t *deviceList, *device;
	char errorBuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&deviceList, errorBuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errorBuf);
		exit(1);
	}
	//Print net device
	int numberOfDevice = 0;
	cout << "您所有的网络适配器信息如下：" << endl;
	for (device = deviceList; device; device = device->next)
	{
		printf("%d. %s", ++numberOfDevice, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" No description\n");
	}
	if (numberOfDevice == 0)
	{
		printf("\nNo interfaces found! \n");
		return 0;
	}
	

	int userChoiceDevice = numberOfDevice + 1;
	cout << "请选择一个网络适配器发送数据：";
	while (userChoiceDevice > numberOfDevice)
	{
		cin >> userChoiceDevice;
		if (userChoiceDevice > numberOfDevice)
		{
			cout << "您选择的适配器不存在，请重新选择！" 
				<< endl << "请选择一个网络适配器发送数据：";
		}
	}


	pcap_t *aDevice;
	device = deviceList;
	for (int i = 1; i < userChoiceDevice; i++)
	{
		device = device->next;
	}
		aDevice = pcap_open_live(device->name, 65535, 1, 1000, errorBuf);
	cout << "连接适配器成功！"<< endl;
	

	u_int32_t net_ip,net_mask;
	pcap_lookupnet(device->name, &net_ip, &net_mask, errorBuf);
	head.ipSorceAddress.s_addr = net_ip;
	struct in_addr ip_sor;
	ip_sor.s_addr = net_ip;
	printf("本机IP地址是: %d.%d.%d.%d\n", ip_sor.S_un.S_un_b.s_b1, 
		ip_sor.S_un.S_un_b.s_b2, 
		ip_sor.S_un.S_un_b.s_b3, 
		ip_sor.S_un.S_un_b.s_b4);
	    //head.ipSorceAddress.s_impno = 36;
		//head.ipSorceAddress.s_impno);
	
	
	ipSendAddress a;
	//目的地址
	cout << "请输入目的IP地址(点分十进制)：";
	scanf_s("%d.%d.%d.%d", &a.section1, &a.section2, &a.section3, &a.section4);
	while (a.section1>255 || a.section2 > 255 || a.section3 > 255 || a.section4 > 255)
	{
		cout << "输入的IP地址不合法，请重新输入：";
		scanf_s("%d.%d.%d.%d", &a.section1, &a.section2, &a.section3, &a.section4);
	}
	head.ipDestinationAddress.S_un.S_un_b.s_b1 = a.section1;
	head.ipDestinationAddress.S_un.S_un_b.s_b2 = a.section2;
	head.ipDestinationAddress.S_un.S_un_b.s_b3 = a.section3;
	head.ipDestinationAddress.S_un.S_un_b.s_b4 = a.section4;
	
	printf("您输入的IP地址是%d.", head.ipDestinationAddress.s_net);
	printf("%d.", head.ipDestinationAddress.s_host);
	printf("%d.", head.ipDestinationAddress.s_lh);
	printf("%d\n", head.ipDestinationAddress.s_impno);
	


	cout << "请输入要发送的数据：";
	cin >> data;
	//data[0] = 0x08;
	//data[1] = 0x00;
	//data[2] = 0xbf;
	//data[3] = 0x11;
	//data[4] = 0x00;
	//data[5] = 0x06;
	//data[6] = 0x8e;
	//data[7] = 0x44;
	//data[8] = 0x61;
	//data[9] = 0x62;
	//data[10] = 0x63;
	//data[11] = 0x64;
	//data[12] = 0x65;
	//data[13] = 0x66;
	//data[14] = 0x67;
	//data[15] = 0x68;
	//data[16] = 0x69;
	//data[17] = 0x6a;
	//data[18] = 0x6b;
	//data[19] = 0x6c;
	//data[20] = 0x6d;
	//data[21] = 0x6e;
	//data[22] = 0x6f;
	//data[23] = 0x70;
	//data[24] = 0x71;
	//data[25] = 0x72;
	//data[26] = 0x73;
	//data[27] = 0x74;
	//data[28] = 0x75;
	//data[29] = 0x76;
	//data[30] = 0x77;
	//data[31] = 0x61;
	//data[32] = 0x62;
	//data[33] = 0x63;
	//data[34] = 0x64;
	//data[35] = 0x65;
	//data[36] = 0x66;
	//data[37] = 0x67;
	//data[38] = 0x68;
	//data[39] = 0x69;


	u_short packgeLocation;
	int numberOfPackge = 1;;
	int pachgeLength = lengthofData(data);
	
	if (pachgeLength> 1440)
	{
		numberOfPackge = (pachgeLength - (pachgeLength % 1440)) / 1440;
		printf("您的数据将分为%d个包进行发送；", numberOfPackge);
		int failcount = 0;
		for (int i = 0; i < numberOfPackge - 1; i++)
		{
			packgeLocation = i * 1440 + 0x0001;
			//001 + 13位偏移
			head.ipFlags_FragmentOffset = 0x02 << 12 + packgeLocation & 0x1fff;
			head.ipTotalLength = 1440 + 20;
			//
			//计算首部校验和
			u_short part[10];
			head.ipHeaderCheckSum = 0x0000;
			part[0] = head.ipVersion_HeadLength << 8 + head.ipServiceType;
			part[1] = head.ipTotalLength;
			part[2] = head.ipIdentification;
			part[3] = head.ipFlags_FragmentOffset;
			part[4] = head.TimeToLive << 8 + head.ipProtocal;
			part[5] = head.ipHeaderCheckSum;
			part[6] = head.ipSorceAddress.s_net << 8 + head.ipSorceAddress.s_host;
			part[7] = head.ipSorceAddress.s_lh << 8 + head.ipSorceAddress.s_impno;
			part[8] = head.ipDestinationAddress.s_net << 8 + head.ipDestinationAddress.s_host;
			part[9] = head.ipDestinationAddress.s_lh << 8 + head.ipDestinationAddress.s_impno;
			u_int32_t Checksum = 0x00000000;
			for (int i = 0; i<10; i++)
			{
				Checksum += part[i];
			}
			while (Checksum >> 16 != 0)
			{
				Checksum = Checksum >> 16 + Checksum & 0x0000ffff;
			}
			head.ipHeaderCheckSum = Checksum;
			//计算首部校验和
			//
			u_char ipPackage[1500];
			//
			//填充IP包
			ipPackage[0] = head.ipVersion_HeadLength;
			ipPackage[1] = head.ipServiceType;
			ipPackage[2] = head.ipTotalLength >> 8;
			ipPackage[3] = head.ipTotalLength;
			ipPackage[4] = head.ipIdentification >> 8;
			ipPackage[5] = head.ipIdentification;
			ipPackage[6] = head.ipFlags_FragmentOffset >> 8;
			ipPackage[7] = head.ipFlags_FragmentOffset;
			ipPackage[8] = head.TimeToLive;
			ipPackage[9] = head.ipProtocal;
			ipPackage[10] = head.ipHeaderCheckSum >> 8;
			ipPackage[11] = head.ipHeaderCheckSum;
			ipPackage[12] = head.ipSorceAddress.s_net;
			ipPackage[13] = head.ipSorceAddress.s_host;
			ipPackage[14] = head.ipSorceAddress.s_lh;
			ipPackage[15] = head.ipSorceAddress.s_impno;
			ipPackage[16] = head.ipDestinationAddress.s_net;
			ipPackage[17] = head.ipDestinationAddress.s_host;
			ipPackage[18] = head.ipDestinationAddress.s_lh;
			ipPackage[19] = head.ipDestinationAddress.s_impno;
			int j;
			for (j = 0; j < 1440; j++)
			{
				ipPackage[20 + j] = data[j];
			}
			ipPackage[20 + j] = '\0';
			//填充IP包
			//
			//
			//发送IP包
			if (pcap_sendpacket(aDevice, ipPackage, 1440 + 20))
			{
				printf("您的第%d包数据发送失败!", i + 1);
				failcount++;
			}
			//发送IP包
			//
		}
		//发送最后一包数据包长度不是1440的,flag为000的包

	}
	else if (pachgeLength <= 1440)//发送1个数据包
	{

		head.ipFlags_FragmentOffset = 0x0000;
		head.ipTotalLength = pachgeLength + 20;
		//
		//计算首部校验和
		u_short part[10];
		head.ipHeaderCheckSum = 0x0000;
		part[0] = head.ipVersion_HeadLength << 8 + head.ipServiceType;
		part[1] = head.ipTotalLength;
		part[2] = head.ipIdentification;
		part[3] = head.ipFlags_FragmentOffset;
		part[4] = head.TimeToLive << 8 + head.ipProtocal;
		part[5] = head.ipHeaderCheckSum;
		part[6] = head.ipSorceAddress.s_net << 8 + head.ipSorceAddress.s_host;
		part[7] = head.ipSorceAddress.s_lh << 8 + head.ipSorceAddress.s_impno;
		part[8] = head.ipDestinationAddress.s_net << 8 + head.ipDestinationAddress.s_host;
		part[9] = head.ipDestinationAddress.s_lh << 8 + head.ipDestinationAddress.s_impno;
		u_int32_t Checksum = 0x00000000;
		for (int i = 0; i<10; i++)
		{
			Checksum += part[i];
		}
		while (Checksum >> 16 != 0)
		{
			Checksum = Checksum>>16 + Checksum & 0x0000ffff;
		}
		head.ipHeaderCheckSum = Checksum;
		//计算首部校验和
		//
		u_char ipPackage[1500];
		//
		//填充IP包
		/* 假设在以太网上，设置MAC的目的地址为 B8-03-05-89-CA-47 */
		//ipPackage[0] = 0x28;
		//ipPackage[1] = 0xe3;
		//ipPackage[2] = 0x47;
		//ipPackage[3] = 0x5a;
		//ipPackage[4] = 0xb2;
		//ipPackage[5] = 0x12;
		//ipPackage[0] = 0x28;
		//ipPackage[1] = 0xe3;
		//ipPackage[2] = 0x47;
		//ipPackage[3] = 0x5a;
		//ipPackage[4] = 0xb2;
		//ipPackage[5] = 0x12;
		ipPackage[0] = 0x68;
		ipPackage[1] = 0x5d;
		ipPackage[2] = 0x43;
		ipPackage[3] = 0x7c;
		ipPackage[4] = 0x18;
		ipPackage[5] = 0x02;
		//MAC源地址为 B8-03-05-89-CA-47 */
		//ipPackage[6] = 0x5c;
		//ipPackage[7] = 0xdd;
		//ipPackage[8] = 0x70;
		//ipPackage[9] = 0xbd;
		//ipPackage[10] = 0x05;
		//ipPackage[11] = 0xda;
		ipPackage[6] = 0x68;
		ipPackage[7] = 0x5d;
		ipPackage[8] = 0x43;
		ipPackage[9] = 0x7c;
		ipPackage[10] = 0x18;
		ipPackage[11] = 0x02;
		ipPackage[12] = 8;
		ipPackage[13] = 0;
		
		ipPackage[14] = head.ipVersion_HeadLength;
		ipPackage[15] = head.ipServiceType;
		ipPackage[16] = head.ipTotalLength >> 8;
		ipPackage[17] = head.ipTotalLength;
		ipPackage[18] = head.ipIdentification >> 8;
		ipPackage[19] = head.ipIdentification;
		ipPackage[20] = head.ipFlags_FragmentOffset >> 8;
		ipPackage[21] = head.ipFlags_FragmentOffset;
		ipPackage[22] = head.TimeToLive;
		ipPackage[23] = head.ipProtocal;
		ipPackage[24] = head.ipHeaderCheckSum >> 8;
		ipPackage[25] = head.ipHeaderCheckSum;
		ipPackage[26] = head.ipSorceAddress.s_net;
		ipPackage[27] = head.ipSorceAddress.s_host;
		ipPackage[28] = head.ipSorceAddress.s_lh;
		ipPackage[29] = head.ipSorceAddress.s_impno;
		//ipPackage[30] = 10;
		//ipPackage[31] = 23;
		//ipPackage[32] = 13;
		//ipPackage[33] = 203;
		ipPackage[30] = head.ipDestinationAddress.s_net;
		ipPackage[31] = head.ipDestinationAddress.s_host;
		ipPackage[32] = head.ipDestinationAddress.s_lh;
		ipPackage[33] = head.ipDestinationAddress.s_impno;
		int i;
		for (i = 0; i < pachgeLength; i++)
		{
			ipPackage[34 + i] = data[i];
		}
		ipPackage[34 + i] = '\0';
		//填充IP包
		//
		//for (int k = 0; k < pachgeLength + 20;k++)
			//printf("%d\n", ipPackage[k]);
		//
		
		//发送IP包
		for (int fa = 0; fa < 200; fa++)
		{
			pcap_sendpacket(aDevice, ipPackage, pachgeLength + 34);
			//pcap_sendpacket(aDevice, ipPackage, 14);
		}
		if (!pcap_sendpacket(aDevice, ipPackage, pachgeLength + 34))
		{
			cout << "您的数据包发送成功!" << endl;
		}
		else
			cout << "发送数据包失败" << endl;
		//发送IP包
		//
		cout << "是否再次发送？(Y/N)";
		char angain = 'N';
		cin >> angain;
		while (angain == 'Y' || angain == 'y'){
			for (int fa = 0; fa < 200; fa++)
			{
				pcap_sendpacket(aDevice, ipPackage, pachgeLength + 34);
				//pcap_sendpacket(aDevice, ipPackage, 14);
			}
			cout << "是否再次发送？(Y/N)";
			cin >> angain;
		}
	}
    





	/*

	u_char ipPackage[1500];
	int packageLength = head.ipTotalLength;
	if (pcap_sendpacket(aDevice, ipPackage, packageLength))
	{
		cout << "数据包发送成功!" << endl;
	}
	else
		cout << "发送数据包失败" << endl;
	*/
	
	Sleep(1000000);
	pcap_close(aDevice);
	pcap_freealldevs(deviceList);
	free(&a);
	return 0;
}

int lengthofData(u_char *achar){
	int count = 0;
	while (achar[count] != '\0')
	{
		count++;
	}
	return count;
}

/*
void calculateJIAOYANHE(){
	u_short part[10];
	part[0] = head.ipVersion_HeadLength << 8 + head.ipServiceType;



	part[6] = head.ipSorceAddress.s_net << 8 + head.ipSorceAddress.s_host;
}
*/