//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (C) 2009-2011  Gar|k.  GNU General Public License.
//
#include "mmp.h"

BOOL md5(unsigned char *hash_value,unsigned char *string,int count) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	BOOL res=FALSE;
	char *keyName=NULL; DWORD dwFlags=0;

	// Инициализация контекста криптопровайдера
init_crypt:
	if (!CryptAcquireContext(&hProv, keyName, NULL, PROV_RSA_FULL, dwFlags))
	{
		if(GetLastError() != NTE_BAD_KEYSET) return FALSE;
		if(!dwFlags) 
		{ 
			keyName="_"; dwFlags=CRYPT_MACHINE_KEYSET;  
			goto init_crypt;  
		}
		dwFlags=CRYPT_NEWKEYSET; 
		goto init_crypt; 
	}

	// Cоздание хеш-объекта
	if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		// Передача хешируемых данных хэш-объекту.
		if (CryptHashData(hHash, string, count, 0))
		{
			// Получение хеш-значения
			count = MD5_SIZE;
			if (CryptGetHashParam(hHash, HP_HASHVAL, hash_value, &count, 0)) res=TRUE;
		}
		CryptDestroyHash(hHash);
	}

	CryptReleaseContext(hProv,0);
	return res;
}

int tcp_rs(unsigned char type,SOCKET s, void *buf, int len, int flags) {
	int total = 0;
	int n;
	*(void* *)&tcp_func=(type==SEND)?&send:&recv;

	while(total < len) {
		n = tcp_func(s, (char *)buf+total, len-total, flags);

		if(n>0) { total += n; }
		else if(n == 0) { 
			closesocket(s);
			return 0;
		}
		else {
			n=WSAGetLastError();
			closesocket(s);
			return (!n+1);
		}
	}

	return total;
}

int SendPack(SOCKET s,unsigned int msg,unsigned int len,void *data) {
	int n;
	struct mrim_packet_header_t pack;
	memset(&pack,0,sizeof(mrim_packet_header_t));
	pack.magic=CS_MAGIC;
	pack.proto=PROTO_VERSION;
	pack.msg=msg;
	pack.dlen=len;

	n=tcp_rs(SEND,s,&pack,sizeof(mrim_packet_header_t),0);
	if(len>0 && n>0){
		n=tcp_rs(SEND,s,data,len,0);
	}
	return n;
}

int RecvPack(SOCKET s,mrim_packet_header_t *pack) {
	int n;
	while(pack->magic!=CS_MAGIC) {
		if((n=tcp_rs(RECV,s,pack,sizeof(pack->magic),0))<=0) return n; 
	}
	n=tcp_rs(RECV,s,&pack->proto,sizeof(mrim_packet_header_t)-sizeof(pack->magic),0);
	return n;
}

int RecvData(SOCKET s,int len) {
	int pMem,n;
	if((pMem=(int)VirtualAlloc(0,len,MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL) return -1;
	if((n=tcp_rs(RECV,s,(unsigned char *)pMem,len,0))>0) return pMem;
	return n;
}

BOOL mmp_get_conserver(struct sockaddr_in *dest_addr) {
	HOSTENT *hst;
	SOCKET my_sock;
	char buff[20],*p;
	BOOL ret=FALSE;

	dest_addr->sin_family = AF_INET;
	dest_addr->sin_port = htons(MRIM_PORT);

	if ((my_sock = socket(AF_INET, SOCK_STREAM, 0)) !=INVALID_SOCKET) {
		if (hst = gethostbyname(MRIM_HOST)) {
			((unsigned long *)&dest_addr->sin_addr)[0] = ((unsigned long **)hst->h_addr_list)[0][0];

			if (connect(my_sock, (struct sockaddr*)dest_addr, sizeof(*dest_addr))==0)
			{
				recv(my_sock, buff, 20, 0);
				p=buff; while(*p++!=':'); *--p=0; 

				dest_addr->sin_addr.s_addr=inet_addr(buff);
				dest_addr->sin_port=htons(atoi(&p[1]));

				ret=TRUE;
			}
		}
		closesocket(my_sock);
	}
	return ret;
}

// инициализация соединения с сервером MMP
SOCKET mmp_connect() {
	SOCKET my_sock;
	struct sockaddr_in dest_addr; // адрес сокета
	static struct tcp_keepalive alive;
	DWORD  dwSize;

	alive.onoff = 1;
	alive.keepalivetime = KEEP_ALIVE;
	alive.keepaliveinterval = 1000;

	if ((my_sock = socket(AF_INET, SOCK_STREAM, 0)) !=INVALID_SOCKET) {
		if(mmp_get_conserver(&dest_addr)) {
			if (connect(my_sock, (struct sockaddr*)&dest_addr, sizeof(dest_addr))==0) {
				WSAIoctl(my_sock, SIO_KEEPALIVE_VALS, &alive, sizeof(alive),NULL, 0, &dwSize, NULL, NULL);
				return my_sock;
			}
		}
		closesocket(my_sock);
		my_sock=INVALID_SOCKET;
	}

	return my_sock;
}

DWORD WINAPI mmp_client(PVOID email) {
	mrim_packet_header_t sc;
	char *data=NULL;

	int cont_count=0;
	char **cont_list;

	int err=0;
	SOCKET sock=mmp_connect();
	if(sock==INVALID_SOCKET) return err;

	err=SendPack(sock,MRIM_CS_HELLO,0,NULL);

	while(sock!=INVALID_SOCKET) 
	{
		memset(&sc,0,sizeof(sc));
		err=RecvPack(sock,&sc);
		if(sc.dlen>0 && err>0) 
		{ 
			data=(char *)RecvData(sock,sc.dlen);
			err=(int)data;
		}
		switch(sc.msg) 
		{
		case MRIM_CS_HELLO_ACK:
			err=mmp_login(sock,(char *)email);
			break;
		case MRIM_CS_LOGIN_ACK:
			printf("[+] LOGIN OK\n");
			break;
		case MRIM_CS_LOGIN_REJ:
			printf("[-] LOGIN ERR\n");
			err=0;
			break;
		case MRIM_CS_CONTACT_LIST2:
			cont_list=contact_list(data,sc.dlen,&cont_count);
			// освобождаем список
			if(cont_count>0) {
				while(cont_count-- > 0) { 
					printf("%s\n",cont_list[cont_count]);
					free(cont_list[cont_count]);
				}
				free(cont_list);
			}
			err=0;
			break;
		}
		if(sc.dlen>0) FreeData(data);
		if(err<=0) break;
	}

	if(sock!=INVALID_SOCKET) closesocket(sock);
	return err;
}

//------------------------------------------
int mmp_login(SOCKET sock,char *email) // оптимизированная версия
{
	char *p,*p1,*p2,buff[512];
	struct mrim_packet_header_t pack;
	memset(&pack,0,sizeof(mrim_packet_header_t));

	p=buff;
	p2=email;
	while(*p2++!=':'); // терь p2 указывает на пасс с завершающим нулем

	*(DWORD *)&p[0]=p2-email-1; pack.dlen=4;
	memcpy(&p[pack.dlen],email,*(DWORD *)&p[0]); pack.dlen+=*(DWORD *)&p[0];
	*(DWORD *)&p[pack.dlen]=MD5_SIZE; pack.dlen+=4;

	p1=p2;
	while(*p2++!=0);

	md5((BYTE *)&p[pack.dlen],(BYTE *)p1,(p2-p1-1)); pack.dlen+=MD5_SIZE;

	pack.dlen+=sizeof(client_info);
	pack.msg=MRIM_CS_LOGIN3;
	pack.magic=CS_MAGIC;
	pack.proto=PROTO_VERSION;

	pack.seq=tcp_rs(SEND,sock,(char *)&pack,sizeof(mrim_packet_header_t),0);
	if(pack.dlen>0 && pack.seq>0){
		if((pack.seq=tcp_rs(SEND,sock,(char *)p,pack.dlen-sizeof(client_info),0))>0)
			pack.seq=tcp_rs(SEND,sock,(char *)client_info,sizeof(client_info),0);
	}
	return pack.seq;
}

__inline int get_data(char *buf,char mask,struct LPS *l)
{
	//*n=-666;
	l->str=NULL;
	l->len=0;
	if(mask=='u') { 
		//*n=*(int *)buf;
		return 4;
	}
	if(mask=='s') {
		l->len=*((int *)buf);
		l->str=&buf[4];
		return l->len+4;
	}
}

char **contact_list(char *buffer,int len,int *cnt)
{
	int count=0,i=4,k,j,offset=0,group_number,group_mask_size,contact_mask_size;
	char *group_mask,*contackt_mask;
	char **list;
	LPS lps;

	if(buffer==NULL || *((DWORD *)buffer)!=GET_CONTACTS_OK) return NULL;
	list=(char **)malloc(sizeof(char *)*2);

	//---------------------------------------------------------------------------------------------
	group_number=*((int *)&buffer[i]); i+=4;
	group_mask_size=*((int *)&buffer[i]); i+=4;
	group_mask=&buffer[i]; i+=group_mask_size;
	contact_mask_size=*((int *)&buffer[i]); i+=4;
	contackt_mask=&buffer[i]; i+=contact_mask_size;

	offset=i;


	// проходимся по группам
	for(k=0;k<group_number;k++)
	{
		for(j=0;j<group_mask_size;j++) {
			offset+=get_data(&buffer[offset],group_mask[j],&lps);
		}
	}
	// теперь пошли контакты

	while(offset<len) // пока смещение меньше буфера
	{
		char femail=0; // нас интересует только первое поле e-mail
		for(j=0;j<contact_mask_size;j++) {
			offset+=get_data(&buffer[offset],contackt_mask[j],&lps);
			if(lps.len>0 && femail==0) { 						
				char *p=(char *)malloc(lps.len+1);
				memcpy(p,lps.str,lps.len);
				p[lps.len]=0;
				list[count++]=p;
				if(count % 2 == 0){ list=(char **)realloc(list,sizeof(char *) * (count+2));  } // расширим если переполнение
				p=NULL;

				femail=1;
			}
		}
	}
	//---------------------------------------------------------------------------------------------


	list[count]=NULL;
	*cnt=count;
	return list;
}
