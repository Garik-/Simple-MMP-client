//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (C) 2009-2011  Gar|k.  GNU General Public License.
//
#include "mmp.h"

int main()
{
	WSADATA ws;
	HANDLE hTh;
	WSAStartup(0x202, &ws);
	hTh=CreateThread(NULL,0,mmp_client,(LPVOID)"email:password",0,NULL);
	WaitForSingleObject(hTh, INFINITE); 
	WSACleanup();
	getchar();
	return 0;
}