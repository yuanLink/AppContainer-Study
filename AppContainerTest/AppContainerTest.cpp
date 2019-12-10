// AppContainerTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "../AppContainer/CommHeader.h"
#include <iostream>
#include <Windows.h>
#include <strsafe.h>
#include <sddl.h>
#include <UserEnv.h>
#include <Shlwapi.h>

#pragma comment(lib,"Userenv")
#pragma comment(lib,"Shlwapi")
#pragma comment(lib,"kernel32")
#pragma comment(lib,"user32")
#pragma comment(lib,"Advapi32")
#pragma comment(lib,"Ole32")


int main()
{
	HANDLE hToken = GetCurrentProcessToken();
	DWORD dwRetLength;
	LPWSTR wszTokenSID = nullptr;
	_TOKEN_APPCONTAINER_INFORMATION * tkAppContainer;
	GetTokenInformation(hToken, TokenAppContainerSid, NULL, NULL, &dwRetLength);
	tkAppContainer = reinterpret_cast<_TOKEN_APPCONTAINER_INFORMATION *>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRetLength));

	if (!GetTokenInformation(hToken, TokenAppContainerSid, tkAppContainer, dwRetLength, &dwRetLength)) {
		std::cout << "Get User Token faield with error code 0x:" << std::hex << GetLastError() << std::endl;
		return -1;
	}
	ConvertSidToStringSidW(tkAppContainer->TokenAppContainer, &wszTokenSID);
	if(wszTokenSID != nullptr)
		std::wcout << wszTokenSID << std::endl;
	HANDLE mEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, COMMONOBJECT);
	std::cout << "mEvent is :" << std::hex << mEvent << std::endl;
	std::cout << "GetLastError is :" << std::hex << GetLastError() << std::endl;
	//LocalFree(tkAppContainer);
	HeapFree(GetProcessHeap(), NULL, tkAppContainer);
	LocalFree(wszTokenSID);
	Sleep(5000);
	//system("pause");
	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
