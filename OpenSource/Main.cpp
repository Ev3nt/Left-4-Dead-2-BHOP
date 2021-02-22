#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#define WINDOWNAME "Left 4 Dead 2"
#define SERVERDLL "server.dll"
#define CLIENTDLL "\\client.dll"

const DWORD plr_list_offset = 0x7CC53C;
const DWORD plr_status_offset = 0x13C;
const DWORD fJump = 0x739A48;

DWORD server_dll_base;
DWORD client_dll_base;
HANDLE hProcess;

const bool b_true = true;
const bool b_false = false;

HANDLE get_process_handle();
int read_bytes(LPVOID addr, int num, LPVOID buf);
int write_bytes(LPVOID addr, int num, LPCVOID buf);

void Routine();

//-------------------------------------------------------

int main()
{
	hProcess = get_process_handle();
	Routine();
	CloseHandle(hProcess);

	return 0;
}

//-------------------------------------------------------

void Routine()
{
	DWORD plr_addr;
	DWORD addr = server_dll_base + plr_list_offset;

	int status;

	for (;; Sleep(20))
	{
		if (GetAsyncKeyState(VK_SPACE))
		{
			read_bytes((LPVOID)(addr), 4, &plr_addr);
			read_bytes((LPVOID)(plr_addr + plr_status_offset), 4, &status);

			if (status & (1 << 0))
				write_bytes((LPVOID)(client_dll_base + fJump), sizeof(bool), &b_true);
			else if (status & (2 << 0))
				write_bytes((LPVOID)(client_dll_base + fJump), sizeof(bool), &b_false);
		}
	}
}

int read_bytes(LPVOID addr, int num, LPVOID buf)
{
	if (!ReadProcessMemory(hProcess, addr, buf, num, NULL))
	{
		printf("readprocessmemory failed. %08X\n", GetLastError());

		return 0;
	}

	return 1;
}

int write_bytes(LPVOID addr, int num, LPCVOID buf)
{
	if (!WriteProcessMemory(hProcess, addr, buf, num, NULL))
	{
		printf("writeprocessmemory failed. %08X\n", GetLastError());

		return 0;
	}

	return 1;
}

HANDLE get_process_handle()
{
	HANDLE handle = NULL;
	DWORD pid = 0;
	HWND hWnd = FindWindow(0, WINDOWNAME);

	if (!hWnd)
	{
		printf("FindWindow failed. %08X\n", GetLastError());

		return handle;
	}

	printf("hWnd = %08X\n", (UINT)hWnd);

	GetWindowThreadProcessId(hWnd, &pid);
	handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

	if (!handle)
	{
		printf("OpenProcess failed. %08X\n", GetLastError());

		return handle;
	}

	printf("process handle = %08X\n", (UINT)handle);

	HMODULE hMods[1024];
	if (!EnumProcessModules(handle, hMods, sizeof(hMods), &pid))
		printf("enumprocessmodules failed. %08X\n", GetLastError());
	else
	{
		for (unsigned int i = 0; i < (pid / sizeof(HMODULE)); i++)
		{
			char szModName[MAX_PATH];
			if (GetModuleFileNameEx(handle, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
			{
				if (strstr(szModName, SERVERDLL))
				{
					printf("server dll base: %08X\n", (UINT)hMods[i]);
					server_dll_base = (DWORD)hMods[i];
				}
				else if (strstr(szModName, CLIENTDLL))
				{
					printf("client dll base: %08X\n", (UINT)hMods[i]);
					client_dll_base = (DWORD)hMods[i];
				}
			}
		}
	}

	return handle;
}