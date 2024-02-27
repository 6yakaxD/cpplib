/*******************************************************\
*	@author			Ramil																			*	
*	@date				03-11-2023																*
*	@brief			This is a library for personal use.				*
*							First of all, I wrote it for myself,			*
*							so as not to repeat myself many times			*
*							and for ease of development.							*
*	@version		(beta) under development									*
*	@warning		Use at your own risk											*
*	@pre				Use strictly the C++20 standard				 		*
*							and multibyte encoding										*
*	@todo				Expand functionality and make							*
*							development easier												*
* @bug				Maybe many bugs and not the most					*
							productive solutions, but it's under			*
							development																*
*	@copyright	2023											 								*
*																  											*																	
\*******************************************************/

#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <string_view>
#include <stdio.h>
#include <thread>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <stdlib.h>
#include <direct.h>
#include <io.h>
#include <iostream>
#include <cstdlib>
#include <AclAPI.h>
#include "Sddl.h"
#include <time.h>
#include <comdef.h>
#include <WbemIdl.h>
#include <shellapi.h>

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#pragma warning(disable:4996)
#pragma warning(disable:4703)
#pragma comment(lib, "wbemuuid.lib")

/*
* @todo			Make normal structure and
*						add to all functions docs 
*/
namespace cpplib
{

	namespace file
	{
		bool remove_file(const std::string& filePath)
		{
			if (std::remove(filePath.c_str()) == 0)
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		bool clear_file(const std::string& filename)
		{
			std::ofstream out(filename);
			out.close();
			return true;
		}

		bool write_file(const std::string& text, const std::string& path)
		{
			std::ofstream file(path, std::ios_base::app);

			if (file.is_open())
			{
				file << text;
				file.close();
				return true;
			}
			else
			{
				return false;
			}
		}

		std::string read_file(const std::string& path)
		{
			std::ifstream file(path);
			if (!file.is_open())
			{
				throw std::runtime_error("Could not open file: " + path);
			}

			std::string line;
			std::string ans;
			while (std::getline(file, line))
			{
				ans += line;
				ans += "\n";
			}
			return ans;
		}

		bool path_exist(const std::string& path)
		{
			if (std::filesystem::exists(path))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		bool create_dir(const std::filesystem::path& path)
		{
			if (!std::filesystem::exists(path))
			{
				try
				{
					std::filesystem::create_directory(path);
					return true;
				}
				catch (const std::filesystem::filesystem_error& e)
				{
					return false;
				}
			}
			else
			{
				return true;
			}
		}
	}

	namespace memory
	{
		/*
	DWORD FindProcessId(const wchar_t* processName)
	{
		DWORD processId = 0;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32 processEntry;
			processEntry.dwSize = sizeof(processEntry);
			if (Process32First(hSnapshot, &processEntry))
			{
				do
				{
					if (_wcsicmp(processEntry.szExeFile, processName) == 0)
					{
						processId = processEntry.th32ProcessID;
						break;
					}
				} while (Process32Next(hSnapshot, &processEntry));
			}
			CloseHandle(hSnapshot);
		}
		return processId;
	}

	uintptr_t readProcessMemory(HANDLE process_handle, const std::uintptr_t target_address) noexcept
	{
		std::uintptr_t buffer = { };

		if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(target_address), &buffer, sizeof(std::uintptr_t), nullptr))
		{
			std::cout << "ReadProcessMemoryError: " + GetLastError() << std::endl;
		}

		return buffer;
	}

	bool writeProcessMemory(HANDLE process_handle, const std::uintptr_t target_address, const std::uintptr_t& value) noexcept
	{
		if (!WriteProcessMemory(process_handle, reinterpret_cast<void*>(target_address), &value, sizeof(std::uintptr_t), nullptr))
		{
			return false;
		}
		return true;
	}

	uintptr_t getModuleBaseAddress(DWORD process_id, const std::string& module_name)
	{
		HANDLE l_ModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32 a;

		l_ModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, process_id);
		if (l_ModuleSnap == INVALID_HANDLE_VALUE)
			return 0;

		a.dwSize = sizeof(MODULEENTRY32);
		if (!Module32First(l_ModuleSnap, &a))
		{
			CloseHandle(l_ModuleSnap);
			return 0;
		}

		do
		{

			if (strcmp(a.szModule, module_name.c_str()) == 0)
			{
				CloseHandle(l_ModuleSnap);
				return (uintptr_t)a.modBaseAddr;
			}

		} while (Module32Next(l_ModuleSnap, &a));

		return 0;
	}
	*/
	}

	namespace system
	{
		int get_screen_width()
		{
			return GetSystemMetrics(SM_CXSCREEN);
		}

		int get_screen_height()
		{
			return GetSystemMetrics(SM_CYSCREEN);
		}

		void hide_console()
		{
			/*
			HWND hWnd;
			AllocConsole();
			hWnd = FindWindowA("ConsoleWindowClass", 0);
			ShowWindow(hWnd, 0);

			ShowWindow(FindWindowA("ConsoleWindowClass", NULL), 1); // 0 -> консоль спрятана
			*/
			ShowWindow(FindWindowA("ConsoleWindowClass", NULL), 0); // 0 -> консоль спрятана 
		}

		void show_console()
		{
			ShowWindow(FindWindowA("ConsoleWindowClass", NULL), 1); // 0 -> консоль спрятана
		}

		std::string get_username()
		{
			char env[] = "USERNAME";
			DWORD username_len = 257;
			char buffer[4096];

			unsigned int out_size = GetEnvironmentVariableA(env, buffer, username_len);

			return std::string(buffer, out_size);
		}

		std::string get_date()
		{
			auto t = std::time(nullptr);
			auto tm = *std::localtime(&t);

			std::ostringstream oss;
			oss << std::put_time(&tm, "%d-%m-%Y-%H-%M-%S");
			auto str = oss.str();
			/*output: day-month-year-hour-minute-second*/
			return str;
		}

		void add_toAutoLoad(std::string Name, std::string Path)
		{
			std::string command = "REG ADD \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /V " + Name + " /t REG_SZ /F /D " + Path;
			system(command.c_str());
		}

		DWORD get_hwid() {
			char volumeName[MAX_PATH + 1] = { 0 };
			char fileSystemName[MAX_PATH + 1] = { 0 };
			DWORD serialNumber = 0;
			DWORD maxComponentLen = 0;
			DWORD fileSystemFlags = 0;

			if (GetVolumeInformation("C:\\", volumeName, ARRAYSIZE(volumeName), &serialNumber, &maxComponentLen, &fileSystemFlags, fileSystemName, ARRAYSIZE(fileSystemName)))
			{
				return serialNumber;
			}
			else
			{
				return false;
			}
		}

		int get_ProcessorName() {
			HRESULT hres;

			hres = CoInitializeEx(0, COINIT_MULTITHREADED);
			if (FAILED(hres))
			{
				std::cout << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
				return 1;
			}

			hres = CoInitializeSecurity(
				NULL,
				-1,
				NULL,
				NULL,
				RPC_C_AUTHN_LEVEL_DEFAULT,
				RPC_C_IMP_LEVEL_IMPERSONATE,
				NULL,
				EOAC_NONE,
				NULL);
			if (FAILED(hres))
			{
				std::cout << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
				CoUninitialize();
				return 1;
			}

			IWbemLocator* pLoc = NULL;
			hres = CoCreateInstance(
				CLSID_WbemLocator, 0,
				CLSCTX_INPROC_SERVER,
				IID_IWbemLocator, (LPVOID*)&pLoc);
			if (FAILED(hres))
			{
				std::cout << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hres << std::endl;
				CoUninitialize();
				return 1;
			}

			IWbemServices* pSvc = NULL;
			hres = pLoc->ConnectServer(
				_bstr_t(L"ROOT\\CIMV2"),
				NULL,
				NULL,
				0,
				NULL,
				0,
				0,
				&pSvc);
			if (FAILED(hres))
			{
				std::cout << "Could not connect to WMI namespace. Error code = 0x" << std::hex << hres << std::endl;
				pLoc->Release();
				CoUninitialize();
				return 1;
			}

			hres = CoSetProxyBlanket(
				pSvc,
				RPC_C_AUTHN_WINNT,
				RPC_C_AUTHZ_NONE,
				NULL,
				RPC_C_AUTHN_LEVEL_CALL,
				RPC_C_IMP_LEVEL_IMPERSONATE,
				NULL,
				EOAC_NONE);
			if (FAILED(hres))
			{
				std::cout << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
				pSvc->Release();
				pLoc->Release();
				CoUninitialize();
				return 1;
			}

			IEnumWbemClassObject* pEnumerator = NULL;
			hres = pSvc->ExecQuery(
				_bstr_t("WQL"),
				_bstr_t("SELECT * FROM Win32_Processor"),
				WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
				NULL,
				&pEnumerator);
			if (FAILED(hres))
			{
				std::cout << "Query for operating system name failed. Error code = 0x" << std::hex << hres << std::endl;
				pSvc->Release();
				pLoc->Release();
				CoUninitialize();
				return 1;
			}

			IWbemClassObject* pclsObj = NULL;
			ULONG uReturn = 0;

			while (pEnumerator)
			{
				hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

				if (0 == uReturn)
				{
					break;
				}

				VARIANT vtProp;
				hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);

				wprintf(L"Processor Name: %s\n", vtProp.bstrVal);
				VariantClear(&vtProp);

				pclsObj->Release();
			}

			pSvc->Release();
			pLoc->Release();
			pEnumerator->Release();
			CoUninitialize();
		}

		std::string get_OsName()
		{
			std::string os;
			char* ostype = getenv("OSTYPE");
			if (ostype == NULL)
			{
				ostype = getenv("windir");
				if (ostype != NULL)
				{
					os = "Windows";
					return os;
				}
			}
			else
			{
				if (strcmp(ostype, "linux") == 0)
				{
					os = "Linux";
					return os;
				}
				else if (strcmp(ostype, "hpux") == 0)
				{
					os = "Hpux";
					return os;
				}
				else if (strcmp(ostype, "solaris") == 0)
				{
					os = "Solaris";
					return os;
				}
				else if (strcmp(ostype, "darwin") == 0)
				{
					os = "Darwin";
					return os;
				}
			}
		}

		void turnOff_monitor()
		{
			SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)2);
		}

		void turnOn_monitor()
		{
			SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)-1);
		}

		void SendInformationNotification(const char* title, const char* message) {
			NOTIFYICONDATA nid = { sizeof(NOTIFYICONDATA) };
			nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
			nid.hIcon = LoadIcon(NULL, IDI_INFORMATION);
			nid.uCallbackMessage = WM_USER;
			lstrcpy(nid.szTip, "Информация");
			Shell_NotifyIcon(NIM_ADD, &nid);
			nid.uFlags = NIF_INFO;
			lstrcpyn(nid.szInfo, message, sizeof(nid.szInfo));
			lstrcpyn(nid.szInfoTitle, title, sizeof(nid.szInfoTitle));
			nid.dwInfoFlags = NIIF_INFO;
			Shell_NotifyIcon(NIM_MODIFY, &nid);
			Sleep(5000); // Ожидание 5 секунд
			Shell_NotifyIcon(NIM_DELETE, &nid);
		}

		void print_CurrTime()
		{
			time_t currentTime = time(0);
			struct tm* localTime = localtime(&currentTime);
			std::cout << ", date -> " << localTime->tm_year + 1900 << "-" << localTime->tm_mon + 1 << "-" << localTime->tm_mday << " | " << localTime->tm_hour << ":" << localTime->tm_min << ":" << localTime->tm_sec << std::endl;
		}
	}


	/*---------------[ Files && Directories ]---------------*/

	/*----------------------[ Memory ]----------------------*/

	/*----------------------[ System ]----------------------*/
	

}