#include <StdInc.h>
#include "Utility/InitFunction.h"
#include "Functions/Global.h"
#include "MinHook.h"
#include <Utility/Hooking.Patterns.h>
#include <thread>
#include <iostream>
#include <Windowsx.h>
#include <Utility/TouchSerial/MT6.h>
#include "Network/Certificate.cpp"
#include "Network/AddressHook.cpp"
#include "Banapass/BanapassEmuwM6.h"
#include <Shlwapi.h>
#include "json/json.hpp"
#include <tlhelp32.h>
#ifdef _M_AMD64
#pragma optimize("", off)
#pragma comment(lib, "Ws2_32.lib")

extern LPCSTR hookPort;
static uintptr_t imageBase;
static unsigned char hasp_buffer[0xD40];
static const char* ipaddr;


// Data for Force Feedback OFF
static unsigned char settingData[481] = {
	0x1F, 0x8B, 0x08, 0x00, 0xE4, 0xD8, 0x1E, 0x64, 0x00, 0xFF, 0x85, 0x94, 0xDB, 0x6E, 0xE2, 0x30,
	0x10, 0x86, 0xEF, 0x79, 0x0A, 0x5E, 0x80, 0xAA, 0x04, 0x96, 0xB2, 0x17, 0x7B, 0x01, 0x81, 0x2C,
	0x95, 0x9A, 0x2D, 0x82, 0xA8, 0xD5, 0xF6, 0xCE, 0x38, 0x03, 0xB1, 0xF0, 0x01, 0x39, 0xF6, 0xAE,
	0x78, 0xFB, 0x1D, 0xC7, 0x39, 0x38, 0x2D, 0x5A, 0xB8, 0x88, 0xF8, 0xBF, 0xDF, 0x33, 0x99, 0xF1,
	0x8C, 0x32, 0x1A, 0xFD, 0xFF, 0x37, 0x70, 0x8F, 0x61, 0x09, 0xC6, 0x30, 0x79, 0x7A, 0xE0, 0x96,
	0x0C, 0xEE, 0x04, 0x8C, 0x06, 0x03, 0x11, 0x13, 0xCE, 0x0E, 0x1B, 0x22, 0x73, 0x0E, 0x31, 0x48,
	0x03, 0x7A, 0xF8, 0x63, 0x38, 0x89, 0x9E, 0x66, 0xF3, 0xDA, 0x5A, 0x50, 0x0A, 0xBC, 0x75, 0x1E,
	0x6B, 0xBA, 0xD4, 0xE4, 0x0C, 0x5F, 0x68, 0xAA, 0x8C, 0xD2, 0x2D, 0xFD, 0x36, 0x1E, 0xD7, 0x3C,
	0x53, 0x96, 0x16, 0x2F, 0x70, 0x34, 0x48, 0xA3, 0xC7, 0xE9, 0x3C, 0xC4, 0x3B, 0x76, 0x2A, 0x1C,
	0x1F, 0x4F, 0x27, 0x93, 0x59, 0x68, 0x64, 0xEA, 0x72, 0x0B, 0x2F, 0x95, 0x31, 0x4A, 0x74, 0x89,
	0x14, 0x93, 0x71, 0x61, 0x0D, 0xB8, 0xB3, 0x03, 0xB1, 0xB4, 0xD7, 0x98, 0xE8, 0x3C, 0x56, 0xA5,
	0xCB, 0x89, 0xFE, 0x4F, 0x22, 0xA0, 0x56, 0x13, 0x77, 0x5A, 0xE2, 0xDD, 0xD8, 0x80, 0x24, 0x96,
	0xF3, 0x58, 0x59, 0x5D, 0x36, 0xEC, 0x09, 0x99, 0x06, 0xD8, 0x72, 0x72, 0xF5, 0x29, 0xB7, 0xF4,
	0xF0, 0x9C, 0xFB, 0x26, 0x9F, 0xA9, 0x4B, 0xBE, 0xFB, 0xEB, 0x0D, 0xAF, 0xDE, 0x40, 0xE6, 0xCD,
	0x25, 0xA4, 0xA7, 0xD6, 0x47, 0x95, 0x28, 0x4D, 0x21, 0x01, 0xC8, 0x0F, 0x84, 0x9E, 0x3D, 0x7A,
	0x67, 0xB2, 0x5C, 0xC8, 0x7C, 0x07, 0x82, 0xE0, 0x3F, 0x9F, 0x66, 0xFD, 0x07, 0x2F, 0x2C, 0x55,
	0x39, 0xF8, 0x23, 0xAD, 0x5C, 0xB1, 0xAA, 0x9E, 0x10, 0x61, 0xA1, 0xD2, 0xB1, 0x69, 0xC0, 0x22,
	0x25, 0xA3, 0x7A, 0x04, 0x5C, 0x95, 0x90, 0x5D, 0x2F, 0x2E, 0x51, 0x54, 0xCB, 0xBD, 0x95, 0xA8,
	0xBE, 0xCF, 0x6A, 0x99, 0xAA, 0x9E, 0xCC, 0x2C, 0x84, 0xF2, 0x1D, 0xF2, 0x9E, 0x5B, 0xD8, 0x50,
	0x26, 0x9A, 0x85, 0x72, 0x4F, 0x4C, 0x28, 0x57, 0xD5, 0x75, 0x39, 0x59, 0x4D, 0x69, 0x4B, 0x24,
	0x70, 0xDF, 0x9F, 0x9B, 0xC0, 0x9B, 0xAA, 0x04, 0x16, 0xB9, 0x30, 0x46, 0x13, 0x6A, 0x3A, 0x80,
	0xD1, 0xF4, 0xFC, 0x7A, 0x3C, 0xE2, 0xDA, 0xFA, 0x36, 0x32, 0x26, 0xE0, 0x43, 0xC9, 0xA6, 0x13,
	0x37, 0x7D, 0x87, 0xF0, 0x05, 0x2F, 0xF5, 0xAA, 0x04, 0x87, 0x36, 0x38, 0xBA, 0x36, 0x78, 0xDE,
	0xF1, 0x94, 0xC9, 0x30, 0xE7, 0xDE, 0x0A, 0x01, 0xDA, 0x99, 0xBD, 0x80, 0x9E, 0xF3, 0x29, 0x04,
	0xDB, 0xD0, 0x12, 0x4B, 0x0F, 0x67, 0xD3, 0xB1, 0x8D, 0xE2, 0xF9, 0x6F, 0x20, 0xBA, 0xDA, 0xC3,
	0xF1, 0xEC, 0xB3, 0x85, 0xF7, 0x6C, 0x0A, 0xDF, 0x7E, 0xDF, 0x58, 0x35, 0x5B, 0xD5, 0xE1, 0xB5,
	0x34, 0xFA, 0xEA, 0xCA, 0xBA, 0x69, 0x60, 0x55, 0x7E, 0xB9, 0xBF, 0xBC, 0xBE, 0x09, 0x89, 0x42,
	0xA3, 0x70, 0x2F, 0xBF, 0x19, 0x12, 0x2B, 0x71, 0x01, 0xC3, 0x0C, 0x53, 0xF2, 0x97, 0x15, 0x7E,
	0x89, 0x3A, 0x77, 0x4B, 0xB4, 0x61, 0x94, 0x5D, 0x88, 0x34, 0xDE, 0xC5, 0x9E, 0xEE, 0x7E, 0x3C,
	0xAA, 0xCF, 0xCD, 0xFA, 0x35, 0xB9, 0x7F, 0xF2, 0x1F, 0xDD, 0x12, 0x36, 0xDA, 0xBA, 0x04, 0x00,
	0x00
};

static std::string removeCharsFromString(std::string& str, char* charsToRemove) {
	for (unsigned int i = 0; i < strlen(charsToRemove); ++i) {
		str.erase(remove(str.begin(), str.end(), charsToRemove[i]), str.end());
	}

	return str;
}

#define HASP_STATUS_OK 0
static unsigned int Hook_hasp_login(int feature_id, void* vendor_code, int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_login\n");
#endif
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_logout(int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_logout\n");
#endif
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_encrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_encrypt\n");
#endif
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_decrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_decrypt\n");
#endif
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_get_size(int hasp_handle, int hasp_fileid, unsigned int* hasp_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_get_size\n");
#endif
	* hasp_size = 0xD40; // Max addressable size by the game... absmax is 4k
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_read(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_read\n");
#endif
	memcpy(buffer, hasp_buffer + offset, length);
	return HASP_STATUS_OK;
}

static unsigned int Hook_hasp_write(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
	return HASP_STATUS_OK;
}

//set system date patch by pockywitch
typedef bool (WINAPI* SETSYSTEMTIME)(SYSTEMTIME* in);
static SETSYSTEMTIME pSetSystemTime = NULL;

static bool WINAPI Hook_SetSystemTime(SYSTEMTIME* in)
{
	return TRUE;
}

typedef int (WINAPI* BIND)(SOCKET, CONST SOCKADDR*, INT);
static BIND pbind = NULL;

static unsigned int WINAPI Hook_bind(SOCKET s, const sockaddr* addr, int namelen) {
	sockaddr_in bindAddr = { 0 };
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_addr.s_addr = inet_addr("192.168.96.20");
	bindAddr.sin_port = htons(50765);
	if (addr == (sockaddr*)&bindAddr) {
		sockaddr_in bindAddr2 = { 0 };
		bindAddr2.sin_family = AF_INET;
		bindAddr2.sin_addr.s_addr = inet_addr(ipaddr);
		bindAddr2.sin_port = htons(50765);
		return pbind(s, (sockaddr*)&bindAddr2, namelen);
	}
	else {
		return pbind(s, addr, namelen);

	}
}

static int ReturnTrue()
{
	return 1;
}

static BYTE GenerateChecksum(unsigned char *myArray, int index, int length)
{
	BYTE crc = 0;
	for(int i = 0; i < length; i++)
	{
		crc += myArray[index + i];
	}
	return crc & 0xFF;
}

static void GenerateDongleData(bool isTerminal)
{
	memset(hasp_buffer, 0, 0xD40);
	hasp_buffer[0] = 0x01;
	hasp_buffer[0x13] = 0x01;
	hasp_buffer[0x17] = 0x0A;
	hasp_buffer[0x1B] = 0x04;
	hasp_buffer[0x1C] = 0x3B;
	hasp_buffer[0x1D] = 0x6B;
	hasp_buffer[0x1E] = 0x40;
	hasp_buffer[0x1F] = 0x87;

	hasp_buffer[0x23] = 0x01;
	hasp_buffer[0x27] = 0x0A;
	hasp_buffer[0x2B] = 0x04;
	hasp_buffer[0x2C] = 0x3B;
	hasp_buffer[0x2D] = 0x6B;
	hasp_buffer[0x2E] = 0x40;
	hasp_buffer[0x2F] = 0x87;
	if (isTerminal)
	{
		memcpy(hasp_buffer + 0xD00, "280811990002", 12); // not sure these are OK, since its from google lol.
		hasp_buffer[0xD3E] = GenerateChecksum(hasp_buffer, 0xD00, 62);
		hasp_buffer[0xD3F] = hasp_buffer[0xD3E] ^ 0xFF;
	}
	else
	{
		memcpy(hasp_buffer + 0xD00, "280813990002", 12);
		hasp_buffer[0xD3E] = GenerateChecksum(hasp_buffer, 0xD00, 62);
		hasp_buffer[0xD3F] = hasp_buffer[0xD3E] ^ 0xFF;
	}
}

static HWND mt6Hwnd;

typedef BOOL (WINAPI* ShowWindow_t)(HWND, int);
static ShowWindow_t pShowWindow;

// Hello Win32 my old friend...
typedef LRESULT (WINAPI* WindowProcedure_t)(HWND, UINT, WPARAM, LPARAM);
static WindowProcedure_t pMaxituneWndProc;

static BOOL gotWindowSize = FALSE;

static LRESULT Hook_WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (!gotWindowSize)
	{
		mt6SetDisplayParams(hwnd);
		gotWindowSize = TRUE;
	}

	if (msg == WM_LBUTTONDOWN ||
		msg == WM_LBUTTONUP)
	{
		mt6SetTouchData(lParam, msg == WM_LBUTTONDOWN, false);
		return 0;
	}

	if (msg == WM_POINTERDOWN ||
		msg == WM_POINTERUP)
	{
		mt6SetTouchData(lParam, msg == WM_POINTERDOWN, true);
		return 0;
	}

	return pMaxituneWndProc(hwnd, msg, wParam, lParam);
}

static BOOL Hook_ShowWindow(HWND hwnd, int nCmdShow)
{
	SetWindowLongPtrW(hwnd, -4, (LONG_PTR)Hook_WndProc);
	ShowCursor(1);

	mt6Hwnd = hwnd;
	return pShowWindow(hwnd, nCmdShow);
}

typedef void (WINAPI* OutputDebugStringA_t)(LPCSTR);

static void Hook_OutputDebugStringA(LPCSTR str)
{
	printf("debug> %s", str);
}

// Fix Crash
char hook_chargeCrash_6(int a1, int a2) {
	return 1;
}

static void patchResolution() {
	// thx kitsu
	std::string ystr = config["General"]["Resolution"];

	int32_t yRes = std::stoi(ystr);
	int32_t xRes = (16 * yRes) / 9;
	float ratio = (float)765.0 / (float)yRes;

	if (yRes == 768) { return; }
	// custom scaling machine code
	// shape
	injector::WriteMemoryRaw(imageBase + 0x909496, "\xE9\xD5\x5F\x5F\x00\x90", 6, true);
	injector::WriteMemoryRaw(imageBase + 0xEFF470, "\xC7\x45\xD8\x55\x55\x35\x3F\xF3\x44\x0F\x59\x5D\xD8\xF3\x44\x0F\x11\x5D\xD8\xE9\x14\xA0\xA0\xFF", 24, true);

	// text
	injector::WriteMemoryRaw(imageBase + 0x90C852, "\xE9\x31\x2C\x5F\x00\x90\x90\x90\x90", 9, true);
	injector::WriteMemoryRaw(imageBase + 0xEFF488, "\xC7\x85\xF8\x00\x00\x00\x55\x55\x35\x3F\xF3\x44\x0F\x59\xB5\xF8\x00\x00\x00\xF3\x44\x0F\x11\xB5\xF8\x00\x00\x00\xE9\xB2\xD3\xA0\xFF", 33, true);


	// window res
	injector::WriteMemory<short>(imageBase + 0x26A5EB, xRes, true);
	injector::WriteMemory<short>(imageBase + 0x26A5F1, yRes, true);
	injector::WriteMemory<short>(imageBase + 0xB2D102, xRes, true);
	injector::WriteMemory<short>(imageBase + 0xB2D10F, yRes, true);
	injector::WriteMemory<short>(imageBase + 0xB2D82B, xRes, true);
	injector::WriteMemory<short>(imageBase + 0xB2D833, yRes, true);


	// 16:9 specific stuff
	// shape
	injector::WriteMemory<float>(imageBase + 0xEFF473, ratio, true);

	// text
	injector::WriteMemory<float>(imageBase + 0xEFF48E, ratio, true);
}

// Borderless Fullscreen
static HWND(WINAPI* CreateWindowExAOri)(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
static HWND WINAPI CreateWindowExAHook(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	int w = GetSystemMetrics(SM_CXSCREEN);
	int h = GetSystemMetrics(SM_CYSCREEN);

	dwStyle = SWP_FRAMECHANGED | SWP_SHOWWINDOW | WS_POPUP | SWP_NOSIZE;

	return CreateWindowExAOri(dwExStyle, lpClassName, lpWindowName, dwStyle, 0, 0, w, h, hWndParent, hMenu, hInstance, lpParam);
}

static HWND(WINAPI* CreateWindowExWOri)(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
static HWND WINAPI CreateWindowExWHook(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	int w = GetSystemMetrics(SM_CXSCREEN);
	int h = GetSystemMetrics(SM_CYSCREEN);

	dwStyle = SWP_FRAMECHANGED | SWP_SHOWWINDOW | WS_POPUP | SWP_NOSIZE;

	return CreateWindowExWOri(dwExStyle, lpClassName, lpWindowName, dwStyle, 0, 0, w, h, hWndParent, hMenu, hInstance, lpParam);
}

static std::string getProfileString(LPCSTR name, LPCSTR key, LPCSTR def, LPCSTR filename)
{
	char temp[1024];
	int result = GetPrivateProfileStringA(name, key, def, temp, sizeof(temp), filename);
	return std::string(temp, result);
}

#define WanganStruct struct __declspec(align(1)) alignas(1)
#pragma pack(push, 1)
WanganStruct BGMInfo{
	char name[64];
	int type;
};
#pragma pack(pop)

const char** customSongs = NULL;
const char** customSongNames = NULL;
int numCustomSongs = 0;

const char* (__cdecl* old_GetBgmFile)(int id);
const char* jmp_GetBgmFile(int id) {
	if (id >= 143)
		return customSongs[id - 143];
	return old_GetBgmFile(id);
}

int jmp_SoundManager_GetBGMStart(int type) {
	return 143;
}

int jmp_SoundManager_GetBGMEnd(int type) {
	return 143 + (numCustomSongs);
}

void* (__cdecl* old_SoundManager_GetBGMInfo)(BGMInfo* info, int id);
void* jmp_SoundManager_GetBGMInfo(BGMInfo* info, int id) {
	if (id >= 143) {
		_snprintf_s(info->name, 0x40, 0xffffffffffffffff, customSongNames[id - 143]);
		info->type = 1; // type
		return info;
	}
	return old_SoundManager_GetBGMInfo(info, id);
}

void populateSongList() {
	CreateDirectoryA("./customSongs", nullptr);
	WIN32_FIND_DATAA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	char searchPath[MAX_PATH];
	snprintf(searchPath, MAX_PATH, "./customSongs/*.nub");

	hFind = FindFirstFileA(searchPath, &ffd);

	if (hFind == INVALID_HANDLE_VALUE) {
		std::cerr << "No files found.\n";
		return;
	}

	do {
		if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { // Check if it's not a directory
			std::cout << "found custom bgm at: " << ffd.cFileName << "\n";

			char songPath[MAX_PATH];
			snprintf(songPath, MAX_PATH, "./customSongs/%s", ffd.cFileName);

			// Get the filename without extension
			char fileNameWithoutExt[MAX_PATH];
			strncpy(fileNameWithoutExt, ffd.cFileName, MAX_PATH);
			PathRemoveExtensionA(fileNameWithoutExt);

			customSongs = (const char**)realloc(customSongs, (numCustomSongs + 1) * sizeof(const char*));
			customSongNames = (const char**)realloc(customSongNames, (numCustomSongs + 1) * sizeof(const char*));

			customSongs[numCustomSongs] = strdup(songPath);

			// Create the formatted song name with index
			char indexedSongName[MAX_PATH];
			snprintf(indexedSongName, MAX_PATH, "%d. %s", numCustomSongs + 1, fileNameWithoutExt);

			customSongNames[numCustomSongs] = strdup(indexedSongName);

			numCustomSongs++;
		}
	} while (FindNextFileA(hFind, &ffd) != 0);

	FindClose(hFind);
}

bool isProcessRunning() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return false;
	}

	if (Process32First(snapshot, &entry)) {
		do {
			if (_wcsicmp(entry.szExeFile, L"maxiterminal.exe") == 0) {
				CloseHandle(snapshot);
				return true;
			}
		} while (Process32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return false;
}

static void launchMaxiTerminalIfNotRunning(const std::string& currentDir) {
	std::string exeName = "maxiterminal.exe";
	std::string maxiterminalPath = currentDir + "\\" + exeName;

	if (GetFileAttributesA(maxiterminalPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
		MessageBoxA(NULL,
			"maxiterminal.exe not found in game folder.\nPlease ensure it exists.",
			"Error", MB_ICONERROR | MB_OK);
		throw std::exception();
	}

	if (isProcessRunning()) {
		// Already running ¡ª skip launching
		return;
	}
	else
	{
		using json = nlohmann::json;
		// Check config.json
		if (FILE* file = fopen("config.json", "r"))
		{
			fclose(file);
		}
		else
		{
			// Default config.json
			static const unsigned char configFile[] = {
				0x7B, 0x0A, 0x20, 0x20, 0x22, 0x61, 0x64, 0x61, 0x70, 0x74, 0x65, 0x72, 0x22, 0x3A, 0x20, 0x22,
				0x30, 0x2E, 0x30, 0x2E, 0x30, 0x2E, 0x30, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x62, 0x75, 0x79,
				0x63, 0x61, 0x72, 0x64, 0x5F, 0x63, 0x6F, 0x73, 0x74, 0x22, 0x3A, 0x20, 0x38, 0x2C, 0x0A, 0x20,
				0x20, 0x22, 0x63, 0x6F, 0x69, 0x6E, 0x5F, 0x63, 0x68, 0x75, 0x74, 0x65, 0x22, 0x3A, 0x20, 0x31,
				0x2C, 0x0A, 0x20, 0x20, 0x22, 0x63, 0x6F, 0x6E, 0x74, 0x69, 0x6E, 0x75, 0x65, 0x5F, 0x63, 0x6F,
				0x73, 0x74, 0x22, 0x3A, 0x20, 0x33, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x65, 0x76, 0x65, 0x6E, 0x74,
				0x5F, 0x32, 0x6F, 0x6E, 0x32, 0x22, 0x3A, 0x20, 0x22, 0x30, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22,
				0x65, 0x76, 0x65, 0x6E, 0x74, 0x5F, 0x64, 0x6F, 0x75, 0x62, 0x6C, 0x65, 0x22, 0x3A, 0x20, 0x22,
				0x30, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x65, 0x76, 0x65, 0x6E, 0x74, 0x5F, 0x6D, 0x6F, 0x64,
				0x65, 0x22, 0x3A, 0x20, 0x22, 0x30, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x65, 0x76, 0x65, 0x6E,
				0x74, 0x5F, 0x6D, 0x6F, 0x64, 0x65, 0x5F, 0x63, 0x6F, 0x75, 0x6E, 0x74, 0x22, 0x3A, 0x20, 0x22,
				0x34, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x65, 0x76, 0x65, 0x6E, 0x74, 0x5F, 0x73, 0x65, 0x72,
				0x69, 0x61, 0x6C, 0x22, 0x3A, 0x20, 0x22, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
				0x30, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5F, 0x6D,
				0x6F, 0x6E, 0x74, 0x68, 0x22, 0x3A, 0x20, 0x22, 0x30, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x66,
				0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5F, 0x70, 0x6C, 0x75, 0x73, 0x65, 0x73, 0x22, 0x3A, 0x20,
				0x22, 0x30, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5F,
				0x72, 0x65, 0x6C, 0x65, 0x61, 0x73, 0x65, 0x5F, 0x61, 0x74, 0x22, 0x3A, 0x20, 0x22, 0x30, 0x22,
				0x2C, 0x0A, 0x20, 0x20, 0x22, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5F, 0x79, 0x65, 0x61,
				0x72, 0x22, 0x3A, 0x20, 0x22, 0x30, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x66, 0x72, 0x65, 0x65,
				0x70, 0x6C, 0x61, 0x79, 0x22, 0x3A, 0x20, 0x22, 0x31, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x66,
				0x75, 0x6C, 0x6C, 0x63, 0x6F, 0x75, 0x72, 0x73, 0x65, 0x5F, 0x63, 0x6F, 0x73, 0x74, 0x22, 0x3A,
				0x20, 0x37, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x67, 0x61, 0x6D, 0x65, 0x5F, 0x63, 0x6F, 0x73, 0x74,
				0x22, 0x3A, 0x20, 0x33, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x6F, 0x6E, 0x6C, 0x69, 0x6E, 0x65, 0x5F,
				0x6D, 0x6F, 0x64, 0x65, 0x22, 0x3A, 0x20, 0x22, 0x31, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x70,
				0x61, 0x63, 0x6B, 0x65, 0x74, 0x5F, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6C, 0x22, 0x3A,
				0x20, 0x22, 0x35, 0x30, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x70, 0x63, 0x62, 0x5F, 0x73, 0x65,
				0x72, 0x69, 0x61, 0x6C, 0x22, 0x3A, 0x20, 0x22, 0x32, 0x38, 0x30, 0x38, 0x31, 0x31, 0x39, 0x39,
				0x30, 0x30, 0x30, 0x33, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
				0x5F, 0x75, 0x72, 0x69, 0x22, 0x3A, 0x20, 0x22, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F,
				0x77, 0x61, 0x6E, 0x67, 0x61, 0x6E, 0x2E, 0x6E, 0x65, 0x74, 0x77, 0x6F, 0x72, 0x6B, 0x3A, 0x39,
				0x30, 0x30, 0x32, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x73, 0x6F, 0x66, 0x74, 0x77, 0x61, 0x72,
				0x65, 0x5F, 0x72, 0x65, 0x76, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x22, 0x3A, 0x20, 0x22, 0x31, 0x30,
				0x33, 0x30, 0x34, 0x22, 0x2C, 0x0A, 0x20, 0x20, 0x22, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E,
				0x22, 0x3A, 0x20, 0x31, 0x30, 0x0A, 0x7D
			};

			// Create config.json
			FILE* file2 = fopen("config.json", "wb");

			fwrite(configFile, 1, sizeof(configFile), file2);
			fclose(file2);
		}

		// Read config.json
		std::ifstream in("config.json");
		json file = json::parse(in);

		// Update the json data value
		std::string gameRevision = removeCharsFromString(config["Version"]["GameRevision"], ".");
		file["adapter"] = "0.0.0.0"; // config["General"]["NetworkAdapterIP"];
		file["server_uri"] = "https://wangan.network:9002";
		file["pcb_serial"] = "280811990003";
		file["software_revision"] = "10304";
		file["version"] = 10;

		// Erase useless json data
		file.erase("adapter_ip");

		// Save the updated json data
		std::ofstream out("config.json");
		out << std::setw(4) << file << std::endl;

		// Close fstream
		in.close();
		out.close();
	}

	WinExec(maxiterminalPath.c_str(), SW_SHOWNORMAL);
}

static void checkCard()
{
	char accessCode[64] = { 0 };
	char chipId[64] = { 0 };

	GetPrivateProfileStringA("card", "accessCode", "", accessCode, sizeof(accessCode), ".\\card.ini");
	GetPrivateProfileStringA("card", "chipId", "", chipId, sizeof(chipId), ".\\card.ini");

	if (strcmp(accessCode, "0") == 0 || strcmp(chipId, "0") == 0) {
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof(PROCESSENTRY32);

			if (Process32First(hSnapshot, &pe32)) {
				do {
					if (_wcsicmp(pe32.szExeFile, L"maxiterminal.exe") == 0) {
						HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
						if (hProc) {
							TerminateProcess(hProc, 1); // Exit code 1
							CloseHandle(hProc);
						}
					}
				} while (Process32Next(hSnapshot, &pe32));
			}
		}
		CloseHandle(hSnapshot);
		MessageBoxA(NULL,
			"Detected Card.ini contains invalid value.\nPlease head over to Project Asakura support channel for assistance.",
			"Error", MB_ICONERROR | MB_OK);
		throw std::exception();
	}
}

static InitFunction Wmmt6Func([]()
{
	// Alloc debug console
	FreeConsole();
	AllocConsole();
	SetConsoleTitle(L"Maxitune6 Console");

	FILE* pNewStdout = nullptr;
	FILE* pNewStderr = nullptr;
	FILE* pNewStdin = nullptr;

	::freopen_s(&pNewStdout, "CONOUT$", "w", stdout);
	::freopen_s(&pNewStderr, "CONOUT$", "w", stderr);
	::freopen_s(&pNewStdin, "CONIN$", "r", stdin);
	std::cout.clear();
	std::cerr.clear();
	std::cin.clear();
	std::wcout.clear();
	std::wcerr.clear();
	std::wcin.clear();

	puts("hello there, maxitune");

	// Borderless Fullscreen
	if (!ToBool(config["General"]["Windowed"]))
	{
		if (ToBool(config["General"]["Borderless Fullscreen"]))
		{
			MH_CreateHookApi(L"user32.dll", "CreateWindowExW", CreateWindowExWHook, (void**)&CreateWindowExWOri);
			MH_CreateHookApi(L"user32.dll", "CreateWindowExA", CreateWindowExAHook, (void**)&CreateWindowExAOri);
		}
	}

	// Folder for Path Redirections
	CreateDirectoryA(".\\TP", nullptr);

	// Create the Setting Data
	FILE* fileF = _wfopen(L".\\TP\\setting.lua.gz", L"r");
	if (fileF == NULL)
	{
		FILE* settingsF = _wfopen(L".\\TP\\setting.lua.gz", L"wb");
		fwrite(settingData, 1, sizeof(settingData), settingsF);
		fclose(settingsF);
	}
	else
	{
		fclose(fileF);
	}

	// Prepare Certs
	prepareCerts();

	bool isTerminal = false;
	if (ToBool(config["General"]["TerminalMode"]))
	{
		isTerminal = true;
	}

	std::string networkip = config["General"]["NetworkAdapterIP"];
	if (!networkip.empty())
	{
		ipaddr = networkip.c_str();
	}

	hookPort = "COM3";
	imageBase = (uintptr_t)GetModuleHandleA(0);
	MH_Initialize();

	// Hook dongle funcs
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_write", Hook_hasp_write, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_read", Hook_hasp_read, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_get_size", Hook_hasp_get_size, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_decrypt", Hook_hasp_decrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_encrypt", Hook_hasp_encrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_logout", Hook_hasp_logout, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_28756.dll", "hasp_login", Hook_hasp_login, NULL);
	MH_CreateHookApi(L"WS2_32", "bind", Hook_bind, reinterpret_cast<LPVOID*>(&pbind));
	MH_CreateHookApi(L"kernel32", "OutputDebugStringA", Hook_OutputDebugStringA, NULL);
	MH_CreateHookApi(L"dnsapi.dll", "DnsQuery_A", DnsQuery_AHook, (void**)&g_origDnsQuery_A);
	MH_CreateHookApi(L"dnsapi.dll", "DnsQueryEx", DnsQueryExHook, (void**)&g_origDnsQueryEx);
	MH_CreateHookApi(L"ws2_32.dll", "getaddrinfo", getaddrinfoHook, (void**)&g_origgetaddrinfo);
	MH_CreateHookApi(L"ws2_32.dll", "InetPtonW", InetPtonWHook, (void**)&g_origInetPtonW);
	// CreateFile* hooks are in the JVS FILE

	// Prevents game from setting time, thanks pockywitch!
	MH_CreateHookApi(L"KERNEL32", "SetSystemTime", Hook_SetSystemTime, reinterpret_cast<LPVOID*>(&pSetSystemTime));

	GenerateDongleData(isTerminal);

	// resolves a system error
	injector::WriteMemory<uint8_t>(hook::get_pattern("0F 94 C0 84 C0 0F 94 C0 84 C0 75 05 45 32 ? EB", 0x13), 0, true);

	// Skip weird camera init that stucks entire pc on certain brands. TESTED ONLY ON 05!!!!
	if (ToBool(config["General"]["WhiteScreenFix"]))
	{
		injector::WriteMemory<DWORD>(hook::get_pattern("48 8B C4 55 57 41 54 41 55 41 56 48 8D 68 A1 48 81 EC 90 00 00 00 48 C7 45 D7 FE FF FF FF 48 89 58 08 48 89 70 18 45 33 F6 4C 89 75 DF 33 C0 48 89 45 E7", 0), 0x90C3C032, true);
	}

	// Best LAN setting by doomertheboomer
	injector::WriteMemory<BYTE>(imageBase + 0xA36CAA, 0xEB, true); //content router patch
	injector::MakeNOP(imageBase + 0x690876, 2, true);

	auto location = hook::get_pattern<char>("48 83 EC 28 33 D2 B9 70 00 02 00 E8 ? ? ? ? 85 C0 79 06");

	if (isTerminal)
	{
		// More dongle error shit?
		safeJMP(hook::get_pattern("8B 01 0F B6 40 78 C3 CC CC CC CC"), ReturnTrue);

		// Give me the HWND please maxitune
		MH_CreateHookApi(L"user32", "ShowWindow", Hook_ShowWindow, reinterpret_cast<LPVOID*>(&pShowWindow));

		// Hook the window procedure
		pMaxituneWndProc = (WindowProcedure_t)(imageBase + 0xB7C030);
	}
	else
	{
		// Terminal on same machine check.
		injector::MakeNOP(hook::get_pattern("74 ? 80 7B 31 00 75 ? 48 8B 43 10 80 78 31 00 75 1A 48 8B D8 48 8B 00 80 78 31 00 75 ? 48 8B D8"), 2);

		std::string res = config["General"]["Resolution"];
		int32_t Res = std::stoi(res);
		if (Res != 768)
		{
			// resolution patch
			patchResolution();
		}

		if (ToBool(config["General"]["Use custom playlist"])) {
			populateSongList();

			if (numCustomSongs != 0) {
				// thanks for hooks axy
				safeJMP(imageBase + 0x729d90, jmp_SoundManager_GetBGMStart);
				safeJMP(imageBase + 0x729e90, jmp_SoundManager_GetBGMEnd);
				MH_CreateHook((void*)(imageBase + 0x720f30), jmp_GetBgmFile, (void**)(&old_GetBgmFile));
				MH_CreateHook((void*)(imageBase + 0x72a0f0), jmp_SoundManager_GetBGMInfo, (void**)(&old_SoundManager_GetBGMInfo));
			}
			else
			{
				std::cout << "skip custom playlist injection due to no custom song is found" << std::endl;
			}
		}

		if (!ToBool(config["General"]["Don't Run MaxiTerminal"])) {
			char currentDir[MAX_PATH];
			GetCurrentDirectoryA(MAX_PATH, currentDir);
			launchMaxiTerminalIfNotRunning(currentDir);
		}
	}

	// path fixes
	injector::WriteMemoryRaw(imageBase + 0x12C5248, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x12C5268, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x12C5288, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x12C52A8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x12C52C8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x12C52E8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x12C5308, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x12C5328, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x12C5348, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x12C5360, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A708, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A720, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A738, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A760, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A788, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A7A0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A7B8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A7C8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A7D8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A7F0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A808, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A828, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A848, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A858, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A868, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A880, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A898, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A8B0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A8C8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A8E0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A8F8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A910, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A928, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x135A940, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1362D48, "TP", 2, true); // F:/contents/
	injector::WriteMemoryRaw(imageBase + 0x13B2890, "TP/contents/", 12, true); // F:contents/
	injector::WriteMemoryRaw(imageBase + 0x13B28A0, "TP/contents/", 12, true);	// G:contents/
	injector::WriteMemoryRaw(imageBase + 0x1401030, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1401048, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1401E08, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1401E20, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1401E38, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1401E60, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1401E88, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1401EA0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x14028E0, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1402900, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1401DDC, "TP", 2, true); // F:
	injector::WriteMemoryRaw(imageBase + 0x13652B8, "TP", 2, true);
	injector::WriteMemoryRaw(imageBase + 0x1365AC8, "TP", 2, true);

	// Fix dongle error (can be triggered by various USB hubs, dongles)
	injector::MakeNOP(imageBase + 0x8C140F, 2, true);

	// Save story stuff (only 05)
	{
		// Bypass Card Vendor
		// 41 83 FB (01) 0F 85 41 18
		injector::WriteMemoryRaw(imageBase + 0x8B8A33, "\x02", 1, true);
		// 89 00 (44 0F B6 D8 41 3B FB 7E ..)
		//injector::WriteMemoryRaw(imageBase + 0x667C12, "\x41\xBB\x02\x00\x00\x00\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90", 19, true);

		//Fix crash when saving story mode and Time attack
		safeJMP(imageBase + 0x8A6AC0, hook_chargeCrash_6);
	}
	// Check card
	checkCard();

	// Bana pass emu
	init_BanapassEmu();

	MH_EnableHook(MH_ALL_HOOKS);
}, GameID::WMMT6);
#endif
#pragma optimize("", on)