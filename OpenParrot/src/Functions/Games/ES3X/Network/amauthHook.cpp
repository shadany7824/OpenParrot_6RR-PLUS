// Here be lions
// The following code is shit
// It attempts to recreate the functionality of AMAuthd
// However some of this functionality is needless
// Thanks BroGamer for this file
#include "amauthHook.h"

#define i64 int64_t
#define u32 uint32_t
#define i32 int32_t
#define u8 uint8_t

#ifdef DEFINE_GUID
#undef DEFINE_GUID
#endif
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) const GUID name = {l, w1, w2, {b1, b2, b3, b4, b5, b6, b7, b8}}


DWORD reg = 0;
char server_ip[0x10];
char* server_hostname = (char*)"127.0.0.1";
char* shop_name = (char*)"Bayshore";
char* server_uri = (char*)"https://127.0.0.1:9002";
char* server_host = (char*)"127.0.0.1:9002";

DEFINE_GUID(IID_CAuthFactory, 0x4603BB03, 0x58D, 0x43D9, 0xB9, 0x6F, 0x63, 0x9B, 0xE9, 0x08, 0xC1, 0xED);
DEFINE_GUID(IID_CAuth, 0x045A5150, 0xD2B3, 0x4590, 0xA3, 0x8B, 0xC1, 0x15, 0x86, 0x78, 0xE1, 0xAC);

class CAuth : public IUnknown {
public:
	STDMETHODIMP
		QueryInterface(REFIID riid, LPVOID* ppvObj) {
		wchar_t* iid_str;
		StringFromCLSID(riid, &iid_str);
		//printf("QueryInterface %ls\n", iid_str);

		if (riid == IID_IUnknown || riid == IID_CAuth) {
			*ppvObj = this;
			this->AddRef();
			return 0;
		}
		else {
			*ppvObj = 0;
			return E_NOINTERFACE;
		}
	}
	STDMETHODIMP_(ULONG) AddRef() { return this->refCount++; }
	STDMETHODIMP_(ULONG) Release() {
		this->refCount--;
		if (this->refCount <= 0) {
			// delete this;
			return 0;
		}
		return this->refCount;
	}

	virtual i64 Unk3(u32 a1) { return 1; }
	virtual i64 Unk4() { return 0; }
	virtual i32 Unk5() { return 0; }
	virtual i64 Unk6() { return 0; }
	virtual i32 Unk7() { return 0; }
	virtual i32 Unk8() { return 0; }
	virtual i32 Unk9(i32* a1) {
		memset(a1, 0, sizeof(i32) * 0x31);
		a1[0] = 15;
		a1[2] = 2;
		a1[3] = 1;
		a1[6] = 15;
		a1[8] = 1;
		a1[9] = 0;
		a1[10] = 28;
		a1[11] = 31;
		a1[12] = 41;
		a1[13] = 50;
		a1[14] = 59;
		a1[15] = 196613;
		a1[30] = 1;
		a1[46] = 1;
		a1[47] = 1;
		a1[48] = 15;
		return 0;
	}
	virtual i32 Unk10(char* a1) {
		memset(a1, 0, 0xB0);
		strncpy_s(a1, 0x10, "STANDALONE", 0xF);
		strncpy_s(a1 + 0x10, 0x10, "280813990002", 0xF); // PCB ID
		strncpy_s(a1 + 0x20, 0x10, "000000-00000", 0xF); // ignored by game
		strncpy_s(a1 + 0x30, 0x10, server_ip, 0xF);
		strncpy_s(a1 + 0x40, 0x10, server_ip, 0xF);
		strncpy_s(a1 + 0x50, 0x10, server_ip, 0xF);
		strncpy_s(a1 + 0x60, 0x10, "***.***.***.***", 0xF); // Subnet mask
		strncpy_s(a1 + 0x70, 0x10, "***.***.***.***", 0xF); // GATEWAY
		strncpy_s(a1 + 0x80, 0x10, "***.***.***.***", 0xF); // PRIMARY DNS
		return 0;
	}
	virtual i32 GetMuchaCAConfig(char* a1) {
		memset(a1, 0, 0x13C);
		strncpy_s(a1, 4, "1", 3);           // type
		strncpy_s(a1 + 4, 0x10, "ALL.NET", 0xF);
		strncpy_s(a1 + 20, 8, "SBWJ", 7);   // allcfg-gameID
		strncpy_s(a1 + 28, 8, "15.00", 7);  // allcfg-gameVer
		strncpy_s(a1 + 36, 8, "W6P1", 7);   // cacfg-game_cd
		strncpy_s(a1 + 44, 8, "00.13", 7);  // cacfg-game_ver
		strncpy_s(a1 + 52, 4, "0", 3);      // cacfg-game_board_type
		strncpy_s(a1 + 56, 4, "W6P", 3);    // cacfg-game_board_id
		return 0;
	}
	virtual i32 Unk12() { return 0; }
	virtual i32 Unk13() { return 1; }
	virtual i32 GetPowerOnResponse(char* a1) {
		memset(a1, 0, 0x8A2);
		strncpy_s(a1, 0x101, server_uri, 0x100);
		strncpy_s(a1 + 0x101, 0x101, server_host, 0x100);
		strncpy_s(a1 + 0x202, 0x100, shop_name, 0xFF); // ALL.Net SHOP NAME
		strncpy_s(a1 + 0x302, 0x100, shop_name, 0xFF);
		strncpy_s(a1 + 0x402, 0x10, "1", 0xF);
		strncpy_s(a1 + 0x412, 0x100, "JPN0123", 0xFF);
		strncpy_s(a1 + 0x512, 0x100, "X", 0xFF);
		strncpy_s(a1 + 0x612, 0x100, "Y", 0xFF);
		strncpy_s(a1 + 0x712, 0x100, "Z", 0xFF);
		strncpy_s(a1 + 0x812, 0x10, "JPN0123", 0xF); // Place ID
		strncpy_s(a1 + 0x832, 0x10, "JPN", 0xF);
		strncpy_s(a1 + 0x842, 0x10, "002,00", 0xF);
		strncpy_s(a1 + 0x842, 0x10, "PowerOnResponseVer2", 0xF);
		return 0;
	}
	virtual i32 Unk15() { return 0; }
	virtual i32 Unk16() { return 0; }
	virtual i32 Unk17() { return 0; }
	virtual i32 Unk18(void* a1) { return 0; }
	virtual i32 Unk19(u8* a1) {
		memset(a1, 0, 0x38);
		a1[0] = 1;
		return 1;
	}
	virtual i32 Unk20() { return 0; }
	virtual i32 Unk21() { return 1; }
	virtual i32 Unk22() { return 0; }
	virtual i32 Unk23() { return 0; }
	virtual i32 Unk24() { return 0; }
	virtual i32 Unk25() { return 3; }
	virtual i32 Unk26() { return 0; }
	virtual i32 Unk27() { return 3; }
	virtual i32 Unk28() { return 0; }
	virtual i32 Unk29() { return 0; }
	virtual i32 Unk30() { return 0; }
	virtual i32 PrintDebugInfo() { return 0; }
	virtual i32 Unk32(void* a1) { return 0; }
	virtual void Unk33() {}

public:
	CAuth() {}
	virtual ~CAuth() {}

private:
	i32 refCount = 0;
};


class CAuthFactory : public IClassFactory {
public:
	STDMETHODIMP
		QueryInterface(REFIID riid, LPVOID* ppvObj) {
		wchar_t* iid_str;
		StringFromCLSID(riid, &iid_str);
		//printf("QueryInterface %ls\n", iid_str);

		if (riid == IID_IUnknown || riid == IID_IClassFactory || riid == IID_CAuthFactory) {
			*ppvObj = this;
			return 0;
		}
		else {
			*ppvObj = 0;
			return E_NOINTERFACE;
		}
	}
	STDMETHODIMP_(ULONG) AddRef() { return 2; }
	STDMETHODIMP_(ULONG) Release() { return 3; }
	virtual HRESULT CreateInstance(IUnknown* outer, REFIID riid, void** object) {
		if (outer != 0) return CLASS_E_NOAGGREGATION;
		wchar_t* iid_str;
		StringFromCLSID(riid, &iid_str);
		printf("CreateInstance %ls\n", iid_str);
		CAuth* auth = new CAuth();
		return auth->QueryInterface(riid, object);
	}
	virtual HRESULT LockServer(i32 lock) { return 0; }
};


void initAmauth(std::string serverHostname) {
	CoInitializeEx(0, 0);
	CoRegisterClassObject(IID_CAuthFactory, (IUnknown*)new CAuthFactory(), CLSCTX_LOCAL_SERVER, 1, &reg);

	server_hostname = strdup(serverHostname.c_str());

	// Get ipv4 address of server
	struct addrinfo* res = 0;
	getaddrinfo(server_hostname, "", 0, &res);
	for (struct addrinfo* i = res; i != 0; i = i->ai_next) {
		if (res->ai_addr->sa_family != AF_INET) continue;
		struct sockaddr_in* p = (struct sockaddr_in*)res->ai_addr;
		inet_ntop(AF_INET, &p->sin_addr, server_ip, 0x10);
		break;
	}

	// make proper server uri and hosts
	std::string serverUri = "https://" + serverHostname + ":9002";
	std::string serverHost = serverHostname + ":9002";
	server_uri = strdup(serverUri.c_str());
	server_host = strdup(serverHost.c_str());
}