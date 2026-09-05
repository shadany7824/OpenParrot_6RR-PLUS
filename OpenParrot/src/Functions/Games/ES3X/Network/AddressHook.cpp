#include <StdInc.h>
#include <WinDNS.h>

static DNS_STATUS(WINAPI* g_origDnsQuery_A)(PCSTR pszName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved);

static DNS_STATUS WINAPI DnsQuery_AHook(PCSTR pszName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved)
{
#if _DEBUG
	info("DnsQuery_AHook: %s", pszName);
#endif

	if (strncmp(pszName, "tenporouter.loc", 15) == 0 || strncmp(pszName, "bbrouter.loc", 15) == 0)
	{
		// TODO: make this configurable?
		const char* dnsName = config["Network"]["RouterIP"].c_str();

		return g_origDnsQuery_A(dnsName, wType, Options, pExtra, ppQueryResults, pReserved);
	}
	if (strncmp(pszName, "naominet.jp", 15) == 0)
	{
		const char* dnsName = "teknoparrot.xyz";

		return g_origDnsQuery_A(dnsName, wType, Options, pExtra, ppQueryResults, pReserved);
	}
	if (strncmp(pszName, "mobirouter.loc", 14) == 0 || strncmp(pszName, "dslrouter.loc", 13) == 0)
	{
		return NULL;
	}

	return g_origDnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
}

static DNS_STATUS(WINAPI* g_origDnsQueryEx)(PDNS_QUERY_REQUEST pQueryRequest, PDNS_QUERY_RESULT pQueryResults, PDNS_QUERY_CANCEL pCancelHandle);

static DNS_STATUS WINAPI DnsQueryExHook(PDNS_QUERY_REQUEST pQueryRequest, PDNS_QUERY_RESULT pQueryResults, PDNS_QUERY_CANCEL pCancelHandle)
{
#if _DEBUG
	//info(true, "DnsQueryEx: %s", pQueryRequest->QueryName);
#endif
	if (wcsncmp(pQueryRequest->QueryName, L"mobirouter.loc", 14) == 0)
	{
		DNS_QUERY_REQUEST QueryRequest;
		QueryRequest.Version = pQueryRequest->Version;
		QueryRequest.QueryName = L"plsfail";
		QueryRequest.QueryOptions = pQueryRequest->QueryOptions;
		QueryRequest.pDnsServerList = pQueryRequest->pDnsServerList;
		QueryRequest.InterfaceIndex = pQueryRequest->InterfaceIndex;
		QueryRequest.pQueryCompletionCallback = pQueryRequest->pQueryCompletionCallback;
		QueryRequest.pQueryContext = pQueryRequest->pQueryContext;

		return g_origDnsQueryEx(&QueryRequest, pQueryResults, pCancelHandle);
	}

	if (wcsncmp(pQueryRequest->QueryName, L"tenporouter.loc", 15) == 0 || wcsncmp(pQueryRequest->QueryName, L"bbrouter.loc", 15) == 0)
	{
		// TODO: make it configurable? Add check for other common sega stuff?
		wchar_t* wString = new wchar_t[4096];
		MultiByteToWideChar(CP_ACP, 0, config["Network"]["RouterIP"].c_str(), -1, wString, 4096);
		DNS_QUERY_REQUEST QueryRequest;
		QueryRequest.Version = pQueryRequest->Version;
		QueryRequest.QueryName = wString;
		QueryRequest.QueryOptions = pQueryRequest->QueryOptions;
		QueryRequest.pDnsServerList = pQueryRequest->pDnsServerList;
		QueryRequest.InterfaceIndex = pQueryRequest->InterfaceIndex;
		QueryRequest.pQueryCompletionCallback = pQueryRequest->pQueryCompletionCallback;
		QueryRequest.pQueryContext = pQueryRequest->pQueryContext;

		return g_origDnsQueryEx(&QueryRequest, pQueryResults, pCancelHandle);
	}

	return g_origDnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);
}

static int(WSAAPI* g_origInetPtonW)(INT Family, PCWSTR pszAddrString, PVOID pAddrBuf);

static int WSAAPI InetPtonWHook(INT Family, PCWSTR pszAddrString, PVOID pAddrBuf)
{
#if _DEBUG
	//infoW(true, L"InetPtonWHook: %s", pszAddrString);
#endif
	// idk yet if this is also needed or not.
	//if (wcsncmp(pszAddrString, L"tenporouter.loc", 15) == 0)
	//{
	//	return g_origInetPtonW(Family, L"localhost", pAddrBuf);
	//}
	//if (wcsncmp(pszAddrString, L"mobirouter.loc", 15) == 0) 
	//{
	//	return g_origInetPtonW(Family, L"plsfail", pAddrBuf);
	//}

	return g_origInetPtonW(Family, pszAddrString, pAddrBuf);
}

static int(WSAAPI* g_origgetaddrinfo)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);

static int WSAAPI getaddrinfoHook(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{
#if _DEBUG
	info("getaddrinfo: %s, %s", pNodeName, pServiceName);
#endif

	return g_origgetaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}