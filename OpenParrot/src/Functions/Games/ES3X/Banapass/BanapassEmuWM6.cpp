#include "BanapassEmu.cpp"

void init_BanapassEmu()
{
	MH_Initialize();
	MH_CreateHookApi(L"bngrw.dll", "BngRwAttach", BngRwAttach, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwDevReset", BngRwDevReset, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwExReadMifareAllBlock", BngRwExReadMifareAllBlock, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwFin", BngRwFin, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwGetFwVersion", BngRwGetFwVersion, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwGetStationID", BngRwGetStationID, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwGetTotalRetryCount", BngRwGetTotalRetryCount, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwGetVersion", BngRwGetVersion, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwInit", BngRwInit, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwIsCmdExec", BngRwIsCmdExec, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqAction", BngRwReqAction, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqAiccAuth", BngRwReqAiccAuth, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqBeep", BngRwReqBeep, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqCancel", BngRwReqCancel, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqFwCleanup", BngRwReqFwCleanup, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqFwVersionup", BngRwReqFwVersionup, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqLatchID", BngRwReqLatchID, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqLed", BngRwReqLed, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqSendMailTo", BngRwReqSendMailTo, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqSendUrlTo", BngRwReqSendUrlTo, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqWaitTouch", BngRwReqWaitTouch, NULL);
	MH_CreateHookApi(L"bngrw.dll", "BngRwReqSetLedPower", BngRwReqSetLedPower, NULL);


	MH_EnableHook(MH_ALL_HOOKS);
}