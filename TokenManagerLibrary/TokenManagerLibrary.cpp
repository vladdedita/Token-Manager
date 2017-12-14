// TokenManagerDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#define EXPORTING_DLL
#include"TokenManagerLibrary.h"

#define MAX_COUNT 20

#define E_BASE 0x200
#define E_PKCS11_TEST_LIBRARY_NOT_FOUND E_BASE+1
#define E_PKCS11_TEST_CRYPTOKIFUNCTIONS E_BASE+2
#define E_PKCS11_TEST_NO_TOKENS_PRESENT E_BASE+3
#define E_PKCS11_TEST_ALLOC				E_BASE+4
#define E_PKCS11_TEST_NOT_FOUND			E_BASE+5
#define E_PKCS11_TEST_IO				E_BASE+6


HINSTANCE				hDll;
CK_FUNCTION_LIST_PTR	pFunctionList = NULL;
CK_C_GetFunctionList	pC_GetFunctionList = NULL;


void asteaptaToken() {
	CK_RV	rv;
	CK_FLAGS flags = 0;
	CK_SLOT_ID slotID;
	CK_SLOT_INFO slotInfo;

	while (1)
	{
		rv = pFunctionList->C_WaitForSlotEvent(NULL, &slotID, NULL_PTR);
		if (rv == CKR_OK)
		{
			rv = pFunctionList->C_GetSlotInfo(slotID, &slotInfo);
			if (slotInfo.flags & CKF_TOKEN_PRESENT)
			{
				printf("BAGA\n");
				printf((char*)slotInfo.manufacturerID);
				//cautaObiecte(slotID);
			}
			else
			{
				printf("SCOATE");
			}

		}
		printf("\n");
	}


}