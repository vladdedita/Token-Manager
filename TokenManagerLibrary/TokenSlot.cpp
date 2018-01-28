#include "stdafx.h"
#define EXPORTING_DLL
#include "TokenSlot.h"


TokenSlot::TokenSlot(PKCS11Library* library)
{
	this->library = library;
}

int TokenSlot::asteaptaToken()
{
		CK_RV	rv;
		CK_FLAGS flags = 0;
		CK_SLOT_ID slotID;
		CK_SLOT_INFO slotInfo;
		CK_FUNCTION_LIST_PTR	pFunctionList = library->getFunctionList();

		if (pFunctionList == NULL) {
			return CKR_CRYPTOKI_NOT_INITIALIZED;
		}

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

int TokenSlot::freeTokenSlot()
{
	if (pSlotList != NULL)
	{
		free(pSlotList);
		pSlotList = NULL;
	}

	return CKR_OK;
}
CK_CHAR_PTR listToken(CK_TOKEN_INFO tokenInfo) {
	//returns a char* with the token info

	CK_CHAR_PTR info = NULL;

	char buff[100];
	int newsize;
	int oldsize;



	sprintf(buff, "\n\tFirmware Version:%d.%d", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);
	newsize = strlen(buff);


	info = (CK_CHAR_PTR)realloc(info, newsize);
	strcpy((char*)info, buff);
	oldsize = strlen((const char*)info);

	sprintf(buff, "\n\tHardware Version:%d.%d", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);

	tokenInfo.label[31] = '\0';
	sprintf(buff, "\n\tLabel:%s", tokenInfo.label);
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);


	tokenInfo.manufacturerID[31] = '\0';
	sprintf(buff, "\n\tManufacturer ID:%s", tokenInfo.manufacturerID);
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);


	tokenInfo.model[15] = '\0';
	sprintf(buff, "\n\tModel:%s", tokenInfo.model);
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);


	tokenInfo.serialNumber[15] = '\0';
	sprintf(buff, "\n\tSerial No.:%s", tokenInfo.serialNumber);
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);


	tokenInfo.utcTime[15] = '\0';
	sprintf(buff, "\n\tUTC Time:%s", tokenInfo.utcTime);
	newsize = strlen((const char*)info) + strlen(buff) + 1;
	info = (CK_CHAR_PTR)realloc(info, newsize);
	info[oldsize] = '\0';
	strcat((char*)info, buff);
	oldsize = strlen((const char*)info);

	return info;
	//printf("\n\tFirmware Version:%d.%d", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);
	//printf("\n\tHardware Version:%d.%d", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
	//tokenInfo.label[31] = '\0';
	//printf("\n\tLabel:%s", tokenInfo.label);
	//tokenInfo.manufacturerID[31] = '\0';
	//printf("\n\tManufacturer ID:%s", tokenInfo.manufacturerID);
	//tokenInfo.model[15] = '\0';
	//printf("\n\tModel:%s",tokenInfo.model);
	//tokenInfo.serialNumber[15] = '\0';
	//printf("\n\tSerial No.:%s", tokenInfo.serialNumber);
	//tokenInfo.utcTime[15] = '\0';
	//printf("\n\tUTC Time:%s", tokenInfo.utcTime);	

}
CK_SLOT_ID_PTR TokenSlot::getSlotList()
{
	CK_RV					rv;
	CK_FUNCTION_LIST_PTR	pFunctionList = library->getFunctionList();

	if (pFunctionList == NULL) {
		return NULL;
	}

	// obtin nr de sloturi (ocupate cu tokenuri)
	printf("\nObtinere lista sloturi de PKCS#11.....");
	rv = pFunctionList->C_GetSlotList(TRUE, NULL, &ulSlotCount);
	if (rv != CKR_OK)
	{
		printf("EROARE");
		return NULL;
	}

	if (ulSlotCount == 0)
	{
		printf("%d slot(uri)", ulSlotCount);
		rv = E_PKCS11_TEST_NO_TOKENS_PRESENT;
		return NULL;
	}


	//obtin lista de sloturi (doar cele cu tokenuri)	
	pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
	if (pSlotList == 0)
	{
		printf("EROARE");
		rv = E_PKCS11_TEST_ALLOC;
		return NULL;
		
	}
	rv = pFunctionList->C_GetSlotList(TRUE, pSlotList, &ulSlotCount);
	if (rv)
	{
		printf("EROARE");
		return NULL;
		
	}
	printf("gasit %d slot(uri)", ulSlotCount);


	if (ulSlotCount == 0)
	{
		rv = E_PKCS11_TEST_NO_TOKENS_PRESENT;
		return NULL;
	}
	tokenInfo = (CK_TOKEN_INFO*)malloc(ulSlotCount * sizeof(CK_TOKEN_INFO));
	for (unsigned int i = 0; i < ulSlotCount; i++)
	{
		pFunctionList->C_GetTokenInfo(pSlotList[i], &tokenInfo[i]);
//		printf("%s", listToken(tokenInfo));

	}
	return pSlotList;
}
