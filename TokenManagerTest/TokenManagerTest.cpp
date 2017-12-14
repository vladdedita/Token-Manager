// TokenManagerTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "TokenManagerLibrary.h"

int main()
{
	PKCS11Library*	library = new PKCS11Library();
	TokenSlot*		tokenSlot = new TokenSlot(library);
	TokenSession *	tokenSession = new TokenSession(library, tokenSlot);
	TokenManager*	tokenManager = new TokenManager(library, tokenSlot, tokenSession);
	CK_SLOT_ID_PTR slots;
	int rv;
	
	rv =  library->incarcaLibrarie("eTPKCS11.dll");
	if (rv != 0)
		goto free;

	slots = tokenSlot->getSlotList();
	if(slots == NULL)
		goto free;

	//tokenSlot->asteaptaToken();

	rv = tokenSession->openSession();
	if (rv != 0)
		goto free;

	rv = tokenSession->authentificate("1234");
	if (rv != 0)
		goto free;

free: 	
	tokenSession->closeSession();
	tokenSlot->freeTokenSlot();
	library->freeLibrarie();
	getchar();
	
	return 0;
}