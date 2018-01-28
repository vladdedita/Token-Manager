// TokenManagerTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "TokenManagerLibrary.h" 



int main()
{

	//RegistryManager* manager = new RegistryManager();
	//const unsigned char value[] = "anaare mere banane mari";
	//TCHAR* valueRead = 0;
	//DWORD valueReadLenght = 0;

	//manager->createRegistryKey(HKEY_CURRENT_USER, "Software\\TokenManager\\SubKeyOne\\SubKeyTwo");
	//manager->setRegistryValue(HKEY_CURRENT_USER, "Software\\TokenManager\\SubKeyOne\\SubKeyTwo","Service",value,sizeof(value));
	//manager->readValueFromRegistry(HKEY_CURRENT_USER, "Software\\TokenManager\\SubKeyOne\\SubKeyTwo", "Service", valueRead, valueReadLenght);
	////manager->deleteRegistryKey(HKEY_CURRENT_USER, "Software\\TokenManager");

	int rv;
	PKCS11Library*	library = new PKCS11Library(); //cryptoki library
	rv = library->incarcaLibrarie("eTPKCS11.dll");
	TokenSlot*		tokenSlot = new TokenSlot(library);
	TokenSession *	tokenSession = new TokenSession(library, tokenSlot);
	TokenManager*	tokenManager = new TokenManager(library, tokenSlot, tokenSession); //format/change pin
	tokenSession->authentificateAsUser("123456");
	tokenManager->retrieveTokenObjects();
	ObjectCertificate**list=tokenManager->getCertificates();

	for (int i = 0; i < tokenManager->getCertificatesCount(); i++)
	{
		printf("\nObject:%d", i);

		printf("\nPem:%s", list[i]->getPem());
	}

	
	if (rv != 0)
		goto free;

	/*CK_SLOT_ID_PTR slots = tokenSlot->getSlotList();
	if(slots == NULL)
	goto free;*/

	//rv = tokenSession->openSession();
	//if (rv != 0)
	//	goto free;

	//rv = tokenSession->authentificateAsUser("123qwe!@#QWE");
	//if (rv != 0)
	//	goto free;

	/*tokenManager->changePINasUSER();*/

	/*TokenKey* keyManager = new TokenKey(library, tokenSession);
	rv = keyManager->importKeyOnToken("C:\\Users\\Baal\\Documents\\Visual Studio 2017\\Projects\\TokenManager\\TokenManagerLibrary\\privateU.pem", "parola");
	if (rv != 0)
		goto free;*/
free:
	tokenSession->closeSession();
	tokenSlot->freeTokenSlot();
	library->freeLibrarie();
	return 0;
}