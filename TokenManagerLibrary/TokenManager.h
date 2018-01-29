#ifndef TKN_MANAGER
#define TKN_MANAGER

#include "cryptoki.h"
#include "defined_tkn_mgr_header.h"
#include "PKCS11Library.h"
#include "TokenSession.h"
#include "TokenObject.h"

#include "ObjectPrivateKey.h"
#include "ObjectSymmetricKey.h"

/*
Pentru tudor
*/

class TKN_API TokenManager { 

private:
	// Put here only services which this class uses (maybe not all 3)
	PKCS11Library*	library;
	TokenSlot*		tokenSlot;
	TokenSession*	tokenSession;
	CK_FUNCTION_LIST_PTR pFunctionList;


	/*
	Objects
	*/

	ObjectCertificate **certList; //certificates
	size_t certCount;

	ObjectPrivateKey **keyList; //private keys
	size_t keyCount;

	ObjectSymmetricKey **symmetricKeyList; //symmetric keys
	size_t sKeyCount;

	CK_RV retrieveCerts();
	CK_RV retrievePrivateKeys();
	CK_RV retrieveSymmetricKeys();

public:
	TokenManager(PKCS11Library* library, TokenSlot* tokenSlot, TokenSession* session);

	int ChangePINAsUser(char *OLDp11PinCode, char *NEWp11PinCode);
	int ChangePINAsSO(char *OLDp11PinCode, char *NEWp11PinCode);
	int formatToken();
	int changePINasUSER();
	int changePINasSO();
	int unblockPIN();
	int initializeToken(char *p11PinCodeSO);
	int initializePIN(char *NEWp11PinCode);


	//////////////////////////////////////////////////////////////////////////
	///////////////////////////ded//////////////////////////////////////////

	CK_RV retrieveTokenObjects();
	ObjectCertificate** getCertificates();
	size_t getCertificatesCount();

	ObjectPrivateKey** getKeys();
	size_t getKeysCount();

	ObjectSymmetricKey **getSymmetricKeys();
	size_t getSymmetricKeysCount();

	CK_RV deleteObject(unsigned int i);

};


#endif