// TokenManagerTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "TokenManagerLibrary.h"

int main()
{
	PKCS11Library* library = new PKCS11Library();


	library->incarcaLibrarie("eTPKCS11.dll");

	//asteaptaToken();

	library->freeLibrarie();
	getchar();
	return 0;
}

