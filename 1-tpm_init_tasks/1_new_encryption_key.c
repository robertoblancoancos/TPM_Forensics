#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tss/tddl_error.h"
#include "tss/tcs_error.h"
#include "tss/tspi.h"


#define TSS_ERROR_CODE(x)       (x & 0xFFF)
#define TSS_ERROR_LAYER(x)      (x & 0x3000)



int main(int argc, char **argv)
{
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_RESULT	result;
	int		auxSubK_uuid = 2; // Sub-value used to create Key UUID
	if (argc > 1) auxSubK_uuid = 3;  // Change Key UUID if dealing with software TPM
	TSS_UUID        SRK_UUID = TSS_UUID_SRK;
	TSS_UUID	KEY_UUID = {0,0,0,0,0,{0,0,0,auxSubK_uuid,10}};
	TSS_HPOLICY	srkUsagePolicy, newKeyUsagePolicy;
	initFlags	= TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048  |
			TSS_KEY_NON_VOLATILE | TSS_KEY_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	BYTE		secret_SRK_SHA1[20];
	memset(secret_SRK_SHA1, 0x00, 20); // SRK Password = Well-known 20 zeros

	char		secret_NewKey_plain[] = "P4ssw0rd123"; // New binding key usage-secret
	BYTE		secret_NewKey_SHA1[20] = {0xe8,0xd9,0x02,0x19,0xb7,0x4d,0xf2,0x96,0xf9,0xf7,0x90,0x6f,0xfc,0x9c,0x3c,0xfd,0x0a,0x76,0x13,0xd3};



	printf("STARTING...\n");

	//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Context_Create %d\n", result);
		exit(result);
	}
	//Connect Context
	result = Tspi_Context_Connect(hContext, NULL);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Context_Connect %d\n", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}


	//Load SRK Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
				TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Context_LoadKeyByUUID %d\n", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Get Policy Object for SRK Authorization
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		printf("Tspi_GetPolicyObject(SRK) %d\n", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret for SRK Authorization
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TSS_SECRET_MODE_SHA1,
			20, secret_SRK_SHA1);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Policy_SetSecret(SRK Policy) %d\n", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	//Create New Key Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
							initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Context_CreateObject %d\n", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// Set the padding type for new key
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_ENCSCHEME, TSS_ES_RSAESPKCSV15);
	if (result != TSS_SUCCESS) {
		printf("Tspi_SetAttribUint32(New Key) %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// Create a policy for the new key
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &newKeyUsagePolicy);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Context_CreateObject(New Key Policy) %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set new key secret
	result = Tspi_Policy_SetSecret(newKeyUsagePolicy, TSS_SECRET_MODE_SHA1, 20, secret_NewKey_SHA1);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Policy_SetSecret(New Key) %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// Assign the new key policy to the new key object
	result = Tspi_Policy_AssignToObject(newKeyUsagePolicy, hKey);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Policy_AssignToObject(New Key) %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Create Key
	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Key_CreateKey %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	// Register the key blob int TSS permanent storage, so we can retrieve it later through Tspi_Context_LoadKeyByUUID()
	result = Tspi_Context_RegisterKey(hContext, hKey, TSS_PS_TYPE_SYSTEM, KEY_UUID, TSS_PS_TYPE_SYSTEM, SRK_UUID);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Context_RegisterKey %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	//Load Key (hKey)
	result = Tspi_Key_LoadKey(hKey, hSRK);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Key_LoadKey %d\n", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	else {
		printf("NEW KEY LOADED TO TPM SUCCESSFULLY\n");
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
