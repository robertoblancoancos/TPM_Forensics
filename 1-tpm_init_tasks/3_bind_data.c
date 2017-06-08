#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tss/tddl_error.h"
#include "tss/tcs_error.h"
#include "tss/tspi.h"

#define TSS_ERROR_CODE(x)	(x & 0xFFF)
#define TSS_ERROR_LAYER(x)	(x & 0x3000)



int main(int argc, char **argv)
{
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_RESULT	result;
	int             auxSubK_uuid = 2; // Sub-value used to create Key UUID
	if (argc > 2) auxSubK_uuid = 3;  // Change Key UUID if dealing with software TPM
	TSS_UUID        SRK_UUID = TSS_UUID_SRK;
	TSS_UUID        ENCRYPTION_KEY_UUID = {0,0,0,0,0,{0,0,0,auxSubK_uuid,10}};
	TSS_HPOLICY	srkUsagePolicy;
	TSS_HPOLICY	encryptionKeyUsagePolicy;
	BYTE		*data;
	uint32_t	dataLen;
	BYTE		*encryptedData;
	uint32_t        encryptedDataLen;
	TSS_HENCDATA	hEncryptedData;

	BYTE		secret_SRK_SHA1[20];
	memset(secret_SRK_SHA1, 0x00, 20); // SRK Password = Well-known 20 zeros

	char		secret_BindKey_plain[] = "P4ssw0rd123"; // Binding key usage-secret
	BYTE		secret_BindKey_SHA1[20] = {0xe8,0xd9,0x02,0x19,0xb7,0x4d,0xf2,0x96,0xf9,0xf7,0x90,0x6f,0xfc,0x9c,0x3c,0xfd,0x0a,0x76,0x13,0xd3};



	printf("STARTING...\n");


	// Read input data file
	if (argc <= 1) {
		printf("Error: You need to specify an input data file as argument\n");
		exit(-1);
	}
	else {
		FILE *fData = fopen(argv[1], "r");
		fseek(fData, 0, SEEK_END);
		dataLen = ftell(fData);
		fseek(fData, 0, SEEK_SET);

		data = (BYTE*)malloc(dataLen);
		fread(data, 1, dataLen, fData);
		fclose(fData);
	}

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


	//Load SRK By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
							TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Context_LoadKeyByUUID(SRK) %d\n", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Get Policy Object for SRK Authorization
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		printf("Tspi_GetPolicyObject(SRK) %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret for SRK Authorization
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TSS_SECRET_MODE_SHA1,
					20, secret_SRK_SHA1);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Policy_SetSecret(SRK) %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}


	//Load Binding Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
				TSS_PS_TYPE_SYSTEM, ENCRYPTION_KEY_UUID, &hKey);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Context_LoadKeyByUUID(BindingKey) %d\n", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Get Policy Object for Binding Key Authorization
	result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &encryptionKeyUsagePolicy);
	if (result != TSS_SUCCESS) {
		printf("Tspi_GetPolicyObject(BindingKey) %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret for Binding Key Authorization
	result = Tspi_Policy_SetSecret(encryptionKeyUsagePolicy, TSS_SECRET_MODE_SHA1,
			20, secret_BindKey_SHA1);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Policy_SetSecret(BindingKey) %d\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}


	// Create encrypted data object from current context
	result = Tspi_Context_CreateObject(hContext,
						TSS_OBJECT_TYPE_ENCDATA,
						TSS_ENCDATA_BIND, &hEncryptedData);
	if ( result != TSS_SUCCESS )
	{
		printf( "Tspi_Context_CreateObject (hEncryptedData) %d\n", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	// Encrypt input data
	result = Tspi_Data_Bind(hEncryptedData, hKey, dataLen, data);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Data_Bind %s\n", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	else { // Save encrypted data to file
		Tspi_GetAttribData(hEncryptedData, TSS_TSPATTRIB_ENCDATA_BLOB,
			      TSS_TSPATTRIB_ENCDATABLOB_BLOB,
			      &encryptedDataLen, &encryptedData);

		char filenameOUT[encryptedDataLen + 11];
		if (argc > 2) sprintf(filenameOUT, "%s_encr_sw", argv[1]); // Using software TPM
		else sprintf(filenameOUT, "%s_encrypted", argv[1]); // Using hardware TPM
		FILE* fEnc = fopen(filenameOUT, "wb");
		fwrite(encryptedData, 1, encryptedDataLen, fEnc);
		fclose(fEnc);
	}


	// Free resources and exit
	printf("FINISHED \n");
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_CloseObject(hContext, hKey);
	Tspi_Context_Close(hContext);
	exit(0);
}
