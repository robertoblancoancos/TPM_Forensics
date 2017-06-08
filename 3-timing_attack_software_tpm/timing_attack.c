#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include "tss/tddl_error.h"
#include "tss/tcs_error.h"
#include "tss/tspi.h"


#define TSS_ERROR_CODE(x)	(x & 0xFFF)
#define TSS_ERROR_LAYER(x)	(x & 0x3000)



void main( int argc, char **argv ) {
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

	BYTE		secret_SRK_SHA1[20];
	memset(secret_SRK_SHA1, 0x00, 20); // SRK Password = Well-known 20 zeros

	char            secret_BindKey_plain[] = "P4ssw0rd123"; // Binding key usage-secret
	BYTE            secret_BindKey_SHA1[20] = {0xe8,0xd9,0x02,0x19,0xb7,0x4d,0xf2,0x96,0xf9,0xf7,0x90,0x6f,0xfc,0x9c,0x3c,0xfd,0x0a,0x76,0x13,0xd3};//xxx FIRSTBYTE=0xE8


	char encryptedData[256];
	int encryptedDataLen;
	char buf[319]; // TPM_Unbind command buffer
	int pos;
	char bufOIAP[10] = {0x00,0xC1,0x00,0x00,0x00,0x0A,0x00,0x00,0x00,0x0A}; // TPM_OIAP command buffer
	char bufRecv[1024];
	char bufGetCapability[18] = {0x00,0xC1,0x00,0x00,0x00,0x12,0x00,0x00,0x00,0x65,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00}; // TPM_GetCapability command buffer
	char bufTerminateHandle[14] = {0x00,0xC1,0x00,0x00,0x00,0x0E,0x00,0x00,0x00,0x96,0x00,0x00,0x00,0x00}; // Terminate_Handle command buffer
	char authHandle[4];
	char keyHandle[4];
	int sockfd = 0;
	struct sockaddr_in server_addr;
	int rc;
	int countWaitRecv;
	struct timespec tsIni = {0, 0};
	struct timespec tsFin = {0, 0};
	long c, i;


	// Program start
	printf("STARTING...\n");
	if (argc > 2)
		printf("<Software TPM mode>\n");
	//else
	//	printf("<Hardware TPM mode>\n"); **DISABLED


	// Read input file
	if (argc <= 1) {
		printf("Error: You need to specify an input encrypted file as argument\n");
		return;
	}
	else {
		FILE *fEncData = fopen(argv[1], "r");
		fseek(fEncData, 0, SEEK_END);
		encryptedDataLen = ftell(fEncData);
		fseek(fEncData, 0, SEEK_SET);

		fread(encryptedData, 1, encryptedDataLen, fEncData);
		fclose(fEncData);

		if (encryptedDataLen != 256) {
			printf("Error: Unexpected encrypted data length\n");
			return;
		}
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



	// Initializations for socket comms
	memset(&server_addr, 0x00, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(6545);
	
	// Initialize variables for GetCapability command
	rc = 0;
	countWaitRecv = 0;
	memset(bufRecv,0x00, sizeof(bufRecv));
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	printf("Error : Could not create socket\n");
		return;
	}

	// Connect socket
	if(connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		printf("Error : Socket connect Failed\n");
		return;
	}

	// Send GetCapability command
	if(send(sockfd, bufGetCapability, sizeof(bufGetCapability), 0) < 0) {
			printf("Error: Send failed\n");
			return;
	}

	// Get GetCapability response
	if((rc = recv(sockfd, bufRecv, sizeof(bufRecv), 0)) < 0) {
			printf("Error: Recv failed\n");
			return;
	}

	// Save key handle (assumes only one key handle existing in the software TPM)
	keyHandle[0] = bufRecv[16];
	keyHandle[1] = bufRecv[17];
	keyHandle[2] = bufRecv[18];
	keyHandle[3] = bufRecv[19];

	// Close socket
	close(sockfd);

	
	

	// SETUP AND SEND COMMANDS
	pos = 0;

	// Unbind command header
	buf[pos++] = 0x00; buf[pos++] = 0xC2;
	buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x01; buf[pos++] = 0x3F;
	buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x1E;
	buf[pos++] = keyHandle[0]; buf[pos++] = keyHandle[1]; buf[pos++] = keyHandle[2]; buf[pos++] = keyHandle[3];
	buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x01; buf[pos++] = 0x00;

	// Insert encrypted data
	for (i = 0; i < encryptedDataLen; i++) buf[pos++] = encryptedData[i];

	// Authorization handle
	buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;

	// Hardcode compliance-mode nonceOdd
	buf[pos++] = 0xB9; buf[pos++] = 0x73; buf[pos++] = 0x05; buf[pos++] = 0xFA; buf[pos++] = 0xDB;
	buf[pos++] = 0xE3; buf[pos++] = 0x4D; buf[pos++] = 0xC5; buf[pos++] = 0x46; buf[pos++] = 0x65;
	buf[pos++] = 0x10; buf[pos++] = 0x00; buf[pos++] = 0x0A; buf[pos++] = 0x55; buf[pos++] = 0x04;
	buf[pos++] = 0x2E; buf[pos++] = 0x3F; buf[pos++] = 0xEA; buf[pos++] = 0xBF; buf[pos++] = 0x27;

	// ContinueAuthSession - false
	buf[pos++] = 0x00;

	// HMAC Authorization digest
	if (argc > 2) { // *Externally calculated test HMAC = 0xE1,0x1A,0xC1,0x78,0x20,0x78,0x7B,0xE9,0x4B,0x2A,0xC7,0x65,0xA0,0x15,0x8D,0x72,0x29,0xAD,0x47,0x16
		buf[pos++] = 0xE1; buf[pos++] = 0x1A; buf[pos++] = 0xC1; buf[pos++] = 0x78; buf[pos++] = 0x20;
		buf[pos++] = 0x78; buf[pos++] = 0x7B; buf[pos++] = 0xE9; buf[pos++] = 0x4B; buf[pos++] = 0x2A;
		buf[pos++] = 0xC7; buf[pos++] = 0x65; buf[pos++] = 0xA0; buf[pos++] = 0x15; buf[pos++] = 0x8D;
		buf[pos++] = 0x72; buf[pos++] = 0x29; buf[pos++] = 0xAD; buf[pos++] = 0x47; buf[pos++] = 0x00; // **Last byte set to zero to force AUTHFAIL errors
	}
	
	for (c = 0; c < 1000000; c++) { // Set to 1 million loops to enhance average precision
		// Initialize variables for OIAP command
		rc = 0;
		if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				printf("Error : Could not create socket\n");
				return;
		}

		// Connect socket
		if(connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
				printf("Error : Socket connect Failed\n");
				return;
		}

		// Send OIAP command
		if(send(sockfd, bufOIAP, sizeof(bufOIAP), 0) < 0) {
			printf("Error: Send failed\n");
			return;
		}

		// Get OIAP response
		if((rc = recv(sockfd, bufRecv, sizeof(bufRecv), 0)) < 0) {
			printf("Error: Recv failed\n");
			return;
		}

		// Save authorization handle
		authHandle[0] = bufRecv[10];
		authHandle[1] = bufRecv[11];
		authHandle[2] = bufRecv[12];
		authHandle[3] = bufRecv[13];

		// Close socket
		close(sockfd);



		// Initialize variables for Unbind command
		rc = 0;
		if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			printf("Error : Could not create socket\n");
			return;
		}

		// Connect socket
		if(connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
			printf("Error : Socket connect Failed\n");
			return;
		}

		// Set Authorization Handle (received in OIAP response)
		buf[sizeof(buf) - 45] = authHandle[0];
		buf[sizeof(buf) - 44] = authHandle[1];
		buf[sizeof(buf) - 43] = authHandle[2];
		buf[sizeof(buf) - 42] = authHandle[3];

		// Send Unbind command
		if(send(sockfd, buf, sizeof(buf), 0) < 0) {
			printf("Error: Send failed\n");
			return;
		}

		// Get response
        if((rc = recv(sockfd, bufRecv, sizeof(bufRecv), 0)) < 0) {
			printf("Error: Recv failed\n");
			return;
		}
		
		// Close socket
		close(sockfd);

	}



	// Initialize variables for Terminate_Handle command
	rc = 0;
	countWaitRecv = 0;
	memset(bufRecv,0x00, sizeof(bufRecv));
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			printf("Error : Could not create socket\n");
			return;
	}

	// Connect socket
	if(connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
			printf("Error : Socket connect Failed\n");
			return;
	}

	// Set Authorization Handle (received in OIAP response)
	bufTerminateHandle[10] = authHandle[0];
	bufTerminateHandle[11] = authHandle[1];
	bufTerminateHandle[12] = authHandle[2];
	bufTerminateHandle[13] = authHandle[3];

	// Send Terminate_Handle command
    if(send(sockfd, bufTerminateHandle, sizeof(bufTerminateHandle), 0) < 0) {
		printf("Error: Send failed\n");
		return;
	}

	// Get response
	if((rc = recv(sockfd, bufRecv, sizeof(bufRecv), 0)) < 0) {
		printf("Error: Recv failed\n");
		return;
	}

	// Close socket
	close(sockfd);



	// Free TSS resources and exit (unloads binding key from TPM)
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_CloseObject(hContext, hKey);
	Tspi_Context_Close(hContext);
	printf("FINISHED\n");
	exit(0);

}







