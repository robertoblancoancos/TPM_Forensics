#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "tss/tddl_error.h"
#include "tss/tcs_error.h"
#include "tss/tspi.h"

#define TSS_ERROR_CODE(x)	(x & 0xFFF)
#define TSS_ERROR_LAYER(x)	(x & 0x3000)



char *
err_string(TSS_RESULT r)
{
	/* Check the return code to see if it is common to all layers.
	 * If so, return it.
	 */
	switch (TSS_ERROR_CODE(r)) {
		case TSS_SUCCESS:			return "TSS_SUCCESS";
		default:
			break;
	}

	/* The return code is either unknown, or specific to a layer */
	if (TSS_ERROR_LAYER(r) == TSS_LAYER_TPM) {
		switch (TSS_ERROR_CODE(r)) {
			case TPM_E_AUTHFAIL:			return "TPM_E_AUTHFAIL";
			case TPM_E_BAD_PARAMETER:		return "TPM_E_BAD_PARAMETER";
			case TPM_E_BADINDEX:			return "TPM_E_BADINDEX";
			case TPM_E_AUDITFAILURE:		return "TPM_E_AUDITFAILURE";
			case TPM_E_CLEAR_DISABLED:		return "TPM_E_CLEAR_DISABLED";
			case TPM_E_DEACTIVATED:			return "TPM_E_DEACTIVATED";
			case TPM_E_DISABLED:			return "TPM_E_DISABLED";
			case TPM_E_FAIL:			return "TPM_E_FAIL";
			case TPM_E_BAD_ORDINAL:			return "TPM_E_BAD_ORDINAL";
			case TPM_E_INSTALL_DISABLED:		return "TPM_E_INSTALL_DISABLED";
			case TPM_E_INVALID_KEYHANDLE:		return "TPM_E_INVALID_KEYHANDLE";
			case TPM_E_KEYNOTFOUND:			return "TPM_E_KEYNOTFOUND";
			case TPM_E_INAPPROPRIATE_ENC:		return "TPM_E_INAPPROPRIATE_ENC";
			case TPM_E_MIGRATEFAIL:			return "TPM_E_MIGRATEFAIL";
			case TPM_E_INVALID_PCR_INFO:		return "TPM_E_INVALID_PCR_INFO";
			case TPM_E_NOSPACE:			return "TPM_E_NOSPACE";
			case TPM_E_NOSRK:			return "TPM_E_NOSRK";
			case TPM_E_NOTSEALED_BLOB:		return "TPM_E_NOTSEALED_BLOB";
			case TPM_E_OWNER_SET:			return "TPM_E_OWNER_SET";
			case TPM_E_RESOURCES:			return "TPM_E_RESOURCES";
			case TPM_E_SHORTRANDOM:			return "TPM_E_SHORTRANDOM";
			case TPM_E_SIZE:			return "TPM_E_SIZE";
			case TPM_E_WRONGPCRVAL:			return "TPM_E_WRONGPCRVAL";
			case TPM_E_BAD_PARAM_SIZE:		return "TPM_E_BAD_PARAM_SIZE";
			case TPM_E_SHA_THREAD:			return "TPM_E_SHA_THREAD";
			case TPM_E_SHA_ERROR:			return "TPM_E_SHA_ERROR";
			case TPM_E_FAILEDSELFTEST:		return "TPM_E_FAILEDSELFTEST";
			case TPM_E_AUTH2FAIL:			return "TPM_E_AUTH2FAIL";
			case TPM_E_BADTAG:			return "TPM_E_BADTAG";
			case TPM_E_IOERROR:			return "TPM_E_IOERROR";
			case TPM_E_ENCRYPT_ERROR:		return "TPM_E_ENCRYPT_ERROR";
			case TPM_E_DECRYPT_ERROR:		return "TPM_E_DECRYPT_ERROR";
			case TPM_E_INVALID_AUTHHANDLE:		return "TPM_E_INVALID_AUTHHANDLE";
			case TPM_E_NO_ENDORSEMENT:		return "TPM_E_NO_ENDORSEMENT";
			case TPM_E_INVALID_KEYUSAGE:		return "TPM_E_INVALID_KEYUSAGE";
			case TPM_E_WRONG_ENTITYTYPE:		return "TPM_E_WRONG_ENTITYTYPE";
			case TPM_E_INVALID_POSTINIT:		return "TPM_E_INVALID_POSTINIT";
			case TPM_E_INAPPROPRIATE_SIG:		return "TPM_E_INAPPROPRIATE_SIG";
			case TPM_E_BAD_KEY_PROPERTY:		return "TPM_E_BAD_KEY_PROPERTY";
			case TPM_E_BAD_MIGRATION:		return "TPM_E_BAD_MIGRATION";
			case TPM_E_BAD_SCHEME:			return "TPM_E_BAD_SCHEME";
			case TPM_E_BAD_DATASIZE:		return "TPM_E_BAD_DATASIZE";
			case TPM_E_BAD_MODE:			return "TPM_E_BAD_MODE";
			case TPM_E_BAD_PRESENCE:		return "TPM_E_BAD_PRESENCE";
			case TPM_E_BAD_VERSION:			return "TPM_E_BAD_VERSION";
			case TPM_E_NO_WRAP_TRANSPORT:		return "TPM_E_NO_WRAP_TRANSPORT";
			case TPM_E_AUDITFAIL_UNSUCCESSFUL:	return "TPM_E_AUDITFAIL_UNSUCCESSFUL";
			case TPM_E_AUDITFAIL_SUCCESSFUL:	return "TPM_E_AUDITFAIL_SUCCESSFUL";
			case TPM_E_NOTRESETABLE:		return "TPM_E_NOTRESETABLE";
			case TPM_E_NOTLOCAL:			return "TPM_E_NOTLOCAL";
			case TPM_E_BAD_TYPE:			return "TPM_E_BAD_TYPE";
			case TPM_E_INVALID_RESOURCE:		return "TPM_E_INVALID_RESOURCE";
			case TPM_E_NOTFIPS:			return "TPM_E_NOTFIPS";
			case TPM_E_INVALID_FAMILY:		return "TPM_E_INVALID_FAMILY";
			case TPM_E_NO_NV_PERMISSION:		return "TPM_E_NO_NV_PERMISSION";
			case TPM_E_REQUIRES_SIGN:		return "TPM_E_REQUIRES_SIGN";
			case TPM_E_KEY_NOTSUPPORTED:		return "TPM_E_KEY_NOTSUPPORTED";
			case TPM_E_AUTH_CONFLICT:		return "TPM_E_AUTH_CONFLICT";
			case TPM_E_AREA_LOCKED:			return "TPM_E_AREA_LOCKED";
			case TPM_E_BAD_LOCALITY:		return "TPM_E_BAD_LOCALITY";
			case TPM_E_READ_ONLY:			return "TPM_E_READ_ONLY";
			case TPM_E_PER_NOWRITE:			return "TPM_E_PER_NOWRITE";
			case TPM_E_FAMILYCOUNT:			return "TPM_E_FAMILYCOUNT";
			case TPM_E_WRITE_LOCKED:		return "TPM_E_WRITE_LOCKED";
			case TPM_E_BAD_ATTRIBUTES:		return "TPM_E_BAD_ATTRIBUTES";
			case TPM_E_INVALID_STRUCTURE:		return "TPM_E_INVALID_STRUCTURE";
			case TPM_E_KEY_OWNER_CONTROL:		return "TPM_E_KEY_OWNER_CONTROL";
			case TPM_E_BAD_COUNTER:			return "TPM_E_BAD_COUNTER";
			case TPM_E_NOT_FULLWRITE:		return "TPM_E_NOT_FULLWRITE";
			case TPM_E_CONTEXT_GAP:			return "TPM_E_CONTEXT_GAP";
			case TPM_E_MAXNVWRITES:			return "TPM_E_MAXNVWRITES";
			case TPM_E_NOOPERATOR:			return "TPM_E_NOOPERATOR";
			case TPM_E_RESOURCEMISSING:		return "TPM_E_RESOURCEMISSING";
			case TPM_E_DELEGATE_LOCK:		return "TPM_E_DELEGATE_LOCK";
			case TPM_E_DELEGATE_FAMILY:		return "TPM_E_DELEGATE_FAMILY";
			case TPM_E_DELEGATE_ADMIN:		return "TPM_E_DELEGATE_ADMIN";
			case TPM_E_TRANSPORT_NOTEXCLUSIVE:	return "TPM_E_TRANSPORT_NOTEXCLUSIVE";
			case TPM_E_OWNER_CONTROL:		return "TPM_E_OWNER_CONTROL";
			case TPM_E_DAA_RESOURCES:		return "TPM_E_DAA_RESOURCES";
			case TPM_E_DAA_INPUT_DATA0:		return "TPM_E_DAA_INPUT_DATA0";
			case TPM_E_DAA_INPUT_DATA1:		return "TPM_E_DAA_INPUT_DATA1";
			case TPM_E_DAA_ISSUER_SETTINGS:		return "TPM_E_DAA_ISSUER_SETTINGS";
			case TPM_E_DAA_TPM_SETTINGS:		return "TPM_E_DAA_TPM_SETTINGS";
			case TPM_E_DAA_STAGE:			return "TPM_E_DAA_STAGE";
			case TPM_E_DAA_ISSUER_VALIDITY:		return "TPM_E_DAA_ISSUER_VALIDITY";
			case TPM_E_DAA_WRONG_W:			return "TPM_E_DAA_WRONG_W";
			case TPM_E_BAD_HANDLE:			return "TPM_E_BAD_HANDLE";
			case TPM_E_BAD_DELEGATE:		return "TPM_E_BAD_DELEGATE";
			case TPM_E_BADCONTEXT:			return "TPM_E_BADCONTEXT";
			case TPM_E_TOOMANYCONTEXTS:		return "TPM_E_TOOMANYCONTEXTS";
			case TPM_E_MA_TICKET_SIGNATURE:		return "TPM_E_MA_TICKET_SIGNATURE";
			case TPM_E_MA_DESTINATION:		return "TPM_E_MA_DESTINATION";
			case TPM_E_MA_SOURCE:			return "TPM_E_MA_SOURCE";
			case TPM_E_MA_AUTHORITY:		return "TPM_E_MA_AUTHORITY";
			case TPM_E_PERMANENTEK:			return "TPM_E_PERMANENTEK";
			case TPM_E_BAD_SIGNATURE:		return "TPM_E_BAD_SIGNATURE";
			case TPM_E_NOCONTEXTSPACE:		return "TPM_E_NOCONTEXTSPACE";
			case TPM_E_RETRY:			return "TPM_E_RETRY";
			case TPM_E_NEEDS_SELFTEST:		return "TPM_E_NEEDS_SELFTEST";
			case TPM_E_DOING_SELFTEST:		return "TPM_E_DOING_SELFTEST";
			case TPM_E_DEFEND_LOCK_RUNNING:		return "TPM_E_DEFEND_LOCK_RUNNING";
			case TPM_E_DISABLED_CMD:		return "TPM_E_DISABLED_CMD";
			default:				return "UNKNOWN TPM ERROR";
		}
	} else if (TSS_ERROR_LAYER(r) == TSS_LAYER_TDDL) {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "TSS_E_FAIL";
			case TSS_E_BAD_PARAMETER:		return "TSS_E_BAD_PARAMETER";
			case TSS_E_INTERNAL_ERROR:		return "TSS_E_INTERNAL_ERROR";
			case TSS_E_NOTIMPL:			return "TSS_E_NOTIMPL";
			case TSS_E_PS_KEY_NOTFOUND:		return "TSS_E_PS_KEY_NOTFOUND";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "TSS_E_KEY_ALREADY_REGISTERED";
			case TSS_E_CANCELED:			return "TSS_E_CANCELED";
			case TSS_E_TIMEOUT:			return "TSS_E_TIMEOUT";
			case TSS_E_OUTOFMEMORY:			return "TSS_E_OUTOFMEMORY";
			case TSS_E_TPM_UNEXPECTED:		return "TSS_E_TPM_UNEXPECTED";
			case TSS_E_COMM_FAILURE:		return "TSS_E_COMM_FAILURE";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "TSS_E_TPM_UNSUPPORTED_FEATURE";
			case TDDL_E_COMPONENT_NOT_FOUND:	return "TDDL_E_COMPONENT_NOT_FOUND";
			case TDDL_E_ALREADY_OPENED:		return "TDDL_E_ALREADY_OPENED";
			case TDDL_E_BADTAG:			return "TDDL_E_BADTAG";
			case TDDL_E_INSUFFICIENT_BUFFER:	return "TDDL_E_INSUFFICIENT_BUFFER";
			case TDDL_E_COMMAND_COMPLETED:		return "TDDL_E_COMMAND_COMPLETED";
			case TDDL_E_COMMAND_ABORTED:		return "TDDL_E_COMMAND_ABORTED";
			case TDDL_E_ALREADY_CLOSED:		return "TDDL_E_ALREADY_CLOSED";
			case TDDL_E_IOERROR:			return "TDDL_E_IOERROR";
			default:				return "UNKNOWN TDDL ERROR";
		}
	} else if (TSS_ERROR_LAYER(r) == TSS_LAYER_TCS) {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "TSS_E_FAIL";
			case TSS_E_BAD_PARAMETER:		return "TCS_E_BAD_PARAMETER";
			case TSS_E_INTERNAL_ERROR:		return "TCS_E_INTERNAL_ERROR";
			case TSS_E_NOTIMPL:			return "TCS_E_NOTIMPL";
			case TSS_E_PS_KEY_NOTFOUND:		return "TSS_E_PS_KEY_NOTFOUND";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "TCS_E_KEY_ALREADY_REGISTERED";
			case TSS_E_CANCELED:			return "TSS_E_CANCELED";
			case TSS_E_TIMEOUT:			return "TSS_E_TIMEOUT";
			case TSS_E_OUTOFMEMORY:			return "TCS_E_OUTOFMEMORY";
			case TSS_E_TPM_UNEXPECTED:		return "TSS_E_TPM_UNEXPECTED";
			case TSS_E_COMM_FAILURE:		return "TSS_E_COMM_FAILURE";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "TSS_E_TPM_UNSUPPORTED_FEATURE";
			case TCS_E_KEY_MISMATCH:		return "TCS_E_KEY_MISMATCH";
			case TCS_E_KM_LOADFAILED:		return "TCS_E_KM_LOADFAILED";
			case TCS_E_KEY_CONTEXT_RELOAD:		return "TCS_E_KEY_CONTEXT_RELOAD";
			case TCS_E_BAD_INDEX:			return "TCS_E_BAD_INDEX";
			case TCS_E_INVALID_CONTEXTHANDLE:	return "TCS_E_INVALID_CONTEXTHANDLE";
			case TCS_E_INVALID_KEYHANDLE:		return "TCS_E_INVALID_KEYHANDLE";
			case TCS_E_INVALID_AUTHHANDLE:		return "TCS_E_INVALID_AUTHHANDLE";
			case TCS_E_INVALID_AUTHSESSION:		return "TCS_E_INVALID_AUTHSESSION";
			case TCS_E_INVALID_KEY:			return "TCS_E_INVALID_KEY";
			default:				return "UNKNOWN TCS ERROR";
		}
	} else {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "TSS_E_FAIL";
			case TSS_E_BAD_PARAMETER:		return "TSS_E_BAD_PARAMETER";
			case TSS_E_INTERNAL_ERROR:		return "TSS_E_INTERNAL_ERROR";
			case TSS_E_NOTIMPL:			return "TSS_E_NOTIMPL";
			case TSS_E_PS_KEY_NOTFOUND:		return "TSS_E_PS_KEY_NOTFOUND";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "TSS_E_KEY_ALREADY_REGISTERED";
			case TSS_E_CANCELED:			return "TSS_E_CANCELED";
			case TSS_E_TIMEOUT:			return "TSS_E_TIMEOUT";
			case TSS_E_OUTOFMEMORY:			return "TSS_E_OUTOFMEMORY";
			case TSS_E_TPM_UNEXPECTED:		return "TSS_E_TPM_UNEXPECTED";
			case TSS_E_COMM_FAILURE:		return "TSS_E_COMM_FAILURE";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "TSS_E_TPM_UNSUPPORTED_FEATURE";
			case TSS_E_INVALID_OBJECT_TYPE:		return "TSS_E_INVALID_OBJECT_TYPE";
			case TSS_E_INVALID_OBJECT_INITFLAG:	return "TSS_E_INVALID_OBJECT_INITFLAG";
			case TSS_E_INVALID_HANDLE:		return "TSS_E_INVALID_HANDLE";
			case TSS_E_NO_CONNECTION:		return "TSS_E_NO_CONNECTION";
			case TSS_E_CONNECTION_FAILED:		return "TSS_E_CONNECTION_FAILED";
			case TSS_E_CONNECTION_BROKEN:		return "TSS_E_CONNECTION_BROKEN";
			case TSS_E_HASH_INVALID_ALG:		return "TSS_E_HASH_INVALID_ALG";
			case TSS_E_HASH_INVALID_LENGTH:		return "TSS_E_HASH_INVALID_LENGTH";
			case TSS_E_HASH_NO_DATA:		return "TSS_E_HASH_NO_DATA";
			case TSS_E_SILENT_CONTEXT:		return "TSS_E_SILENT_CONTEXT";
			case TSS_E_INVALID_ATTRIB_FLAG:		return "TSS_E_INVALID_ATTRIB_FLAG";
			case TSS_E_INVALID_ATTRIB_SUBFLAG:	return "TSS_E_INVALID_ATTRIB_SUBFLAG";
			case TSS_E_INVALID_ATTRIB_DATA:		return "TSS_E_INVALID_ATTRIB_DATA";
			case TSS_E_NO_PCRS_SET:			return "TSS_E_NO_PCRS_SET";
			case TSS_E_KEY_NOT_LOADED:		return "TSS_E_KEY_NOT_LOADED";
			case TSS_E_KEY_NOT_SET:			return "TSS_E_KEY_NOT_SET";
			case TSS_E_VALIDATION_FAILED:		return "TSS_E_VALIDATION_FAILED";
			case TSS_E_TSP_AUTHREQUIRED:		return "TSS_E_TSP_AUTHREQUIRED";
			case TSS_E_TSP_AUTH2REQUIRED:		return "TSS_E_TSP_AUTH2REQUIRED";
			case TSS_E_TSP_AUTHFAIL:		return "TSS_E_TSP_AUTHFAIL";
			case TSS_E_TSP_AUTH2FAIL:		return "TSS_E_TSP_AUTH2FAIL";
			case TSS_E_KEY_NO_MIGRATION_POLICY:	return "TSS_E_KEY_NO_MIGRATION_POLICY";
			case TSS_E_POLICY_NO_SECRET:		return "TSS_E_POLICY_NO_SECRET";
			case TSS_E_INVALID_OBJ_ACCESS:		return "TSS_E_INVALID_OBJ_ACCESS";
			case TSS_E_INVALID_ENCSCHEME:		return "TSS_E_INVALID_ENCSCHEME";
			case TSS_E_INVALID_SIGSCHEME:		return "TSS_E_INVALID_SIGSCHEME";
			case TSS_E_ENC_INVALID_LENGTH:		return "TSS_E_ENC_INVALID_LENGTH";
			case TSS_E_ENC_NO_DATA:			return "TSS_E_ENC_NO_DATA";
			case TSS_E_ENC_INVALID_TYPE:		return "TSS_E_ENC_INVALID_TYPE";
			case TSS_E_INVALID_KEYUSAGE:		return "TSS_E_INVALID_KEYUSAGE";
			case TSS_E_VERIFICATION_FAILED:		return "TSS_E_VERIFICATION_FAILED";
			case TSS_E_HASH_NO_IDENTIFIER:		return "TSS_E_HASH_NO_IDENTIFIER";
			case TSS_E_PS_KEY_EXISTS:		return "TSS_E_PS_KEY_EXISTS";
			case TSS_E_PS_BAD_KEY_STATE:		return "TSS_E_PS_BAD_KEY_STATE";
			case TSS_E_EK_CHECKSUM:			return "TSS_E_EK_CHECKSUM";
			case TSS_E_DELEGATION_NOTSET:		return "TSS_E_DELEGATION_NOTSET";
			case TSS_E_DELFAMILY_NOTFOUND:		return "TSS_E_DELFAMILY_NOTFOUND";
			case TSS_E_DELFAMILY_ROWEXISTS:		return "TSS_E_DELFAMILY_ROWEXISTS";
			case TSS_E_VERSION_MISMATCH:		return "TSS_E_VERSION_MISMATCH";
			case TSS_E_DAA_AR_DECRYPTION_ERROR:	return "TSS_E_DAA_AR_DECRYPTION_ERROR";
			case TSS_E_DAA_AUTHENTICATION_ERROR:	return "TSS_E_DAA_AUTHENTICATION_ERROR";
			case TSS_E_DAA_CHALLENGE_RESPONSE_ERROR:return "TSS_E_DAA_CHALLENGE_RESPONSE_ERROR";
			case TSS_E_DAA_CREDENTIAL_PROOF_ERROR:	return "TSS_E_DAA_CREDENTIAL_PROOF_ERROR";
			case TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR:return "TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR";
			case TSS_E_DAA_ISSUER_KEY_ERROR:	return "TSS_E_DAA_ISSUER_KEY_ERROR";
			case TSS_E_DAA_PSEUDONYM_ERROR:		return "TSS_E_DAA_PSEUDONYM_ERROR";
			case TSS_E_INVALID_RESOURCE:		return "TSS_E_INVALID_RESOURCE";
			case TSS_E_NV_AREA_EXIST:		return "TSS_E_NV_AREA_EXIST";
			case TSS_E_NV_AREA_NOT_EXIST:		return "TSS_E_NV_AREA_NOT_EXIST";
			case TSS_E_TSP_TRANS_AUTHFAIL:		return "TSS_E_TSP_TRANS_AUTHFAIL";
			case TSS_E_TSP_TRANS_AUTHREQUIRED:	return "TSS_E_TSP_TRANS_AUTHREQUIRED";
			case TSS_E_TSP_TRANS_NOTEXCLUSIVE:	return "TSS_E_TSP_TRANS_NOTEXCLUSIVE";
			case TSS_E_NO_ACTIVE_COUNTER:		return "TSS_E_NO_ACTIVE_COUNTER";
			case TSS_E_TSP_TRANS_NO_PUBKEY:		return "TSS_E_TSP_TRANS_NO_PUBKEY";
			case TSS_E_TSP_TRANS_FAIL:		return "TSS_E_TSP_TRANS_FAIL";
			default:				return "UNKNOWN TSS ERROR";
		}
	}
}






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
		printf("Error: You need to specify an input encrypted file as argument\n");
		exit(-1);
	}
	else {
		FILE *fEncData = fopen(argv[1], "r");
		fseek(fEncData, 0, SEEK_END);
		encryptedDataLen = ftell(fEncData);
		fseek(fEncData, 0, SEEK_SET);

		encryptedData = (BYTE*)malloc(encryptedDataLen);
		fread(encryptedData, 1, encryptedDataLen, fEncData);
		fclose(fEncData);
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
		printf("Tspi_Context_LoadKeyByUUID(SRK) %s\n", err_string(result));
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
		printf("Tspi_Context_LoadKeyByUUID(BindingKey) %s\n", err_string(result));
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
	// Assign input encrypted data to object
	result = Tspi_SetAttribData(hEncryptedData, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, encryptedDataLen, encryptedData);
	if (result != TSS_SUCCESS) {
		printf( "Tspi_SetAttribData (hEncryptedData) %d\n", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}


	// Decrypt input data
	result = Tspi_Data_Unbind(hEncryptedData, hKey, &dataLen, &data);
	if (result != TSS_SUCCESS) {
		printf("Tspi_Data_Unbind %s\n", err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	else { // Save plaintext data to file
		char filenameOUT[15] = "data_decrypted\0"; // Using hardware TPM
		if (argc > 2) sprintf(filenameOUT, "data_decr_sw\0"); // Using software TPM
		FILE* f = fopen(filenameOUT, "wb");
		fwrite(data, 1, dataLen, f);
		fclose(f);
	}



	// Free resources and exit
	printf("FINISHED \n");
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_CloseObject(hContext, hKey);
	Tspi_Context_Close(hContext);
	exit(0);
}
