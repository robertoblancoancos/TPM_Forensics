// ***CYBERSEC-TFM(RBA)*** Timing functions include
#include <time.h>
// ***********************************************

// ***CYBERSEC-TFM(RBA)*** Timing variables
static uint64_t start, end;
static unsigned cycles_low = 0, cycles_high = 0, cycles_low1 = 0, cycles_high1 = 0;
static unsigned int num_unbinds = 0;
static unsigned long long time_unbinds = 0;
static int list_timings[1000000];
static unsigned int iAux;
// ****************************************



TPM_RESULT TPM_Process(TPM_STORE_BUFFER *response,
		       unsigned char *command,		/* complete command array */
		       uint32_t command_size)		/* actual bytes in command */
{
    TPM_RESULT		rc = 0;				/* fatal error, no response */
    TPM_RESULT		returnCode = TPM_SUCCESS;	/* fatal error in ordinal processing,
							   can be returned */
    TPM_TAG		tag = 0;
    uint32_t		paramSize = 0;
    TPM_COMMAND_CODE	ordinal = 0;
    tpm_process_function_t tpm_process_function = NULL;	/* based on ordinal */
    tpm_state_t		*targetInstance = NULL;		/* TPM global state */
    TPM_STORE_BUFFER	localBuffer;		/* for response if instance was not found */
    TPM_STORE_BUFFER	*sbuffer;		/* either localBuffer or the instance response
						   buffer */


    // *** CYBERSER-TFM(RBA) *** Variables
    int isUnbind = (command_size >= 10 && command[9] == 0x1E);
    int isTerminate = (command_size >= 10 && command[9] == 0x96);
	// ***********************************
	

    TPM_Sbuffer_Init(&localBuffer);	/* freed @1 */
    /* get the global TPM state */
    if ((rc == 0) && (returnCode == TPM_SUCCESS)) {
	targetInstance = tpm_instances[0];
    }
    if ((rc == 0) && (returnCode == TPM_SUCCESS)) {
	/* clear the response form the previous ordinal, the response buffer is reused */
	TPM_Sbuffer_Clear(&(targetInstance->tpm_stclear_data.ordinalResponse));
	/* extract the standard command parameters from the command stream */
	returnCode = TPM_Process_GetCommandParams(&tag, &paramSize, &ordinal,
						  &command, &command_size);
    }	 
    /* preprocessing common to all ordinals */
    if ((rc == 0) && (returnCode == TPM_SUCCESS)) {
	returnCode = TPM_Process_Preprocess(targetInstance, ordinal, NULL);
    }
    /* NOTE Only for debugging */
    if ((rc == 0) && (returnCode == TPM_SUCCESS)) {
	TPM_KeyHandleEntries_Trace(targetInstance->tpm_key_handle_entries);
    }
    /* process the ordinal */
    if ((rc == 0) && (returnCode == TPM_SUCCESS)) {
		
		// ***CYBERSEC-TFM(RBA)*** Get time upon command reception
        if (isUnbind) { // Unbind commands only
			asm volatile ("CPUID\n\t"
				"RDTSC\n\t"
				"mov %%edx, %0\n\t"
				"mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
				(cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");
        }
        else if (isTerminate) { // Terminate-handle command detected: reset values
			FILE* f = fopen("/home/roberto/tpm_test/timing_attacks/sw_tpm_timings.txt", "a"); // Timing values are saved to file for plotting
			for(iAux = 0; iAux < num_unbinds; iAux++) fprintf(f, "%d\n", list_timings[iAux]);
			fclose(f);


			time_unbinds = 0;
			num_unbinds = 0;
        }
		// ****************************************************


		
		/* get the processing function from the ordinal table */
		TPM_OrdinalTable_GetProcessFunction(&tpm_process_function, tpm_ordinal_table, ordinal);
		/* call the processing function to execute the command */
		returnCode = tpm_process_function(targetInstance,
						  &(targetInstance->tpm_stclear_data.ordinalResponse),
						  tag, command_size, ordinal, command,
						  NULL);	/* not from encrypted transport */


						  
		// ***CYBERSEC-TFM(RBA)*** Get timing value after command execution
		if (isUnbind) { // Unbind commands only
	        asm volatile("RDTSCP\n\t"
	            "mov %%edx, %0\n\t"
	            "mov %%eax, %1\n\t"
	            "CPUID\n\t": "=r" (cycles_high1), "=r"
	            (cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");

	        num_unbinds++;
	        if (num_unbinds > 0) {
				start = ( ((uint64_t)cycles_high << 32) | cycles_low );
				end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );
				time_unbinds += (end - start);
				list_timings[num_unbinds - 1] = (end - start);
	        }

	        cycles_high = 0;
	        cycles_low = 0;
		}
		// ****************************************************

    }
    /* NOTE Only for debugging */
    if ((rc == 0) && (returnCode == TPM_SUCCESS)) {
	TPM_KeyHandleEntries_Trace(targetInstance->tpm_key_handle_entries);
    }
    /* NOTE Only for debugging */
    if ((rc == 0) && (returnCode == TPM_SUCCESS)) {
	TPM_State_Trace(targetInstance);
    }
#ifdef TPM_VOLATILE_STORE
    /* save the volatile state after each command to handle fail-over restart */
    if ((rc == 0) && (returnCode == TPM_SUCCESS)) {
	returnCode = TPM_VolatileAll_NVStore(targetInstance);
    }
#endif	/* TPM_VOLATILE_STORE */
    /* If the ordinal processing function returned without a fatal error, append its ordinalResponse
       to the output response buffer */
    if ((rc == 0) && (returnCode == TPM_SUCCESS)) {
	returnCode = TPM_Sbuffer_AppendSBuffer(response,
					       &(targetInstance->tpm_stclear_data.ordinalResponse));
    }
    if ((rc == 0) && (returnCode != TPM_SUCCESS)) {
	/* gets here if:
	   
	   - there was an error before the ordinal was processed	
	   - the ordinal returned a fatal error
	   - an error occurred appending the ordinal response
	    
	   returnCode should be the response
	   errors here are fatal, can't create an error response
	*/
	/* if it failed after the target instance was found, use the instance's response buffer */
	if (targetInstance != NULL) {
	    sbuffer = &(targetInstance->tpm_stclear_data.ordinalResponse);
	}
	/* if it failed before even the target instance was found, use a local buffer */
	else {
	    sbuffer = &localBuffer;
	}
	if (rc == 0) {
	    /* it's not even known whether the initial response was stored, so just start
	       over */
	    TPM_Sbuffer_Clear(sbuffer);
	    /* store the tag, paramSize, and returnCode */
	    printf("TPM_Process: Ordinal returnCode %08x %u\n",
		   returnCode, returnCode);
	    rc = TPM_Sbuffer_StoreInitialResponse(sbuffer, TPM_TAG_RQU_COMMAND, returnCode);
	}
	/* call this to handle the TPM_FAIL causing the TPM going into failure mode */
	if (rc == 0) {
	    rc = TPM_Sbuffer_StoreFinalResponse(sbuffer, returnCode, targetInstance);
	}
	if (rc == 0) {
	    rc = TPM_Sbuffer_AppendSBuffer(response, sbuffer);
	}
    }

    /*
      cleanup
    */
    TPM_Sbuffer_Delete(&localBuffer);	/* @1 */
    return rc;
}
