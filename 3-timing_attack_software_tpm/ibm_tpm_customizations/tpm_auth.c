TPM_RESULT TPM_Authdata_Fail(tpm_state_t *tpm_state)
{
    TPM_RESULT		rc = 0;
    uint32_t		tv_usec;	/* dummy, discard usec */

    if (rc == 0) {
	/* Each failure increments the counter.	 No need to check for overflow.	 Unless
	   TPM_LOCKOUT_THRESHOLD is absurdly large, the left shift overflows first.  */
	
	// ***CYBERSEC-TFM(RBA)*** Disable AUTHFAIL counter
	//tpm_state->tpm_stclear_data.authFailCount++;
	
	printf("  TPM_Authdata_Fail: New authFailCount %u\n",
	       tpm_state->tpm_stclear_data.authFailCount);
	/* Test if past the failure threshold.	Each time authorization fails, this test is made.
	   Once in dictionary attack mitigation, there will be no authdata check until the
	   mitigation period is exceeded.  After that, if there is another failure, the fail count
	   increases and mitigation begins again.

	   Note that a successful authorization does NOT reset authFailCount, as this would allow a
	   dictionary attack by an attacker that knew ANY good authorization value.  The count is
	   only reset by the owner using TPM_ResetLockValue.
	*/
	if (tpm_state->tpm_stclear_data.authFailCount > TPM_LOCKOUT_THRESHOLD) {
	    /* the current authorization failure time is the start time */
	    rc = TPM_GetTimeOfDay(&(tpm_state->tpm_stclear_data.authFailTime), &tv_usec);
	    printf("   TPM_Authdata_Fail: Past limit, authFailTime %u\n",
		   tpm_state->tpm_stclear_data.authFailTime);
	}
    }
    return rc;
}
