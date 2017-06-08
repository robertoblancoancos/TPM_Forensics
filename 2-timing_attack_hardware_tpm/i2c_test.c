#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <time.h>




int main(int argc, char **argv)
{
	char bufStartUp[12] = {0x00,0xC1,0x00,0x00,0x00,0x0C,0x00,0x00,0x00,0x99,0x00,0x01}; // TPM_StartUp command buffer
	char bufOIAP[10] = {0x00,0xC1,0x00,0x00,0x00,0x0A,0x00,0x00,0x00,0x0A}; // TPM_OIAP command buffer
	char bufGetCapability[18] = {0x00,0xC1,0x00,0x00,0x00,0x12,0x00,0x00,0x00,0x65,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00}; // TPM_GetCapability command buffer
	char bufTerminateHandle[14] = {0x00,0xC1,0x00,0x00,0x00,0x0E,0x00,0x00,0x00,0x96,0x00,0x00,0x00,0x00}; // Terminate_Handle command buffer
	char buf[319]; // TPM_Unbind command buffer
	char authHandle[4];
	char keyHandle[4];
	char encryptedData[256];
	int encryptedDataLen;
	char bufRecv[1024];
	int pos;
	int file;
	char *filename = "/dev/i2c-1"; // Communication with TPM directly via I2C protocol
	int i, j, b, d;
	int rc;
	int numReads_command;
	int numFirstReads_currentDelay = 0;
	struct timespec tsIni = {0, 0};
	struct timespec tsFin = {0, 0};
	unsigned int num_cmds = 0;
	unsigned long long time_cmds = 0;




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


	// Set fixed CPU frequency
	system("cpufreq-set -g userspace");
	system("cpufreq-set -c 0 --max 1000MHz");
	system("cpufreq-set -c 0 --min 1000MHz");

	// Stop Tousers service
	system("service tcsd stop");

	// Unload TPM driver
	system("rmmod tpm_i2c_atmel");



	// Open i2c connection
	if ((file = open(filename, O_RDWR)) < 0) {
		printf("Error: Failed to open the i2c bus\n");
		exit(-1);
	}
	int addr = 0b00101001;          // The I2C address of the TPM
	if (ioctl(file, I2C_SLAVE, addr) < 0) {
		printf("Error: Failed to acquire bus access and/or talk to slave.\n");
		printf(strerror(errno));
		printf("\n\n");
		exit(-1);
	}


	// Send StartUp command
	rc = 0;
	memset(bufRecv, 0x00, sizeof(bufRecv));
	if (write(file, bufStartUp, sizeof(bufStartUp)) != sizeof(bufStartUp)) {
			printf("Error: Failed to write to the i2c bus (StartUp) \n");
	}
	while (rc <= 0) {
		rc = read(file, bufRecv, 1);
	}
	read(file, bufRecv, 6);
	read(file, bufRecv, (bufRecv[4] * 256) + bufRecv[5]);
	printf("Data received (STARTUP): ");
	for (b = 0; b < ((bufRecv[4] * 256) + bufRecv[5]); b++) printf("%02X ", bufRecv[b]);
	printf("\n");


	// Send GetCapability command
	rc = 0;
	memset(bufRecv, 0x00, sizeof(bufRecv));
	if (write(file, bufGetCapability, sizeof(bufGetCapability)) != sizeof(bufGetCapability)) {
			printf("Error: Failed to write to the i2c bus (GetCapability) \n");
	}
	while (rc <= 0) {
		rc = read(file, bufRecv, 1);
	}
	read(file, bufRecv, 6);
	rc = read(file, bufRecv, (bufRecv[4] * 256) + bufRecv[5]);
	printf("Data received (GETCAPABILITY): ");
	for (b = 0; b < ((bufRecv[4] * 256) + bufRecv[5]); b++) printf("%02X ", bufRecv[b]);
	printf("\n");

	// Save key handle (assumes our key is the last one loaded into the TPM)
	keyHandle[0] = bufRecv[rc - 4];
	keyHandle[1] = bufRecv[rc - 3];
	keyHandle[2] = bufRecv[rc - 2];
	keyHandle[3] = bufRecv[rc - 1];



	// SETUP UNBIND COMMAND
	pos = 0;
	// Unbind command header
	buf[pos++] = 0x00; buf[pos++] = 0xC2;
	buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x01; buf[pos++] = 0x3F;
	buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x1E;
	buf[pos++] = keyHandle[0]; buf[pos++] = keyHandle[1]; buf[pos++] = keyHandle[2]; buf[pos++] = keyHandle[3]; // Key Handle
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
	// HMAC Authorization digest (Calculated externally for our binding key) = 0xC2,0xE5,0x22,0x9D,0x58,0xBE,0x62,0x58,0xDC,0x13,0xA0,0x62,0x04,0x8B,0xBB,0xD8,0x64,0x38,0x5D,0x07
	buf[pos++] = 0xC2; buf[pos++] = 0xE5; buf[pos++] = 0x22; buf[pos++] = 0x9D; buf[pos++] = 0x58;
	buf[pos++] = 0xBE; buf[pos++] = 0x62; buf[pos++] = 0x58; buf[pos++] = 0xDC; buf[pos++] = 0x13;
	buf[pos++] = 0xA0; buf[pos++] = 0x62; buf[pos++] = 0x04; buf[pos++] = 0x8B; buf[pos++] = 0xBB;
	buf[pos++] = 0xD8; buf[pos++] = 0x64; buf[pos++] = 0x38; buf[pos++] = 0x5D; buf[pos++] = 0x00;// **Last byte set to zero to force an AUTHFAIL error



	// Establish a set of pre-read delays (10usec jumps)
	int NUM_LOOPS = 10;
	for(d = 11500; d <= 12500; d += 10) {
		numFirstReads_currentDelay = 0;

		// Send OIAP-Unbind commands in a loop
		for(i = 0; i < NUM_LOOPS; i++) { // 10-100 seems enough to have 10usec precision (TPM clock is 100KHz, much slower than CPU clock)
			numReads_command = 0;

			// Send OIAP command
			rc = 0;
			if (write(file, bufOIAP, sizeof(bufOIAP)) != sizeof(bufOIAP)) {
				printf("Error: Failed to write to the i2c bus (OIAP) \n");
			}
			while (rc <= 0) {
				rc = read(file, bufRecv, 1);
			}
			read(file, bufRecv, 6);
			read(file, bufRecv, (bufRecv[4] * 256) + bufRecv[5]);

			// Save authorization handle
			authHandle[0] = bufRecv[10];
			authHandle[1] = bufRecv[11];
			authHandle[2] = bufRecv[12];
			authHandle[3] = bufRecv[13];

			// Set Authorization Handle (received in OIAP response)
			buf[sizeof(buf) - 45] = authHandle[0];
			buf[sizeof(buf) - 44] = authHandle[1];
			buf[sizeof(buf) - 43] = authHandle[2];
			buf[sizeof(buf) - 42] = authHandle[3];

			// Send Unbind command
			rc = 0;
			if (write(file, buf, sizeof(buf)) != sizeof(buf)) {
				printf("Error: Failed to write to the i2c bus (UNBIND) \n");
			}
			clock_gettime(CLOCK_MONOTONIC, &tsIni);
			usleep(d); // Pre-set delay
			while (rc <= 0) {
				rc = read(file, bufRecv, 1);
				numReads_command++;
			}
			clock_gettime(CLOCK_MONOTONIC, &tsFin);
			read(file, bufRecv, 6);
			read(file, bufRecv, (bufRecv[4] * 256) + bufRecv[5]);

			// Timing calculations (using approximation method to circumvent I2C reading delays)
			if (numReads_command == 1) {
				if (tsFin.tv_sec != tsIni.tv_sec) tsFin.tv_nsec += 1000000000;
				numFirstReads_currentDelay++;
				num_cmds++;
				time_cmds += (tsFin.tv_nsec - tsIni.tv_nsec);
			}

		}

		// Observe results for current delay value
		if (numFirstReads_currentDelay != 0) printf(">> %d first reads for a %d usec delay.\n", numFirstReads_currentDelay, d);
		if (numFirstReads_currentDelay == NUM_LOOPS) break;
	}


	// Output final average
	printf("FINAL AVERAGE = %llu nanosec\n", (time_cmds / num_cmds));


	// Send Terminate_Handle command
	rc = 0;
	bufTerminateHandle[10] = authHandle[0];
	bufTerminateHandle[11] = authHandle[1];
	bufTerminateHandle[12] = authHandle[2];
	bufTerminateHandle[13] = authHandle[3];
	if (write(file, bufTerminateHandle, sizeof(bufTerminateHandle)) != sizeof(bufTerminateHandle)) {
		printf("Error: Failed to write to the i2c bus (TERMINATE_HANDLE) \n");
	}
	while (rc <= 0) rc = read(file, bufRecv, 6);
	read(file, bufRecv, (bufRecv[4] * 256) + bufRecv[5]);


	// Close i2c connection
	close(file);

}
