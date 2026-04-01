const char*AUTHOR="Watchful_IP";
const char*URL="watchfulip.github.io";  //https://watchfulip.github.io/28-12-24/tp-link_c210_v2.html

const char* VDATE="29-12-24";
const char*VERSION="0.0.3";

/* THIS PROGRAM WILL NOT WORK UNTIL ./extract_keys.sh HAS BEEN USED */

/*
    For decrypting TP-Link firmware
    
    v0.0.2   added second RSA key and adjusted detection and offsets for that firmware format
    v0.0.3   libsecurity moved into src instead of using a library.   RSA keys now can be extracted from fw into includes with extract_keys.sh
    
    Ref:    https://static.tp-link.com/upload/gpl-code/2022/202211/20221130/c310v2_GPL.tar.bz2
    /camera_slp/torchlight/tp_package/lib/libsecurity/src
    
    also valid for:  
    
    Tapo_C225v2_en_1.0.7_Build_231022_Rel.37222n_up_boot-signed_1697944831712.bin
    Tapo_C425v1_en_1.2.10_Build_230817_Rel.66253n_up_boot-signed_1694757161571.bin
    Tapo_C520WSv1_en_1.0.11_Build_230621_Rel.72773n_up_boot-signed_1689911553894.bin
    Tapo_C720v1_en_1.0.15_Build_230309_Rel.45493n_up_boot-signed_1692170680796.bin
    Tapo_D130v1_en_1.0.16_Build_230829_Rel.56497n_up_boot-signed_1696921651739.bin
    D230-up-ver1-1-9-P1[20230614-rel54173]-signed_1686728417801.bin
    Tapo_D235v1_en_1.1.2_Build_231012_Rel.41779n_up_boot-signed_1697200873075.bin.rollback
    Tapo_TC71v2_en_1.3.8_Build_230913_Rel.59332n_up_boot-signed_1695869613098.bin
    H200-up-ver1-2-23-P1\[20231012-rel49638\]-signed_1697774013433.bin 
    
    ax90v1-up-ver1-1-9-P120220512-rel83908_2048_si_1656329037964.bin
    ax11000v2-up-ver2-1-6-P1[20230907-rel65510]_2048_sign_2023-09-07_18.31.59_1694737907340.bin
    axe300v1-up-ver1-0-6-P420230109-rel13284_2048__1677120050594.bin
    be9300v1-up-all-ver1-0-3-P1[20230911-rel70411]_sign_2023-09-11_20.23.49_1695823725657.bin
    XE75 Pro 2.0_en_1.2.6 Build 20230904 Rel. 50316_SG_up_RSA2048_1694166784549.bin
    etc.
    
    Not valid for:
    
    TL-S* switches
*/

/* 
 * tp-link-decrypt - Decrypt TP-Link Firnware
 * Copyright (C) 2024 Watchful_IP   
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "rsa_verify/rsaVerify.h"

static const char *TP_TAPO_RSA_KEYS[] = {
    "BgIAAAwkAABSU0ExAAgAAAEAAQBzhFrp9KOUU2PYuWKTq+qcKVU5B5Oq/uHFK7zLEkfZmHW+5VuSypXOYSB45C80xZhRRjta3MiwbPIjCFEsdc9o7uWfACYn7a9YhZaCJkFTULz1RMQIap9RVznKN5QhV9/kxxZPymeH2H8JkMR3T4JJY1ceBfqtGYnbAIV4+yof+X76Ou73ce82AU79QOnZyfbbZ2MiHpFogv3YLSYrOlccZaDSDiid+qWqIlaQoShrdN0PgfGcL/C6vQhTP4/NeQIR7u8qI2RIsc9b9ZvhyrFXNqpD1wdpHifrl7MX6TqxYWL1j4QNyPDrDCZVSRNtf8EAcAyFIqjWzT1+jpvLiPOz",
    "BgIAAACkAABSU0ExAAQAAAEAAQArjNXuvBeCGfOD19AGJGmceW+ip5W76C+sOHk0bJgrtZhk+t/ZzZwAv/TLA+MwNipNZSd+fOysmqDsA53cEIKdzor0WbWGq0n/BYr1o8fh4Pm656mOn9C6LH6nCf6w48Nog84Pc+NuwHcB93p6Wj0y3YVl8sGn+eeokA8ltZzLnA==",
    "BgIAAACkAABSU0ExAAQAAAEAAQAHNt5fFl0BUlLkPjKJloZFlVFkegFjEsVJCRjwbRD6i646tpvc/Z5MK6SuXcz3yizxDGMnZ6BJdqCR9SJTdd3b11F7Q+pgetcAgX5X9NZTzo1MCvpkKAlEyZG0rXMpSbADNNqtACNT0BLhHu4nyiDBBIIOSZljQAzHiqSquxHDsg==",
    "BgIAAACkAABSU0ExAAQAAAEAAQD7Bk7f7fdnL9drucbr+P9wA2JUlYP/OH4zvIS69eY3KKmUB1fs9ND06EINqTQ4vQ4gCeekU1dRi3WiZLgVjo/UzovplddUezNMWq0gk4TVbsGf/xzXZN+pDWid9zYsSr9qvINId6cnMR+s/wXB1TOE6t6wfzHvnbkJR0r1mqG4yA==",
    "BgIAAACkAABSU0ExAAQAAAEAAQA1Ccyu85b65TawjvSQTaryGNk1gBJVn6kEIJq6m0hagsqkiy32v4ui41ucp6tKfaoqb7AHDBq41dcEMgM6YBF2e3aRKQqZ6EwgCvAi3O81n7UbE97lD+FhvqlYxyqqMbSdvNmCiAoujheUs9DUaOCHq4K3McDxATMVOnCtT1H+wQ==",
};
static const size_t TP_TAPO_RSA_KEY_COUNT =
    sizeof(TP_TAPO_RSA_KEYS) / sizeof(TP_TAPO_RSA_KEYS[0]);


//#define DEBUG



// -libsecurity compiled from https://static.tp-link.com/upload/gpl-code/2022/202211/20221130/c310v2_GPL.tar.bz2
extern int rsaVerifyPSSSignByBase64EncodePublicKeyBlob(unsigned char *pPublicKeyBlob,
    unsigned long PublicKeyBlobLen,
    unsigned char *pInData,
    unsigned long inDataLen,
    unsigned char *PInSignature,
    unsigned long inSignatureLen,
    unsigned int bCheckOnly,
    unsigned int header_align_size,
unsigned int data_dec_offset);  //added data_dec_offset due to different platforms having encrypted data at different offsets - could use #extern in libsecurity instead

#define FW_TYPE_OFFSET 0x14
#define FW_TYPE_STRING "fw-type:"
#define FW_TYPE_LENGTH 8  

int detect_firmware_ver(const unsigned char *fw_buffer, size_t buffer_size) 
{
    
    if (buffer_size < FW_TYPE_OFFSET + FW_TYPE_LENGTH) {
        return -1;  
    }
    
    if (memcmp(fw_buffer + FW_TYPE_OFFSET, FW_TYPE_STRING, FW_TYPE_LENGTH) == 0) {
        printf("%s found\n",FW_TYPE_STRING);
        return 1;  
    }
    
    return 0;  
}

int verify_and_decrypt(
    unsigned char *fw_buffer,
    unsigned int verify_size,
    int sig_pos,
    int sig_size,
    int fw_data_pos,
    int data_dec_offset,
    const char *rsa_key)
{
    unsigned char signature[0x100];
    if (sig_size > (int)sizeof(signature)) {
        fprintf(stderr, "Unsupported signature size %d\n", sig_size);
        return -1;
    }

    memcpy(signature, fw_buffer + sig_pos, sig_size);
    memset(fw_buffer + sig_pos, 0, sig_size);

    return rsaVerifyPSSSignByBase64EncodePublicKeyBlob(
        (unsigned char *)rsa_key,
        strlen(rsa_key),
        fw_buffer + fw_data_pos,
        verify_size,
        signature,
        256,
        0,
        0,
        data_dec_offset);
}

int main(int argc, char *argv[]) 
{
	printf("\nTP-link firmware decrypt\n\n%s %s v%s\n%s\n\n", AUTHOR, VDATE, VERSION,URL);
	
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <firmware_file> [tapo_key_index]\n", argv[0]);
        return 1;
    }
    
    const char *firmware_file = argv[1];
    FILE *fp = fopen(firmware_file, "rb");
    if (!fp) {
        perror("Error opening firmware file\n");
        return 1;
    }
    
    fseek(fp, 0, SEEK_END);
    unsigned int fw_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    //printf("fw_size is %u\n", fw_size);
    
    // Read firmware into buffer
    unsigned char *fw_buffer = calloc(1,fw_size);
    if (!fw_buffer) {
        perror("Error allocating memory");
        fclose(fp);
        return 1;
    }
    fread(fw_buffer, 1, fw_size, fp);
    fclose(fp);
    //printf("fw_buffer is size %u\n", fw_size);

    unsigned char *orig_fw_buffer = malloc(fw_size);
    if (!orig_fw_buffer) {
        perror("Error allocating firmware backup");
        free(fw_buffer);
        return 1;
    }
    memcpy(orig_fw_buffer, fw_buffer, fw_size);
    
    const char *RSA_KEY; 
    int SIG_SIZE=0;
    int RSA_VER_pos=0;
    int fw_data_pos=0;
    int sig_pos=0;
    int data_dec_offset=0;
    
    
    int firmware_ver = detect_firmware_ver(fw_buffer,fw_size);
    //printf("firmware_ver: %d\n",firmware_ver );
    
    switch (firmware_ver) {
        case 1:   //  fw-type: in header
        fprintf(stderr, "This local build only supports Tapo IPC firmware.\n");
        free(orig_fw_buffer);
        free(fw_buffer);
        return 1;
        
        case 0:   // Tapo IPC
        RSA_KEY=NULL;
        sig_pos=0x20; 
        RSA_VER_pos=0x00;
        fw_data_pos=0x00;
        data_dec_offset=0;	
        break;
        
        default:
        printf("Unknown firmware_ver %d\n",firmware_ver);
        exit(1);
        break;	     
    }    
    
	uint32_t RSA_VER = (fw_buffer[RSA_VER_pos+0] << 24) | (fw_buffer[RSA_VER_pos+1] << 16) | (fw_buffer[RSA_VER_pos+2] << 8) | fw_buffer[RSA_VER_pos+3];
    
	if (RSA_VER == 0x200) 
	{
		SIG_SIZE = 0x100;
    }
	else if (RSA_VER == 0x100) 
	{
		SIG_SIZE = 0x80;
		printf("RSA-1024 not tested and firmware likely not encrypted\n");
		exit(1);
    }
	else	
	{
		printf("Unable to determine RSA\n");
		exit(1);
    }	
    
	printf("RSA-%d\n\n", RSA_VER*4);    

    unsigned int verify_size = fw_size;
    int result = -1;
    if (firmware_ver == 0) {
        size_t i;
        size_t start_idx = 0;
        size_t end_idx = TP_TAPO_RSA_KEY_COUNT;
        if (argc == 3) {
            long forced_idx = strtol(argv[2], NULL, 10);
            if (forced_idx < 1 || forced_idx > (long)TP_TAPO_RSA_KEY_COUNT) {
                fprintf(stderr, "Invalid tapo_key_index: %ld\n", forced_idx);
                free(orig_fw_buffer);
                free(fw_buffer);
                return 1;
            }
            start_idx = (size_t)(forced_idx - 1);
            end_idx = start_idx + 1;
        }

        for (i = start_idx; i < end_idx; ++i) {
            memcpy(fw_buffer, orig_fw_buffer, fw_size);
            RSA_KEY = TP_TAPO_RSA_KEYS[i];
            printf("Trying Tapo RSA key %zu/%zu...\n", i + 1, TP_TAPO_RSA_KEY_COUNT);
            result = verify_and_decrypt(
                fw_buffer,
                verify_size,
                sig_pos,
                SIG_SIZE,
                fw_data_pos,
                data_dec_offset,
                RSA_KEY);
            if (result == 1) {
                printf("Matched Tapo RSA key %zu\n", i + 1);
                break;
            }
        }
    } else {
        result = verify_and_decrypt(
            fw_buffer,
            verify_size,
            sig_pos,
            SIG_SIZE,
            fw_data_pos,
            data_dec_offset,
            RSA_KEY);
    }

    #ifdef DEBUG    	    
	printf("Debug: rsaVerifyPSSSignByBase64EncodePublicKeyBlob returned: %d\n", result);
    #endif
    
	if (result !=1) 
	{
        fprintf(stderr, "Firmware verification failed.\n");
        return -1;
    }
	else
	    printf("\nFirmware verification successful\n");
    
    
	char *dec_fw_file = malloc(strlen(firmware_file) + 5);
	if (dec_fw_file == NULL) {
		return -1;
    }
	strcpy(dec_fw_file, firmware_file);
	strcat(dec_fw_file, ".dec");
    
    // Write decrypted firmware to new file
    FILE *out_fp = fopen(dec_fw_file, "wb");
    if (!out_fp) {
        perror("Error creating output file\n");
        free(fw_buffer);
        return 1;
    }
    
    fwrite(fw_buffer, 1, fw_size, out_fp);
    fclose(out_fp);
    
    printf("\nDecrypted firmware written to %s\n\n",dec_fw_file);
    
    free(dec_fw_file);
    free(orig_fw_buffer);
    free(fw_buffer);
    return 0;
}
