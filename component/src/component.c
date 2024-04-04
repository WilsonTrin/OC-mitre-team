/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/mcapi/crypto.h"

// Includes from containerized build
#include "ectf_params.h"
#include "com_secrets.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/
#define CVERTMESSAGE "DLK1fU2x1uq+DbXL0oUvK4iQxjcw87Bhkpf6DdHS6lTH+bFxIAzVWBOgbWs7P/6yiRpCPS8BvRcgmzAnaDqr1VPxq9nyLlmeSqcvpV2TsbfcE8A3mTfyTl9V/PwmaiL8Bn5Wep+lD4q1D87gMKK+zt7xP0dpZ95ATbufA3eJoc8="

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint32_t component_id;
    uint8_t cVertMessage[MAX_I2C_MESSAGE_LEN-4];
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
void secure_send(uint8_t len, uint8_t* buffer) {
    // Get the component validation message
	RsaKey * key = APPUBLIC; // the AP public key
	RNG * rng;
    int rngReturn = wc_InitRng(rng);
    if(rngReturn < 0)
    {
        return ERROR_RETURN;
    }
    byte* out; // Pointer to a pointer for decrypted information.
    word32 outLen = 0;
    int result = wc_RsaPublicEncrypt(buffer, len, out, outLen, key, rng)

    rngReturn = wc_FreeRng(rng)
    if(rngReturn < 0)
    {
        return ERROR_RETURN;
    }
    if(result < 0)
    {
        return ERROR_RETURN;
    }
    send_packet_and_ack(outlen, out);   // Send the packet
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(uint8_t* buffer) {
    int len = wait_and_receive_packet(buffer);  // Recieve encrypted packet and store the returned length of the packet.
    RsaKey * key = COMPRIVATE; // the component Private key
	RNG * rng;
    int rngReturn = wc_InitRng(rng);
    if(rngReturn < 0)
    {
        return ERROR_RETURN;
    }	
    byte* out; // Pointer to a pointer for decrypted information.

    ret = wc_RsaPrivateDecryptInline(buffer, len, out, key);
    
    rngReturn = wc_FreeRng(rng)
    if(rngReturn < 0)
    {
        return ERROR_RETURN;
    }
    if(ret == RSA_PAD_E)
    {
        return ERROR_RETURN;
    }
    return ret; // number of bytes recieved 
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

// Handle a transaction from the AP
void component_process_cmd() {
    command_message* command = (command_message*) receive_buffer;

    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_VALIDATE:
        process_validate();
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

int process_boot(command_message* command) {
    // The AP requested a boot. Set component_boot for the main loop and
    // respond with the boot message
    RsaKey *key = COMPUBLIC;               // the component public key
    byte in[] = command->params; // Byte array to be decrypted.
    byte out; // Pointer to a pointer for decrypted information.
    // Confirm the message with component public key
    if (wc_RsaSSL_VerifyInline(in, sizeof(in), &out, &key) < 0)
        return ERROR_RETURN;
    else {

        uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
        memcpy((void)transmit_buffer, COMPONENT_BOOT_MSG, len);
        secure_send(len, transmit_buffer);
        // Call the boot function
        boot();
        return 0
    }
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    secure_send(sizeof(scan_message), transmit_buffer);
}

void process_validate() {
    // The AP requested a validation. Respond with the Component ID
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t inByte[sizeof(apvertMessage)] = apvertMessage;
    int ret;
    RsaKey key = COMPRIVATE;
    RNG rng;
    ret = wc_InitRNG(&rng);
    uint8_t outByte[MAX_I2C_MESSAGE_LEN - 1];
    //Sign with the CVERTMESSAGE  with the COM private key here:
    ret = wc_RsaSSL_Sign(inByte, sizeof(inByte),outByte, sizeof(outByte),key,rng);
    byte inByte[sizeof(CVERTMESSAGE)] = CVERTMESSAGE;
    ret = wc_FreeRNG(&rng);
    // create a packet with component id and encrypted message
    validate_message* packet1 = (validate_message*) transmit_buffer;
    packet1->component_id = COMPONENT_ID;
    memcpy(packet1->cVertMessage, outByte, sizeof(outByte));

    //Send the signed verification message here: 
    secure_send(sizeof(validate_message), transmit_buffer);

}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    secure_send(len, transmit_buffer);
}

/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    
    LED_On(LED2);

    while (1) {
        secure_receive(receive_buffer);

        component_process_cmd();
    }
}
