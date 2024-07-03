/*
 * AES.c
 *
 * Created: 03/07/2024 11:55:54 ص
 * Author: Mohamed
 * Embedded Software Engineer
 */ 
#include "stdint.h"


#include "AES_Private.h"
#include "AES.h"


/* Helper Function for AES encryption process */
static void SubBytes(uint8_t* message);
static void ShiftRows(uint8_t* message);
static void MixColumns(uint8_t* message);
static void AddRoundKey(uint8_t* key , uint8_t* message);

/* Helper Function for AES encryption process */
static void InverseShiftRows(uint8_t* message);
static void InverseSubBytes(uint8_t* message);
static void InverseMixColumns(uint8_t* message);

/* Key expanding */
static void KeyExpansion(uint8_t* InputKey, uint8_t it);
static void KeyExpansion_mainFunction(uint8_t* InputKey, uint8_t* OutputKey, uint8_t it );


void AES_encrpt(uint8_t* key , uint8_t* message,uint8_t* encrptedMessage)
{
	uint8_t local_message[16];
	uint8_t local_u8subkeys[11][16] ={0};

	for(uint8_t j=0;j<16;j++)
	{
		local_u8subkeys[0][j]=key[j];
	}
	for(uint8_t k=1;k<11;k++)
	{
		KeyExpansion_mainFunction(local_u8subkeys[k-1], local_u8subkeys[k], k-1);

	}
	/* copy message to local array*/
	for(uint8_t i=0;i<16;i++)
	{
		local_message[i] = message[i];
	}
	/* firt round message XOR key */
	AddRoundKey( local_u8subkeys[0],local_message);
	


	for (uint8_t i = 1; i < 10; i++)
	{
		SubBytes(local_message);
		ShiftRows(local_message);
		MixColumns(local_message);
		AddRoundKey(local_u8subkeys[i] , local_message);
	}

	SubBytes(local_message);
	ShiftRows(local_message);

	
	AddRoundKey(local_u8subkeys[10] , local_message);

	for(uint8_t i=0;i<16;i++)
	{
		encrptedMessage[i] = local_message[i];
	}
	
}

void AES_decrpt(uint8_t* key , uint8_t* message,uint8_t* decrptedMessage)
{
	uint8_t local_message[16];
	uint8_t local_u8subkeys[11][16] ={0};

	for(uint8_t j=0;j<16;j++)
	{
		local_u8subkeys[0][j]=key[j];
	}
	for(uint8_t k=1;k<11;k++)
	{
		KeyExpansion_mainFunction(local_u8subkeys[k-1], local_u8subkeys[k], k-1);

	}
	/* copy message to local array*/
	for(uint8_t i=0;i<16;i++)
	{
		local_message[i] = message[i];
	}
	/* firt round message XOR key */
	AddRoundKey( local_u8subkeys[10],local_message);
	InverseSubBytes(local_message);
	InverseShiftRows(local_message);
	for (uint8_t i = 9; i >0; i--)
	{
		AddRoundKey(local_u8subkeys[i] , local_message);
		InverseMixColumns(local_message);
		InverseSubBytes(local_message);
		InverseShiftRows(local_message);
	}
	AddRoundKey(local_u8subkeys[0] , local_message);

	for(uint8_t i=0;i<16;i++)
	{
		decrptedMessage[i] = local_message[i];
	}

}
/************************************************************************/
/*                      AES Encryption function                         */
/************************************************************************/

static void AddRoundKey(uint8_t* key , uint8_t* message)
{
	for(int i =0;i<16;i++)
	{
		message[i] ^= key[i];
	}
}
static void SubBytes(uint8_t* message)
{
	for (uint8_t i = 0; i < 16; i++)
	{
		message[i] = s_Box[message[i]];
	}
	
	
}
static void ShiftRows(uint8_t* message)
{
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = message[0];
	tmp[1] = message[5];
	tmp[2] = message[10];
	tmp[3] = message[15];
	
	/* Column 2 */
	tmp[4] = message[4];
	tmp[5] = message[9];
	tmp[6] = message[14];
	tmp[7] = message[3];

	/* Column 3 */
	tmp[8] = message[8];
	tmp[9] = message[13];
	tmp[10] = message[2];
	tmp[11] = message[7];
	
	/* Column 4 */
	tmp[12] = message[12];
	tmp[13] = message[1];
	tmp[14] = message[6];
	tmp[15] = message[11];

	for (int i = 0; i < 16; i++) {
		message[i] = tmp[i];
	}
}
static void MixColumns(uint8_t* message)
{
	int temp[16];
	temp[0] = (uint8_t) mul2[message[0]] ^ mul3[message[1]] ^ message[2] ^ message[3];
	temp[1] = (uint8_t) message[0] ^ mul2[message[1]] ^ mul3[message[2]] ^ message[3];
	temp[2] = (uint8_t) message[0] ^ message[1] ^ mul2[message[2]] ^ mul3[message[3]];
	temp[3] = (uint8_t) mul3[message[0]] ^ message[1] ^ message[2] ^ mul2[message[3]];

	temp[4] = (uint8_t)mul2[message[4]] ^ mul3[message[5]] ^ message[6] ^ message[7];
	temp[5] = (uint8_t)message[4] ^ mul2[message[5]] ^ mul3[message[6]] ^ message[7];
	temp[6] = (uint8_t)message[4] ^ message[5] ^ mul2[message[6]] ^ mul3[message[7]];
	temp[7] = (uint8_t)mul3[message[4]] ^ message[5] ^ message[6] ^ mul2[message[7]];

	temp[8] = (uint8_t)mul2[message[8]] ^ mul3[message[9]] ^ message[10] ^ message[11];
	temp[9] = (uint8_t)message[8] ^ mul2[message[9]] ^ mul3[message[10]] ^ message[11];
	temp[10] = (uint8_t)message[8] ^ message[9] ^ mul2[message[10]] ^ mul3[message[11]];
	temp[11] = (uint8_t)mul3[message[8]] ^ message[9] ^ message[10] ^ mul2[message[11]];

	temp[12] = (uint8_t)mul2[message[12]] ^ mul3[message[13]] ^ message[14] ^ message[15];
	temp[13] = (uint8_t)message[12] ^ mul2[message[13]] ^ mul3[message[14]] ^ message[15];
	temp[14] = (uint8_t)message[12] ^ message[13] ^ mul2[message[14]] ^ mul3[message[15]];
	temp[15] = (uint8_t)mul3[message[12]] ^ message[13] ^ message[14] ^ mul2[message[15]];
	for (int i = 0; i < 16; i++) {
		message[i] = temp[i];
	}
}

/************************************************************************/
/*                      AES decryption function                         */
/************************************************************************/

static void InverseShiftRows(uint8_t* message)
{
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = message[0];
	tmp[1] = message[13];
	tmp[2] = message[10];
	tmp[3] = message[7];

	/* Column 2 */
	tmp[4] = message[4];
	tmp[5] = message[1];
	tmp[6] = message[14];
	tmp[7] = message[11];

	/* Column 3 */
	tmp[8] = message[8];
	tmp[9] = message[5];
	tmp[10] = message[2];
	tmp[11] = message[15];

	/* Column 4 */
	tmp[12] = message[12];
	tmp[13] = message[9];
	tmp[14] = message[6];
	tmp[15] = message[3];

	for (int i = 0; i < 16; i++) {
		message[i] = tmp[i];
	}
}
static void InverseSubBytes(uint8_t* message)
{
	for (uint8_t i = 0; i < 16; i++)
	{
		message[i] = Inv_s_Box[message[i]];
	}
	
	
}
static void InverseMixColumns(uint8_t* message)
{
	int temp[16];
	temp[0] = (uint8_t)mul14[message[0]] ^ mul11[message[1]] ^ mul13[message[2]] ^ mul9[message[3]];
	temp[1] = (uint8_t)mul9[message[0]] ^ mul14[message[1]] ^ mul11[message[2]] ^ mul13[message[3]];
	temp[2] = (uint8_t)mul13[message[0]] ^ mul9[message[1]] ^ mul14[message[2]] ^ mul11[message[3]];
	temp[3] = (uint8_t)mul11[message[0]] ^ mul13[message[1]] ^ mul9[message[2]] ^ mul14[message[3]];

	temp[4] = (uint8_t)mul14[message[4]] ^ mul11[message[5]] ^ mul13[message[6]] ^ mul9[message[7]];
	temp[5] = (uint8_t)mul9[message[4]] ^ mul14[message[5]] ^ mul11[message[6]] ^ mul13[message[7]];
	temp[6] = (uint8_t)mul13[message[4]] ^ mul9[message[5]] ^ mul14[message[6]] ^ mul11[message[7]];
	temp[7] = (uint8_t)mul11[message[4]] ^ mul13[message[5]] ^ mul9[message[6]] ^ mul14[message[7]];

	temp[8] = (uint8_t)mul14[message[8]] ^ mul11[message[9]] ^ mul13[message[10]] ^ mul9[message[11]];
	temp[9] = (uint8_t)mul9[message[8]] ^ mul14[message[9]] ^ mul11[message[10]] ^ mul13[message[11]];
	temp[10] = (uint8_t)mul13[message[8]] ^ mul9[message[9]] ^ mul14[message[10]] ^ mul11[message[11]];
	temp[11] = (uint8_t)mul11[message[8]] ^ mul13[message[9]] ^ mul9[message[10]] ^ mul14[message[11]];

	temp[12] = (uint8_t)mul14[message[12]] ^ mul11[message[13]] ^ mul13[message[14]] ^ mul9[message[15]];
	temp[13] = (uint8_t)mul9[message[12]] ^ mul14[message[13]] ^ mul11[message[14]] ^ mul13[message[15]];
	temp[14] = (uint8_t)mul13[message[12]] ^ mul9[message[13]] ^ mul14[message[14]] ^ mul11[message[15]];
	temp[15] = (uint8_t)mul11[message[12]] ^ mul13[message[13]] ^ mul9[message[14]] ^ mul14[message[15]];
	for (int i = 0; i < 16; i++) {
		message[i] = temp[i];
	}
}

/************************************************************************/
/*                      key expanding function                          */
/************************************************************************/

static void KeyExpansion(uint8_t* InputKey, uint8_t it)
{
	uint8_t temp = InputKey[0];
	InputKey[0] = InputKey[1];
	InputKey[1] = InputKey[2];
	InputKey[2] = InputKey[3];
	InputKey[3] = temp;

	// S-box 4 bytes
	InputKey[0] = s_Box[InputKey[0]];
	InputKey[1] = s_Box[InputKey[1]];
	InputKey[2] = s_Box[InputKey[2]];
	InputKey[3] = s_Box[InputKey[3]];

	// RCon
	InputKey[0] ^= rcon[it];
}
static void KeyExpansion_mainFunction(uint8_t* InputKey, uint8_t* OutputKey, uint8_t it )
{

	uint8_t local_u8KeyLastRow[4] ;
	for (uint8_t i = 0; i < 4; i++)
	{
		local_u8KeyLastRow[i] = InputKey[i+12];
	}
	KeyExpansion(local_u8KeyLastRow,  it);
	for(uint8_t i=0 ;i<4;i++ )
	{
		OutputKey[i] = local_u8KeyLastRow[i] ^InputKey[i];
	}
	for(uint8_t i=4 ;i<16;i++ )
	{
		OutputKey[i] = InputKey[i]^OutputKey[i-4];
	}

	


}
