/*
 * AES.h
 *
 * Created: 03/07/2024 11:55:39 ص
 *  Author: Moham
 */ 


#ifndef AES_H_
#define AES_H_

void AES_encrpt(uint8_t* key , uint8_t* message,uint8_t* encrptedMessage);
void AES_decrpt(uint8_t* key , uint8_t* message,uint8_t* decrptedMessage);



#endif /* AES_H_ */
