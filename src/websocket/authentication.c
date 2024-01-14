#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>



#define WEBSOCKET_REQUEST_KEY_FIELD "Sec-WebSocket-Key:"
#define WEBSOCKET_RESPONSE_PREFIX "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
#define WEBSOCKET_RESPONSE_SUFFIX "############################\r\n\r\n"

#define WEBSOCKET_REQUEST_KEY_LENGTH 24
#define WEBSOCKET_KEY_HASH_SEED "########################258EAFA5-E914-47DA-95CA-C5AB0DC85B11"



#define SHA1_ROTATE_BITS(a,b) (((a)<<(b))|((a)>>(32-(b))))

#define SHA1_STEP0(b,c,d) (d^(b&(c^d)))+0x5a827999
#define SHA1_STEP1(b,c,d) (b^c^d)+0x6ed9eba1
#define SHA1_STEP2(b,c,d) ((b&c)|(b&d)|(c&d))+0x8f1bbcdc
#define SHA1_STEP3(b,c,d) (b^c^d)+0xca62c1d6
#define SHA1_STEP(a,b,c,d,e,fn,v) \
	e=SHA1_ROTATE_BITS(a,5)+SHA1_STEP##fn(b,c,d)+e+v; \
	b=SHA1_ROTATE_BITS(b,30);



static const char* _base64_alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";



static void _base64_encode_hash_inplace(const unsigned char* src,char* out){
	uint32_t j=0;
	for (uint32_t i=0;i<18;i+=3){
		out[j]=_base64_alphabet[src[i]>>2];
		out[j+1]=_base64_alphabet[((src[i]<<4)&0x3f)|(src[i+1]>>4)];
		out[j+2]=_base64_alphabet[((src[i+1]<<2)&0x3f)|(src[i+2]>>6)];
		out[j+3]=_base64_alphabet[src[i+2]&0x3f];
		j+=4;
	}
	out[24]=_base64_alphabet[src[18]>>2];
	out[25]=_base64_alphabet[((src[18]<<4)&0x3f)|(src[19]>>4)];
	out[26]=_base64_alphabet[(src[19]<<2)&0x3f];
	out[27]='=';
}



static void _sha1_process_chunk(const uint32_t* buffer,uint32_t* hash_state){
	uint32_t w[80];
	for (uint8_t i=0;i<16;i++){
		w[i]=__builtin_bswap32(buffer[i]);
	}
	for (uint8_t i=16;i<80;i++){
		w[i]=SHA1_ROTATE_BITS(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
	}
	uint32_t a=hash_state[0];
	uint32_t b=hash_state[1];
	uint32_t c=hash_state[2];
	uint32_t d=hash_state[3];
	uint32_t e=hash_state[4];
	SHA1_STEP(a,b,c,d,e,0,w[0]);
	SHA1_STEP(e,a,b,c,d,0,w[1]);
	SHA1_STEP(d,e,a,b,c,0,w[2]);
	SHA1_STEP(c,d,e,a,b,0,w[3]);
	SHA1_STEP(b,c,d,e,a,0,w[4]);
	SHA1_STEP(a,b,c,d,e,0,w[5]);
	SHA1_STEP(e,a,b,c,d,0,w[6]);
	SHA1_STEP(d,e,a,b,c,0,w[7]);
	SHA1_STEP(c,d,e,a,b,0,w[8]);
	SHA1_STEP(b,c,d,e,a,0,w[9]);
	SHA1_STEP(a,b,c,d,e,0,w[10]);
	SHA1_STEP(e,a,b,c,d,0,w[11]);
	SHA1_STEP(d,e,a,b,c,0,w[12]);
	SHA1_STEP(c,d,e,a,b,0,w[13]);
	SHA1_STEP(b,c,d,e,a,0,w[14]);
	SHA1_STEP(a,b,c,d,e,0,w[15]);
	SHA1_STEP(e,a,b,c,d,0,w[16]);
	SHA1_STEP(d,e,a,b,c,0,w[17]);
	SHA1_STEP(c,d,e,a,b,0,w[18]);
	SHA1_STEP(b,c,d,e,a,0,w[19]);
	SHA1_STEP(a,b,c,d,e,1,w[20]);
	SHA1_STEP(e,a,b,c,d,1,w[21]);
	SHA1_STEP(d,e,a,b,c,1,w[22]);
	SHA1_STEP(c,d,e,a,b,1,w[23]);
	SHA1_STEP(b,c,d,e,a,1,w[24]);
	SHA1_STEP(a,b,c,d,e,1,w[25]);
	SHA1_STEP(e,a,b,c,d,1,w[26]);
	SHA1_STEP(d,e,a,b,c,1,w[27]);
	SHA1_STEP(c,d,e,a,b,1,w[28]);
	SHA1_STEP(b,c,d,e,a,1,w[29]);
	SHA1_STEP(a,b,c,d,e,1,w[30]);
	SHA1_STEP(e,a,b,c,d,1,w[31]);
	SHA1_STEP(d,e,a,b,c,1,w[32]);
	SHA1_STEP(c,d,e,a,b,1,w[33]);
	SHA1_STEP(b,c,d,e,a,1,w[34]);
	SHA1_STEP(a,b,c,d,e,1,w[35]);
	SHA1_STEP(e,a,b,c,d,1,w[36]);
	SHA1_STEP(d,e,a,b,c,1,w[37]);
	SHA1_STEP(c,d,e,a,b,1,w[38]);
	SHA1_STEP(b,c,d,e,a,1,w[39]);
	SHA1_STEP(a,b,c,d,e,2,w[40]);
	SHA1_STEP(e,a,b,c,d,2,w[41]);
	SHA1_STEP(d,e,a,b,c,2,w[42]);
	SHA1_STEP(c,d,e,a,b,2,w[43]);
	SHA1_STEP(b,c,d,e,a,2,w[44]);
	SHA1_STEP(a,b,c,d,e,2,w[45]);
	SHA1_STEP(e,a,b,c,d,2,w[46]);
	SHA1_STEP(d,e,a,b,c,2,w[47]);
	SHA1_STEP(c,d,e,a,b,2,w[48]);
	SHA1_STEP(b,c,d,e,a,2,w[49]);
	SHA1_STEP(a,b,c,d,e,2,w[50]);
	SHA1_STEP(e,a,b,c,d,2,w[51]);
	SHA1_STEP(d,e,a,b,c,2,w[52]);
	SHA1_STEP(c,d,e,a,b,2,w[53]);
	SHA1_STEP(b,c,d,e,a,2,w[54]);
	SHA1_STEP(a,b,c,d,e,2,w[55]);
	SHA1_STEP(e,a,b,c,d,2,w[56]);
	SHA1_STEP(d,e,a,b,c,2,w[57]);
	SHA1_STEP(c,d,e,a,b,2,w[58]);
	SHA1_STEP(b,c,d,e,a,2,w[59]);
	SHA1_STEP(a,b,c,d,e,3,w[60]);
	SHA1_STEP(e,a,b,c,d,3,w[61]);
	SHA1_STEP(d,e,a,b,c,3,w[62]);
	SHA1_STEP(c,d,e,a,b,3,w[63]);
	SHA1_STEP(b,c,d,e,a,3,w[64]);
	SHA1_STEP(a,b,c,d,e,3,w[65]);
	SHA1_STEP(e,a,b,c,d,3,w[66]);
	SHA1_STEP(d,e,a,b,c,3,w[67]);
	SHA1_STEP(c,d,e,a,b,3,w[68]);
	SHA1_STEP(b,c,d,e,a,3,w[69]);
	SHA1_STEP(a,b,c,d,e,3,w[70]);
	SHA1_STEP(e,a,b,c,d,3,w[71]);
	SHA1_STEP(d,e,a,b,c,3,w[72]);
	SHA1_STEP(c,d,e,a,b,3,w[73]);
	SHA1_STEP(b,c,d,e,a,3,w[74]);
	SHA1_STEP(a,b,c,d,e,3,w[75]);
	SHA1_STEP(e,a,b,c,d,3,w[76]);
	SHA1_STEP(d,e,a,b,c,3,w[77]);
	SHA1_STEP(c,d,e,a,b,3,w[78]);
	SHA1_STEP(b,c,d,e,a,3,w[79]);
	hash_state[0]+=a;
	hash_state[1]+=b;
	hash_state[2]+=c;
	hash_state[3]+=d;
	hash_state[4]+=e;
}



static void _calculate_sha1(const uint8_t* data,unsigned int length,uint8_t* out){
	uint8_t buffer[128];
	memset(buffer,0,128);
	memcpy(buffer,data,length);
	buffer[length]=0x80;
	buffer[124]=length>>21;
	buffer[125]=length>>13;
	buffer[126]=length>>5;
	buffer[127]=length<<3;
	uint32_t hash_state[5]={
		0x67452301,
		0xefcdab89,
		0x98badcfe,
		0x10325476,
		0xc3d2e1f0
	};
	for (uint8_t i=0;i<128;i+=64){
		_sha1_process_chunk((const uint32_t*)(buffer+i),hash_state);
	}
	for (int i=0;i<20;i++){
		out[i]=hash_state[i>>2]>>((3-(i&3))<<3);
	}
}



_Bool _ws_authenticate(int socket,const char* request){
	while (request[0]){
		if (request[0]==' '||request[0]=='\t'||request[0]=='\r'||request[0]=='\n'){
			request++;
			continue;
		}
		if (memcmp(request,WEBSOCKET_REQUEST_KEY_FIELD,sizeof(WEBSOCKET_REQUEST_KEY_FIELD)-1)){
			for (;request[0]&&request[0]!='\r';request++);
			continue;
		}
		request+=sizeof(WEBSOCKET_REQUEST_KEY_FIELD)-1;
		for (;request[0]==' '||request[0]=='\t';request++);
		goto _key_found;
	}
	return 0;
_key_found:;
	char hashed_buffer[]=WEBSOCKET_KEY_HASH_SEED;
	memcpy(hashed_buffer,request,WEBSOCKET_REQUEST_KEY_LENGTH);
	unsigned char hash[20];
	_calculate_sha1((const uint8_t*)hashed_buffer,sizeof(WEBSOCKET_KEY_HASH_SEED)-1,hash);
	char response_buffer[]=WEBSOCKET_RESPONSE_PREFIX WEBSOCKET_RESPONSE_SUFFIX;
	_base64_encode_hash_inplace(hash,response_buffer+sizeof(WEBSOCKET_RESPONSE_PREFIX)-1);
	return send(socket,response_buffer,sizeof(WEBSOCKET_RESPONSE_PREFIX WEBSOCKET_RESPONSE_SUFFIX)-1,MSG_NOSIGNAL)==sizeof(WEBSOCKET_RESPONSE_PREFIX WEBSOCKET_RESPONSE_SUFFIX)-1;
}
