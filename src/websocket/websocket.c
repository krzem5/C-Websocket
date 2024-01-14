#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <websocket/websocket.h>



#define WEBSOCKET_FRAME_TYPE_CONTINUATION 0
#define WEBSOCKET_FRAME_TYPE_TEXT 1
#define WEBSOCKET_FRAME_TYPE_BINARY 2
#define WEBSOCKET_FRAME_TYPE_CLOSE 8
#define WEBSOCKET_FRAME_TYPE_PING 9
#define WEBSOCKET_FRAME_TYPE_PONG 10

#define WEBSOCKET_BUFFER_SIZE 4096



static ws_callback_t _ws_callback=NULL;
static int _ws_server_socket=0;
static int _ws_client_socket=0;
static _Bool _ws_client_connected=0;



static _Bool _send_packet(uint8_t frame_header,const void* data,uint16_t length){
	if (!_ws_client_connected||(length>>16)){
		return 0;
	}
	uint8_t header_length=(length>125?4:2);
	uint8_t* buffer=malloc(length+header_length);
	buffer[0]=frame_header;
	if (header_length==2){
		buffer[1]=length;
	}
	else{
		buffer[1]=126;
		buffer[2]=length;
		buffer[3]=length>>8;
	}
	memcpy(buffer+header_length,data,length);
	_Bool out=(send(_ws_client_socket,buffer,length+header_length,MSG_NOSIGNAL)==length+header_length);
	free(buffer);
	return out;
}



_Bool ws_init(uint16_t port,ws_callback_t callback){
	struct sockaddr_in address;
	address.sin_family=AF_INET;
	address.sin_port=__builtin_bswap16(port);
	address.sin_addr.s_addr=0x00000000;
	_ws_server_socket=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0);
	int reuse=1;
	if (_ws_server_socket<0||setsockopt(_ws_server_socket,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(int))<0||bind(_ws_server_socket,(struct sockaddr*)(&address),sizeof(struct sockaddr_in))<0){
		return 0;
	}
	listen(_ws_server_socket,16);
	_ws_callback=callback;
	_ws_client_socket=0;
	_ws_client_connected=0;
	return 1;
}



void ws_update(void){
	if (!_ws_client_socket){
		int sock=accept4(_ws_server_socket,NULL,NULL,SOCK_NONBLOCK);
		if (sock<=0){
			return;
		}
		_ws_client_socket=sock;
		_ws_client_connected=0;
	}
	uint8_t buffer[WEBSOCKET_BUFFER_SIZE];
	ssize_t buffer_length=read(_ws_client_socket,buffer,WEBSOCKET_BUFFER_SIZE);
	if (buffer_length<=0){
		return;
	}
	if (!_ws_client_connected){
		buffer[(buffer_length==WEBSOCKET_BUFFER_SIZE?buffer_length-1:buffer_length)]=0;
		if (!_ws_authenticate(_ws_client_socket,(const char*)buffer)){
			goto _error;
		}
		_ws_client_connected=1;
		return;
	}
	uint8_t current_frame_type=0xff;
	uint32_t current_frame_length=0;
	uint8_t* current_frame_data=NULL;
	for (uint32_t buffer_offset=0;buffer_offset+1<buffer_length;){
		uint8_t frame_type=buffer[buffer_offset];
		_Bool frame_masking_key_present=buffer[buffer_offset+1]>>7;
		uint16_t frame_length=buffer[buffer_offset+1]&0x7f;
		buffer_offset+=2;
		if (frame_length==126){
			buffer_offset+=2;
			if (buffer_offset>buffer_length){
				return;
			}
			frame_length=buffer[buffer_offset-2]|(buffer[buffer_offset-1]<<8);
		}
		else if (frame_length==127){
			printf("64-bit length\n");
			goto _error;
		}
		uint32_t mask=0;
		if (frame_masking_key_present){
			mask=*((const uint32_t*)(buffer+buffer_offset));
			buffer_offset+=sizeof(uint32_t);
		}
		if (buffer_offset+frame_length>buffer_length){
			printf("Packet too large\n");
			return;
		}
		if (frame_type&0x70){
			goto _error;
		}
		_Bool frame_is_last=frame_type>>7;
		frame_type&=0x0f;
		if (frame_type==WEBSOCKET_FRAME_TYPE_CONTINUATION){
			if (current_frame_type==0xff){
				goto _error;
			}
			goto _read_frame;
		}
		else if (frame_type==WEBSOCKET_FRAME_TYPE_TEXT||frame_type==WEBSOCKET_FRAME_TYPE_BINARY){
			if (current_frame_type!=0xff){
				goto _error;
			}
			current_frame_type=frame_type;
_read_frame:
			current_frame_data=realloc(current_frame_data,current_frame_length+frame_length+1);
			for (uint32_t i=0;i<frame_length;i++){
				current_frame_data[current_frame_length+i]=buffer[buffer_offset+i]^(mask>>((i&3)<<3));
			}
			current_frame_length+=frame_length;
			if (frame_is_last){
				current_frame_data[current_frame_length]=0;
				_ws_callback(current_frame_type==WEBSOCKET_FRAME_TYPE_BINARY,current_frame_data,current_frame_length);
				current_frame_type=0xff;
				current_frame_length=0;
				free(current_frame_data);
				current_frame_data=NULL;
			}
		}
		else if (frame_type==WEBSOCKET_FRAME_TYPE_CLOSE){
			goto _error;
		}
		else if (frame_type==WEBSOCKET_FRAME_TYPE_PING){
			printf("WEBSOCKET_FRAME_TYPE_PING\n");
		}
		else if (frame_type==WEBSOCKET_FRAME_TYPE_PONG){
			printf("WEBSOCKET_FRAME_TYPE_PONG\n");
		}
		else{
			goto _error;
		}
		buffer_offset+=buffer_length;
	}
	return;
_error:
	shutdown(_ws_client_socket,SHUT_RDWR);
	close(_ws_client_socket);
	_ws_client_socket=0;
	_ws_client_connected=0;
}



_Bool ws_send_packet(_Bool binary,const void* data,uint16_t length){
	return _send_packet((binary?WEBSOCKET_FRAME_TYPE_BINARY:WEBSOCKET_FRAME_TYPE_TEXT)|0x80,data,length);
}
