#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <websocket/websocket.h>



static void _callback(_Bool binary,const void* data,uint16_t length){
	printf("%u %u %s\n",binary,length,(const char*)data);
	ws_send_packet(binary,data,length);
}



int main(void){
	if (!ws_init(8080,_callback)){
		return 1;
	}
	while (1){
		ws_update();
		usleep(16000);
	}
	return 0;
}
