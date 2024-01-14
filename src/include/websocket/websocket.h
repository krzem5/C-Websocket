#ifndef _WEBSOCKET_WEBSOCKET_H_
#define _WEBSOCKET_WEBSOCKET_H_ 1
#include <stdint.h>



typedef void (*ws_callback_t)(_Bool binary,const void* data,uint16_t length);



_Bool ws_init(uint16_t port,ws_callback_t callback);



void ws_update(void);



_Bool ws_send_packet(_Bool binary,const void* data,uint16_t length);



_Bool _ws_authenticate(int socket,const char* request);



#endif
