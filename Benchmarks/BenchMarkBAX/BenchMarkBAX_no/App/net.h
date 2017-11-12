/******************************************************************************
BINIAX NETWORK-RELATED DEFINITIONS
COPYRIGHT JORDAN TUZSUZOV, (C) 2006.

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

LICENSE ORIGIN : http://www.gzip.org/zlib/zlib_license.html

For complete product license refer to LICENSE.TXT file

******************************************************************************/

#ifndef _BNX_NET_H
#define _BNX_NET_H

/******************************************************************************
INCLUDES
******************************************************************************/

#include <SDL_net.h>

#include "inc.h"

/******************************************************************************
LOCAL NETWORK DATA (SOCKETS, IP's, ETC.)
******************************************************************************/

#define cNetPortServer	8291
#define cNetPortClient	8192
#define cNetTimeout	(5*1000)
#define cNetFlagByte (BNX_UINT8) (69)

typedef struct BNX_NET 
{

	TCPsocket		tcpServerRead;
	TCPsocket		tcpClientRead;

} BNX_NET;

/******************************************************************************
FUNCTIONS
******************************************************************************/

BNX_BOOL netInit();
void netClose();

BNX_BOOL netSendGame( BNX_GAME *game );
BNX_BOOL netSendKeys( BNX_INP *keys );

BNX_BOOL netReceiveGame( BNX_GAME *game );
BNX_BOOL netReceiveKeys( BNX_INP *keys );

BNX_BOOL netListen();
BNX_BOOL netConnect( char* host );

#endif
