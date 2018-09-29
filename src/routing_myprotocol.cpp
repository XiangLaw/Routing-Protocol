#include<stdio.h>
#include<stdlib.h>
#include<limits.h>

#include "api.h"
#include "network_ip.h"
#include "routing_myprotocol.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#define DEBUG_TRACE               0

#define DEBUG_ROUTE_CACHE         0

#define DEBUG_ROUTING_TABLE       0

#define DEBUG_ERROR               0

#define DEBUG_MAINTENANCE_BUFFER  0

#define DEBUG_SEND_BUFFER         0

#define DEBUG_RREQ_BUFFER         0

#define DEBUG_DISCOVERY           0


//------------------------------------------
// Myprotocol Memory Manager
//------------------------------------------

//-------------------------------------------------------------------------
// FUNCTION: MyprotocolMemoryChunkAlloc
// PURPOSE: Function to allocate a chunk of memory
// ARGUMENTS: Pointer to Myprotocol main data structure
// RETURN: void
//-------------------------------------------------------------------------

static
void MyprotocolMemoryChunkAlloc(MyprotocolData* myprotocol)
{
    int i = 0;
    MyprotocolMemPollEntry* freeList = NULL;

    myprotocol->freeList = (MyprotocolMemPollEntry *) MEM_malloc(
                         MYPROTOCOL_MEM_UNIT * sizeof(MyprotocolMemPollEntry));

    ERROR_Assert(myprotocol->freeList != NULL, " No available Memory");

    freeList = myprotocol->freeList;

    for (i = 0; i < MYPROTOCOL_MEM_UNIT - 1; i++)
    {
        freeList[i].next = &freeList[i+1];
    }

    freeList[MYPROTOCOL_MEM_UNIT - 1].next = NULL;
}


//-------------------------------------------------------------------------
// FUNCTION: MyprotocolMemoryMalloc
// PURPOSE: Function to allocate a single cell of memory from the memory
//          chunk
// ARGUMENTS: Pointer to Myprotocol main data structure
// RETURN: Address of free memory cell
//-------------------------------------------------------------------------

static
MyprotocolRouteEntry* MyprotocolMemoryMalloc(MyprotocolData* myprotocol)
{
    MyprotocolRouteEntry* temp = NULL;

    if (!myprotocol->freeList)
    {
        MyprotocolMemoryChunkAlloc(myprotocol);
    }

    temp = (MyprotocolRouteEntry*)myprotocol->freeList;
    myprotocol->freeList = myprotocol->freeList->next;
    return temp;
}


//-------------------------------------------------------------------------
// FUNCTION: MyprotocolMemoryFree
// PURPOSE: Function to return a memory cell to the memory pool
// ARGUMENTS: Pointer to Myprotocol main data structure,
//            pointer to route entry
// RETURN: void
//-------------------------------------------------------------------------


static
void MyprotocolMemoryFree(MyprotocolData* myprotocol,MyprotocolRouteEntry* ptr)
{
    MyprotocolMemPollEntry* temp = (MyprotocolMemPollEntry*)ptr;
    temp->next = myprotocol->freeList;
    myprotocol->freeList = temp;
}


//--------------------------------------------------------------------------
// FUNCTION: MyprotocolPeekFunction
// PURPOSE:  Processing a overheard packet.
// ARGUMENTS: node, The node initializing Myprotocol
//            msg, Packet received for overhearing the channel
//            previousHop, The node from which the packet has been received
// RETURN:   None
//--------------------------------------------------------------------------

void
MyprotocolPeekFunction(Node *node, const Message *msg, NodeAddress previousHop)
{
    IpHeaderType* ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
    int ipHdrLen = IpHeaderSize(ipHeader);

    if (ipHeader->ip_p == IPPROTO_MYPROTOCOL)
    {
        unsigned char* myprotocolPktPtr = (unsigned char *) ipHeader + ipHdrLen;

        // This is dsr control packet
        unsigned char* optPtr = dsrPktPtr + DSR_SIZE_OF_HEADER;
        unsigned short payloadLen = 0;
        memcpy(&payloadLen, dsrPktPtr + sizeof(unsigned short),
            sizeof(unsigned short));

        if (*optPtr == DSR_ROUTE_REQUEST)
        {
            // Process overheard route request
            // Nothing to do as request is sent as
            // broadcast so the will have or already
            // has processed one
            return;
        }
        else
        {
            // Need to process dsr specific information
            Message* duplicateMsg = MESSAGE_Duplicate(node, msg);

            if (DEBUG_TRACE)
            {
                DsrData* dsr = (DsrData *)
                    NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DSR);
                DsrTrace(
                    node,
                    dsr,
                    dsrPktPtr,
                    "Receive",
                    ipHeader->ip_dst,
                    ipHeader->ip_src);
            }

            DsrHandleOptions(
                node,
                duplicateMsg,
                optPtr,
                payloadLen,
                ipHeader->ip_src,
                ipHeader->ip_dst,
                ipHeader->ip_ttl,
                previousHop,
                TRUE);

            MESSAGE_Free(node, duplicateMsg);
        }
    }
    else
    {
        // This packet does not contain any dsr information so there
        // is nothing to do
    }
}

//--------------------------------------------------------------------------
// FUNCTION: MyprotocolInitRouteCache
// PURPOSE:  Function to initialize Myprotocol route cache
// ARGUMENTS: route cache pointer
// ASSUMPTION: None
//--------------------------------------------------------------------------

static
void MyprotocolInitRouteCache(MyprotocolRouteCache* routeCache)
{
    // Initialize Myprotocol route Cache
    int i = 0;
    for (i = 0; i < MYPROTOCOL_ROUTE_HASH_TABLE_SIZE; i++)
    {
        routeCache->hashTable[i] = NULL;
    }
    routeCache->deleteListHead = NULL;
    routeCache->deleteListTail = NULL;
    routeCache->count = 0;
 }

//////////////////////////////////////////////////////////////////////
// Functions related to message buffer

//-------------------------------------------------------------------------
// FUNCTION: MyprotocolInitBuffer
// PURPOSE:  Initializing myprotocol packet buffer where packets waiting for a
//           route are to be stored
// ARGUMENTS: Pointer to the message buffer
// RETURN:   None
//-------------------------------------------------------------------------

static
void MyprotocolInitBuffer(MyprotocolBuffer *msgBuffer)
{
    // Initialize message buffer
    msgBuffer->head = NULL;
    msgBuffer->sizeInPacket = 0;
    msgBuffer->sizeInByte = 0;
}


//--------------------------------------------------------------------------
// FUNCTION: MyprotocolInit
// PURPOSE:  Initializing Myprotocol internal variables and structures
//           as well as providing network with a router function
//           a Mac status handler and a promiscuous mode operation
//           function.
// ARGUMENTS: node, The node initializing Myprotocol
//            myprotocolPtr, Space to allocate Myprotocol internal structure
//            nodeInput, Qualnet main configuration file
//            interfaceIndex, The interface where myprotocol has been assigned
//                             as a routing protocol
// RETURN:   None
//--------------------------------------------------------------------------


void MyprotocolInit(
         Node* node,
         MyprotocolData** myprotocolPtr,
         const NodeInput* nodeInput,
         int interfaceIndex)
{
		BOOL retVal = FALSE;
		char buf[MAX_STRING_LENGTH];
	
		if (MAC_IsWiredNetwork(node, interfaceIndex))
		{
			ERROR_ReportError("Myprotocol can only support wireless interfaces");
		}
	
		if (node->numberInterfaces > 1)
		{
			ERROR_ReportError("Myprotocol only supports one interface of node");
		}
	
		(*myprotocolPtr) = (MyprotocolData *) MEM_malloc(sizeof(MyprotocolData));
	
		if ((*myprotocolPtr) == NULL)
		{
			fprintf(stderr, "Myprotocol: Cannot alloc memory for MYPROTOCOL struct!\n");
			assert (FALSE);
		}
	
		RANDOM_SetSeed((*myprotocolPtr)->seed,
					   node->globalSeed,
					   node->nodeId,
					   ROUTING_PROTOCOL_MYPROTOCOL,
					   interfaceIndex);
	
		(*myprotocolPtr)->isTimerSet = FALSE;
	
		IO_ReadString(
			node->nodeId,
			ANY_ADDRESS,
			nodeInput,
			"ROUTING-STATISTICS",
			&retVal,
			buf);
	
		if ((retVal == FALSE) || (strcmp(buf, "NO") == 0))
		{
			((*myprotocolPtr)->statsCollected) = FALSE;
		}
		else if (strcmp(buf, "YES") == 0)
		{
			((*myprotocolPtr)->statsCollected) = TRUE;
		}
		else
		{
			ERROR_ReportError("Need YES or NO for ROUTING-STATISTICS");
		}
	
		// Initialize statistics
		memset(&((*myprotocolPtr)->stats), 0, sizeof(MyprotocolStats));
		(*myprotocolPtr)->statsPrinted = FALSE;
	
		IO_ReadInt(
			node->nodeId,
			NetworkIpGetInterfaceAddress(node, 0),
			nodeInput,
			"MYPROTOCOL-BUFFER-MAX-PACKET",
			&retVal,
			&((*myprotocolPtr)->bufferMaxSizeInPacket));
	
		if (retVal == FALSE)
		{
			(*myprotocolPtr)->bufferMaxSizeInPacket = MYPROTOCOL_REXMT_BUFFER_SIZE;
		}
	
		ERROR_Assert(((*myprotocolPtr)->bufferMaxSizeInPacket) > 0,
			"MYPROTOCOL-BUFFER-MAX-PACKET needs to be a positive number\n");
	
		IO_ReadInt(
			node->nodeId,
			NetworkIpGetInterfaceAddress(node, 0),
			nodeInput,
			"MYPROTOCOL-BUFFER-MAX-BYTE",
			&retVal,
			&((*myprotocolPtr)->bufferMaxSizeInByte));
	
		if (retVal == FALSE)
		{
			(*myprotocolPtr)->bufferMaxSizeInByte = 0;
		}
	
		ERROR_Assert((*myprotocolPtr)->bufferMaxSizeInByte >= 0,
			"MYPROTOCOL-BUFFER-MAX-BYTE cannot be negative\n");
	
		// Initialize myprotocol internal structures
	
		// Initialize statistical variables
		memset(&(*myprotocolPtr)->stats, 0, sizeof(MyprotocolStats));
	
		// Allocate chunk of memory
		MyprotocolMemoryChunkAlloc(*myprotocolPtr);
	
		// Initialize request table
		MyprotocolInitRequestTable(&(*myprotocolPtr)->reqTable);
	
		// Initialize route cache
		MyprotocolInitRouteCache(&(*myprotocolPtr)->routeCache);
	      
		// Initialize message buffer;
		MyprotocolInitBuffer(&(*myprotocolPtr)->msgBuffer);
	
		MyprotocolInitRexmtBuffer(&(*myprotocolPtr)->rexmtBuffer);
	
		// Initialize sequence number
		(*myprotocolPtr)->identificationNumber = 0;
	
		// Assign 0 th interface address as myprotocol local address.
		// This message should be used to send any request or reply
	
		(*myprotocolPtr)->localAddress = NetworkIpGetInterfaceAddress(node, 0);
	
		// Set network router function
		NetworkIpSetRouterFunction(
			node,
			&MyprotocolRouterFunction,
			interfaceIndex);
	
		// Set mac layer status event handler
		NetworkIpSetMacLayerStatusEventHandlerFunction(
			node,
			&MyprotocolMacLayerStatusHandler,
			interfaceIndex);
	
		// Set promiscuous message peek function
		NetworkIpSetPromiscuousMessagePeekFunction(
			node,
			&MyprotocolPeekFunction,
			interfaceIndex);
	
		NetworkIpSetMacLayerAckHandler(
			node,
			&MyprotocolMacAckHandler,
			interfaceIndex);
	
		if (DEBUG_TRACE)
		{
			MyprotocolTraceInit(node, nodeInput, *myprotocolPtr);
		}
}
         

