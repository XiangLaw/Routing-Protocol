#include<stdio.h>
#include<stdlib.h>
#include<limits.h>

#include "api.h"
#include "network_ip.h"
#include "routing_myprotocol.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#define  MYPROTOCOL_DEBUG 0

//------------------------------------------
// Myprotocol Memory Manager
//------------------------------------------

// /**
// FUNCTION : MyprotocolMemoryChunkAlloc
// LAYER    : NETWORK
// PURPOSE  : Function to allocate a chunk of memory
// PARAMETERS:
// +myprotocol:MyprotocolData*:Pointer to MyprotocolData
// RETURN   ::void:NULL
// **/

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


// /**
// FUNCTION  : MyprotocolMemoryMalloc
// LAYER     : NETWORK
// PURPOSE   : Function to allocate a single cell of
//             memory from the memory chunk
// PARAMETERS:
// +myprotocol:MyprotocolData*:Pointer to Myprotocol main data structure
// RETURN    :
// temp:MyprotocolRouteEntry*:Address of free memory cell
// **/

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


// /**
// FUNCTION : MyprotocolMemoryFree
// LAYER    : NETWORK
// PURPOSE  : Function to return a memory cell to the memory pool
// PARAMETERS:
// +myprotocol:MyprotocolData*:Pointer to Myprotocol main data structure
// +ptr:MyprotocolRouteEntry*: Pointer to myprotocol route entry
// RETURN   ::void:NULL
// **/


static
void MyprotocolMemoryFree(MyprotocolData* myprotocol,MyprotocolRouteEntry* ptr)
{
    MyprotocolMemPollEntry* temp = (MyprotocolMemPollEntry*)ptr;
    temp->next = myprotocol->freeList;
    myprotocol->freeList = temp;
}


// /**
// FUNCTION   :: MyprotocolReplaceInsertRouteTable
// LAYER      :: NETWORK
// PURPOSE    :: Insert/Update an entry into the route table.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:   Message* : Pointer to the Rreq packet
// RETURN     :: void : NULL.
// **/

static
void MyprotocolReplaceInsertRouteTable(
                    Node* node,
                    Message* msg,
                    MyprotocolRouteCache* routeCache)
{
	MyprotocolData* myprotocol = NULL;
	MyprotocolRreqPacket* oldRreq = NULL;
	MyprotocolRouteEntry* theNode = NULL;
	myprotocol = (MyprotocolData*)NetworkIpGetRoutingProtocol(
					  node, 
					  ROUTING_PROTOCOL_MYPROTOCOL, 
					  NETWORK_IPV4);
	oldRreq = (MyprotocolRreqPacket *) MESSAGE_ReturnPacket(msg);
	if(myprotocol->routeCache.count == 0)
	{
	     ++(myprotocol->routeCache.count);	
		 theNode = MyprotocolMemoryMalloc(myprotocol);
		 memset(theNode, 0,sizeof(MyprotocolRouteEntry));
		 theNode->hopCount = (oldRreq->hopCount)+1;
		 theNode->nextHop = oldRreq->address;
		 theNode->isCongested = FALSE;
		 theNode->sequenceNumber = oldRreq->sequenceNumber;
		 theNode->routeEntryTime = getSimTime(node);
		 theNode->prev = NULL;
		 theNode->next = NULL;
		 theNode->deletePrev = NULL;
		 theNode->deleteNext = NULL;
	}
	else
	{
		for(int i = 0; i < myprotocol->routeCache.count; i++)
		{
			if(oldRreq->address == routeCache->hashTable[i]->nextHop))
			{
				if(oldRreq->sequenceNumber > routeCache->hashTable[i]->sequenceNumber)
				{
					routeCache->hashTable[i]->hopCount = (oldRreq->hopCount)+1;
					routeCache->hashTable[i]->sequenceNumber = oldRreq->sequenceNumber;
					routeCache->hashTable[i]->routeEntryTime = getSimTime(node);
				}
				else if((oldRreq->sequenceNumber == routeCache->hashTable[i]->sequenceNumber )&& (((oldRreq->hopCount)+1) < routeCache->hashTable[i]->hopCount) )
				{
					routeCache->hashTable[i]->hopCount = (oldRreq->hopCount)+1;	 
					routeCache->hashTable[i]->routeEntryTime = getSimTime(node);
			    }
			}
		}
	}	
}

					
// /**
// FUNCTION : MyprotocolFloodRREQ
// LAYER    : NETWORK
// PURPOSE  : Function to flood RREQ in all interfaces
// PARAMETERS:
//  +node:Node*:Pointer to the node which is flooding RREQ
//  +myprotocol:MyprotocolData*:Pointer to Myprotocol internal data structure
//  +hopCount:UInt32:hop count in request
//  +sequenceNumber:int:sequence number in request
//  +address:Address:relay node's address in the request
// RETURN   ::void:NULL
// **/

static
void MyprotocolFloodRREQ(
		   Node* node,
		   MyprotocolData* myprotocol,
		   UInt32 hopCount,
		   UInt32 sequenceNumber,
		   NodeAddress address)
{ 
	Message* newMsg = NULL;
	MyprotocolRreqPacket* rreqPkt = NULL;
	int pktSize = 0;
	int i = 0;
	int routingProtocol = 0;
	
	pktSize = sizeof(MyprotocolRreqPacket);
	routingProtocol = ROUTING_PROTOCOL_MYPROTOCOL;

	//Allocate the route request packet
	newMsg = MESSAGE_Alloc(
				 node,
				 MAC_LAYER,
				 routingProtocol,
				 MSG_MAC_FromNetwork);

	MESSAGE_PacketAlloc(
		 node,
		 newMsg,
		 pktSize,
		 TRACE_MYPROTCOL);

	rreqPkt = (MyprotocolRreqPacket *) MESSAGE_ReturnPacket(newMsg);
	memset(rreqPkt, 0, pktSize);

	rreqPkt->address=address;
	rreqPkt->hopCount=hopCount;
	rreqPkt->sequenceNumber=sequenceNumber;
	
	NetworkIpSendRawMessageToMacLayerWithDelay(
    node,
    newMsg,
    myprotocol->localAddress,
    ANY_DEST,
    IPTOS_PREC_INTERNETCONTROL,
    IPPROTO_MYPROTOCOL,
    1,
    DEFAULT_INTERFACE,
    ANY_DEST,
    (clocktype) (RANDOM_erand(myprotocol->seed) * MYPROTOCOL_BROADCAST_JITTER));
	
}
		   






// /**
// FUNCTION     : MyprotocolInitiateRREQ
// LAYER        : NETWORK
// PURPOSE      : Initiate a Route Request packet by sink node    
// PARAMETERS   :
//  +node:Node*: Pointer to the sink node which is sending the Route Request
// RETURN       ::void:NULL
// **/


static
void MyprotocolInitiateRREQ(Node* node)
{
	MyprotocolData* myprotocol = NULL;
	myprotocol = (MyprotocolData*)NetworkIpGetRoutingProtocol(
				  node, 
				  ROUTING_PROTOCOL_MYPROTOCOL, 
				  NETWORK_IPV4);
	
	if (MYPROTOCOL_DEBUG)
	{
		char clockStr[MAX_STRING_LENGTH];
	    TIME_PrintClockInSecond(getSimTime(node), clockStr);
        printf("Node %u initiating RREQ at %s\n", node->nodeId, clockStr);
    }
	//Increase own sequence number before flooding route request
	myprotocol->sequenceNumber++;

	// The message will be broadcasted to all the interfaces which are
    // running Myprotocol as their routing protocol

	MyprotocolFloodRREQ(node,                        //Node* node
						myprotocol,                  //MyprotocolData* myprotocol
						0,                           //UInt32 hopCount
						myprotocol->sequenceNumber,  //UInt sequenceNumber
						myprotocol->localAddress);   //NodeAddress address
						
	//update statistical variable for route request initiated					
	myprotocol->stats.numRequestInitiated++;	
}

// /**
// FUNCTION: MyprotocolRelayRREQ
// LAYER    : NETWORK
// PURPOSE:  Forward (re-broadcast) the RREQ
// ARGUMENTS:
//  +node:Node*:Pointer to the node forwarding the Route Request
//  +msg:Message*:Pointer to the Rreq packet
//  +ttl:int:Time to leave of the message
// RETURN   ::void:NULL
// **/


static
void MyprotocolRelayRREQ(
			Node* node,
			Message* msg,
			int ttl)
{
	MyprotocolData* myprotocol = NULL;
	MyprotocolRreqPacket* oldRreq = NULL;
	myprotocol = (MyprotocolData*)NetworkIpGetRoutingProtocol(
				  node, 
				  ROUTING_PROTOCOL_MYPROTOCOL, 
				  NETWORK_IPV4);
	oldRreq = (MyprotocolRreqPacket *) MESSAGE_ReturnPacket(msg);

	if(MYPROTOCOL_DEBUG)
	{
		char clockStr[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(getSimTime(node), clockStr);
        printf("Node %u relaying RREQ at %s\n", node->nodeId, clockStr);
	}
	
	//Relay the packet after decreasing the TTL
    ttl = ttl - IP_TTL_DEC;
	MyprotocolFloodRREQ(
		  	node,
		    myprotocol,
		    (oldRreq->hopCount)++,
		    oldRreq->sequenceNumber,
		    myprotocol->localAddress);
	
	//update statistical variable for route request relayed
	myprotocol->stats.numRequestRelayed++
}


// /**
// FUNCTION: MyprotocolHandleRequest
// LAYER    : NETWORK
// PURPOSE:  Processing procedure when RREQ is received
// ARGUMENTS:
//  +node:Node*: The node which has received the RREQ
//  +msg:Message*:The message contain the RREQ packet
//  +srcAddr:NodeAddress:Previous hop
//  +ttl:int:The ttl of the message
//  +interfaceIndex:int:The interface index through which the RREQ has
//                      been received.
// RETURN   ::void:NULL
// **/


static
void MyprotocolHandleRequest(
         Node* node,
         Message* msg,
         Address srcAddr,
         int ttl,
         int interfaceIndex)
{

}


// /**
// FUNCTION   :: MyprotocolHandleProtocolEvent
// LAYER      :: NETWORK
// PURPOSE    :: Handles all the protocol events.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to message.
// RETURN     :: void : NULL.
// **/


void
MyprotocolHandleProtocolEvent(
    Node* node,
    Message* msg)
{

}


	
// /**
// FUNCTION : MyprotocolHandleProtocolPacket
// LAYER	: NETWORK
// PURPOSE	: Called when Myprotocol packet is received from MAC, the packets
//			  may be of following types, Route Request, Route Reply
// PARAMETERS:
//+node: Node*: The node received message
//+msg: Message*:The message received
//+srcAddr:  NodeAddress:Source Address of the message
//+destAddr: NodeAddress: Destination Address of the message
//+ttl: int: Time to leave
//+interfaceIndex: int :Receiving interface
// RETURN	: None
// **/
	
void
AodvHandleProtocolPacket(
		Node* node,
		Message* msg,
		NodeAddress srcAddr,
		NodeAddress destAddr,
		int ttl,
		int interfaceIndex)
	{
		UInt32* packetType = (UInt32* )MESSAGE_ReturnPacket(msg);
		BOOL IPV6 = FALSE;
	
		if (srcAddr.networkType == NETWORK_IPV6)
		{
			IPV6 = TRUE;
		}
	
		  //trace recd pkt
		  ActionData acnData;
		  acnData.actionType = RECV;
		  acnData.actionComment = NO_COMMENT;
		  TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
			  PACKET_IN, &acnData , srcAddr.networkType);
	
		if (AODV_DEBUG_AODV_TRACE)
		{
			AodvPrintTrace(node, msg, 'R',IPV6);
		}
	
		switch (*packetType >> 24)
		{
			case AODV_RREQ:
			{
				if (AODV_DEBUG)
				{
					char clockStr[MAX_STRING_LENGTH];
					char address[MAX_STRING_LENGTH];
	
					TIME_PrintClockInSecond(getSimTime(node), clockStr);
					printf("Node %u got RREQ at time %s\n", node->nodeId,
						clockStr);
	
					IO_ConvertIpAddressToString(
						&srcAddr,
						address);
	
					printf("\tfrom: %s\n", address);
	
					IO_ConvertIpAddressToString(
						&destAddr,
						address);
	
					printf("\tdestination: %s\n", address);
				}
	
				AodvHandleRequest(
					node,
					msg,
					srcAddr,
					ttl,
					interfaceIndex);
	
				MESSAGE_Free(node, msg);
				break;
			}
	
			case AODV_RREP:
			{
				if (AODV_DEBUG)
				{
					char clockStr[MAX_STRING_LENGTH];
					char address[MAX_STRING_LENGTH];
	
					TIME_PrintClockInSecond(getSimTime(node), clockStr);
	
					printf("Node %u got RREP at time %s\n", node->nodeId,
						clockStr);
	
					IO_ConvertIpAddressToString(&srcAddr, address);
	
					printf("\tfrom: %s\n", address);
	
					IO_ConvertIpAddressToString(&destAddr, address);
	
					printf("\tdestination: %s\n", address);
				}
	
	
				AodvHandleReply(
					node,
					msg,
					srcAddr,
					interfaceIndex,
					destAddr);
	
				MESSAGE_Free(node, msg);
	
				break;
			}
	
			case AODV_RERR:
			{
				if (AODV_DEBUG)
				{
					char clockStr[MAX_STRING_LENGTH];
					char address[MAX_STRING_LENGTH];
	
					TIME_PrintClockInSecond(getSimTime(node), clockStr);
					printf("Node %u got RERR at time %s\n", node->nodeId,
						clockStr);
	
					IO_ConvertIpAddressToString(&srcAddr,address);
					printf("\tfrom: %s\n", address);
					IO_ConvertIpAddressToString(&destAddr,address);
					printf("\tdestination: %s\n", address);
				}
	
				AodvHandleRouteError(
					node,
					msg,
					srcAddr,
					interfaceIndex);
	
				MESSAGE_Free(node, msg);
				break;
			}
	
			default:
			{
			   ERROR_Assert(FALSE, "Unknown packet type for Aodv");
			   break;
			}
		}
	}

		 
