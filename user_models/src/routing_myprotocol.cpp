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
// FUNCTION  : MyprotocolMemoryFree
// LAYER     : NETWORK
// PURPOSE    : Function to return a memory cell to the memory pool
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
// FUNCTION : MyprotocolSetTimer
// LAYER    : NETWORK
// PURPOSE  : Set timers for protocol events
// PARAMETERS:
// +node:Node*:Pointer to node which is scheduling an event
// +data:Void*:Pointer to the data attached to message info filed
// +size:unsigned int:Size of the data attached to message info filed
// +eventType:int:The event type of the message
// +delay:clocktype:Time after which the event will expire
//RETURN    ::void:NULL
// **/


static
void MyprotocolSetTimer(
    Node* node,
    void* data,
    unsigned int size,
    int eventType,
    clocktype delay)
{
    Message* newMsg = NULL;

    newMsg = MESSAGE_Alloc(
                node,
                NETWORK_LAYER,
                ROUTING_PROTOCOL_MYPROTOCOL,
                eventType);

    if (data != NULL && size != 0)
    {
        MESSAGE_InfoAlloc(node, newMsg, size);
        memcpy(MESSAGE_ReturnInfo(newMsg), data, size);
    }

    MESSAGE_Send(node, newMsg, delay);
}


// /**
// FUNCTION  : MyprotocolInitRouteCache
// LAYER     : NETWORK
// PURPOSE   : Function to initialize Myprotocol route cache
// PARAMETERS:
// +routeCache:MyprotocolRouteCache*:Pointer to Myprotocol route cache
// RETURN   ::void:NULL
// **/
static
void MyprotocolInitRouteCache(MyprotocolRouteCache* routeCache)
{
    // Initialize MYPROTOCOL route Cache
    int i = 0;
    for (i = 0; i < MYPROTOCOL_ROUTE_HASH_TABLE_SIZE; i++)
    {
        routeCache->hashTable[i] = NULL;
    }
    routeCache->deleteListHead = NULL;
    routeCache->deleteListTail = NULL;
    routeCache->count = 0;
 }


// /**
// FUNCTION : MyprotocolCheckNodeAddressExist
// LAYER    : NETWORK
// PURPOSE  : To check whether route table includes route request packet's node address.
// PARAMETERS:
//  +address:NodeAddress: relay node address in route request packet
//  +routeCache:MyprotocolRouteCache*: Pointer to myprotocol routing table                                
// RETURN   :
//  +current:MyprotocolRouteEntry*:pointer to the route entry if it exists in the
//                           routing table, else to the next route entry of the last
//							 route entry in the current route table
// **/

static
MyprotocolRouteEntry* MyprotocolCheckNodeAddressExist(
                    NodeAddress address,
                    MyprotocolRouteCache* routeCache)
{
    MyprotocolRouteEntry* current = NULL;
	for(current = routeCache->hashTable[0];current != NULL; current = current->next)
    {
    	if(current->nextHop == address)
			break;
		else
			continue;
    }
	return current;
}


// /**
// FUNCTION   :: MyprotocolReplaceInsertRouteTable
// LAYER      :: NETWORK
// PURPOSE    :: Insert/Update an entry into the route table.
// PARAMETERS ::
//  +node:  	  Node* : Pointer to node.
//  +msg:   	  Message* : Pointer to the Rreq packet
//  +routeCache:  MyprotocolRouteCache* : Pointer to Myprotocol route table
// RETURN     ::  BOOL : true or false (flag for continuing to broadcast Rreq packet)                     
// **/

static
BOOL MyprotocolReplaceInsertRouteTable(
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
	theNode = MyprotocolCheckNodeAddressExist(oldRreq->address,routeCache);
	if(theNode)
	{
		if(oldRreq->sequenceNumber > theNode->sequenceNumber)
		{
			theNode->hopCount = (oldRreq->hopCount)+1;
			theNode->sequenceNumber = oldRreq->sequenceNumber;
			theNode->routeEntryTime = getSimTime(node);
			return true;
		}
		else if((oldRreq->sequenceNumber == theNode->sequenceNumber )&& (((oldRreq->hopCount)+1) < theNode->hopCount) )
		{
			theNode->hopCount = (oldRreq->hopCount)+1;	 
			theNode->routeEntryTime = getSimTime(node);
			return true;
		}
		else
			return false;
	}
	else
	{
	    myprotocol->routeCache.count += 1;	
		theNode = MyprotocolMemoryMalloc(myprotocol);
		memset(theNode, 0,sizeof(MyprotocolRouteEntry));
		theNode->hopCount = (oldRreq->hopCount)+1;
		theNode->nextHop = oldRreq->address;
		theNode->sequenceNumber = oldRreq->sequenceNumber;
		theNode->routeEntryTime = getSimTime(node);
		return true;
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
		 TRACE_MYPROTOCOL);

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
// FUNCTION     :MyprotocolInitBuffer
// LAYER        :NETWORK
// PURPOSE      :Initializing packet buffer where packets waiting for a
//           	 route are to be stored
// PARAMETERS   :
//  +msgBuffer  :MyprotocolBuffer*:Pointer to the message buffer
// RETURN  		::void:NULL
// **/
static
void MyprotocolInitBuffer(MyprotocolBuffer* msgBuffer)
{
	// Initialize message buffer
	msgBuffer->head = NULL;
	msgBuffer->sizeInPacket = 0;
	msgBuffer->sizeInByte = 0;	
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
			Message* msg)
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
	MyprotocolFloodRREQ(
		  	node,
		    myprotocol,
		    (oldRreq->hopCount)++,
		    oldRreq->sequenceNumber,
		    myprotocol->localAddress);
	
	//update statistical variable for route request relayed
	myprotocol->stats.numRequestRelayed++;
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
// RETURN   ::void:NULL
// **/


static
void MyprotocolHandleRequest(
         Node* node,
         Message* msg)
{
	MyprotocolData* myprotocol = NULL;
	MyprotocolRreqPacket* rreqPkt = NULL;
	BOOL flag = FALSE;
	myprotocol = (MyprotocolData*) NetworkIpGetRoutingProtocol(node,
												ROUTING_PROTOCOL_MYPROTOCOL,
                                                NETWORK_IPV4);
	flag = MyprotocolReplaceInsertRouteTable(node,msg,&(myprotocol->routeCache));
	if(flag)
	{
		MyprotocolRelayRREQ(node,msg);
	}
}	


// /**
// FUNCTION : MyprotocolHandleProtocolPacket
// LAYER	 : NETWORK
// PURPOSE  : Called when Myprotocol packet is received from MAC, the packets
// 		   may be of following types, Route Request, Route Reply
// PARAMETERS:
//    +node: Node*: The node received message
//    +msg: Message*:The message received
//    +srcAddr: Address:Source Address of the message
//    +destAddr: Address: Destination Address of the message
//    +ttl: int: Time to leave
//    +interfaceIndex: int :Receiving interface
// RETURN	 : None
// **/

void
MyprotocolHandleProtocolPacket(
	Node* node,
	Message* msg)
{
	UInt8* packetType = (UInt8* )MESSAGE_ReturnPacket(msg);
    switch (*packetType)
    {
        case MYPROTOCOL_RREQ:
        {
        /*
            if (MYPROTOCOL_DEBUG)
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
*/
            MyprotocolHandleRequest(node,msg);
            MESSAGE_Free(node, msg);
            break;
        }

        case MYPROTOCOL_RREP:
        {
        /*
            if (MYPROTOCOL_DEBUG)
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
*/

  //          MyprotocolHandleReply(node, msg);

            MESSAGE_Free(node, msg);

            break;
        }

        default:
        {
           ERROR_Assert(FALSE, "Unknown packet type for Myprotocol");
           break;
        }
    }
}


	
// /**
// FUNCTION   :: MyprotocolHandleReply
// LAYER	  :: NETWORK
// PURPOSE	  :: Processing procedure when a node 
//				 found its neighbor lost in communication
//				 beyond a certain time or a node itself has
//				 been congested for a certain time .
// PARAMETERS ::
//	+node:	Node* : Pointer to node.
//	+msg:  Message* : Pointer to Message.
//	+srcAddr:  Address : Source Address.
//	+interfaceIndex:  int : Interface Index.
// RETURN	  :: void : NULL.
// **/
static
void MyprotocolHandleReply(
			 Node* node,
			 Message* msg)
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
	MyprotocolData* myprotocol = NULL;

  
    myprotocol = (MyprotocolData *) NetworkIpGetRoutingProtocol(
                                	node,
                                	ROUTING_PROTOCOL_MYPROTOCOL,
                                	NETWORK_IPV4);
/*
    switch (MESSAGE_GetEvent(msg))
    {
        // Remove an entry from the RREQ Seen Table
        case MSG_NETWORK_FlushTables:
        {
            if (AODV_DEBUG)
            {
                char address[MAX_STRING_LENGTH];

                IO_ConvertIpAddressToString(
                    &aodv->seenTable.front->srcAddr,
                    address);

                printf("Node %u is deleting from seen table(%d), "
                       "Source Address: %s, Flood ID: %d \n",
                       node->nodeId,
                       aodv->seenTable.size,
                       address,
                       aodv->seenTable.front->floodingId);
            }

            AodvDeleteSeenTable(&aodv->seenTable);

            MESSAGE_Free(node, msg);

            break;
        }

        default:
        {
            ERROR_Assert(FALSE, "Myprotocol: Unknown MSG type!\n");
            break;
        }
    }*/
}



	
// /*
// FUNCTION :: MyprotocolInit.
// LAYER	:: NETWORK.
// PURPOSE	:: Initialization function for MYPROTOCOL protocol.
// PARAMETERS ::
// + node : Node* : Pointer to Node.
// + aodvPtr : MyprotocolData** : Pointer to pointer to MYPROTOCOL data.
// + nodeInput : const NodeInput* : Pointer to chached config file.
// + interfaceIndex : int : Interface Index.
// RETURN	:: void : NULL.
// **/
	

void
MyprotocolInit(
	Node* node,
	MyprotocolData** myprotocolPtr,
	const NodeInput* nodeInput,
	int interfaceIndex)
{
	BOOL retVal = FALSE;
    char buf[MAX_STRING_LENGTH];

    if (MAC_IsWiredNetwork(node, interfaceIndex))
    {
        ERROR_ReportError("MYPROTOCOL can only support wireless interfaces");
    }

    if (node->numberInterfaces > 1)
    {
        ERROR_ReportError("MYPROTOCOL only supports one interface of node");
    }

    (*myprotocolPtr) = (MyprotocolData *) MEM_malloc(sizeof(MyprotocolData));

    if ((*myprotocolPtr) == NULL)
    {
        fprintf(stderr, "MYPROTOCOL: Cannot alloc memory for MYPROTOCOL struct!\n");
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
    //MyprotocolInitRequestTable(&(*dsrPtr)->reqTable);

    // Initialize route cache
    MyprotocolInitRouteCache(&(*myprotocolPtr)->routeCache);

    // Initialize message buffer;
    MyprotocolInitBuffer(&(*myprotocolPtr)->msgBuffer);

    //MyprotocolInitRexmtBuffer(&(*dsrPtr)->rexmtBuffer);

    // Initialize sequence number
    (*myprotocolPtr)->sequenceNumber = 0;

    // Assign 0 th interface address as myprotocol local address.
    // This message should be used to send any request or reply

    (*myprotocolPtr)->localAddress = NetworkIpGetInterfaceAddress(node, 0);

    // Set network router function
    NetworkIpSetRouterFunction(
        node,
        &MyprotocolRouterFunction,
        interfaceIndex);
/*
    // Set mac layer status event handler
    NetworkIpSetMacLayerStatusEventHandlerFunction(
        node,
        &DsrMacLayerStatusHandler,
        interfaceIndex);

    // Set promiscuous message peek function
    NetworkIpSetPromiscuousMessagePeekFunction(
        node,
        &DsrPeekFunction,
        interfaceIndex);

    NetworkIpSetMacLayerAckHandler(
        node,
        &DsrMacAckHandler,
        interfaceIndex);

    if (DEBUG_TRACE)
    {
        DsrTraceInit(node, nodeInput, *dsrPtr);
    }	
*/    
}


// /**
// FUNCTION : MyprotocolFinalize
// LAYER    : NETWORK
// PURPOSE  :  Called at the end of the simulation to collect the results
// PARAMETERS:
//    +node: Node *:Pointer to Node
//    +i : int: The node for which the statistics are to be printed
// RETURN:    None
// **/

void
MyprotocolFinalize(Node* node)
{
	
}



// /**
// FUNCTION: MyprotocolRouterFunction
// LAYER   : NETWROK
// PURPOSE : Determine the routing action to take for a the given data packet
//          set the PacketWasRouted variable to TRUE if no further handling
//          of this packet by IP is necessary
// PARAMETERS:
// +node:Node *::Pointer to node
// + msg:Message*:The packet to route to the destination
// +destAddr:Address:The destination of the packet
// +previousHopAddress:Address:Last hop of this packet
// +packetWasRouted:BOOL*:set to FALSE if ip is supposed to handle the
//                        routing otherwise TRUE
// RETURN   ::void:NULL
// **/

void
MyprotocolRouterFunction(
    Node* node,
    Message* msg,
    NodeAddress destAddr,
    NodeAddress previousHopAddress,
    BOOL* packetWasRouted)
{
	
}

