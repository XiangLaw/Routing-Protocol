#ifndef MYPROTOCOL_H
#define MYPROTOCOL_H


//symbolic constants
#define MYPROTOCOL_BROADCAST_JITTER            (100 * MILLI_SECOND)

#define MYPROTOCOL_MAX_REQUEST_PERIOD          (10 * SECOND)

#define MYPROTOCOL_REQUEST_PERIOD              (500 * MILLI_SECOND)

#define MYPROTOCOL_ROUTE_CACHE_TIMEOUT         (300 * SECOND)

#define MYPROTOCOL_SEND_BUFFER_TIMEOUT         (30 * SECOND)

#define MYPROTOCOL_REQUEST_TABLE_SIZE           64

#define MYPROTOCOL_REQUEST_TABLE_IDS            16

#define MYPROTOCOL_MAX_REQUEST_REXMT            16

#define MYPROTOCOL_NON_PROP_REQUEST_TIMEOUT    (30 * MILLI_SECOND)

#define MYPROTOCOL_REXMT_BUFFER_SIZE            50

#define MYPROTOCOL_MAIN_THOLDOFF_TIME          (250 * MILLI_SECOND)

#define MYPROTOCOL_MAX_MAIN_TREXMT              2

#define MYPROTOCOL_TRY_PASSIVE_ACKS             1

#define MYPROTOCOL_PASSIVE_ACK_TIMEOUT         (100 * MILLI_SECOND)

#define MYPROTOCOL_MAX_SALVAGE_COUNT            15

#define MYPROTOCOL_NON_PROPAGATING_TTL          1

#define MYPROTOCOL_PROPAGATING_TTL              65

#define MYPROTOCOL_NO_MORE_HEADER               0

#define MYPROTOCOL_ROUTE_TIMER                  (30 * SECOND)

#define MYPROTOCOL_MEM_UNIT                     100

#define MYPROTOCOL_ROUTE_HASH_TABLE_SIZE        100

#define MYPROTOCOL_SIZE_OF_HEADER 4

typedef enum
{
    MYPROTOCOL_ROUTE_REQUEST = 0,
    MYPROTOCOL_ROUTE_ERROR = 1,
} MyprotocolPacketType;

//Format of route request packet(RRP)
typedef struct
{
	NodeAddress relayNodeAddr;		//relay node address
	int	hopNumber;                  //hop number from relay node to destination node
	unsigned short serialNumber;	//serial number of RRP
} MyprotocolRouteRequest;

//Route cache entry structure
typedef struct str_myprotocol_route_cache_entry
{		 
	NodeAddress nextHop;	 //next hop neighbor node's address
	unsigned short	hopCount;            //hop length to root node through neighbor node
	bool isCongestion; 		 //next hop neighbor node's congestion status	
	unsigned short serialNumber;//serial number corresponding to the record's RRP
	clocktype   routeEntryTime;//the time when route entry was generated
	struct str_myprotocol_route_cache_entry* prev;//pointer to previous route cache entry struct
	struct str_myprotocol_route_cache_entry* next;//pointer to next route cache entry struct
	struct str_myprotocol_route_cache_entry* deletePrev;//pointer to previous route cache entry struct for deletion
    struct str_myprotocol_route_cache_entry* deleteNext;//pointer to next route cache entry struct for deletion
} MyprotocolRouteEntry;

//Route cache structure
typedef struct
{
	MyprotocolRouteEntry* hashTable[MYPROTOCOL_ROUTE_HASH_TABLE_SIZE];
	MyprotocolRouteEntry* deleteListHead;
	MyprotocolRouteEntry* deleteListTail;
    int count;               // Count of current entries
} MyprotocolRouteCache;

typedef struct str_myprotocol_mem_poll
{
    MyprotocolRouteEntry routeEntry ;
    struct str_myprotocol_mem_poll* next;
} MyprotocolMemPollEntry;


// Myprotocol message buffer entry. Buffer to temporarily store messages when there
// is no route for a destination.
typedef struct str_myprotocol_msg_buffer_entry
{
    NodeAddress destAddr;
    clocktype timeStamp;
    BOOL isErrorPacket;
    Message* msg;
    struct str_myprotocol_msg_buffer_entry* next;
} MyprotocolBufferEntry;

// Myprotocol message buffer
typedef struct
{
    MyprotocolBufferEntry* head;
    int sizeInPacket;
    int sizeInByte;
} MyprotocolBuffer;

// Myprotocol message retransmit buffer entry. Buffer to temporarily store messages
// After sending the message out to destination, until an acknowledgement
// comes for the message.

typedef struct str_myprotocol_rexmt_buffer_entry
{
    NodeAddress destAddr; // destination for which the message has been sent
    NodeAddress srcAddr;
    NodeAddress nextHop;  // next hop to which the message has been sent
    unsigned int count;   // number of times retransmitted
    unsigned short msgId;
    clocktype timeStamp;  // when the message has been inserted
    Message* msg;         // sent message
    struct str_myprotocol_rexmt_buffer_entry* next;
} MyprotocolRexmtBufferEntry;

// Myprotocol message buffer
typedef struct
{
    MyprotocolRexmtBufferEntry* head; // pointer to the first entry
    int sizeInPacket;          // number of packets in the retransmit buffer
} MyprotocolRexmtBuffer;

// Myprotocol statistical variables
typedef struct
{
    unsigned int numRequestInitiated;
    unsigned int numRequestResent;
    unsigned int numRequestRelayed;

    unsigned int numRequestRecved;
    unsigned int numRequestDuplicate;
    unsigned int numRequestTtlExpired;
    unsigned int numRequestRecvedAsDest;
    unsigned int numRequestInLoop;

    unsigned int numReplyInitiatedAsDest;
    unsigned int numReplyInitiatedAsIntermediate;

    unsigned int numReplyRecved;
    unsigned int numReplyRecvedAsSource;

    unsigned int numRerrInitiated;

    unsigned int numRerrRecvedAsSource;
    unsigned int numRerrRecved;

    unsigned int numDataInitiated;
    unsigned int numDataForwarded;

    unsigned int numDataRecved;

    unsigned int numDataDroppedForNoRoute;
    unsigned int numDataDroppedForOverlimit;
    unsigned int numDataDroppedRexmtTO;

    unsigned int numRoutes;
    unsigned int numHops;

    unsigned int numSalvagedPackets;
    unsigned int numLinkBreaks;

    unsigned int numPacketsGreaterMTU;
}MyprotocolStats;


// Myprotocol main data structure
typedef struct
{
    MyprotocolBuffer msgBuffer;           // Myprotocol messge buffer
    MyprotocolRexmtBuffer rexmtBuffer;

    MyprotocolRouteCache routeCache;      // Myprotocol Route Cache

    MyprotocolMemPollEntry* freeList;

	unsigned short serialNumber;

    BOOL statsCollected;           // Whether or not to collect statistics
    BOOL statsPrinted;
    MyprotocolStats stats;                // Myprotocol statistical variables

    int bufferMaxSizeInByte;       // Maximum size of message buffer
    int bufferMaxSizeInPacket;     // Maximum size of message buffer in
                                   // number of packets
    NodeAddress localAddress;      // 0th interface address

    BOOL isTimerSet;
    // For packet trace
    #define     ROUTING_Myprotocol_TRACE_NO    0
    #define     ROUTING_Myprotocol_TRACE_YES   1

    int trace;    
    // End packet trace

    RandomSeed seed;
} MyprotocolData;


// Function to initialize routing protocol
void MyprotocolInit(
         Node* node,
         MyprotocolData** myprotocolPtr,
         const NodeInput* nodeInput,
         int interfaceIndex);

// Function to handle protocol specific packets.
void MyprotocolHandleProtocolPacket(
         Node* node,
         Message* msg,
         NodeAddress srcAddr,
         NodeAddress destAddr,
         int ttl,
         NodeAddress prevHop);

// Function to handle internal messages such as timers
void  MyprotocolHandleProtocolEvent(Node* node, Message* msg);

// Function to handle data packets. Sometimes for incoming packets
// to update internal variables. Sometimes outgoing packets from nodes
// upperlayer or protocols
void MyprotocolRouterFunction(
         Node* node,
         Message* msg,
         NodeAddress destAddr,
         NodeAddress previousHopAddress,
         BOOL* packetWasRouted);

// Function to print statistical variables at the end of simulation.
void MyprotocolFinalize(Node* node);
#endif

