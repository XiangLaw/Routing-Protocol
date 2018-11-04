// Copyright (c) 2001-2009, Scalable Network Technologies, Inc.  All Rights Reserved.
//                          6100 Center Drive
//                          Suite 1250
//                          Los Angeles, CA 90045
//                          sales@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for a derivative work, or used, in
// whole or in part, for any program or purpose other than its intended
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

//
// Objectives: IP (Internet Protocol)
//             A very simple IP that does multiplexing and demultiplexing.
// References: RFC 791
// Date: 8/20/1999
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "partition.h"
#include "adaptation_aal5.h"
#include "ipv6.h"
#include "ip6_icmp.h"
#include "ip6_output.h"
#include "network_ip.h"
#include "network_dualip.h"
#include "network_icmp.h"
#include "multicast_static.h"
#include "multicast_igmp.h"
#include "mac.h"
#include "if_queue.h"
#include "queue_red.h"
#include "queue_wred_ecn.h"
#include "queue_rio_ecn.h"

#include "sch_graph.h"
#include "sch_strictprio.h"
#include "sch_wfq.h"
#include "sch_roundrobin.h"
#include "sch_scfq.h"
#include "sch_wrr.h"
#include "resource_manager_cbq.h"

#include "transport_tcp_hdr.h"
#include "transport_udp.h"
#include "app_superapplication.h"
#include "mac_arp.h"
#include "WallClock.h"
#include "fixed_comms.h"
#include "stats_net.h"

#ifdef ADDON_DB
#include "db.h"
#include "dbapi.h"
#endif

#ifdef WIRELESS_LIB
#include "multicast_odmrp.h"
#include "network_ipv4_ndp.h"
#include "routing_aodv.h"
#include "routing_dsr.h"
#include "routing_fsrl.h"
#include "routing_iarp.h"
#include "routing_ierp.h"
#include "routing_brp.h" // brp needs to follow ierp
#include "routing_lar1.h"
#include "routing_star.h"
#include "routing_zrp.h"
#include "routing_dymo.h"
#include "manet_packet.h"
#include "routing_myprotocol.h"
#endif // WIRELESS_LIB

#ifdef ENTERPRISE_LIB
#include "mf_traffic_conditioner.h"
#include "mpls.h"
#include "multicast_dvmrp.h"
#include "multicast_mospf.h"
#include "multicast_pim.h"
#include "network_mobileip.h"
#include "network_access_list.h"
#include "route_parse_util.h"
//#include "route_map.h"
#include "routing_eigrp.h"
#include "routing_igrp.h"
#include "routing_ospfv2.h"
#include "routing_policy_routing.h"
#include "routing_qospf.h"
#include "sch_diffserv.h"
#endif // ENTERPRISE_LIB

#ifdef MILITARY_RADIOS_LIB
#include "routing_odr.h"
#endif

#ifdef ADDON_MAODV
#include "multicast_maodv.h"
#endif // ADDON_MAODV

#ifdef CELLULAR_LIB
#include "cellular_gsm.h"
#include "layer3_gsm.h"
#include "cellular_layer3.h"
#elif UMTS_LIB
#include "cellular_layer3.h"
#endif // CELLULAR_LIB

#ifdef ADVANCED_WIRELESS_LIB
#include "dot16_backbone.h"
#endif // ADVANCED_WIRELESS_LIB

#ifdef EXATA
#include "ipnetworkemulator.h"
#include "auto-ipnetworkemulator.h"
#include "record_replay.h"
#endif

#ifdef GATEWAY_INTERFACE
#include "internetgateway.h"
#endif

#ifdef PAS_INTERFACE
#include "packet_analyzer.h"
#endif

#ifdef HITL_INTERFACE
#include "hitl.h"
#endif // HITL_INTERFACE

//InsertPatch HEADER_FILES

#ifdef MPI_DEBUG
#include "parallel.h"
#endif

#ifdef CYBER_LIB
#include "routing_anodr.h"
#include "os_resource_manager.h"
#include "firewall_model.h"
#include "attack_sequence.h"
#endif // CYBER_LIB

#ifdef CYBER_CORE
#include "network_ipsec_esp.h"
#include "network_iahep.h"
#endif // CYBER_CORE

#ifdef ADDON_BOEINGFCS
#include "routing_ces_malsr.h"
#include "network_ces_region.h"
#include "boeingfcs_network.h"
#include "mode_ces_wnw_receive_only.h"
#include "mac_wnw_main.h"
#include "routing_ces_sdr.h"
#include "routing_ces_rospf.h"
#include "routing_ces_mpr.h"
#include "network_ces_inc_sincgars.h"
//#include "network_ces_inc_eplrst.h"
#include "multicast_ces_rpim_dm.h"
#include "mac_ces_wintncw.h"
#include "multicast_ces_rpim_sm.h"
#include "network_ces_inc.h"
#include "mi_ces_multicast_mesh.h"
#include "network_ces_subnet.h"
#include "network_ces_inc_eplrs.h"
#include "network_security_ces_haipe.h"
#ifdef ADDON_NGCNMS
#include "network_ces_subnet.h"
#include "spectrum_manager.h"
#endif
#endif // ADDON_BOEINGFCS
#ifdef ADDON_MA
#include "ma_interface.h"
#endif

#ifdef ADDON_BOEINGFCS
#include "network_security_ces_haipe.h"
#endif

#ifdef JNE_LIB
#include "jne.h"
#include "vis_visual.h"
#endif /* JNE_LIB */

#include "routing_ospfv2.h"

#ifdef CYBER_CORE
extern int IahepFragmentPacket(Node* node,
                             Message* msg,
                             int incomingInterfaceindex,
                             int outgoingInterfaceIndex,
                             int mtu,
                             ipFragmetedMsg** fragmentHead,
                             BOOL iscontrolpkt);

extern Message*
IahepFragmentReassemble(
           Node* node,
           Message* msg,
           int interfaceId,
           BOOL* isReassembled,
           BOOL iscontrolpkt);
#endif

//-----------------------------------------------------------------------------
// DEFINES
//-----------------------------------------------------------------------------
#define INTERFACE_DEBUG 0

#define IPV4_ROUTING_DISABLED_WARNING 0

#define rtDEBUG 0
#define HOP_COUNT_STAT_DEBUG 0
//-----------------------------------------------------------------------------
// IP header
//-----------------------------------------------------------------------------

//
// Additional number of bytes to add to a source route option field,
// to make up for the fact that the option field header is 3 bytes.
// This is so alignment is preserved, making extraction of IP packet
// data easier (casts to structs instead of memcpy()'s).
// (non-standard, may be looked at -- the only supported option
// is strict source routes)
//



//-----------------------------------------------------------------------------
// MACRO        IpHeaderHasSourceRoute()
// PURPOSE      Returns boolean depending on whether IP header has a
//              source route.  (Just calls IpHeaderSourceRouteOptionField()
//              and checks if what's returned is NULL.)
// PARAMETERS   IpHeaderType *IpHeader
//                  Pointer to IP header.
// RETURNS      true, if ipHeader has source route.
//              false, if ipHeader does not have source route.
//-----------------------------------------------------------------------------

#define IpHeaderHasSourceRoute(ipHeader) \
    (IpHeaderSourceRouteOptionField(ipHeader) != NULL)

//---------------------------------------------------------------------------
// MACRO        IpHeaderHasRecordRoute()
// PURPOSE      Returns boolean depending on whether IP header has a
//              Record route.  (Just calls IpHeaderRecordRouteOptionField()
//              and checks if what's returned is NULL.)
// PARAMETERS   IpHeaderType *IpHeader
//                  Pointer to IP header.
// RETURNS      true, if ipHeader has Record route.
//              false, if ipHeader does not have Record route.
//---------------------------------------------------------------------------

#define IpHeaderHasRecordRoute(ipHeader) \
    (IpHeaderRecordRouteOptionField(ipHeader) != NULL)

//---------------------------------------------------------------------------
// MACRO        IpHeaderHasTimestamp()
// PURPOSE      Returns boolean depending on whether IP header has a
//              Timestamp.  (Just calls IpHeaderTimestampOptionField()
//              and checks if what's returned is NULL.)
// PARAMETERS   IpHeaderType *IpHeader
//                  Pointer to IP header.
// RETURNS      true, if ipHeader has Timestamp.
//              false, if ipHeader does not have Timestamp.
//---------------------------------------------------------------------------

#define IpHeaderHasTimestamp(ipHeader) \
    (IpHeaderTimestampOptionField(ipHeader) != NULL)
//---------------------------------------------------------------------------
// Per hop behavior (PHB)
//-----------------------------------------------------------------------------

#define NUM_INITIAL_PHB_INFO_ENTRIES 4

//-----------------------------------------------------------------------------
// Routing table (forwarding table)
//-----------------------------------------------------------------------------

//
// Initial allocated entries for routing table.
//

#define FORWARDING_TABLE_ROW_START_SIZE 8

//-----------------------------------------------------------------------------
// Router info
//-----------------------------------------------------------------------------

#define NUM_INITIAL_ROUTER_INFO_ENTRIES 2

//-----------------------------------------------------------------------------
// Maximum value of IP-QUEUE-NUM-PRIORITIES at any interface
//-----------------------------------------------------------------------------

#define NUM_MAX_IP_QUEUE        256

//-----------------------------------------------------------------------------
// ECN debug test
//-----------------------------------------------------------------------------

#define NoECN_DEBUG_TEST

/*
 * Change this value to the number of drops required
 * e.g. #define ECN_TEST_PKT_MARK 3 for 3 drops
 * The value should be 0 (zero) for no marks
 */
#define ECN_TEST_PKT_MARK 0

#include "external.h"
#include "external_util.h"
#include "external_socket.h"


#if defined(ADDON_BOEINGFCS)
static void HandleNetworkIpStats(Node* node,
                                 NetworkDataIp* ip,
                                 Message* msg,
                                 int interfaceIndex,
                                 BOOL inComingData);
#endif /* ADDON_BOEINGFCS */

// Changed location here as compilation error was
// coming when ADDON_DB was not enabled

BOOL IsDataPacket(Message* msg, IpHeaderType* ipHeader)
{
    unsigned char nextProto;
    nextProto = ipHeader->ip_p;
    if (ipHeader->ip_p == IPPROTO_DSR)
    {
        unsigned char* dataPtr = (unsigned char*)MESSAGE_ReturnPacket(msg);
        int hLen = (int)IpHeaderSize(ipHeader);
        unsigned char* nextHdr = (unsigned char*)(dataPtr + hLen);
        nextProto = *nextHdr;
    }
    if (nextProto == IPPROTO_UDP ||
        nextProto == IPPROTO_TCP)
    {
        return TRUE;
    }

    return FALSE;
}

IpInterfaceInfoType::IpInterfaceInfoType()
{
    scheduler = NULL;
    inputScheduler = NULL;
    backplaneStatus = NETWORK_IP_BACKPLANE_IDLE;
    ipAddress = 0;
    numHostBits = 0;
    memset(interfaceName, 0, MAX_STRING_LENGTH);
    intfNumber = NULL;
    routerFunction = NULL;
    routingProtocolType = ROUTING_PROTOCOL_NONE;
    routingProtocol = NULL;

#ifdef ADDON_BOEINGFCS
    intraRegionRouterFunction = NULL;
    intraRegionRoutingProtocolType = ROUTING_PROTOCOL_NONE;
    intraRegionRoutingProtocol = NULL;
#endif

    multicastEnabled = FALSE;
    multicastRouterFunction = NULL;
    multicastProtocolType = ROUTING_PROTOCOL_NONE;
    multicastRoutingProtocol = NULL;
    macLayerStatusEventHandlerFunction = NULL;
    promiscuousMessagePeekFunction = NULL;
    macAckHandler = NULL;
#ifdef CYBER_CORE
    spdIN = NULL;
    spdOUT = NULL;
#endif //CYBER_CORE
    hsrpEnabled = FALSE;
    interfaceType = NETWORK_INVALID;
    isVirtualInterface = FALSE;

#ifdef ENTERPRISE_LIB
    intfType = INVALID_TYPE;
    accessListInPointer = NULL;
    accessListOutPointer = NULL;
    memset(&accessListStat, 0, sizeof(AccessListStats));
    routingTableUpdateFunction = NULL;
    rMapForPbr = NULL;
    memset(&pbrStat, 0, sizeof(PbrStat));
#endif // ENTERPRISE_LIB

    useRoutingCesMpr = FALSE;
    ipv6InterfaceInfo = NULL;
    InterfacetunnelInfo = NULL;
    disBackplaneCapacity = 0;

#ifdef TRANSPORT_AND_HAIPE
    memset(&haipeSpec, 0, sizeof(HAIPESpec));
#endif // TRANSPORT_AND_HAIPE

#ifdef CYBER_LIB
    countWormholeVictimTurnaroundTime = FALSE;
    wormholeVictimTurnaroundTime = 0;
    eavesdropFile = NULL;
    auditFile = NULL;
    certificate = NULL;
    certificateLength = 0;
    certificateFileLog = FALSE;
#ifdef DO_ECC_CRYPTO
    memset(eccKey, 0, sizeof(MPI) * 12);
#endif // DO_ECC_CRYPTO
#endif // CYBER_LIB

#ifdef CYBER_CORE
    isISAKMPEnabled = FALSE;
    isakmpdata = NULL;
    iahepFragUnit = 0;
    iahepInterfaceType = 0;
    /***** Start: OPAQUE-LSA *****/
    iahepDeviceAddress = ANY_INTERFACE;
    /***** End: OPAQUE-LSA *****/
#endif // CYBER_CORE
    ipFragUnit = 0;

    // Interface based stats. MIBS
    ifInUcastPkts = 0;
    ifInNUcastPkts = 0;
    ifOutUcastPkts = 0;
    ifOutNUcastPkts = 0;
    ifInMulticastPkts = 0;
    ifInBroadcastPkts = 0;
    ifOutMulticastPkts = 0;
    ifOutBroadcastPkts = 0;
    ifInDiscards = 0;
    ifOutDiscards = 0;
    ifHCInUcastPkts = 0;
    ifHCInMulticastPkts = 0;
    ifHCInBroadcastPkts = 0;
    ifHCOutUcastPkts = 0;
    ifHCOutMulticastPkts = 0;
    ifHCOutBroadcastPkts = 0;
    ipAddrIfIdx = 0;
    ipAddrNetMask = 0;
    ipAddrBcast = 0;
    ifInUcastDataPackets = 0;
    ifOutUcastDataPackets = 0;
    inUcastDataPacketSize = 0;
    inUcastPacketSize = 0;
    inNUcastPacketSize = 0;
    inMulticastPacketSize = 0;
    inBroadcastPacketSize = 0;
    firstInUcastPacketTime = 0;
    lastInUcastPacketTime = 0;
    firstInUcastDataPacketTime = 0;
    lastInUcastDataPacketTime = 0;
    firstInNUcastPacketTime = 0;
    lastInNUcastPacketTime = 0;
    firstInMulticastPacketTime = 0;
    lastInMulticastPacketTime = 0;
    firstInBroadcastPacketTime = 0;
    lastInBroadcastPacketTime = 0;

    outUcastDataPacketSize = 0;
    outUcastPacketSize = 0;
    outNUcastPacketSize = 0;
    outMulticastPacketSize = 0;
    outBroadcastPacketSize = 0;
    firstOutUcastPacketTime = 0;
    lastOutUcastPacketTime = 0;
    firstOutUcastDataPacketTime = 0;
    lastOutUcastDataPacketTime = 0;
    firstOutNUcastPacketTime = 0;
    lastOutNUcastPacketTime = 0;
    firstOutMulticastPacketTime = 0;
    lastOutMulticastPacketTime = 0;
    firstOutBroadcastPacketTime = 0;
    lastOutBroadcastPacketTime = 0;

    ifDescr.Set("");
#ifdef ADDON_DB
    metaData = NULL ;
#endif
#ifdef ADDON_BOEINGFCS
    useMiMulticastMesh = FALSE;
    networkCesIncData = NULL;
#endif
}

void D_IpPrint::ExecuteAsString(const std::string& in, std::string& out)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *rt = &ip->forwardTable;

    int i;
    char clockStr[MAX_CLOCK_STRING_LENGTH];
    char str[MAX_STRING_LENGTH];
    EXTERNAL_VarArray v;

    EXTERNAL_VarArrayInit(&v, 400);


    ctoa((getSimTime(node) / SECOND), clockStr);

    // TODO: build directly into C++ out string
    EXTERNAL_VarArrayConcatString(&v, "Forwarding Table\n");
    EXTERNAL_VarArrayConcatString(&v,
        "---------------------------------------------------------------"
        "--------------------\n");
    EXTERNAL_VarArrayConcatString(&v,
        "          dest          mask        intf       nextHop    protocol"
        "    admin    Flag\n");
    EXTERNAL_VarArrayConcatString(&v,
        "---------------------------------------------------------------"
        "--------------------\n");
    for (i = 0; i < rt->size; i++)
    {
        char address[20];
        IO_ConvertIpAddressToString(rt->row[i].destAddress, address);
        sprintf(str, "%15s  ", address);
        EXTERNAL_VarArrayConcatString(&v, str);
        IO_ConvertIpAddressToString(rt->row[i].destAddressMask, address);
        sprintf(str, "%15s  ", address);
        EXTERNAL_VarArrayConcatString(&v, str);
        sprintf(str, "%5u", rt->row[i].interfaceIndex);
        EXTERNAL_VarArrayConcatString(&v, str);
        IO_ConvertIpAddressToString(rt->row[i].nextHopAddress, address);
        sprintf(str, "%15s   ", address);
        EXTERNAL_VarArrayConcatString(&v, str);
        sprintf(str, "%5u      ", rt->row[i].protocolType);
        EXTERNAL_VarArrayConcatString(&v, str);
        sprintf(str, "%5u", rt->row[i].adminDistance);
        EXTERNAL_VarArrayConcatString(&v, str);

        if (rt->row[i].interfaceIsEnabled) {
            EXTERNAL_VarArrayConcatString(&v, "       U\n");
        } else {
            EXTERNAL_VarArrayConcatString(&v, "       D\n");
        }
    }

    EXTERNAL_VarArrayConcatString(&v, "\n");

    out = v.data;
    EXTERNAL_VarArrayFree(&v);
}

//-----------------------------------------------------------------------------
// STRUCTS, ENUMS, AND TYPEDEFS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// PROTOTYPES FOR FUNCTIONS WITH INTERNAL LINKAGE
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Packet delivery and forwarding
//-----------------------------------------------------------------------------

void //inline//
DeliverPacket(Node *node, Message *msg,
              int interfaceIndex, NodeAddress previousHopAddress);

#ifndef ADDON_BOEINGFCS
static
#endif
void //inline//
ForwardPacket(
    Node *node,
    Message *msg,
    int incomingInterface,
    NodeAddress previousHopAddress);

static void //inline//
QueueUpIpFragmentForMacLayer(
    Node *node,
    Message *msg,
    int interfaceIndex,
    NodeAddress nextHop,
    int incomingInterface);

static void //inline//
ProcessDelayedSendToMac(Node *node, Message *msg);

//-----------------------------------------------------------------------------
// Source route
//-----------------------------------------------------------------------------




static BOOL //inline//
SourceRouteThePacket(Node *node, Message *msg, int incomingInterface);

void
ExtractIpSourceAndRecordedRoute(
    Message *msg,
    NodeAddress RouteAddresses[],
    int *NumAddresses,
    int *RouteAddressIndex);

//-----------------------------------------------------------------------------
// Boolean utility routines for packet forwarding process
//-----------------------------------------------------------------------------

BOOL //inline//
IsMyPacket(Node *node, NodeAddress destAddress);

BOOL
IsOutgoingBroadcast(
    Node *node,
    NodeAddress destAddress,
    int *outgoingInterface,
    NodeAddress *outgoingBroadcastAddress);

//-----------------------------------------------------------------------------
// Update Stats API
//-----------------------------------------------------------------------------

static STAT_DestAddressType StatsApiAddrType(Node* node, Message* msg)
{
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    return STAT_NodeAddressToDestAddressType(node, ipHeader->ip_dst);
}

// wrapper for other network layer protocols to add necessary Stats API
// info fields
void NetworkIpAddPacketSentToMacDataPoints(
    Node* node,
    Message* msg,
    int interfaceIndex)
{
    ERROR_Assert(node->networkData.networkProtocol != IPV6_ONLY,
        "NetworkIpAddPacketSentToMacDataPoints was called on an IPv6 network layer");

    if (!node->networkData.networkStats)
    {
        return;
    }

    IpHeaderType *ipHeader = (IpHeaderType*)msg->packet;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    BOOL isForward = node->nodeId != msg->originatingNodeId;

    ip->newStats->AddPacketSentToMacDataPoints(
        node,
        msg,
        StatsApiAddrType(node, msg),
        IsDataPacket(msg, ipHeader),
        isForward);

#ifdef ADDON_DB
    HandleNetworkDBEvents(
        node,
        msg,
        interfaceIndex,
        "NetworkSendToLower",
        "",
        0,
        0,
        0,
        0);

    HandleMacDBEvents(
        node,
        msg,
        node->macData[interfaceIndex]->phyNumber,
        interfaceIndex,
        MAC_ReceiveFromUpper,
        node->macData[interfaceIndex]->macProtocol);
#endif /* ADDON_DB */
}
                                           
                                           

//-----------------------------------------------------------------------------
// Per hop behavior (PHB)
//-----------------------------------------------------------------------------

/*static void //inline//
IpInitPerHopBehaviors(
    Node *node,
    const NodeInput *nodeInput);*/

static void //inline//
AddPHBEntry(
    Node *node,
    unsigned char ds, //dscp value
    QueuePriorityType priority);

static unsigned //inline//
GetQueuePriorityFromUserTos(
    Node *node,
    TosType userTos,
    int numQueues);

//-----------------------------------------------------------------------------
// Callbacks into IP made by the MAC layer, helper functions
//-----------------------------------------------------------------------------

static void //inline//
HandleSpecialMacLayerStatusEvents(Node *node,
                                  Message *msg,
                                  const NodeAddress nextHopAddress,
                                  int interfaceIndex);

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpParseAndSetRoutingProtocolType()
// PURPOSE      Parse ROUTING-PROTOCOL parameter and set routingProtocolType.
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
//-----------------------------------------------------------------------------
void NetworkIpParseAndSetRoutingProtocolType(
    Node* node,
    const NodeInput* nodeInput);



//-----------------------------------------------------------------------------
// IP header option field
//-----------------------------------------------------------------------------

static void //inline//
ExpandOrShrinkIpOptionField(
    Node *node,
    Message *msg,
    const int optionCode,
    const int newIpOptionSize);

#ifdef CYBER_CORE
static BOOL NetworkIpNeedsToForwardAppBroadcast(Node* node,
                                     Message *msg,
                                     NodeAddress destAddress);

static BOOL NetworkIpCheckDuplicateAppBroadcastReceived(
    Node* node,
    Message *msg);

static void NetworkIpRemoveBroadcastForwardMappingEntries(Node* node,
    Message *msg);
#endif // CYBER_CORE

//-----------------------------------------------------------------------------
// Statistics
//-----------------------------------------------------------------------------

/*
 * FUNCTION:   NetworkIpCheckIpAddressIsInSameSubnet()
 * PURPOSE:    This function check this argument ip address and ip address
 *             of this specified interfaceIndex are in same subnet.
 * RETURN:     BOOL
 * ASSUMPTION: None
 * PARAMETERS: node,              node in which this interfaceIndex belong.
 *             interfaceIndex,    interface index.
 *             ipAddress,         ip address.
 */

BOOL NetworkIpCheckIpAddressIsInSameSubnet(Node *node,
                                           int interfaceIndex,
                                           NodeAddress ipAddress)
{
    NodeAddress networkAddress =
                       NetworkIpGetInterfaceNetworkAddress(node,
                                                           interfaceIndex);

    int numHostBits = NetworkIpGetInterfaceNumHostBits(node, interfaceIndex);

    return(IsIpAddressInSubnet(ipAddress, networkAddress, numHostBits));
}
static void //inline//
NetworkIpInitStats(Node* node, NetworkIpStatsType *stats);

void
NetworkIpPrintStats(Node *node);

//-----------------------------------------------------------------------------
// FUNCTIONS WITH EXTERNAL LINKAGE
//-----------------------------------------------------------------------------



//---------------------------------------------------------------------------
// FUNCTION   NetworkIpCheckMulticastRoutingProtocol
//
// PURPOSE    Check if this node running the given multicast routing protocol
//
// PARAMETERS node - this node.
//            routingProtcolType - the multicast protocol to get.
//            interfaceId - specific interface index or ANY_INTERFACE
//
// RETURN     TRUE if match found, FALSE otherwise.
//---------------------------------------------------------------------------
static
BOOL NetworkIpCheckMulticastRoutingProtocol(
    Node* node,
    NetworkRoutingProtocolType routingProtocolType,
    int interfaceId)
{
    int i;
    BOOL retVal = FALSE;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    if (interfaceId == ANY_INTERFACE)
    {
        for (i = 0; i < node->numberInterfaces; i++)
        {
            if (ip->interfaceInfo[i]->multicastProtocolType ==
                    routingProtocolType)
            {
                retVal =  TRUE;
                break;
            }
        }
    }
    else if (ip->interfaceInfo[interfaceId]->multicastProtocolType ==
                routingProtocolType)
    {
        retVal = TRUE;
    }

    return retVal;
}



//-----------------------------------------------------------------------------
// Init functions
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpPreInit()
// PURPOSE      IP initialization required before any of the other
//              layers are initialized.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
// NOTES        This is mainly for MAC initialization, which requires
//              certain IP structures be pre-initialized.
//-----------------------------------------------------------------------------

void
NetworkIpPreInit(Node *node)
{
    NetworkDataIp *ip;

    int i;

#ifndef ADDON_NGCNMS
    if (node->networkData.networkVar != NULL)
        return;

    ip = (NetworkDataIp *) MEM_malloc(sizeof(NetworkDataIp));
    memset(ip, 0, sizeof(NetworkDataIp));

#else
        //m.t.
    if (node->networkData.networkVar == NULL)
    {
        ip = (NetworkDataIp *) MEM_malloc(sizeof(NetworkDataIp));
        memset(ip, 0, sizeof(NetworkDataIp));

        node->networkData.networkVar = ip;
    }
    else
        ip = (NetworkDataIp *) node->networkData.networkVar;
#endif

    node->networkData.networkVar = ip;

    ip->packetIdCounter = 0;
    ip->checkMessagePeekFunction = FALSE;
    ip->checkMacAckHandler = FALSE;

    NetworkInitForwardingTable(node);
    NetworkInitMulticastForwardingTable(node);

    // Initialize the multicast group list
    ListInit(node, &ip->multicastGroupList);

    ip->routeUpdateFunction = NULL;

#ifndef ADDON_BOEINGFCS
    ip->ipFragUnit = MAX_NW_PKT_SIZE;
#endif

    ip->ipFragHoldTime = IP_FRAGMENT_HOLD_TIME;
    ip->maxPacketLength = MAX_NW_PKT_SIZE;

    NetworkIpInitStats(node, &(ip->stats));


    for (i = 0; i < MAX_NUM_INTERFACES; i++)
    {
        ip->interfaceInfo[i] = NULL;
    }

    ip->reflexTimeout = -1;
    ip->ipv6 = NULL;

#ifdef ENTERPRISE_LIB
    ip->allNameValueLists = NULL;
    ip->accessListName = NULL;
    ip->nestReflex = NULL;
    ip->accessListSession = NULL;
    ip->isACLStatOn = FALSE;
    ip->accessListTrace = FALSE;
    ip->routeMapList = NULL;
    ip->bufferLastEntryRMap = NULL;
    ip->pbrTrace = FALSE;
    ip->isPBRStatOn = FALSE;
    ip->local = FALSE;
    ip->rMapForPbr = FALSE;
    ip->pbrStat.packetsPolicyRoutedLocal = 0;
    ip->pbrStat.packetsNotPolicyRouted = 0;
    ip->pbrStat.packetPrecSet = 0;
    ip->pbrStat.packetsPolicyRouted = 0;

    //Initialize for route redistribution
    ip->rtRedistributeIsEnabled = FALSE;
    ip->rtRedistributeIsEnabled = FALSE;
    ip->rtRedistributeInfo = NULL;
#endif // ENTERPRISE_LIB

    // By default Loopback is kept enabled
    ip->isLoopbackEnabled = TRUE;

    NetworkIpLoopbackForwardingTableInit(node);

    std::string path;
    D_Hierarchy *h = &node->partitionData->dynamicHierarchy;

    if (h->CreateNetworkPath(
            node,
            "ip",
            "ipInReceives",
            path))
    {
        h->AddObject(
            path,
            new D_UInt32Obj(&ip->stats.ipInReceives));
    }

    if (h->CreateNetworkPath(
            node,
            "ip",
            "ipReasmReqds",
            path))
    {
        h->AddObject(
            path,
            new D_UInt32Obj(&ip->stats.ipReasmReqds));
    }

    if (h->CreateNetworkPath(
            node,
            "ip",
            "ipFragsCreated",
            path))
    {
        h->AddObject(
            path,
            new D_UInt32Obj(&ip->stats.ipFragsCreated));
    }

#ifndef ADDON_BOEINGFCS
    if (h->CreateNetworkPath(
            node,
            "ip",
            "ipFragUnit",
            path))
    {
        h->AddObject(
            path,
            new D_Int32Obj(&ip->ipFragUnit));
        node->partitionData->dynamicHierarchy.SetWriteable(
            path,
            FALSE);
    }
#endif

    if (h->CreateNetworkPath(
            node,
            "ip",
            "print",
            path))
    {
        D_IpPrint *ipPrint = new D_IpPrint(node);
        h->AddObject(
            path,
            ipPrint);
    }

#ifdef ADDON_DB
    StatsDBInitializeNetSummaryStructure(node) ;
#endif
}

// /**
// FUNCTION   :: NetworkIpPrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
// **/

void NetworkIpPrintTraceXML(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    IpHeaderType *ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);


    char addr1[20];
    char addr2[20];


    sprintf(buf, "<ipv4>");
    TRACE_WriteToBufferXML(node, buf);

    sprintf(buf, "%hu %hu %hu %hu %hu %hu %hu",
        IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len),
        IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len),
        ((IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len)) >> 2),//R SFT for ECN
        ((IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len)) & 0x00000010),// ECN ECT
        ((IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len)) & 0x00000001),// ECN CE
            MESSAGE_ReturnPacketSize(msg),
            ipHeader->ip_id);
    TRACE_WriteToBufferXML(node, buf);

    sprintf(buf, " <flags>%hu %hu %hu</flags>",
            IpHeaderGetIpReserved(ipHeader->ipFragment),
            IpHeaderGetIpDontFrag(ipHeader->ipFragment),
            IpHeaderGetIpMoreFrag(ipHeader->ipFragment));
    TRACE_WriteToBufferXML(node, buf);

    IO_ConvertIpAddressToString(ipHeader->ip_src, addr1);
    IO_ConvertIpAddressToString(ipHeader->ip_dst, addr2);
    sprintf(buf, " %hu %hu %hu %hu %s %s",
            IpHeaderGetIpFragOffset(ipHeader->ipFragment),
            ipHeader->ip_ttl,
            ipHeader->ip_p,
            ipHeader->ip_sum,
            addr1,
            addr2);
    TRACE_WriteToBufferXML(node, buf);

    sprintf(buf, "</ipv4>");
    TRACE_WriteToBufferXML(node, buf);
}


// /**
// FUNCTION   :: NetworkIpInitTrace
// LAYER      :: NETWORK
// PURPOSE    :: IP initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/

static
void NetworkIpInitTrace(Node* node, const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll = TRACE_IsTraceAll(node);
    BOOL trace = FALSE;
    static BOOL writeMap = TRUE;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TRACE-IP",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            trace = TRUE;
        }
        else if (strcmp(buf, "NO") == 0)
        {
            trace = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "TRACE-IP should be either \"YES\" or \"NO\".\n");
        }
    }
    else
    {
        if (traceAll || node->traceData->layer[TRACE_NETWORK_LAYER])
        {
            trace = TRUE;
        }
    }

    if (trace)
    {
            TRACE_EnableTraceXML(node, TRACE_IP,
                "IPv4", NetworkIpPrintTraceXML, writeMap);
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_IP,
                "IPv4", writeMap);
    }
    writeMap = FALSE;
}

// -------------------------------------------------------------------------
// Function: IPParseUnnumbered
// Layer...: Network
// Purpose: Borrow the IP address from node's first interface.
// Parameters:
// Node* : Pointer to the node.
// NodeInput* : Reference to user's configuration parameters.
//             map, the mapping list.
// Return: None
// -------------------------------------------------------------------------

static
void IPParseUnnumbered(Node* node, const NodeInput *nodeInput)
{
    int i;
    NodeId nodeId;
    BOOL isNodeId = FALSE;
    int intfIndex;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    BOOL isAnyIntfUnnumbered = FALSE;

    // Check each user's configuration parameters...
    for (i = 0; i < nodeInput->numLines; i++)
    {
        if (strcmp(nodeInput->variableNames[i], "UNNUMBERED") == 0)
        {
            intfIndex = nodeInput->instanceIds[i];

             // Make sure that the qualifier is a node ID first.
            IO_ParseNodeIdOrHostAddress(
                    nodeInput->qualifiers[i],
                    &nodeId,
                    &isNodeId);

            if (!isNodeId)
            {
                char buf[MAX_STRING_LENGTH];
                sprintf(buf, "IP-ADDRESS parameter must have a node ID as "
                             "its qualifier.\n");
                ERROR_ReportError(buf);
            }
            if (nodeId == node->nodeId)
            {
                if (0 <= intfIndex && intfIndex < node->numberInterfaces)
                {
                    if (strcmp(nodeInput->values[i], "YES") == 0)
                    {
                        if (!(ip->interfaceInfo[intfIndex]->interfaceType ==
                                                             NETWORK_IPV4
                           || ip->interfaceInfo[intfIndex]->interfaceType ==
                                                            NETWORK_DUAL))
                        {
                            char buf[MAX_STRING_LENGTH];
                            sprintf(buf,
                                "IPv6 Interface should not be unnumbered");
                            ERROR_ReportError(buf);
                        }

                        char tempProtocolString[MAX_STRING_LENGTH];
                        BOOL tempRetVal;
                        IO_ReadString(
                          node->nodeId,
                          NetworkIpGetInterfaceAddress(node, intfIndex),
                          nodeInput,
                          "ROUTING-PROTOCOL",
                          &tempRetVal,
                          tempProtocolString);

                        if (!tempRetVal ||
                            (strcmp(tempProtocolString, "OSPFv2") != 0))
                        {
                            char buf[MAX_STRING_LENGTH];
                            sprintf(buf, "Unnumbered interface support only "
                                 "OSPFv2 routing protocol.\n");
                            ERROR_ReportError(buf);
                        }
                        //node has atleast one unnumbered interface
                        isAnyIntfUnnumbered = TRUE;
                        ip->interfaceInfo[intfIndex]->isUnnumbered = TRUE;
                    }
                    else if (strcmp(nodeInput->values[i], "NO") == 0)
                    {
                        ip->interfaceInfo[intfIndex]->isUnnumbered = FALSE;
                    }
                    else
                    {
                        char buf[MAX_STRING_LENGTH];
                        sprintf(buf, "UNNUMBERED: Value Should be YES/NO");
                        ERROR_ReportError(buf);
                    }
                }
                else
                {
                    char buf[MAX_STRING_LENGTH];
                    sprintf(buf, "UNNUMBERED: wrong Interface index");
                    ERROR_ReportError(buf);
                }
            }
        }
    }
    if (isAnyIntfUnnumbered)
    {
        NodeAddress borrowedAddress = ANY_ADDRESS;
        BOOL isCentralizedIp = TRUE;

        // find first non-unnumbered ipv4 interface
        for (i = 0; i < node->numberInterfaces; i++)
        {
            if ((ip->interfaceInfo[i]->interfaceType == NETWORK_IPV4
                || ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL)
                && ip->interfaceInfo[i]->isUnnumbered == FALSE)
            {
                borrowedAddress = NetworkIpGetInterfaceAddress(node, i);
                isCentralizedIp = FALSE;
                break;
            }
        }

        // All ipv4 interfaces are unnumbered
        if (isCentralizedIp == TRUE)
        {
            //find first ipv4 interface
            for (i = 0; i < node->numberInterfaces; i++)
            {
                if ((ip->interfaceInfo[i]->interfaceType == NETWORK_IPV4
                    || ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL))
                {
                    borrowedAddress = NetworkIpGetInterfaceAddress(node, i);
                    break;
                }
            }
        }

        //borrow ip-address for all unnumbered interface
        for (i = 0; i < node->numberInterfaces; i++)
        {
            if (ip->interfaceInfo[i]->isUnnumbered == TRUE)
            {
                ip->interfaceInfo[i]->ipAddress = borrowedAddress;
                ip->interfaceInfo[i]->numHostBits = 0;
            }
        }
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpInit
// PURPOSE      Initialize IP variables, and all network-layer IP
//              protocols.
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpInit(Node *node, const NodeInput *nodeInput)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    BOOL retVal;
    char protocolString[MAX_STRING_LENGTH];
    char forwardingEnabledString[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    int i;
    clocktype ipFragHoldTime = 0;
    int ipFragUnit = 0;

    double throughput = 0.0;
    float rtPerformVar; // router performance variation
    char rtBackType[MAX_STRING_LENGTH]; //router backplane type
    char backplaneThroughput[MAX_STRING_LENGTH];

#ifdef ADDON_BOEINGFCS
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "CES-TOS-ROUTING-ENABLED",
        &retVal,
        buf);

    if ((!retVal) || (strcmp(buf, "NO") == 0))
    {
        ip->tosRoutingEnabled = FALSE;
    }
    else if (strcmp(buf, "YES") == 0)
    {
        ip->tosRoutingEnabled = TRUE;
    }
    else
    {
        ERROR_ReportError(
            "CES-TOS-ROUTING-ENABLED value is INVALID.\n");
    }
#endif

// For Dymo init default value
    ip->isManetGateway = FALSE;
    ip->manetPrefixlength = 0;
// End for Dymo

    ip->backplaneType = BACKPLANE_TYPE_DISTRIBUTED;
    ip->backplaneStatus = NETWORK_IP_BACKPLANE_IDLE;

    ip->backplaneThroughputCapacity =
        NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT;

    // IGMP is not enabled by default.
    ip->isIgmpEnable = FALSE;

    // ICMP is not enabled by default.
    ip->isIcmpEnable = FALSE;

#ifdef ENTERPRISE_LIB
    // Route Redistribution is disabled by default.
    ip->isRtRedistributeStatOn = FALSE;
#endif // ENTERPRISE_LIB

    // packet is not ECNcapable by default.
    ip->isPacketEcnCapable = FALSE;

    // BEGIN NDP start
    ip->isNdpEnable = FALSE;   // NDP is not enabled by default
    ip->ndpData = NULL;
    // END NDP start.

    // MOBILE-IP is not enabled by default.
    ip->mobileIpStruct = NULL;

    // dualIp is not enabled by default.
    ip->dualIp = NULL;

    //Unnumbered interface support
    IPParseUnnumbered(node, nodeInput);

    NetworkIpInitTrace(node, nodeInput);

#ifdef ADDON_BOEINGFCS
    // The statistic being setup here is no longer used
    // and has been removed from the collection struct.
    //NetworkStatsSetupDropsFromRouting(node, &ip->stats);
#endif

#ifndef ADDON_BOEINGFCS
    IO_ReadInt(node->nodeId,
           ANY_ADDRESS,
           nodeInput,
           "IP-FRAGMENTATION-UNIT",
           &retVal,
           &ipFragUnit);

    if (!retVal)
    {
        ipFragUnit = MAX_NW_PKT_SIZE;
    }
    else if (ipFragUnit < MIN_NW_PKT_SIZE || ipFragUnit > MAX_NW_PKT_SIZE)
    {
        char errString[MAX_STRING_LENGTH];
        sprintf(errString, "IP fragmentation unit (%d) should not be less"
                " than MIN_NW_PKT_SIZE (%d) nor greater than"
                " MAX_NW_PKT_SIZE (%d)", ipFragUnit, MIN_NW_PKT_SIZE,
                MAX_NW_PKT_SIZE);

        ERROR_ReportError(errString);
    }
    ip->ipFragUnit = ipFragUnit;
    ip->maxPacketLength = ip->ipFragUnit;

#endif

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ROUTER-BACKPLANE-THROUGHPUT",
        &retVal,
        backplaneThroughput);

    char *p;

    if (retVal == FALSE ||
        strcmp(backplaneThroughput, "UNLIMITED") == 0 ||
        strcmp(backplaneThroughput, "0") == 0)
    {
        // If not specified, we assume infinite backplane throughput.
        ip->backplaneThroughputCapacity =
            NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT;
    }
    else if ((throughput = strtod(backplaneThroughput , &p)) > 0.0)
    {
        IO_ReadFloat(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "ROUTER-PERFORMANCE-VARIATION",
            &retVal,
            &rtPerformVar);

        if (retVal)
        {
            throughput += ((throughput * rtPerformVar) / 100);
        }

        ip->backplaneThroughputCapacity = (clocktype)throughput;

        for (i = 0; i < node->numberInterfaces; i++)
        {
            ip->interfaceInfo[i]->disBackplaneCapacity =
                (clocktype)(throughput / (node->numberInterfaces + 1));
        }

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "ROUTER-BACKPLANE-TYPE",
            &retVal,
            rtBackType);

        if (strcmp(rtBackType, "CENTRAL") == 0)
        {
            ip->backplaneType = BACKPLANE_TYPE_CENTRAL;
        }
        else if (strcmp(rtBackType, "DISTRIBUTED"))
        {
            ERROR_ReportError("ROUTER-BACKPLANE-TYPE should be "
                              "either \"CENTRAL\" or \"DISTRIBUTED\".\n");
        }
        else
        {
            ip->backplaneThroughputCapacity =
                (clocktype)(throughput / (node->numberInterfaces + 1));
        }
    }
    else if (throughput == 0.0)
    {
        // If not specified, we assume infinite backplane throughput.
        ip->backplaneThroughputCapacity =
            NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT;
    }
    else
    {
        ERROR_ReportError("Wrong ROUTER-BACKPLANE-THROUGHPUT value.\n");
    }

    // Create buffer for CPU
    NetworkIpInitCpuQueueConfiguration(node,
                                       nodeInput);
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "IP-FORWARDING",
        &retVal,
        forwardingEnabledString);

    if (retVal)
    {
        if (strcmp(forwardingEnabledString, "YES") == 0)
        {
            ip->ipForwardingEnabled = TRUE;
        }
        else if (strcmp(forwardingEnabledString, "NO") == 0)
        {
            ip->ipForwardingEnabled = FALSE;
        }
        else
        {
            ERROR_ReportError("IP-FORWARDING should be either \"YES\" or \""
                              "NO\".\n");
        }
    }
    else
    {
        ip->ipForwardingEnabled = TRUE;
    }

    // Loopback Init
    NetworkIpLoopbackInit(node, nodeInput);

    // added for gateway

    char gatewayStr[MAX_ADDRESS_STRING_LENGTH];

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS, // subnet address need to be taken
        nodeInput,
        "DEFAULT-GATEWAY",
        &retVal,
        gatewayStr);

    if (!retVal)
    {
        ip->gatewayConfigured = FALSE;
        ip->defaultGatewayId = 0;
    }
    else
    {
        NodeAddress gatewayRtrId;
        int numHostBits;
        BOOL isNodeId;

        // Parse IP Address
        IO_ParseNodeIdHostOrNetworkAddress(
            gatewayStr,
            &gatewayRtrId,
            &numHostBits,
            &isNodeId);

        if (isNodeId)
        {
            ip->gatewayConfigured = TRUE;

            // consider default address only
            ip->defaultGatewayId =
                MAPPING_GetInterfaceAddressForInterface(
                    node, gatewayRtrId, DEFAULT_INTERFACE);
        }
        else
        {
            ip->gatewayConfigured = TRUE;
            ip->defaultGatewayId = gatewayRtrId;
        }
    }
    // end for gateway
#ifdef CYBER_CORE
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "IPSEC-ENABLED",
        &retVal,
        buf);

    if (!retVal || !strcmp(buf, "NO"))
    {
        ip->isIPsecEnabled = FALSE;
        ip->isIPsecOpenSSLEnabled = FALSE;
    }
    else if (!strcmp(buf, "YES"))
    {
        ip->isIPsecEnabled = TRUE;
        ip->isIPsecOpenSSLEnabled = FALSE;
        IPsecInit(node, nodeInput);
    }
    else
    {
        ERROR_ReportError("IPSEC-ENABLED expects YES or NO");
    }

    retVal = FALSE;
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "IPSEC-REAL-CRYPTO-ENABLED",
        &retVal,
        buf);

    if (!retVal || !strcmp(buf, "NO"))
    {
        ip->isIPsecOpenSSLEnabled = FALSE;
    }
    else if (!strcmp(buf, "YES"))
    {
        ip->isIPsecOpenSSLEnabled = TRUE;
        if (ip->isIPsecEnabled == FALSE)
        {
            ERROR_ReportError("IPSEC-REAL-CRYPTO-ENABLED expects YES "
                "only if IPSEC-ENABLED is YES" );
        }
    }
    else
    {
        ERROR_ReportError("IPSEC-REAL-CRYPTO-ENABLED expects YES or NO");
    }
#endif //CYBER_CORE
    IO_ReadTime(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "IP-FRAGMENT-HOLD-TIME",
        &retVal,
        &ipFragHoldTime);

    if (retVal)
    {
        ip->ipFragHoldTime = ipFragHoldTime;
    }
#ifdef ADDON_BOEINGFCS
    {
        BOOL useSubnet = FALSE;
        BOOL subFormation = FALSE;
        BOOL ncwHandoff = FALSE;

        for (i = 0; i < node->numberInterfaces; i++)
        {
            ip->interfaceInfo[i]->networkSecurityCesHaipeInterfaceType
                = CES_HAIPE_RED_TO_BLACK_INTERFACE;
            ip->interfaceInfo[i]->routingInstance
                = CES_HAIPE_RED_TO_BLACK_INTERFACE;

            IO_ReadBool(
                node->nodeId,
                NetworkIpGetInterfaceAddress(node, i),
                nodeInput,
                "SUBNET-FORMATION",
                &retVal,
                &useSubnet);
            if (useSubnet)
            {
                subFormation = TRUE;
            }
        }

        //if subnet formation is active on an interface, we should init
        if (subFormation)
        {
            NetworkCesSubnetInit(node, nodeInput);
        }

        else {
#ifdef ADDON_NGCNMS
            ip->numSubnets = 0;
            ip->outputStats = FALSE;
#endif
        }

        BOOL useNbrMon = FALSE;
        BOOL nbrMonitoring = FALSE;
        for (i=0; i< node->numberInterfaces; i++)
        {
            IO_ReadBool(node->nodeId,
                        NetworkIpGetInterfaceAddress(node, i),
                        nodeInput,
                        "MI-CES-NEIGHBOR-MONITORING",
                        &retVal,
                        &useNbrMon);

            if (useNbrMon)
            {
                nbrMonitoring = TRUE;
            }
        }

        if (nbrMonitoring )
        {
            MICesNmInit(node, nodeInput);
            ip->cesNetworkProtocol = NETWORK_PROTOCOL_CES_WNW_MI;
        }

        BOOL useRegion = FALSE;
        BOOL regionFormation = FALSE;
        for (i=0; i< node->numberInterfaces; i++)
        {
            IO_ReadBool(node->nodeId,
                        NetworkIpGetInterfaceAddress(node, i),
                        nodeInput,
                        "NETWORK-CES-REGION-FORMATION",
                        &retVal,
                        &useRegion);

            if (useRegion)
            {
                regionFormation = TRUE;
            }
        }

        if (regionFormation)
        {
            NetworkCesRegionInit(node, nodeInput);
        }

        ip->ncwHandoff = FALSE;
        IO_ReadBool(node->nodeId,
                    ANY_ADDRESS,
                    nodeInput,
                    "NCW-HANDOFF",
                    &retVal,
                    &ncwHandoff);
        if (retVal && ncwHandoff)
        {
            ip->ncwHandoff = TRUE;
        }
    }
#endif

    std::string path;
    D_Hierarchy *h = &node->partitionData->dynamicHierarchy;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (h->CreateNetworkPath(
                node,
                i,
                "ip",
                "ipFragUnit",
                path))
        {
            h->AddObject(
                path,
                new D_Int32Obj(&ip->interfaceInfo[i]->ipFragUnit));
            node->partitionData->dynamicHierarchy.SetWriteable(
                path,
                FALSE);
        }

        ip->interfaceInfo[i]->ipFragUnit = MAX_NW_PKT_SIZE;

        IO_ReadInt(node->nodeId,
                   NetworkIpGetInterfaceAddress(node, i),
                   nodeInput,
                   "IP-FRAGMENTATION-UNIT",
                   &retVal,
                   &ipFragUnit);

        if (!retVal)
        {
            ipFragUnit = MAX_NW_PKT_SIZE;
        }
        else if (ipFragUnit < MIN_NW_PKT_SIZE || 
                 ipFragUnit > MAX_NW_PKT_SIZE)
        {
            char errString[MAX_STRING_LENGTH];
            sprintf(errString, "IP fragmentation unit (%d) should not be"
                    " less than MIN_NW_PKT_SIZE (%d) nor greater than"
                    " MAX_NW_PKT_SIZE (%d)", ipFragUnit, MIN_NW_PKT_SIZE,
                    MAX_NW_PKT_SIZE);
            
            ERROR_ReportError(errString);
        }
        ip->interfaceInfo[i]->ipFragUnit = ipFragUnit;
        ip->maxPacketLength = ip->interfaceInfo[i]->ipFragUnit;
        
#ifdef ADDON_BOEINGFCS
        IO_ReadString(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, i),
            nodeInput,
            "MOBILE-INTRANET-ROUTING-PROTOCOL",
            &retVal,
            protocolString);

        if (retVal && strcmp(protocolString, "ROUTING-CES-MALSR") == 0)
        {
            RoutingCesMalsrInit(node, nodeInput, i);
        }
        else if (retVal && (strcmp(protocolString, "N/A") == 0 ||
                            strcmp(protocolString, "NONE") == 0))
        {
            // do nothing
        }
        else if (retVal)
        {
            char errorStr[MAX_STRING_LENGTH];

            sprintf(errorStr, "%s not a valid INTER-REGION-ROUTING-PROTOCOL\n",
                    protocolString);
            ERROR_ReportWarning(errorStr);
        }

        if (h->CreateNetworkPath(
                node,
                i,
                "ip",
                "ipFragUnit",
                path))
        {
            h->AddObject(
                path,
                new D_Int32Obj(&ip->interfaceInfo[i]->ipFragUnit));
            node->partitionData->dynamicHierarchy.SetWriteable(
                path,
                FALSE);
        }

        ip->interfaceInfo[i]->ipFragUnit = MAX_NW_PKT_SIZE;

        IO_ReadInt(node->nodeId,
                   NetworkIpGetInterfaceAddress(node, i),
                   nodeInput,
                   "IP-FRAGMENTATION-UNIT",
                   &retVal,
                   &ipFragUnit);
        
        if (!retVal)
        {
            ipFragUnit = MAX_NW_PKT_SIZE;
        }
        else if (ipFragUnit < MIN_NW_PKT_SIZE || 
                 ipFragUnit > MAX_NW_PKT_SIZE)
        {
            char errString[MAX_STRING_LENGTH];
            sprintf(errString, "IP Fragmentation unit (%d) should not be"
                    " less than MIN_NW_PKT_SIZE (%d) nor greater than"
                    " MAX_NW_PKT_SIZE (%d)", ipFragUnit, MIN_NW_PKT_SIZE,
                    MAX_NW_PKT_SIZE);
            
            ERROR_ReportError(errString);
        }
        
        ip->interfaceInfo[i]->ipFragUnit = ipFragUnit;
        ip->maxPacketLength = ip->interfaceInfo[i]->ipFragUnit;
        
        
        //Initializing MI Multicast Mesh
        BOOL useMiMulticastMesh = FALSE;
        ip->interfaceInfo[i]->useMiMulticastMesh = FALSE;
        IO_ReadBool(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, i),
            nodeInput,
            "MI-CES-MULTICAST-MESH-ENABLED",
            &retVal,
            &useMiMulticastMesh);
            
        if (useMiMulticastMesh)
        {
            ip->interfaceInfo[i]->useMiMulticastMesh = TRUE;
            MiCesMulticastMeshInit(node,nodeInput,i);
        }
        BOOL useRoutingCesMpr = FALSE;
        ip->interfaceInfo[i]->useRoutingCesMpr = FALSE;
        IO_ReadBool(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, i),
            nodeInput,
            "ROUTING-CES-MPR-ENABLED",
                    &retVal,
            &useRoutingCesMpr);
        if (useRoutingCesMpr)
        {
            ip->interfaceInfo[i]->useRoutingCesMpr = TRUE;
            RoutingCesMprInit(node, nodeInput, i);
        }

#ifdef ADDON_NGCNMS
        BOOL useCollectRoutes = FALSE;
        IO_ReadBool(
            ANY_NODEID,
            ANY_ADDRESS,
            nodeInput,
            "GATEWAY-COLLECT-ROUTES",
            &retVal,
            &useCollectRoutes);

        if (!retVal)
            useCollectRoutes = FALSE;

        NetworkCesSubnetData* subnet = ip->subnetData;
        if (subnet != NULL) {
            if (useCollectRoutes) {
                //if (NetworkCesSubnetIsGateway(node, i))
                //collectRoutesInit(node, i, nodeInput);
            }
            else {
                ip->collectRoutes = FALSE;
            }
        }
#endif // ADDON_NGCNMS
#endif // ADDON_BOEINGFCS
}

#ifdef CYBER_CORE
    for (i = 0; i < node->numberInterfaces; ++i)
    {
        IO_ReadString(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, i),
            nodeInput,
            "ISAKMP-SERVER",
            &retVal,
            buf);

        if (!retVal || !strcmp(buf, "NO"))
        {
            ip->interfaceInfo[i]->isISAKMPEnabled = FALSE;
        }
        else if (!strcmp(buf, "YES"))
        {
            ip->interfaceInfo[i]->isISAKMPEnabled = TRUE;
            ISAKMPInit(node, nodeInput, i);
        }
        else
        {
            ERROR_ReportError("ISAKMP-SERVER expects YES or NO");
        }
    }
#endif // CYBER_CORE

    for (i = 0; i < node->numberInterfaces; i++)
    {
#ifdef ENTERPRISE_LIB
        IO_ReadString(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, i),
            nodeInput,
            "MPLS-PROTOCOL",
            &retVal,
            protocolString);

        if (!retVal || strcmp(protocolString, "NO") == 0)
        {
            node->macData[i]->mplsVar = NULL;
        }
        else
        {
            if (strcmp(protocolString, "YES") == 0)
            {
                MplsInit(node, nodeInput, i,
                         (MplsData **) &node->macData[i]->mplsVar);
            }
            else
            {
                ERROR_ReportError("Expecting YES or NO for MPLS-PROTOCOL "
                                  "parameter\n");
            }
        }
#endif // ENTERPRISE_LIB
    }

    //Parse IPV4 unicast, Group Management and multicast routing Protocol
    NetworkIpParseAndSetRoutingProtocolType(node, nodeInput);

#ifdef MILITARY_RADIOS_LIB
    for (i = 0; i < node->numberInterfaces; ++i)
    {
        IO_ReadString(node->nodeId,
                      NetworkIpGetInterfaceAddress(node, i),
                      nodeInput,
                      "INC-TYPE",
                      &retVal,
                      protocolString);

        if (retVal && strcmp(protocolString, "EPLRS") == 0)
        {
            EplrsInit(node, nodeInput, i);
        }
    }
#endif

    FixedComms_Initialize(node, nodeInput);
    
    // Fragmentation id set to 0
    ip->ipFragmentId = 0;
    ip->fragmentListFirst = NULL;

#ifdef CYBER_CORE
    BOOL iahepFound = FALSE;
    char iahepBuf[MAX_STRING_LENGTH];
    char errStr[MAX_STRING_LENGTH];

    IO_ReadString(node->nodeId,
                  ANY_ADDRESS,
                  nodeInput,
                  "IAHEP-NODE-TYPE",
                  &iahepFound,
                  iahepBuf);

    if (iahepFound)
    {
        if (strcmp(iahepBuf,"RED") && strcmp(iahepBuf,"BLACK")
           && strcmp(iahepBuf,"IAHEP"))
        {
            sprintf(errStr,"Invalid Configuration.IAHEP-NODE-TYPE Node [%d]",
                    node->nodeId);
            ERROR_Assert(FALSE, errStr);
        }

        if (!strcmp(iahepBuf, "RED"))
        {
            ip->iahepEnabled = TRUE;
            ip->iahepData = (IAHEPData*) MEM_malloc(sizeof(IAHEPData));
            memset(ip->iahepData, 0, sizeof(IAHEPData));
            ip->iahepData->nodeType = RED_NODE;
            IAHEPInit(node, nodeInput);
        }
        else if (!strcmp(iahepBuf, "IAHEP"))
        {
            ip->iahepEnabled = TRUE;
            ip->iahepData = (IAHEPData*) MEM_malloc(sizeof(IAHEPData));
            memset(ip->iahepData, 0, sizeof(IAHEPData));
            ip->iahepData->nodeType = IAHEP_NODE;
            IAHEPInit(node, nodeInput);

            BOOL useICMP = false;

            IO_ReadBool(
                node->nodeId,
                ANY_ADDRESS,
                nodeInput,
                "ICMP",
                &retVal,
                &useICMP);

            if (retVal && useICMP)
            {
                ERROR_ReportError("Invalid Configuration: ICMP must be set to NO when using IAHEP");
            }
        }
        else if (!strcmp(iahepBuf, "BLACK"))
        {
            ip->iahepEnabled = TRUE;
            ip->iahepData = (IAHEPData*) MEM_malloc(sizeof(IAHEPData));
            memset(ip->iahepData, 0, sizeof(IAHEPData));
            ip->iahepData->nodeType = BLACK_NODE;
            IAHEPInit(node, nodeInput);
        }
    }
#endif // CYBER_CORE

#ifdef ADDON_BOEINGFCS
    for (i = 0; i < node->numberInterfaces; i++)
    {
        ip->interfaceInfo[i]->inReceiveOnlyWnw = FALSE;
        ip->interfaceInfo[i]->receiveOnlyActivated= FALSE;
        ModeCesWnwReceiveOnlyInit(node, i, nodeInput);
    }
#endif

#ifdef ADDON_DB
    ip->ipMulticastNetSummaryStats = new StatsDBMulticastNetworkSummaryContent();
#endif
}

//-----------------------------------------------------------------------------
// Layer function
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// this poriton of code for ATM (Start)
//-----------------------------------------------------------------------------

// /**
// FUNCTION :: Atm_IsMyPacket
// LAYER    :: Network
// PURPOSE ::  Check if this is own packet
// PARAMETERS ::
// + node : Node* : pointer to node.
// + destAddress : NodeAddress : Destination Address
// + incomingInterface : int : Incomming interface.
// RETURN :: BOOL : TRUE or FALSE
// **/
static  //inline//
BOOL Atm_IsMyPacket(Node *node,
                    NodeAddress destAddress,
                    int incomingInterface)
{
    int i;
    if (destAddress == ANY_DEST)
    {
        return TRUE;
    }

    // If the destination of the packet is end system.
    NodeAddress ipAddr = MAPPING_GetInterfaceAddressForInterface(
                                    node, node->nodeId, incomingInterface);

    if (destAddress == ipAddr)
    {
        return TRUE;
    }

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (destAddress == NetworkIpGetInterfaceAddress(node, i)
            || destAddress ==
                NetworkIpGetInterfaceBroadcastAddress(node, i))
        {
            return TRUE;
        }
    }

    // Now check the logical Interface
    const LogicalSubnet* myLogicalSubnet =
            AtmGetLogicalSubnetFromNodeId( node,
            node->nodeId, DEFAULT_INTERFACE);

    if (myLogicalSubnet->ipAddress == destAddress)
    {
        return TRUE;
    }

    return FALSE;
}


// /**
// FUNCTION :: Atm_RouteThePacketUsingLookupTable
// LAYER    :: Network
// PURPOSE ::  Routs the packet using lookup table.
// PARAMETERS ::
// + node : Node* : pointer to node.
// + destAddr : NodeAddress : Destination Address
// + outIntf : int* : Outgoing interface.
// + nextHop : NodeAddress* : Next hop
// RETURN :: void : None
// **/

void Atm_RouteThePacketUsingLookupTable(Node* node,
                                        NodeAddress destAddr,
                                        int* outIntf,
                                        NodeAddress* nextHop)
{
    int i;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;


    // first check if I am the destination
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->ipAddress == destAddr)
        {
            // I am the destination
            *outIntf = 0;
            *nextHop = destAddr;
            return;
        }
    }

    // if not found
    // searching for matching entry in Network forwarding Table
    NetworkGetInterfaceAndNextHopFromForwardingTable(node,
        destAddr, outIntf, nextHop);

    if (*nextHop == 0)
    {
        *nextHop = destAddr;
    }
}


// /**
// FUNCTION :: NetworkIpReceivePacketFromAdaptationLayer
// LAYER    :: Network
// PURPOSE ::  Process packet after receiving from adaptation layer
// PARAMETERS ::
// + node : Node* : Pointer to node.
// + msg : Message * : Pointer to message.
// + incomingInterface : int : Incomming interface.
// RETURN :: void : None
// **/
void NetworkIpReceivePacketFromAdaptationLayer(
    Node *node,
    Message *msg,
    int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    IpHeaderType* ipHeader = (IpHeaderType *) msg->packet;
    ip->stats.ipInReceives++;
    ip->stats.ipRecvdPktFromOtherNetwork++ ;

    if (node->networkData.networkStats)
    {
        ip->newStats->AddPacketReceivedFromMacDataPoints(
            node,
            msg,
            StatsApiAddrType(node, msg),
            incomingInterface,
            IsDataPacket(msg, ipHeader));
    }

    if (Atm_IsMyPacket(node, ipHeader->ip_dst, incomingInterface))
    {
        IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
        NodeAddress src = ipHeader->ip_src;
        NodeAddress dst = ipHeader->ip_dst;
        TosType tos = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);

        MESSAGE_RemoveHeader(node, msg, IpHeaderSize(ipHeader), TRACE_IP);

        if (ipHeader->ip_p == IPPROTO_UDP)
        {
            SendToUdp(node, msg, tos, src, dst, incomingInterface);
        }
        else if (ipHeader->ip_p == IPPROTO_TCP)
        {
            BOOL aCongestionExperienced = FALSE;

            if (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) & IPTOS_CE)
            {
                aCongestionExperienced = TRUE;
            }

            SendToTcp(node,
                msg,
                tos,
                src,
                dst,
                aCongestionExperienced);
        }
        else
        {
            printf(" Node %u receive Erronious pkt \n", node->nodeId);
        }

        return;
    }

    int outgoingInterface;
    NodeAddress nextHop;

    Atm_RouteThePacketUsingLookupTable(node,
        ipHeader->ip_dst,
        &outgoingInterface,
        &nextHop);

    if (nextHop != (unsigned) NETWORK_UNREACHABLE)
    {
        QueueUpIpFragmentForMacLayer(node, msg,
            outgoingInterface, nextHop, incomingInterface);
    }
    else
    {
        // Increment stat for number of IP packets discarded because no
        // route could be found.
        // STATS DB CODE
#ifdef ADDON_DB
        HandleNetworkDBEvents(
            node,
            msg,
            incomingInterface,
            "NetworkPacketDrop",
            "No Route",
            0,
            0,
            0,
            0);

        IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
        if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
        {
            ip->stats.aggregateStats->ipMulticastOutNoRoutes++ ;
        }else ip->stats.aggregateStats->ipUnicastOutNoRoutes++ ;
#endif
        if (ip->isIcmpEnable &&
        (icmp->hostUnreachableEnable || icmp->networkUnreachableEnable))
        {
            unsigned short icmpCode = 0;
            BOOL ICMPErrorMsgCreated = FALSE;
            if (NetworkIpGetInterfaceIndexForNextHop(node,
                                              ipHeader->ip_dst) == -1 &&
                                          icmp->networkUnreachableEnable)
            {
                icmpCode = ICMP_NETWORK_UNREACHABLE;
                ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                      msg,
                                      ipHeader->ip_src,
                                      incomingInterface,
                                      ICMP_DESTINATION_UNREACHABLE,
                                      icmpCode,
                                      0,
                                      0);
            }
            else if (NetworkIpGetInterfaceIndexForNextHop(node,
                                             ipHeader->ip_dst) != -1 &&
                                             icmp->hostUnreachableEnable)
            {
                icmpCode = ICMP_HOST_UNREACHABLE;
                ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                      msg,
                                      ipHeader->ip_src,
                                      incomingInterface,
                                      ICMP_DESTINATION_UNREACHABLE,
                                      icmpCode,
                                      0,
                                      0);
            }

            if (ICMPErrorMsgCreated)
            {
                if (icmpCode == ICMP_NETWORK_UNREACHABLE)
                {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src,
                                                                srcAddr);
                    printf("Node %d sending network unreachable message"
                           " to %s\n", node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpNetworkUnreacableSent)++;
                }
                else if (icmpCode == ICMP_HOST_UNREACHABLE)
                {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src,
                                                                srcAddr);
                    printf("Node %d sending host unreachable message"
                           " to %s\n", node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpHostUnreacableSent)++;
                }
            }
        }
        ip->stats.ipOutNoRoutes++;

    // Handling of new Stat API for collecting unicast and broadcast packets 
    // dropped seperately
        if (node->networkData.networkStats)
        {
            STAT_DestAddressType type;
            type = StatsApiAddrType(node, msg);
            if (type == STAT_Unicast)
            {
                ip->newStats->AddPacketDroppedNoRouteDataPointsUnicast(node);
            }
            else if (type == STAT_Multicast)
            {
                ip->newStats->AddPacketDroppedNoRouteDataPointsMulticast(node);
            }
            ip->newStats->AddPacketDroppedNoRouteDataPoints(node);
        }
        // Free message.
        MESSAGE_Free(node, msg);
    }
}

// added for gateway


// /**
// FUNCTION :: NetworkIpGatewayHandleIPPacket
// LAYER    :: Network
// PURPOSE ::  Tries to route and send the packet using
//             othertype of interface available to taht node
// PARAMETERS ::
// + node : Node* : Pointer to node.
// + msg : Message * : Pointer to message.
// RETURN :: void : None
// **/
static
void NetworkIpGatewayHandleIPPacket(Node* node, Message* msg)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    // Search for associated physical interface other than IP
    // attached with this node, handed over the packet to
    // associated Adaptation layer for processing

    // Presently this case is valid for ATM node i.e.
    // only other type of interface connected is ATM interface
    IpHeaderType* ipHdr = (IpHeaderType *)(msg->packet);

    // differentiate between control & data packet

    if ((ipHdr->ip_p == IPPROTO_UDP)
        || (ipHdr->ip_p == IPPROTO_TCP))
    {
        if ((ipHdr->ip_p == IPPROTO_UDP)
            && (IpHeaderGetTOS(ipHdr->ip_v_hl_tos_len) ==
            IPTOS_PREC_INTERNETCONTROL))
        {
            // It is a control packet
            // Control Packet must be confined within IP cloud
            // No need to send to ATM cloud

            MESSAGE_Free(node, msg);
            return;
        }

        // otherwise it is  a data packet
    }
    else
    {
        // It is a control packet
        // Control Packet must be confined within IP cloud
        // No need to send to ATM cloud

        MESSAGE_Free(node, msg);
        return;
    }

    // Now start processing for data packet

    // Search for associated Adaptation layer
    // And handed over the packet to that layer

    // At present only ATM adaptation layer available
    if (node->adaptationData.adaptationProtocol
        == ADAPTATION_PROTOCOL_NONE)
    {
#ifdef ADDON_DB
        // check iif any of my interface matches with gateway addr
        int gi = 0 ;
        for (gi = 0; gi < node->numberInterfaces; gi++)
        {
            if (ip->interfaceInfo[gi]->ipAddress == ip->defaultGatewayId)
            {
                break ;
            }
        }
        HandleNetworkDBEvents(
            node,
            msg,
            gi,
            "NetworkPacketDrop",
            "Adaptation Protocol Not Available",
            0,
            0,
            0,
            0);
#endif
        // so discard the packet
        MESSAGE_Free(node, msg);
        return;
    }

    // Handed over to adaptation layer
    ip->stats.ipSendPktToOtherNetwork++ ;

    ADAPTATION_ReceivePacketFromNetworkLayer(node, msg);
}


// /**
// FUNCTION :: NetworkIpRoutePacketThroughGateway
// LAYER    :: Network
// PURPOSE ::  Tries to route and send the packet using the node's
//              Configured Gateway.
// PARAMETERS ::
// + node : Node* : Pointer to node.
// + msg : Message * : Pointer to message.
// + incomingInterface : int : incoming interface of packet.
// RETURN :: void : None
// **/
static  //inline//
void NetworkIpRoutePacketThroughGateway(Node *node,
                                   Message *msg,
                                   int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    RouterFunctionType routerFunction = NULL;
    BOOL packetWasRouted = FALSE;
    IpHeaderType *ipHeader = (IpHeaderType *)MESSAGE_ReturnPacket(msg);

    int intfForGt;
    NodeAddress nxtHopForGt;
    int i;

    NodeAddress gatewayAddr = ip->defaultGatewayId;

    ip->stats.ipRoutePktThruGt++;

    // check if any of my interface matches with gateway addr
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->ipAddress == ip->defaultGatewayId)
        {
            NetworkIpGatewayHandleIPPacket(node, msg);
            return;
        }
    }

    // try to route packet towards gateway using router function

    routerFunction = NetworkIpGetRouterFunction(node,
        DEFAULT_INTERFACE);

    if (routerFunction)
    {
        (routerFunction)(node,
            msg,
            gatewayAddr,
            NetworkIpGetInterfaceAddress(node, DEFAULT_INTERFACE),
            &packetWasRouted);
    }

    // route the packet to gateway using forwarding table
    if (!packetWasRouted)
    {
        // Otherwise route the packet to gateway
        NetworkGetInterfaceAndNextHopFromForwardingTable(
            node,
            gatewayAddr,
            &intfForGt,
            &nxtHopForGt);

        if ((int) nxtHopForGt == NETWORK_UNREACHABLE)
        {
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                incomingInterface, // use incoming interface here
                "NetworkPacketDrop",
                "No Route",
                0,
                0,
                0,
                0);
#endif
            // gateway is not reachable from that node
            // Free message.


            if (ip->isIcmpEnable &&
            (icmp->hostUnreachableEnable || icmp->networkUnreachableEnable))
            {
                unsigned short icmpCode = 0;
                BOOL ICMPErrorMsgCreated = FALSE;
                if (NetworkIpGetInterfaceIndexForNextHop(node,
                                                  ipHeader->ip_dst) == -1 &&
                                              icmp->networkUnreachableEnable)
                {
                    icmpCode = ICMP_NETWORK_UNREACHABLE;
                    ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                          msg,
                                          ipHeader->ip_src,
                                          incomingInterface,
                                          ICMP_DESTINATION_UNREACHABLE,
                                          icmpCode,
                                          0,
                                          0);
                }
                else if (NetworkIpGetInterfaceIndexForNextHop(node,
                                                 ipHeader->ip_dst) != -1 &&
                                                 icmp->hostUnreachableEnable)
                {
                    icmpCode = ICMP_HOST_UNREACHABLE;
                    ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                          msg,
                                          ipHeader->ip_src,
                                          incomingInterface,
                                          ICMP_DESTINATION_UNREACHABLE,
                                          icmpCode,
                                          0,
                                          0);
                }

                if (ICMPErrorMsgCreated)
                {
                    if (icmpCode == ICMP_NETWORK_UNREACHABLE)
                    {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                        char srcAddr[MAX_STRING_LENGTH];
                        IO_ConvertIpAddressToString(ipHeader->ip_src,
                                                                    srcAddr);
                        printf("Node %d sending network unreachable message"
                               " to %s\n", node->nodeId, srcAddr);
#endif
                        (icmp->icmpErrorStat.icmpNetworkUnreacableSent)++;
                    }
                    else if (icmpCode == ICMP_HOST_UNREACHABLE)
                    {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                        char srcAddr[MAX_STRING_LENGTH];
                        IO_ConvertIpAddressToString(ipHeader->ip_src,
                                                                    srcAddr);
                        printf("Node %d sending host unreachable message"
                               " to %s\n", node->nodeId, srcAddr);
#endif
                        (icmp->icmpErrorStat.icmpHostUnreacableSent)++;
                    }
                }
            }
            MESSAGE_Free(node, msg);

            return;
        }
        else if (nxtHopForGt == 0)
        {
            // gateway resides in attached network

            NetworkIpSendPacketOnInterface(
                node,
                msg,
                incomingInterface,
                intfForGt,
                gatewayAddr);
        }
        else
        {
            // next hop to gateway is found

            NetworkIpSendPacketOnInterface(node,
                msg,
                incomingInterface,
                intfForGt,
                nxtHopForGt);
        }
    }   // end of if packet was not routed
}

// end for gateway

//-----------------------------------------------------------------------------
// this poriton of code for ATM (End)
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpLayer
// PURPOSE      Handle IP layer events, incoming messages and messages
//              sent to itself (timers, etc.).
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message.
// RETURN       None.
//----------------------------------------------------------------------------

void
NetworkIpLayer(Node *node, Message *msg)
{
    switch (msg->protocolType)
    {
        case GROUP_MANAGEMENT_PROTOCOL_IGMP:
        {
            IgmpLayer(node, msg);
            break;
        }
        case NETWORK_PROTOCOL_ICMP:
        {
            NetworkIcmpHandleProtocolEvent(node, msg);
            break;
        }
        case LINK_MANAGEMENT_PROTOCOL_CBQ:
        {
            CBQResourceManagerHandleProtocolEvent(node, msg);
            break;
        }
        case NETWORK_PROTOCOL_IP:
        {
            switch (msg->eventType)
            {
                // STATS DB CODE

                case MSG_NETWORK_Backplane:
                {
                    NetworkIpReceiveFromBackplane(node, msg);
                    MESSAGE_Free(node, msg);
                    break;
                }
                case MSG_NETWORK_FromTransportOrRoutingProtocol:
                {
                    int *outgoingInterface = (int *)MESSAGE_ReturnInfo(msg);

                    RoutePacketAndSendToMac(node,
                                            msg,
                                            CPU_INTERFACE,
                                            *outgoingInterface,
                                            ANY_IP);
                    break;
                }
                case MSG_NETWORK_FromAdaptation:
                {
                    int intfId = ((AdaptationToNetworkInfo *)
                                 MESSAGE_ReturnInfo(msg))->intfId;

                    NetworkIpReceivePacketFromAdaptationLayer(
                        node, msg, intfId);

                    break;
                }
                case MSG_NETWORK_DelayedSendToMac:
                {
                    ProcessDelayedSendToMac(node, msg);
                    break;
                }
                
                case MSG_NETWORK_DelayFunc:
                {
                    NodeAddress srcNodeId;
                    NodeAddress dstNodeId;
                  
                    IpHeaderType * ipHeader = (IpHeaderType *) 
                        MESSAGE_ReturnPacket(msg);
                    
                    if (!NetworkIpIsMulticastAddress(node, ipHeader->ip_dst) && 
                        (ipHeader->ip_dst != ANY_DEST))
                    {
                        int interfaceIndex = NetworkIpGetInterfaceIndexFromAddress
                            (node, ipHeader->ip_dst);
                        ERROR_Assert(node->partitionId == 
                            node->partitionData->partitionId,
                            "The node's partition Id does not match with the current"
                            "partition we are on");
                        DeliverPacket(node, msg, interfaceIndex, ipHeader->ip_src);
                    }
                    else
                    {
                        Node* tmpNode = node->partitionData->firstNode;
                        srcNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                            node,
                            ipHeader->ip_src);
                        
                        int interfaceIndex;
                        if (srcNodeId != INVALID_MAPPING)
                        {
                            //Check for multicast group
                            while (tmpNode)
                            {
                                if (tmpNode->nodeId != srcNodeId)
                                {
                                    if (NetworkIpIsMulticastAddress(tmpNode, 
                                        ipHeader->ip_dst))
                                    {
                                        if (NetworkIpIsPartOfMulticastGroup
                                            (tmpNode, ipHeader->ip_dst))
                                        {
                                            
#ifdef EXATA
                                            //Check which one is mapped
                                            interfaceIndex = 0;
                                            if (tmpNode->numberInterfaces > 1)
                                            {
                                                
                                                while (!(((tmpNode->macData[interfaceIndex]) &&
                                                ((tmpNode->macData[interfaceIndex]->isIpneInterface) ||
                                                ((node->partitionData->rrInterface->GetReplayMode()) && 
                                                (node->macData[interfaceIndex]->isReplayInterface)))) ||
                                                (interfaceIndex < tmpNode->numberInterfaces)))
                                                {
                                                    interfaceIndex++;
                                                }
                                            }
                                    
#else
                                            //we send it on the destination's 
                                            //Interface 0
                                            interfaceIndex = 0;
#endif
                              
                                            DeliverPacket(tmpNode, 
                                                MESSAGE_Duplicate(tmpNode, msg), 
                                                interfaceIndex, ipHeader->ip_src);
                                        }
                                    }
                                    else // It is a broadcast packet
                                    {
                                        Node* srcNode;
                                        if (PARTITION_ReturnNodePointer(node->partitionData,
                                            &srcNode, srcNodeId, TRUE))
                                        {
                                            BOOL isInSubnet = FALSE;
                                            int dstinterfaceIndex = 0;
                                            while (!isInSubnet &&  
                                                dstinterfaceIndex < tmpNode->numberInterfaces)
                                            {
                                                isInSubnet = NetworkIpCheckIpAddressIsInSameSubnet
                                                    (tmpNode, dstinterfaceIndex, ipHeader->ip_src);
                                                if (!isInSubnet)
                                                {
                                                    dstinterfaceIndex++;
                                                }
                                            }

                                            if (isInSubnet)
                                            {
                                                DeliverPacket(tmpNode, 
                                                    MESSAGE_Duplicate(tmpNode, msg), 
                                                    dstinterfaceIndex, ipHeader->ip_src);
                                            }
                                        }
                                        else
                                        {
                                            ERROR_ReportError("Not found source node\n");
                                        }
                                    }
                                }
                                tmpNode = tmpNode->nextNodeData;
                            }
                            
                            MESSAGE_Free(node, msg);
                        }
                        else
                        {
                            MESSAGE_Free(node, msg);
                        }
                    }
                    break;
                }
                case MSG_NETWORK_JoinGroup:
                {
                    NodeAddress *mcastAddr = (NodeAddress *)
                                             MESSAGE_ReturnInfo(msg);

                    NodeAddress groupAddr = *mcastAddr;
                    NetworkIpAddToMulticastGroupList(node, *mcastAddr);

#ifdef ADDON_DB
                    STATSDB_SendMulticastGroupInfo(node, msg, groupAddr);

#endif

#ifdef WIRELESS_LIB
                    if (NetworkIpCheckMulticastRoutingProtocol(
                            node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE))
                    {
                        OdmrpJoinGroup(node, *mcastAddr);
                    }
#endif // WIRELESS_LIB

#ifdef ADDON_BOEINGFCS
                    RoutingCesSdrSendMulticastJoinMember(node, *mcastAddr);
#endif

                    MESSAGE_Free(node, msg);
                    break;
                }
                case MSG_NETWORK_LeaveGroup:
                {
                    NodeAddress *mcastAddr = (NodeAddress *)
                                             MESSAGE_ReturnInfo(msg);

                    NodeAddress groupAddr = *mcastAddr;
                    NetworkIpRemoveFromMulticastGroupList(node, *mcastAddr);

#ifdef ADDON_DB
                    STATSDB_SendMulticastGroupInfo(node, msg, groupAddr);

#endif

#ifdef WIRELESS_LIB
                    if (NetworkIpCheckMulticastRoutingProtocol(
                            node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE))
                    {
                        OdmrpLeaveGroup(node, *mcastAddr);
                    }
#endif // WIRELESS_LIB

#ifdef ADDON_BOEINGFCS
                    RoutingCesSdrSendMulticastRemoveMember(node, *mcastAddr);
#endif

                    MESSAGE_Free(node, msg);
                    break;
                }
#ifdef ENTERPRISE_LIB
                case MSG_NETWORK_AccessList:
                {
                    AccessListHandleEvent(node, msg);
                    break;
                }
#endif // ENTERPRISE_LIB
#ifdef CYBER_CORE
                case MSG_NETWORK_IPsec:
                {
                    IPsecHandleEvent(node, msg);
                    break;
                }
#endif // CYBER_CORE
                case MSG_NETWORK_Ip_QueueAgingTimer:
#ifdef ADDON_BOEINGFCS
        case MSG_NETWORK_CES_MI_QueueAgingTimer:
#endif
                {
                    QUEUE_HandleEvent(node, msg);
                    break;
                }
#ifdef CYBER_CORE
                case MSG_NETWORK_IAHEP:
                {
                    IAHEPSendRecvPktsWithDelay (node, msg);
                    break;
                }
                case MSG_NETWORK_EmptyBroadcastMapping:
                {
                    NetworkIpRemoveBroadcastForwardMappingEntries(node, msg);
                    break;
                }
#endif // CYBER_CORE
#ifdef ADDON_DB
                case MSG_STATS_MULTICAST_InsertSummary:
                {
                    StatsDb* db = node->partitionData->statsDb;

                    //multicast network summary handling
                    // Check if the Table exists.
                    if (!db || !db->statsSummaryTable ||
                      !db->statsSummaryTable->createMulticastNetSummaryTable)
                    {
                        MESSAGE_Free(node, msg);
                        break;
                    }

                    HandleStatsDBIpMulticastNetSummaryTableInsertion(node);

                    //resend the timer message again
                    MESSAGE_Send(node,
                                 msg,
                                 db->statsSummaryTable->summaryInterval);

                    break;
                }
#endif
                default:
                    ERROR_ReportError("Invalid switch value");
            }//switch//

            break;
        }

#ifdef WIRELESS_LIB
        case ROUTING_PROTOCOL_AODV:
        {
            AodvHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_DYMO:
        {
            DymoHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_DSR:
        {
            DsrHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_FSRL:
        {
            FsrlHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_LAR1:
        {
            Lar1HandleCheckTimeoutAlarm(node, msg);
            break;
        }
        case MULTICAST_PROTOCOL_ODMRP:
        {
            OdmrpHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_BRP:
        {
            BrpProcessEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_ZRP:
        {
            ZrpProcessEvent(node,msg);
            break;
        }
        case ROUTING_PROTOCOL_IARP:
        {
            IarpProcessEvent(node,msg);
            break;
        }
        case ROUTING_PROTOCOL_IERP:
        {
            IerpProcessEvent(node,msg);
            break;
        }
        case NETWORK_PROTOCOL_NDP:
        {
            NdpHandleProtocolEvent(node, msg);
            break;
        }
#endif // WIRELESS_LIB

#ifdef ADDON_BOEINGFCS
        case MI_CES_NM:
        {
            MICesNmHandleProtocolEvent(node, msg);
            break;
        }
        case NETWORK_CES_REGION:
        {
            NetworkCesRegionHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_CES_MALSR:
        {
            RoutingCesMalsrHandleProtocolEvent(node, msg);
            break;
        }
        case MI_MULTICAST_MESH:
        {
            MiCesMulticastMeshHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_CES_ROSPF:
        {
            RoutingCesRospfHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_CES_MPR:
       {
               RoutingCesMprHandleProtocolEvent(node,msg);
               break;
       }
       case NETWORK_PROTOCOL_NETWORK_CES_INC_SINCGARS:
       {
           NetworkCesIncSincgarsHandleProtocolEvent(node, msg);
           break;
       }
       case ROUTING_PROTOCOL_CES_SDR:
       {
           RoutingCesSdrHandleProtocolEvent(node, msg);
           break;
       }
       case NETWORK_PROTOCOL_CES_EPLRS:
       {
           NetworkCesIncEplrsProcessEvent(node, msg);
           break;
       }
#endif
#ifdef ADDON_MA
       case APP_MA_INTERNAL_ROUTING:
       {
           MA_Handle_Bytestream(node, msg);
           break;
       }
#endif
#ifdef ADDON_NGCNMS
       case NETWORK_PROTOCOL_NGC_HAIPE:
       {
           NetworkNgcHaipeHandleProtocolEvent(node, msg);
           break;
       }
#endif

#ifdef ENTERPRISE_LIB
        case NETWORK_ROUTE_REDISTRIBUTION:
        {
            RouteRedistributionLayer(node,msg);
            break;
        }
        case NETWORK_PROTOCOL_MOBILE_IP:
        {
            MobileIpLayer(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_OSPFv2:
        {
            Ospfv2HandleRoutingProtocolEvent(node, msg);
            break;
        }
        case MULTICAST_PROTOCOL_DVMRP:
        {
            RoutingDvmrpHandleProtocolEvent(node, msg);
            break;
        }
        case MULTICAST_PROTOCOL_PIM:
        {
            RoutingPimHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_IGRP:
        {
            IgrpHandleProtocolEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_EIGRP:
        {
            EigrpHandleProtocolEvent(node, msg);
            break;
        }
#endif // ENTERPRISE_LIB

#ifdef MILITARY_RADIOS_LIB
        case ROUTING_PROTOCOL_ODR:
        {
            OdrHandleProtocolEvent(node, msg);
            break;
        }
        case NETWORK_PROTOCOL_EPLRS:
        {
            EplrsProcessEvent(node, msg);
            break;
        }
        case ROUTING_PROTOCOL_SDR:
        {
            SdrHandleProtocolEvent(node, msg);
            break;
        }
#endif // MILITARY_RADIOS_LIB
#ifdef CYBER_CORE
        case NETWORK_PROTOCOL_ISAKMP:
        {
            ISAKMPHandleProtocolEvent(node, msg);
            break;
        }
#endif // CYBER_CORE

#ifdef CYBER_LIB

        case ROUTING_PROTOCOL_ANODR:
        {
            AnodrHandleProtocolEvent(node, msg);
            break;
        }

        case NETWORK_PROTOCOL_SECURENEIGHBOR:
        {
            SecureneighborHandleProtocolEvent(node, msg);
            break;
        }

        case NETWORK_PROTOCOL_ATTACK:
        {
            ATTACK_ProcessEvent(node, msg);
            break;
        }

        //case NETWORK_PROTOCOL_SECURECOMMUNITY:
        //{
        //  SecureCommunityHandleProtocolEvent(node, msg);
        //  break;
        //}
#endif // CYBER_LIB
#ifdef ADDON_MAODV
        case MULTICAST_PROTOCOL_MAODV:
        {
            MaodvHandleProtocolEvent(node, msg);
            break;
        }
#endif // ADDON_MAODV
        case ROUTING_PROTOCOL_ALL:
        {
            ERROR_Assert(FALSE, "IP event error");
            //HandleSpecialMacLayerStatusEvents(node, msg);
            break;
        }
//InsertPatch NETWORK_IP_LAYER
        default:
            ERROR_ReportError("Invalid switch value");
    }//switch//
}

//-----------------------------------------------------------------------------
// Finalize function
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpFinalize()
// PURPOSE      Finalize function for the IP model.  Finalize functions
//              for all network-layer IP protocols are called here.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//
// NOTES        All network-layer models are also finalized here.
//-----------------------------------------------------------------------------

void
NetworkIpFinalize(Node *node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *schedulerPtr = NULL;
    int i = 0;

#ifdef ADDON_BOEINGFCS
    // should be first because sincgars is really a data link protocol with
    // network like capabilities. So while it is implemented at the
    // network layer, it should be considered a data link protocol.
    if (ip->networkCesIncSincgarsData)
    {
        NetworkCesIncSincgarsFinalize(node);
    }
    if (ip->networkCesIncEplrsData)
    {
        NetworkCesIncEplrs_NodeFinalize(node);
        NetworkCesIncEplrs_Finalize();
    }

#endif

#ifdef MILITARY_RADIOS_LIB
    if (ip->eplrsData)
    {
        Eplrs_NodeFinalize(node);
        Eplrs_Finalize();
    }
#endif // MILITARY_RADIOS_LIB
    // NetworkIpLoopbackForwardingTableDisplay(node);
    //NetworkPrintForwardingTable(node);

    if (!node->switchData)
    {
        if (ip->isIgmpEnable == TRUE)
        {
            IgmpFinalize(node);
        }

        if (ip->isIcmpEnable == TRUE)
        {
            NetworkIcmpFinalize(node);
        }
    }

#ifdef ENTERPRISE_LIB
    // Finalize for route map
    RouteMapFinalize(node);

    if (ip->isEdgeRouter == TRUE)
    {
        DIFFSERV_MFTrafficConditionerFinalize(node);
    }

    if (ip->mobileIpStruct)
    {
        MobileIpFinalize(node);
    }

#endif // ENTERPRISE_LIB

#ifdef WIRELESS_LIB
    if (ip->isNdpEnable)
    {
        NdpFinalize(node);
    }
#endif // WIRELESS_LIB

#ifdef ADDON_BOEINGFCS
    MICesNmFinalize(node);

    NetworkCesRegionFinalize(node);

    if (ip->routingCesMalsrData)
    {
        RoutingCesMalsrFinalize(node);
    }

    if (ip->networkCesSdrData)
    {
        RoutingCesSdrFinalize(node);
    }
    if (ip->multicastMeshData)
    {
        MiCesMulticastMeshFinalize(node);
    }

#endif

#ifdef ADDON_NGCNMS
    if (ip->haipeData)
    {
        NetworkNgcHaipeFinalize(node);
    }
#endif

#ifdef MILITARY_RADIOS_LIB
    if (ip->sdrData)
    {
        SdrFinalize(node);
    }
#endif

#ifdef CYBER_LIB
    if (ip->isSecureneighborEnabled)
    {
        SecureneighborFinalize(node);
    }

    //if (ip->isSecureCommunityEnabled)
    //{
    //    SecureCommunityFinalize(node);
    //}
#endif // CYBER_LIB

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->isVirtualInterface == FALSE && !node->switchData)
        {
            TunnelFinalize(node, i);
        }
#ifdef ADDON_BOEINGFCS
        if (ip->interfaceInfo[i]->useRoutingCesMpr) {
            RoutingCesMprFinalize(node);
        }

        if (ModeCesWnwReceiveOnlyEnabled(node, i))
        {
            ModeCesWnwReceiveOnlyFinalize (node, i);
        }
#endif // ADDON_BOEINGFCS

        if (!node->switchData)
        {
            switch (NetworkIpGetUnicastRoutingProtocolType(node, i))
            {
                case MULTICAST_PROTOCOL_STATIC:
                {
                    RoutingMulticastStaticFinalize(node);
                    break;
                }
#ifdef ADDON_BOEINGFCS
                case NETWORK_CES_REGION:
                {
                    NetworkCesRegionFinalize(node);
                    break;
                }
#endif // ADDON_BOEINGFCS
#ifdef WIRELESS_LIB
                case ROUTING_PROTOCOL_LAR1:
                {
                    Lar1Finalize(node);
                    break;
                }
                case ROUTING_PROTOCOL_AODV:
                {
                    AodvFinalize(node, i, NETWORK_IPV4);
                    break;
                }
                case ROUTING_PROTOCOL_DYMO:
                {
                    DymoFinalize(node, i, NETWORK_IPV4);
                    break;
                }
                case ROUTING_PROTOCOL_DSR:
                {
                    DsrFinalize(node);
                    break;
                }
                case ROUTING_PROTOCOL_FSRL:
                {
                    FsrlFinalize(node);
                    break;
                }
                case ROUTING_PROTOCOL_STAR:
                {
                    StarFinalize(node);
                    break;
                }
                case ROUTING_PROTOCOL_BRP:
                {
                    BrpFinalize(node);
                    break;
                }
                case ROUTING_PROTOCOL_ZRP:
                {
                    ZrpFinalize(node);
                    break;
                }
                case ROUTING_PROTOCOL_IARP:
                {
                    IarpFinalize(node);
                    break;
                }
                case ROUTING_PROTOCOL_IERP:
                {
                    IerpFinalize(node);
                    break;
                }
#endif // WIRELESS_LIB
#ifdef ENTERPRISE_LIB
                case ROUTING_PROTOCOL_OSPFv2:
                {
                    Ospfv2Finalize(node);
                    break;
                }
                case ROUTING_PROTOCOL_IGRP:
                {
                    IgrpFinalize(node);
                    break;
                }
                case ROUTING_PROTOCOL_EIGRP:
                {
                    EigrpFinalize(node);
                    break;
                }
#endif // ENTERPRISE_LIB
#ifdef MILITARY_RADIOS_LIB
                case ROUTING_PROTOCOL_ODR:
                {
                    OdrFinalize(node);
                    break;
                }
#endif
#ifdef CYBER_LIB
                case ROUTING_PROTOCOL_ANODR:
                {
                    AnodrFinalize(node);
                    break;
                }
#endif // CYBER_LIB
                case ROUTING_PROTOCOL_NONE:
                {
                    // The user explicitly indicated that this node is not
                    // running a network-layer routing protocol.
                    break;
                }

//InsertPatch FINALIZE_FUNCTION

                default:

                    // This routing protocol is not at the network layer
                    // (it does its finalization at its own layer), so just
                    // break.

                    break;

            }//switch//
        }
    }//for//

    if (!node->switchData)
    {
        for (i = 0; i < node->numberInterfaces; i++)
        {
            switch (ip->interfaceInfo[i]->multicastProtocolType)
            {
#ifdef WIRELESS_LIB
                case MULTICAST_PROTOCOL_ODMRP:
                {
                    OdmrpFinalize(node);
                    break;
                }
#endif // WIRELESS_LIB

#ifdef ENTERPRISE_LIB
                case MULTICAST_PROTOCOL_DVMRP:
                {
                    RoutingDvmrpFinalize(node);
                    break;
                }
                case MULTICAST_PROTOCOL_MOSPF:
                {
                    MospfFinalize(node);
                    break;
                }
                case MULTICAST_PROTOCOL_PIM:
                {
                    RoutingPimFinalize(node);
                    break;
                }
#endif // ENTERPRISE_LIB

#ifdef ADDON_MAODV
                case MULTICAST_PROTOCOL_MAODV:
                {
                    MaodvFinalize(node);
                    break;
                }
#endif // ADDON_MAODV

                default:
                {
                    break;
                }
            }
        }
    }

    if (node->networkData.networkStats == TRUE)
    {
        NetworkIpPrintStats(node);
    }

#if 0
//#ifdef ADDON_BOEINGFCS
    if (ip->networkSecurityCesHaipeEnabled)
    {
        NetworkSecurityCesHaipeFinalize(node);
    }
#endif

#ifdef CYBER_CORE
    if (ip->iahepEnabled)
    {
        IAHEPFinalize(node);
    }


    // Print stats for IPsec
    if (ip->isIPsecEnabled == TRUE)
    {
        IPsecFinalize(node);
    }
#endif // CYBER_CORE
#ifdef ENTERPRISE_LIB
    // Print access list statistics
    if (ip->isACLStatOn == TRUE)
    {
        AccessListFinalize(node);
    }

    // Print access list statistics
    if (ip->isPBRStatOn == TRUE)
    {
        PbrFinalize(node);
    }

    // Print Route Redistribute statistics
    if (ip->isRtRedistributeStatOn)
    {
        // Finalize for Route Redistribution
        RouteRedistributeFinalize(node);
    }
#endif // ENTERPRISE_LIB

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->isVirtualInterface)
        {
            continue;
        }
        int j;

        schedulerPtr = ip->interfaceInfo[i]->scheduler;

        schedulerPtr->finalize(node, "Network", i, "IP");

        for (j = 0; j < schedulerPtr->numQueue(); j++)
        {
            schedulerPtr->invokeQueueFinalize(node, "Network", i, j, "IP");
        }

        // Print INPUT queue statistics
        if (ip->backplaneThroughputCapacity !=
            NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT)
        {
            Scheduler* inputSchedulerPtr =
                ip->interfaceInfo[i]->inputScheduler;

            inputSchedulerPtr->finalize(node, "Network", i, "IP", "Input");

            for (j = 0; j < inputSchedulerPtr->numQueue(); j++)
            {
                inputSchedulerPtr->invokeQueueFinalize(
                                    node, "Network", i, j, "IP", "Input");
            }
        }
#ifdef CYBER_CORE
        // Print stats for ISAKMP
        if (ip->interfaceInfo[i]->isISAKMPEnabled == TRUE)
        {
            ISAKMPFinalize(node, i);
        }
#endif // CYBER_CORE
    }

    // Print CPU queue statistics
    if (ip->backplaneThroughputCapacity !=
        NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT)
    {
        Scheduler* cpuSchedulerPtr = ip->cpuScheduler;

        cpuSchedulerPtr->finalize(node, "Network", 0, "IP", "Cpu");
        cpuSchedulerPtr->invokeQueueFinalize(
                            node, "Network", 0, 0, "IP", "Cpu");
    }
#ifdef CYBER_LIB
    // Finalize per-node and per-interface security information
    for (i = 0; i < node->numberInterfaces; i++)
    {
        IpInterfaceInfoType* intf = (IpInterfaceInfoType*)ip->interfaceInfo[i];

#ifdef DO_ECC_CRYPTO
        // free the key
        for (int j=0; j<12; j++)
        {
            mpi_free(intf->eccKey[j]);
        }
#endif
        // free the certificate
        if (intf->certificate != NULL)
        {
            MEM_free(intf->certificate);
        }

        // close the eavesdrop file
        if (intf->eavesdropFile != NULL)
        {
            fclose(intf->eavesdropFile);
        }

        // close the audit file
        if (intf->auditFile != NULL)
        {
            fclose(intf->auditFile);
        }
    }
#endif // CYBER_LIB

#if ADDON_DB

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->metaData != NULL)
        {
            delete ip->interfaceInfo[i]->metaData;
        }

    }
#endif
}

//-----------------------------------------------------------------------------
// Transport layer to IP, sends IP packets out to network
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpReceivePacketFromTransportLayer()
// PURPOSE      Called by transport layer protocols (UDP, TCP) to send
//              UDP datagrams and TCP segments using IP.  Simply calls
//              NetworkIpSendRawMessage().
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message from transport layer containing
//                  payload data (UDP datagram, TCP segment) for an
//                  IP packet. (IP header needs to be added)
//              NodeAddress sourceAddress
//                  Source IP address.
//                  See NetworkIpSendRawMessage() for special
//                  values.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int outgoingInterface
//                  outgoing interface to use to transmit packet.
//              TosType priority
//                  TOS of packet.
//              unsigned char protocol
//                  IP protocol number.
//              BOOL isEcnCapable
//                  Is this node ECN capable?
// RETURN       None.
//
// NOTES        Currently, the transport layer cannot specify the TTL;
//              the default TTL is used.
//-----------------------------------------------------------------------------

void
NetworkIpReceivePacketFromTransportLayer(
    Node *node,
    Message *msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    int outgoingInterface,
    TosType priority,
    unsigned char protocol,
    BOOL isEcnCapable,
    UInt8 ttl)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    ip->isPacketEcnCapable = isEcnCapable;

    NetworkIpSendRawMessage(
        node,
        msg,
        sourceAddress,
        destinationAddress,
        outgoingInterface,
        priority,
        protocol,
        ttl);
}

void
NetworkIpReceivePacketFromTransportLayer(
    Node *node,
    Message *msg,
    Address sourceAddress,
    Address destinationAddress,
    int outgoingInterface,
    TosType priority,
    unsigned char protocol,
    BOOL isEcnCapable,
    UInt8 ttl)
{

    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    ip->isPacketEcnCapable = isEcnCapable;

#ifdef CELLULAR_LIB
    if ((node->networkData.networkProtocol == IPV4_ONLY ||
         node->networkData.networkProtocol == DUAL_IP ||
         node->networkData.networkProtocol == GSM_LAYER3 ||
         node->networkData.networkProtocol == CELLULAR) &&
        (sourceAddress.networkType == NETWORK_IPV4) &&
        (destinationAddress.networkType == NETWORK_IPV4))
#elif UMTS_LIB
    if ((node->networkData.networkProtocol == IPV4_ONLY ||
         node->networkData.networkProtocol == DUAL_IP ||
         node->networkData.networkProtocol == CELLULAR) &&
        (sourceAddress.networkType == NETWORK_IPV4) &&
        (destinationAddress.networkType == NETWORK_IPV4))
#else
    if (((node->networkData.networkProtocol == IPV4_ONLY ) ||
            (node->networkData.networkProtocol == DUAL_IP))
        && (sourceAddress.networkType == NETWORK_IPV4)
        && (destinationAddress.networkType == NETWORK_IPV4))
#endif // CELLULAR_LIB
    {
        NetworkIpSendRawMessage(
            node,
            msg,
            GetIPv4Address(sourceAddress),
            GetIPv4Address(destinationAddress),
            outgoingInterface,
            priority,
            protocol,
            ttl);
    }
    else if (((node->networkData.networkProtocol == IPV6_ONLY) ||
                (node->networkData.networkProtocol == DUAL_IP))
             && (sourceAddress.networkType == NETWORK_IPV6)
             && (destinationAddress.networkType == NETWORK_IPV6))
    {
        Ipv6SendRawMessage(
                node,
                msg,
                GetIPv6Address(sourceAddress),
                GetIPv6Address(destinationAddress),
                outgoingInterface,
                priority,
                protocol,
                                IPDEFTTL);
               // ttl);
    }
    else if ((node->networkData.networkProtocol == IPV4_ONLY) &&
        ((sourceAddress.networkType == NETWORK_ATM)
         || (destinationAddress.networkType == NETWORK_ATM)))
    {
        NodeAddress srcAddr;
        NodeAddress dstAddr;
        const LogicalSubnet* srcLogicalSubnet;
        const LogicalSubnet* dstLogicalSubnet;

        // If source is pure ATM node
        if (sourceAddress.networkType == NETWORK_ATM)
        {
            srcLogicalSubnet =
                AtmGetLogicalSubnetFromNodeId(
                node,
                sourceAddress.interfaceAddr.atm.ESI_pt1,
                DEFAULT_INTERFACE);

            srcAddr = srcLogicalSubnet->ipAddress;

            // destination is pure ATM node
            if (destinationAddress.networkType == NETWORK_ATM)
            {
                dstLogicalSubnet =
                    AtmGetLogicalSubnetFromNodeId(
                    node,
                    destinationAddress.interfaceAddr.atm.ESI_pt1,
                    DEFAULT_INTERFACE);

                dstAddr = dstLogicalSubnet->ipAddress;
            }
            else
            {
                dstAddr = destinationAddress.interfaceAddr.ipv4;
            }

            // Add dummy IP header
            NetworkIpAddHeader(
                node,
                msg,
                srcAddr,
                dstAddr,
                priority,
                protocol,
                ttl);

            // At present only ATM adaptation layer available
            if (node->adaptationData.adaptationProtocol
                == ADAPTATION_PROTOCOL_NONE)
            {
                // so discard the packet
                MESSAGE_Free(node, msg);
                return;
            }

            // Handed over to adaptation layer
            ip->stats.ipSendPktToOtherNetwork++ ;

            ADAPTATION_ReceivePacketFromNetworkLayer(node, msg);
            return;
        }
        else if (destinationAddress.networkType == NETWORK_ATM)
        {
            dstLogicalSubnet =
                AtmGetLogicalSubnetFromNodeId(
                node,
                destinationAddress.interfaceAddr.atm.ESI_pt1,
                DEFAULT_INTERFACE);

            dstAddr = dstLogicalSubnet->ipAddress;

            srcAddr = sourceAddress.interfaceAddr.ipv4;

            // Process as a simple IP node
            NetworkIpSendRawMessage(
                node,
                msg,
                srcAddr,
                dstAddr,
                outgoingInterface,
                priority,
                protocol,
                ttl);
        }
    }
    else
    {
        ERROR_ReportError("Invalid network type.\n");
    }
}


//-----------------------------------------------------------------------------
// Network layer to MAC layer, sends IP packets out to network
//-----------------------------------------------------------------------------

//
// FUNCTION     NetworkIpSendRawMessage()
// PURPOSE      Called by NetworkIpReceivePacketFromTransportLayer() to
//              send to send UDP datagrams, TCP segments using IP.  Also
//              called by network-layer routing protocols (AODV, OSPF,
//              etc.) to send IP packets.  This function adds an IP
//              header and calls RoutePacketAndSendToMac().
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with payload data for IP packet.
//                  (IP header needs to be added)
//              NodeAddress sourceAddress
//                  Source IP address. (See notes)
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int outgoingInterface
//                  outgoing interface to use to transmit packet.
//              TosType priority
//                  TOS of packet.
//              unsigned char protocol
//                  IP protocol number.
//              unsigned ttl
//                  Time to live.
//                  See AddIpHeader() for special values.
// RETURN       None.
//
// NOTES        If sourceAddress is ANY_IP, lets IP assign the source
//              address (depends on the route).
//

void
NetworkIpSendRawMessage(
    Node *node,
    Message *msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    int outgoingInterface,
    TosType priority,
    unsigned char protocol,
    unsigned ttl)
{
    NodeAddress newSourceAddress;
    int interfaceIndex;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    // We shouldn't be getting the outgoing interface like this.
    // NetworkGetInterfaceIndexForDestAddress() actually checks the
    // lookup table, and we do this is RoutePacketAndSendToMac().
    // We should do all the routing in RoutePacketAndSendToMac(). -Jeff
    if (outgoingInterface == ANY_INTERFACE)
    {
        // Trying to figure the source address and outgoing interface to use
        if (sourceAddress != ANY_IP)
        {
            interfaceIndex =
                   NetworkIpGetInterfaceIndexFromAddress(node, sourceAddress);

            newSourceAddress = sourceAddress;

            if ((interfaceIndex == -1) || (newSourceAddress == (unsigned)-1))
            {
                MESSAGE_Free(node, msg);
                return;
            }
        }
        else
        {
            interfaceIndex =
                 NetworkGetInterfaceIndexForDestAddress(node,
                                                        destinationAddress);

            newSourceAddress = NetworkIpGetInterfaceAddress(node,
                                                            interfaceIndex);
            if ((interfaceIndex == -1) || (newSourceAddress == (unsigned)-1))
            {
                MESSAGE_Free(node, msg);
                return;
            }
        }
    }
    else
    {
        interfaceIndex = outgoingInterface;
        newSourceAddress = sourceAddress;
    }

#ifdef ADDON_DB
    // before adding header to be consistent with
    // that in receiveFromTransport
    HandleNetworkDBEvents(
        node,
        msg,
        interfaceIndex,
        "NetworkReceiveFromUpper",
        "",
        newSourceAddress,
        destinationAddress,
        priority,
        protocol);
#endif

    AddIpHeader(
        node,
        msg,
        newSourceAddress,
        destinationAddress,
        priority,
        protocol,
        ttl);

#if defined(ADDON_BOEINGFCS)
    HandleNetworkIpStats(node, ip, msg, interfaceIndex, TRUE);
#endif

#ifdef CELLULAR_LIB
    if (node->networkData.networkProtocol == CELLULAR &&
        CellularLayer3IsUserDevices(node, interfaceIndex))
    {
        // msg is with IP header
        CellularLayer3HandlePacketFromUpperOrOutside(
            node,
            msg,
            interfaceIndex,
            NETWORK_IPV4);
    }
    else
#elif UMTS_LIB
    if (node->networkData.networkProtocol == CELLULAR &&
        CellularLayer3IsUserDevices(node, interfaceIndex))
    {
        // msg is with IP header
        CellularLayer3HandlePacketFromUpperOrOutside(
            node,
            msg,
            interfaceIndex,
            NETWORK_IPV4);
    }
    else
#endif // CELLULAR_LIB
    {
        // interfaceIndex represents outgoing interface.
        RoutePacketAndSendToMac(node, msg, CPU_INTERFACE, interfaceIndex, ANY_IP);
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendRawMessageWithDelay()
// PURPOSE      Same as NetworkIpSendRawMessage(), but schedules
//              event after a simulation delay.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with payload data for IP packet.
//                  (IP header needs to be added)
//              NodeAddress sourceAddress
//                  Source IP address. (See notes)
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int outgoingInterface
//                  outgoing interface to use to transmit packet.
//              TosType priority
//                  Priority of packet.
//              unsigned char protocol
//                  IP protocol number.
//              unsigned ttl
//                  Time to live.
//                  See AddIpHeader() for special values.
//              clocktype delay
//                  Delay.
// RETURN       None.
//
// NOTES        If sourceAddress is ANY_IP, lets IP assign the source
//              address (depends on the route).
//-----------------------------------------------------------------------------

void
NetworkIpSendRawMessageWithDelay(
    Node *node,
    Message *msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    int outgoingInterface,
    TosType priority,
    unsigned char protocol,
    unsigned ttl,
    clocktype delay)
{
    NodeAddress newSourceAddress;
    int interfaceIndex;
    int *info;

    if (outgoingInterface == ANY_INTERFACE)
    {
        if (sourceAddress != ANY_IP)
        {
            interfaceIndex =
                    NetworkIpGetInterfaceIndexFromAddress(node, sourceAddress);

            newSourceAddress = sourceAddress;
        }
        else
        {
            interfaceIndex =
                NetworkGetInterfaceIndexForDestAddress(node,
                                                       destinationAddress);

            newSourceAddress =
                        NetworkIpGetInterfaceAddress(node, interfaceIndex);
        }
    }
    else
    {
        interfaceIndex = outgoingInterface;
        newSourceAddress = sourceAddress;
    }

#ifdef ADDON_DB
    // before adding header to be consistent with
    // that in receiveFromTransport
    HandleNetworkDBEvents(
        node,
        msg,
        interfaceIndex,
        "NetworkReceiveFromUpper",
        "",
        newSourceAddress,
        destinationAddress,
        priority,
        protocol);
#endif
    AddIpHeader(
        node,
        msg,
        newSourceAddress,
        destinationAddress,
        priority,
        protocol,
        ttl);

    MESSAGE_InfoAlloc(node, msg, sizeof(int));

    info = (int *) MESSAGE_ReturnInfo(msg);
    *info = interfaceIndex;

    MESSAGE_SetEvent(msg, MSG_NETWORK_FromTransportOrRoutingProtocol);
    MESSAGE_SetLayer(msg, NETWORK_LAYER, NETWORK_PROTOCOL_IP);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_Send(node, msg, delay);
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendRawMessageToMacLayer()
// PURPOSE      Called by network-layer routing protocols (AODV, OSPF,
//              etc.) to add an IP header to payload data, and with
//              the resulting IP packet, calls
//              NetworkIpSendPacketOnInterface().
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with payload data for IP packet.
//                  (IP header needs to be added)
//              NodeAddress sourceAddress
//                  Source IP address.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              TosType priority
//                  Priority of packet.
//              unsigned char protocol
//                  IP protocol number.
//              unsigned ttl
//                  Time to live.
//                  See AddIpHeader() for special values.
//              int outgoingInterface
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop IP address.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSendRawMessageToMacLayer(
    Node *node,
    Message *msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    TosType priority,
    unsigned char protocol,
    unsigned ttl,
    int outgoingInterface,
    NodeAddress nextHop)
{
#ifdef ADDON_DB
    // before adding header to be consistent with
    // that in receiveFromTransport
    HandleNetworkDBEvents(
        node,
        msg,
        outgoingInterface,
        "NetworkReceiveFromUpper",
        "",
        sourceAddress,
        destinationAddress,
        priority,
        protocol);
#endif

#ifdef CYBER_CORE
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IgmpMessage* igmpPkt = (IgmpMessage*) MESSAGE_ReturnPacket(msg);

    if (ip->iahepEnabled && ip->iahepData->nodeType == BLACK_NODE &&
         IsIAHEPBlackSecureInterface(node, outgoingInterface)
#ifdef ADDON_BOEINGFCS
        && protocol != IPPROTO_ROUTING_CES_ROSPF
#endif
        )
    {
        //Black Node Should Send Query Message To IAHEP Node
        if (igmpPkt->ver_type != IGMP_QUERY_MSG)
        {
            MESSAGE_Free(node, msg);
            return;
        }
    }
#endif //CYBER_CORE

    AddIpHeader(
        node,
        msg,
        sourceAddress,
        destinationAddress,
        priority,
        protocol,
        ttl);


    NetworkIpSendPacketOnInterface(node,
                                  msg,
                                  CPU_INTERFACE,
                                  outgoingInterface,
                                  nextHop);
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendRawMessageToMacLayerWithDelay()
// PURPOSE      Same as NetworkIpSendRawMessageToMacLayer(),
//              but schedules the event after a simulation delay
//              by calling NetworkIpSendPacketOnInterfaceWithDelay().
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with payload data for IP packet.
//                  (IP header needs to be added)
//              NodeAddress sourceAddress
//                  Source IP address.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              TosType priority
//                  TOS of packet.
//              unsigned char protocol
//                  IP protocol number.
//              unsigned ttl
//                  Time to live.
//                  See AddIpHeader() for special values.
//              int outgoingInterface
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop IP address.
//              clocktype delay
//                  Delay.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSendRawMessageToMacLayerWithDelay(
    Node *node,
    Message *msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    TosType priority,
    unsigned char protocol,
    unsigned ttl,
    int outgoingInterface,
    NodeAddress nextHop,
    clocktype delay)
{
#ifdef ADDON_DB
    // before adding header to be consistent with
    // that in receiveFromTransport
    HandleNetworkDBEvents(
        node,
        msg,
        outgoingInterface,
        "NetworkReceiveFromUpper",
        "",
        sourceAddress,
        destinationAddress,
        priority,
        protocol);
#endif

#ifdef CYBER_CORE
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IgmpMessage* igmpPkt = (IgmpMessage*) MESSAGE_ReturnPacket(msg);

    if (ip->iahepEnabled && ip->iahepData->nodeType == BLACK_NODE &&
         IsIAHEPBlackSecureInterface(node, outgoingInterface))
    {
        //Black Node Should Send Query Message To IAHEP Node
        if (igmpPkt->ver_type != IGMP_QUERY_MSG)
        {
            MESSAGE_Free(node, msg);
            return;
        }
    }
#endif //CYBER_CORE
    AddIpHeader(
        node,
        msg,
        sourceAddress,
        destinationAddress,
        priority,
        protocol,
        ttl);

    NetworkIpSendPacketOnInterfaceWithDelay(
        node, msg, CPU_INTERFACE, outgoingInterface, nextHop, delay);
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendPacketToMacLayer()
// PURPOSE      This function is called once the outgoing interface
//              index and next hop address to which to route an IP
//              packet are known.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int outgoingInterface
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop IP address.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSendPacketToMacLayer(
    Node *node,
    Message *msg,
    int outgoingInterface,
    NodeAddress nextHop)
{
    NetworkIpSendPacketOnInterface(node,
                                  msg,
                                  CPU_INTERFACE,
                                  outgoingInterface,
                                  nextHop);
}

#ifdef ADDON_BOEINGFCS
int NetworkIpGetOutgoingInterfaceFromAddr(Node* node,
                                          int interfaceIndex,
                                          NodeAddress addr)
{
    int i;
    NodeAddress netAddr;
    NodeAddress subnetMask;
    NodeAddress maskedAddr;

    for (i=0; i< node->numberInterfaces; i++)
    {
        netAddr = NetworkIpGetInterfaceNetworkAddress(node, i);
        subnetMask = NetworkIpGetInterfaceSubnetMask(node, i);
        maskedAddr = MaskIpAddress(addr, subnetMask);

        if (netAddr == maskedAddr)
        {
           return i;
        }

    }

    return interfaceIndex;
}
#endif

int NetworkIpGetSmallestFragUnitInterface(Node* node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;
    int minFragUnit = MAX_NW_PKT_SIZE + 1; // cant be greater
    int curFragUnit = 0;
    int minFragIndex = -1;

    for (i=0; i< node->numberInterfaces; i++)
    {
        // only consider frag units of ipv4 interfaces here.
        if (ip->interfaceInfo[i]->interfaceType == NETWORK_IPV4)
        {
            curFragUnit = GetNetworkIPFragUnit(node, i);
            if (curFragUnit < minFragUnit)
            {
                minFragUnit = curFragUnit;
                minFragIndex = i;
            }
        }
        else
        {
            // if this is not a pure IPv4 scenario, we will assume that
            // all interfaces have the same fragmentation unit.

            minFragIndex = GetDefaultInterfaceIndex(node,
                                   ip->interfaceInfo[i]->interfaceType);

            ERROR_Assert(minFragIndex >= 0, "incorrect interface type!");

            return minFragIndex;
        }
    }

    ERROR_Assert(minFragIndex >= 0,
                 "Incorrect fragmentation unit configuration");

    return minFragIndex;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendPacketOnInterface()
// PURPOSE      This function is called once the outgoing interface
//              index and next hop address to which to route an IP
//              packet are known.  This queues an IP packet for delivery
//              to the MAC layer.  This functions calls
//              QueueUpIpFragmentForMacLayer().
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int incomingInterface
//                  Index of incoming interface.
//              int outgoingInterface
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop IP address.
// RETURN       None.
//
// NOTES        This function is used to initiate fragmentation if
//              required.
//-----------------------------------------------------------------------------

void
NetworkIpSendPacketOnInterface(
    Node *node,
    Message *msg,
    int incomingInterface,
    int outgoingInterface,
    NodeAddress nextHop)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

#ifdef EXATA
    // AutoIPNE
    // Ignoring the fact that the packet may be fragmented
    {
        if ((outgoingInterface != CPU_INTERFACE) &&
            (!TunnelIsVirtualInterface(node, outgoingInterface)) &&
            (node->macData[outgoingInterface]->isVirtualLan))
        {
                unsigned int tos = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);

                AddIpHeader(
                        node,
                        msg,
                        ipHeader->ip_src,
                        ipHeader->ip_dst,
                        tos,
                        IPPROTO_EXATA_VIRTUAL_LAN,
                        ipHeader->ip_ttl);

                if (AutoIPNE_ForwardFromNetworkLayer(node,                
                    outgoingInterface,   
                    msg,     
                    ANY_IP,      
                    FALSE))
                {
                    return;
                }

            MESSAGE_RemoveHeader(node, msg, IpHeaderSize(ipHeader), TRACE_IP);
            ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
        }
    }
#endif

    //fragmentation variables for IP fragmentation
    ipFragmetedMsg* fragHead = NULL;
    ipFragmetedMsg* tempFH = NULL;
    BOOL fragmentedByIP = FALSE;
#ifdef CYBER_CORE
    BOOL transportIPsec = FALSE;
    clocktype transportDelay = 0;
#endif //CYBER_CORE

    int interfaceIndex;

    if (incomingInterface == CPU_INTERFACE)
    {
        // If sent by this node, then routing protocol should be
        // associated with the outgoing interface.
        interfaceIndex = outgoingInterface;
    }
    else
    {
        // If packet is being forwarded, then routing protocol should
        // be associated with the incoming interface.
        interfaceIndex = incomingInterface;
    }
#ifdef CYBER_CORE
    if (outgoingInterface != CPU_INTERFACE
        && ip->interfaceInfo[outgoingInterface]->spdOUT &&
        !IsIPsecProcessed(node, msg) &&
        (IPsecIsTransportMode(node, msg, outgoingInterface) == TRUE)
        && ip->isIPsecEnabled == TRUE
        && ipHeader->ip_p != IPPROTO_ISAKMP)
    {
        // Handle packet to security protocol if IPsec enable over this
        // interface. This is to ensure that in Transport mode, the ipsec
        // processing occurs before fragmentation.
        // if the packet is not fragmented, perform outbound handling
        if (!((IpHeaderGetIpFragOffset(ipHeader->ipFragment) != 0) ||
            IpHeaderGetIpMoreFrag(ipHeader->ipFragment)))
        {
            if (IPsecHandleOutboundPacket(node,
                                          msg,
                                          incomingInterface,
                                          outgoingInterface,
                                          nextHop,
                                          NULL,
                                          FALSE))
            {
                transportIPsec = TRUE;
                return;
            }
        }
        else //first reassemble the packet before applying transport outbound
        {
            BOOL isReassembled = FALSE;
            Message* joinedMsg = NULL;
            joinedMsg = IpFragmentInput(node, msg, incomingInterface, &isReassembled);
            if (isReassembled)
            {
                msg = joinedMsg;

                if (IPsecHandleOutboundPacket(node,
                                              msg,
                                              incomingInterface,
                                              outgoingInterface,
                                              nextHop,
                                              NULL,
                                              FALSE))
                {
                    transportIPsec = TRUE;
                    return;
                }
            }
            else
            {
                return;
            }
        }
    }
#endif // CYBER_CORE
    ipHeader = (IpHeaderType*) MESSAGE_ReturnPacket(msg);

    // IP Fragmentation code here.
#ifdef ADDON_BOEINGFCS
    /***** Start: ROSPF Redirect *****/
    RospfRedirectMetadata *redirMeta = (RospfRedirectMetadata *)
                MESSAGE_ReturnInfo(msg, INFO_TYPE_ROSPFRedirectMetadata);
    if ((redirMeta != NULL) 
#ifdef CYBER_CORE
         && ((ip->iahepData == NULL) ||
             (ip->iahepData->nodeType != IAHEP_NODE))
#endif
       )
    {
        // If incoming interface equals outgoing interface
        // and the interface runs ROSPF, notify ROSPF for 
        // possible redirect
        if ((outgoingInterface >= 0) && 
            RoutingCesRospfActiveOnInterface(node, outgoingInterface) && 
            (redirMeta->incomingInterface == outgoingInterface))
        {
            RoutingCesRospfHandleRedirectEvent(node, msg);
        }
        MESSAGE_RemoveInfo(node, 
                           msg, 
                           INFO_TYPE_ROSPFRedirectMetadata);
    }
    /***** End: ROSPF Redirect *****/
#endif
    int fragInterface = NetworkIpGetSmallestFragUnitInterface(node);

#ifdef SENSOR_NETWORKS_LIB
    ZigbeeAppInfo* zigbeeAppInfo = NULL;
    zigbeeAppInfo = (ZigbeeAppInfo*)MESSAGE_ReturnInfo(msg,
                                                 INFO_TYPE_ZigbeeApp_Info);
    if (zigbeeAppInfo)
    {
        zigbeeAppInfo->ipFragUnit = GetNetworkIPFragUnit(node, fragInterface);
    }
#endif // SENSOR_NETWORKS_LIB

    if (MESSAGE_ReturnPacketSize(msg) >
                                    GetNetworkIPFragUnit(node, fragInterface))
    {
        if (IpHeaderHasSourceRoute(ipHeader))
        {
            ERROR_ReportError("Source routing packet is not allowed for "
                              "Ip fragmentation\n");
        }
        if (IpHeaderGetIpDontFrag(ipHeader ->ipFragment))
        {
            if (ip->isIcmpEnable && icmp->fragmentationNeededEnable)
            {
               // send ICMP Message
                BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                              msg,
                                              ipHeader->ip_src,
                                              incomingInterface,
                                              ICMP_DESTINATION_UNREACHABLE,
                                              ICMP_DGRAM_TOO_BIG,
                                              0,
                                              0);
               if (ICMPErrorMsgCreated)
               {

#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                    printf("Node %d sending fragmentation required message"
                             " to %s\n", node->nodeId, srcAddr);
#endif

                   (icmp->icmpErrorStat.icmpFragNeededSent)++;
               }
               ip->stats.ipFragFails++;
#ifdef ADDON_DB

               HandleNetworkDBEvents(
                   node,
                   msg,
                   incomingInterface, // use incoming interface here
                   "NetworkPacketDrop",
                   "Packet Too Big, Fragmentation Not Allowed",
                   0,
                   0,
                   0,
                   0);
#endif
               MESSAGE_Free(node,msg);
               return;
            }
        }


        if (IpFragmentPacket(node,
                    msg,
                    GetNetworkIPFragUnit(node, fragInterface),
                    &fragHead,
                    FALSE)) // Normal IP-fragmentation
        {
            fragmentedByIP = TRUE;
        }
        else
        {
            ERROR_ReportError("IP header with option header, is not "
                    "allowed for IP fragmentation in this version\n");
        }
    }// End of if stmt.


    if (!fragmentedByIP)
    {
#ifdef CYBER_LIB
        // We process the output chain here. Any packet that is sourced by 
        // this node will be processed here. We do so after fragmenting the packet.
        if (node->firewallModel &&
            node->firewallModel->isFirewallOn())
        {
            if (NetworkIpIsMyIP(node, ipHeader->ip_src))
            {
                int response;
                response = node->firewallModel->inspect(
                    FirewallModel::FILTER_TABLE,
                    "OUTPUT",
                    msg,
                    incomingInterface,
                    outgoingInterface);

                if (response == FirewallModel::FIREWALL_ACTION_DROP)
                {
                    MESSAGE_Free(node,  msg);
                    return;
                }
            }
            else if (!NetworkIpIsMyIP(node, ipHeader->ip_src))
            {
                int response;
                response = node->firewallModel->inspect(
                    FirewallModel::FILTER_TABLE,
                    "FORWARD",
                    msg,
                    incomingInterface,
                    outgoingInterface);
                if (response == FirewallModel::FIREWALL_ACTION_DROP)
                {
                    MESSAGE_Free (node, msg);
                    return;
                }
            }
        }
#endif
#ifdef ADDON_NGCNMS
        if (NetworkNgcHaipeIsRedInterface(node, interfaceIndex))
        {
            // If packet is has not already been encapsulated,
            // then we know we havent specified a black address
            // as the ip source and destination.
            if (ipHeader->ip_p != IPPROTO_IPIP_RED)
            {
                NetworkNgcHaipeSendPacketOnInterface(node,
                    msg,
                    incomingInterface,
                    outgoingInterface,
                    nextHop);
                return;
            }
            // Packet must be encapsulated and we are sending
            // the packet on the correct black interface since the
            // packet has already been routed.
        }
#endif


#ifdef PAS_INTERFACE
        int interfaceIndex;
        if (incomingInterface == CPU_INTERFACE)
        {
            interfaceIndex = outgoingInterface;
        }
        else
        {
            interfaceIndex = incomingInterface;
        }

        if (PAS_LayerCheck(node,
                          interfaceIndex,
                          PACKET_SNIFFER_ETHERNET))
        {
            PAS_IPv4(node,
                     ipHeader,
                     0);
        }
#endif

#ifdef CYBER_CORE
        int iahepoutgoingInterfaceToUse = 0;
        NodeAddress iahepoutgoingBroadcastAddress = 0;
//BROADCAST_IAHEP_START
        if (!(ip->iahepEnabled) &&
            NetworkIpNeedsToForwardAppBroadcast(node, msg, ipHeader->ip_dst))
        {
            pair<map<Int64,clocktype>::iterator,bool> ret;

            Int64 tempId = msg->originatingNodeId;
            tempId = tempId << 32;
            tempId = tempId | msg->sequenceNumber;
            ret = ip->broadcastAppMapping->insert(pair<Int64,clocktype> (
                                                    tempId, getSimTime(node)));

            if (!ret.second)
            {
                ret.first->second = getSimTime(node);
            }
        }
//BROADCAST_IAHEP_END

        // Handle packet to security protocol if IPSec enable over
        // this interface
        if (outgoingInterface != CPU_INTERFACE
            && ip->interfaceInfo[outgoingInterface]->spdOUT
            && !IsIPsecProcessed(node, msg)
            && ip->isIPsecEnabled == TRUE
            && ipHeader->ip_p != IPPROTO_ISAKMP)
        {
            if (IPsecHandleOutboundPacket(node,
                                          msg,
                                          incomingInterface,
                                          outgoingInterface,
                                          nextHop,
                                          NULL,
                                          FALSE))
            {
                return;
            }
        }
#endif // CYBER_CORE
        // Increment stat for total number of IP datagrams passed to IP for
        // transmission.Does not include those counted in ipForwardDatagrams.

        ip->stats.ipOutRequests++;

        // DUAL-IP: Check whether outgoing interface is v6-tunneled
        if (TunnelIsVirtualInterface(node, outgoingInterface))
        {
            TunnelSendIPv4Pkt(
                node,
                msg,
                outgoingInterface,
                nextHop);
            return;
        }
        else if (outgoingInterface != CPU_INTERFACE
                 && NetworkIpGetInterfaceType(node, outgoingInterface) == NETWORK_IPV6)
        {
            // Drop the pkt if the interface is not v6-tunneled and
            // also not connected with an IPv4 network.

            MESSAGE_Free(node, msg);
            return;
        }

       //------------------------------------------------------------------//
       //          Removed due to fragmentation.
       /*
        ERROR_Assert(ipHeader->ip_len <= (unsigned) ip->maxPacketLength,
                     "IP datagram is too large, check IP-FRAGMENTATION-UNIT "
                     "in .config file");
        */
        //-----------------------------------------------------------------//


#ifdef ENTERPRISE_LIB
        if ((outgoingInterface != CPU_INTERFACE) &&
            (ip->interfaceInfo[outgoingInterface]->accessListOutPointer))
        {
            if (AccessListFilterPacket(
                        node,
                        msg,
                        ip->interfaceInfo[outgoingInterface]->
                            accessListOutPointer,
                        outgoingInterface,
                        ACCESS_LIST_OUT))
            {
                // Matched, so drop and return
                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment = DROP_ACCESS_LIST;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData,
                                 NETWORK_IPV4);

                return;
            }
        }
#endif // ENTERPRISE_LIB

        // Receive a packet from Loopback Interface, using VT to display.
        if (ip->isLoopbackEnabled && (outgoingInterface == CPU_INTERFACE) &&
            (incomingInterface == CPU_INTERFACE) && node->guiOption)
        {
#ifdef EXATA
            if (msg->isEmulationPacket)
            {
                GUI_Receive(node->nodeId,
                        node->nodeId,
                        GUI_NETWORK_LAYER,
                        GUI_EMULATION_DATA_TYPE,
                        outgoingInterface,
                        incomingInterface,
                        TIME_getSimTime(node) + getSimStartTime(node));
            }
            else
            {
                GUI_Receive(node->nodeId,
                        node->nodeId,
                        GUI_NETWORK_LAYER,
                        GUI_DEFAULT_DATA_TYPE,
                        outgoingInterface,
                        incomingInterface,
                        TIME_getSimTime(node) + getSimStartTime(node));
            }
#else
            GUI_Receive(node->nodeId,
                node->nodeId,
                GUI_NETWORK_LAYER,
                GUI_DEFAULT_DATA_TYPE,
                outgoingInterface,
                incomingInterface,
                TIME_getSimTime(node) + getSimStartTime(node));

#endif
        }

#ifdef ENTERPRISE_LIB
        PbrDebug(node,ipHeader,incomingInterface,nextHop,outgoingInterface);
#endif // ENTERPRISE_LIB

#ifdef ADDON_DB
    //if (msg->pktNetworkSendTime == -1)
    //{
    //    msg->pktNetworkSendTime = getSimTime(node);
    //}

    MESSAGE_AddInfo(
            node,
            msg,
            sizeof(clocktype),
            INFO_TYPE_IPPacketSentTime);
    clocktype *timing = (clocktype*) MESSAGE_ReturnInfo(
            msg,
            INFO_TYPE_IPPacketSentTime);
    *timing = getSimTime(node) ;

    HandleStatsDBNetworkOutUpdate(node, msg,
        nextHop, outgoingInterface ) ; //outgoing
#if 0
        HandleStatsDBNetworkAggregateUpdate(node,
                                            msg,
                                            TRUE,
                                            outgoingInterface);

        HandleStatsDBNetworkSummaryOutUpdate(node, msg,
            nextHop, outgoingInterface); //outgoing
#endif

#endif
        NetworkIpSendOnBackplane(node,
                                 msg,
                                 incomingInterface,
                                 outgoingInterface,
                                 nextHop);
    }
    else
    {
        if (fragHead)
        {
            int fragId = 0 ;
            while (fragHead)
            {
                ipHeader = (IpHeaderType *) fragHead->msg->packet;

#ifdef CYBER_LIB
                // We process the output chain here. Any packet that is sourced by 
                // this node will be processed here. We do so after fragmenting the packet.
                if (node->firewallModel &&
                    node->firewallModel->isFirewallOn())
                {
                    if (NetworkIpIsMyIP(node, ipHeader->ip_src))
                    {
                        int response;
                        response = node->firewallModel->inspect(
                            FirewallModel::FILTER_TABLE,
                            "OUTPUT",
                            fragHead->msg,
                            incomingInterface,
                            outgoingInterface);

                        if (response == FirewallModel::FIREWALL_ACTION_DROP)
                        {
                            MESSAGE_Free(node,  fragHead->msg);
                            return;
                        }
                    }
                    else if (!NetworkIpIsMyIP(node, ipHeader->ip_src))
                    {
                        int response;
                        response = node->firewallModel->inspect(
                            FirewallModel::FILTER_TABLE,
                            "FORWARD",
                            fragHead->msg,
                            incomingInterface,
                            outgoingInterface);
                        if (response == FirewallModel::FIREWALL_ACTION_DROP)
                        {
                            MESSAGE_Free (node, fragHead->msg);
                            return;
                        }
                    }
                }
                //}
#endif
#ifdef PAS_INTERFACE
                IpHeaderType *ipH = (IpHeaderType *)
                                         MESSAGE_ReturnPacket(fragHead->msg);

                if (incomingInterface == CPU_INTERFACE)
                {
                    interfaceIndex = outgoingInterface;
                }
                else
                {
                    interfaceIndex = incomingInterface;
                }

                if (PAS_LayerCheck(node,
                                  interfaceIndex,
                                  PACKET_SNIFFER_ETHERNET))
                {
                    PAS_IPv4(node,
                             ipH,
                             0,
                             MESSAGE_ReturnPacketSize(fragHead->msg));
                }
#endif

                // STATS DB CODE
#ifdef ADDON_DB
                // Here we add the packet to the Network database.
                // Gather as much information we can for the database.

                StatsDBAppendMessageNetworkMsgId(node, fragHead->msg,
                    fragId++) ;
#endif

         // Below is the same code that used for non-fragment message above

#ifdef ADDON_NGCNMS
                if (NetworkNgcHaipeIsRedInterface(node, interfaceIndex))
                {
                    // If packet is has not already been encapsulated,
                    // then we know we havent specified a black address
                    // as the ip source and destination.
                    if (ipHeader->ip_p != IPPROTO_IPIP_RED)
                    {
                        NetworkNgcHaipeSendPacketOnInterface(node,
                            fragHead->msg,
                            incomingInterface,
                            outgoingInterface,
                            nextHop);

                        tempFH = fragHead;
                        fragHead = fragHead->next;
                        MEM_free(tempFH);
                        continue;
                    }
                    // Packet must be encapsulated and we are sending
                    // the packet on the correct black interface since the
                    // packet has already been routed.
                }
#endif

#ifdef CYBER_CORE
                // Handle packet to security protocol if IpSec enable over
                // this interface
                if (outgoingInterface != CPU_INTERFACE
                    && ip->interfaceInfo[outgoingInterface]->spdOUT
                    && !IsIPsecProcessed(node, fragHead->msg)
                    && ip->isIPsecEnabled == TRUE
                    && ipHeader->ip_p != IPPROTO_ISAKMP)
                {
                    if (IPsecHandleOutboundPacket(node,
                                                  fragHead->msg,
                                                  incomingInterface,
                                                  outgoingInterface,
                                                  nextHop,
                                                  NULL,
                                                  FALSE))
                    {
                        tempFH = fragHead;
                        fragHead = fragHead->next;
                        MEM_free(tempFH);
                        continue;
                    }
                }
#endif // CYBER_CORE
                // Increment stat for total number of IP datagrams passed to
                // IP for transmission.Does not include those counted in
                // ipForwardDatagrams.

                ip->stats.ipOutRequests++;

                // DUAL-IP: Check whether outgoing interface is v6-tunneled
                if (TunnelIsVirtualInterface(node, outgoingInterface))
                {
                    TunnelSendIPv4Pkt (node,
                                       fragHead->msg,
                                       outgoingInterface,
                                       nextHop);

                    tempFH = fragHead;
                    fragHead = fragHead->next;
                    MEM_free(tempFH);
                    continue;
                }
                else if (outgoingInterface != CPU_INTERFACE
                         && NetworkIpGetInterfaceType(node,outgoingInterface)
                                                             == NETWORK_IPV6)
                {
                    // Drop the pkt if the interface is not v6-tunneled and
                    // also not connected with an IPv4 network.

                        MESSAGE_Free(node, fragHead->msg);
                        tempFH = fragHead;
                        fragHead = fragHead->next;
                        MEM_free(tempFH);
                        continue;
                }

#ifdef ENTERPRISE_LIB
                if ((outgoingInterface != CPU_INTERFACE) &&
                    (ip->interfaceInfo[outgoingInterface]->
                                                       accessListOutPointer))
                {
                    if (AccessListFilterPacket(
                                node,
                                fragHead->msg,
                                ip->interfaceInfo[outgoingInterface]->
                                                        accessListOutPointer,
                                outgoingInterface,
                                ACCESS_LIST_OUT))
                    {
                        // Matched, so drop and return
                        //Trace drop
                        ActionData acnData;
                        acnData.actionType = DROP;
                        acnData.actionComment = DROP_ACCESS_LIST;
                        TRACE_PrintTrace(node,
                                         fragHead->msg,
                                         TRACE_NETWORK_LAYER,
                                         PACKET_OUT,
                                         &acnData,
                                         NETWORK_IPV4);

                        tempFH = fragHead;
                        fragHead = fragHead->next;
                        MEM_free(tempFH);
                        continue;
                    }
                }
#endif // ENTERPRISE_LIB

                // Receive a packet from Loopback Interface,
                // using VT to display.
                if (ip->isLoopbackEnabled
                    && (outgoingInterface == CPU_INTERFACE)
                    && (incomingInterface == CPU_INTERFACE)
                    && node->guiOption)
                {
#ifdef EXATA
        if (msg->isEmulationPacket)
        {
            GUI_Receive(node->nodeId,
                node->nodeId,
                GUI_NETWORK_LAYER,
                GUI_EMULATION_DATA_TYPE,
                outgoingInterface,
                incomingInterface,
                TIME_getSimTime(node)+getSimStartTime(node));
        }
        else
        {
            GUI_Receive(node->nodeId,
                node->nodeId,
                GUI_NETWORK_LAYER,
                GUI_DEFAULT_DATA_TYPE,
                outgoingInterface,
                incomingInterface,
                TIME_getSimTime(node)+getSimStartTime(node));
        }
#else
                    GUI_Receive(node->nodeId,
                        node->nodeId,
                        GUI_NETWORK_LAYER,
                        GUI_DEFAULT_DATA_TYPE,
                        outgoingInterface,
                        incomingInterface,
                        TIME_getSimTime(node)+getSimStartTime(node));
#endif
                }

#ifdef ENTERPRISE_LIB
                PbrDebug(node,
                         ipHeader,
                         incomingInterface,
                         nextHop,
                         outgoingInterface);
#endif // ENTERPRISE_LIB


#ifdef ADDON_DB
                //if (fragHead->msg->pktNetworkSendTime == -1)
                //{
                //fragHead->msg->pktNetworkSendTime = getSimTime(node);
                //}

                MESSAGE_AddInfo(
                        node,
                        fragHead->msg,
                        sizeof(clocktype),
                        INFO_TYPE_IPPacketSentTime);
                clocktype *timing = (clocktype*) MESSAGE_ReturnInfo(
                        fragHead->msg,
                        INFO_TYPE_IPPacketSentTime);
                *timing = getSimTime(node) ;

                HandleStatsDBNetworkOutUpdate(node,
                                              fragHead->msg,
                                              nextHop,
                                              outgoingInterface);
#endif

                NetworkIpSendOnBackplane(node,
                                         fragHead->msg,
                                         incomingInterface,
                                         outgoingInterface,
                                         nextHop);

                tempFH = fragHead;
                fragHead = fragHead->next;
                MEM_free(tempFH);
            } // end of while loop
            MESSAGE_Free(node, msg);
            return;
        } // end of if block
#ifdef CYBER_CORE
        else if (ip->iahepEnabled && ip->iahepData->nodeType == IAHEP_NODE)
        {
            int blackIntfId = IAHEPGetIAHEPBlackInterfaceIndex(node);
            IpInterfaceInfoType* intfInfo =
                            ip->interfaceInfo[blackIntfId];

            int hlen = sizeof(IpHeaderType);
            hlen +=  sizeof(IahepMLSHeader);

            // Now Calculate the fragmentedLen
            // The Fragmentable Prt of orgnl packet is divided into
            // fragments.

            int fragmentLen = GetNetworkIPFragUnit(node, blackIntfId);
            int frag_size = ((int)(fragmentLen - hlen) / 8) * 8;

            //Add info to carry the pad len
            char *padlen = NULL;
            padlen = MESSAGE_AddInfo(
                        node,
                        msg,
                        sizeof(int),
                        INFO_TYPE_PadLen);

            *((int*) padlen) = frag_size -
                ((MESSAGE_ReturnPacketSize(msg) - hlen));

            // Pad pkt 2 IAHEP-FRAGMENTATION-UNIT to be a full frgmnt
            // and add the fragment header
            MESSAGE_AddVirtualPayload(node,
                                  msg,
                                  *((int*) padlen));

            ipHeader = (IpHeaderType *)MESSAGE_ReturnPacket(msg);
            IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),
                                MESSAGE_ReturnPacketSize(msg));

            intfInfo->iahepstats.iahepIPFragsPadded++;

            NetworkIpSendOnBackplane(node,
                                    msg,
                                    incomingInterface,
                                    blackIntfId,
                                    ANY_DEST);
        }
#endif //CYBER_CORE
    }
}//NetworkIpSendPacketOnInterface//


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendPacketToMacLayerWithDelay()
// PURPOSE      Same as NetworkIpSendPacketOnInterface(), but schedules
//              event after a simulation delay.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int outgoingInterface
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop IP address.
//              clocktype delay
//                  Delay.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSendPacketToMacLayerWithDelay(
    Node *node,
    Message *msg,
    int outgoingInterface,
    NodeAddress nextHop,
    clocktype delay)
{
    NetworkIpSendPacketOnInterfaceWithDelay(node,
                                            msg,
                                            CPU_INTERFACE,
                                            outgoingInterface,
                                            nextHop,
                                            delay);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendPacketOnInterfaceWithDelay()
// PURPOSE      Same as NetworkIpSendPacketOnInterface(), but schedules
//              event after a simulation delay.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int incomingInterface
//                  Index of incoming interface.
//              int outgoingInterface
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop IP address.
//              clocktype delay
//                  Delay.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSendPacketOnInterfaceWithDelay(
    Node *node,
    Message *msg,
    int incomingInterface,
    int outgoingInterface,
    NodeAddress nextHop,
    clocktype delay)
{
    DelayedSendToMacLayerInfoType *info;

    MESSAGE_InfoAlloc(node, msg, sizeof(DelayedSendToMacLayerInfoType));

    info = (DelayedSendToMacLayerInfoType *) MESSAGE_ReturnInfo(msg);
    info->incomingInterface = incomingInterface;
    info->outgoingInterface = outgoingInterface;
    info->nextHop = nextHop;
#ifdef ADDON_DB
    info->rawPacket = FALSE;
#endif // ADDON_DB

    MESSAGE_SetLayer(msg, NETWORK_LAYER, NETWORK_PROTOCOL_IP);
    MESSAGE_SetEvent(msg, MSG_NETWORK_DelayedSendToMac);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_Send(node, msg, delay);
}

#ifdef ADDON_DB
//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendRawPacketOnInterfaceWithDelay()
// PURPOSE      Same as NetworkIpSendPacketOnInterface(), but schedules
//              event after a simulation delay and denotes raw packet.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int incomingInterface
//                  Index of incoming interface.
//              int outgoingInterface
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop IP address.
//              clocktype delay
//                  Delay.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSendRawPacketOnInterfaceWithDelay(
    Node *node,
    Message *msg,
    int incomingInterface,
    int outgoingInterface,
    NodeAddress nextHop,
    clocktype delay)
{
    DelayedSendToMacLayerInfoType *info;

    MESSAGE_InfoAlloc(node, msg, sizeof(DelayedSendToMacLayerInfoType));

    info = (DelayedSendToMacLayerInfoType *) MESSAGE_ReturnInfo(msg);
    info->incomingInterface = incomingInterface;
    info->outgoingInterface = outgoingInterface;
    info->nextHop = nextHop;
    info->rawPacket = TRUE;

    MESSAGE_SetLayer(msg, NETWORK_LAYER, NETWORK_PROTOCOL_IP);
    MESSAGE_SetEvent(msg, MSG_NETWORK_DelayedSendToMac);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_Send(node, msg, delay);
}
#endif // ADDON_DB

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendPacketToMacLayerWithNewStrictSourceRoute()
// PURPOSE      Tacks on a new source route to an existing IP packet and
//              then sends the packet to the MAC layer.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                   Pointer to message with IP packet.
//              NodeAddress newRouteAddresses[]
//                   Source route (address array).
//              int numNewRouteAddresses
//                   Number of array elements.
//              BOOL removeExistingRecordedRoute
// RETURN       None.
//
// NOTES        BSD modifies the source route in the IP header as the
//              packet traverses each node in the source route.  QualNet
//              doesn't do this.
//
//              There is not a "WithDelay" version of this function.
//-----------------------------------------------------------------------------

void
NetworkIpSendPacketToMacLayerWithNewStrictSourceRoute(
    Node *node,
    Message *msg,
    NodeAddress newRouteAddresses[],
    int numNewRouteAddresses,
    BOOL removeExistingRecordedRoute)
{
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    char *NewRoutePositionPtr;

    IpOptionsHeaderType *ipOption = IpHeaderSourceRouteOptionField(ipHeader);

    if (ipOption == NULL)
    {
        //
        // Add a source route to a packet with no source route
        // currently. The next equation uses the fact that this
        // sum will always be divisable by 4.
        //
        AddIpOptionField(node, msg, IPOPT_SSRR,
                         ((numNewRouteAddresses *sizeof(NodeAddress)) +
                          IP_SOURCE_ROUTE_OPTION_PADDING));
    }
    else
    {
        //
        // Replace a source route to already existing source routing option
        // header.
        //
        if (removeExistingRecordedRoute)
        {
            ipOption->ptr = IPOPT_MINOFF;
        }//if//

        ExpandOrShrinkIpOptionField(node, msg, IPOPT_SSRR,
                                    ((ipOption->ptr - 1) +
                                     (numNewRouteAddresses *
                                      sizeof(NodeAddress)) +
                                     IP_SOURCE_ROUTE_OPTION_PADDING));
    }//if//

    // Copy the new route into the option header. Must be
    // byte copy because of alignment issues.

    ipHeader = (IpHeaderType *) msg->packet;
    ipOption = IpHeaderSourceRouteOptionField(ipHeader);
    NewRoutePositionPtr =
        (char *) IpHeaderSourceRouteOptionField(ipHeader) + (ipOption->ptr -
                                                             1);

    memcpy(NewRoutePositionPtr, newRouteAddresses,
           (sizeof(NodeAddress) *numNewRouteAddresses));
    char *endRoute = (char *)ipOption + ipOption->len;
    *endRoute = IPOPT_EOL;

    // Special case for DSR. Allows for new replacement source route
    // whose first addresses is current node. It just moves the route
    // pointer to the correct next hop.

    if ((removeExistingRecordedRoute) &&
        (newRouteAddresses[0] == node->nodeId))
    {
        ipOption->ptr = (unsigned char) (ipOption->ptr + (sizeof(NodeAddress)));
    }//if//

    SourceRouteThePacket(node, msg, CPU_INTERFACE);

}//NetworkIpSendPacketToMacLayerWithNewStrictSourceRoute//

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpRoutingProtocolBroadcastMessageWithDelay()
// PURPOSE      Broadcast packet with a specified delay.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *rawMessage
//                  Pointer to message with payload data for IP packet.
//                  (IP header needs to be added)
//              NetworkRoutingProtocolType routingProtocol
//
//              TosType priority
//                  TOS of packet.
//              unsigned char protocol
//                  IP protocol number.
//              unsigned ttl
//                  Time to live.
//                  See AddIpHeader() for special values.
//              clocktype delay
//                  Delay.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpRoutingProtocolBroadcastMessageWithDelay(
    Node *node,
    Message *rawMessage,
    NetworkRoutingProtocolType routingProtocol,
    TosType priority,
    unsigned char protocol,
    unsigned ttl,
    clocktype delay)
{
    Message *nextMessage;
    int i;
    int firstIndex = -1;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (NetworkIpGetUnicastRoutingProtocolType(node, i) == routingProtocol)
        {
            if (firstIndex == -1)
            {
                firstIndex = i;
            }
            else
            {
                nextMessage = MESSAGE_Duplicate(node, rawMessage);

                AddIpHeader(
                    node,
                    nextMessage,
                    NetworkIpGetInterfaceAddress(
                        node, i),
                    NetworkIpGetInterfaceBroadcastAddress(
                        node, i),
                    priority,
                    protocol,
                    ttl);

                NetworkIpSendPacketOnInterfaceWithDelay(
                    node, nextMessage, CPU_INTERFACE, i, ANY_DEST, delay);
            }
        }
    }

    if (firstIndex > -1)
    {
        AddIpHeader(
           node,
           rawMessage,
           NetworkIpGetInterfaceAddress(
               node, firstIndex),
           NetworkIpGetInterfaceBroadcastAddress(
               node, firstIndex),
           priority,
           protocol,
           ttl);

         NetworkIpSendPacketOnInterfaceWithDelay(
             node, rawMessage, CPU_INTERFACE,
             firstIndex, ANY_DEST, delay);
    }
}

//-----------------------------------------------------------------------------
// MAC layer to IP, receives IP packets from the MAC layer
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpReceivePacketFromMacLayer()
// PURPOSE      IP received IP packet from MAC layer.  Determine whether
//              the packet is to be delivered to this node, or needs to
//              be forwarded.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress previousHopAddress
//                  nodeId of the previous hop.
//              int incomingInterface
//                  Index of interface on which packet arrived.
// RETURN       None.
//
// NOTES        ipHeader->ip_ttl is decremented here, instead of the
//              way BSD TCP/IP does it, which is to decrement TTL right
//              before forwarding the packet.  QualNet's alternative
//              method suits its network-layer ad hoc routing protocols,
//              which may do their own forwarding.
//-----------------------------------------------------------------------------

void
NetworkIpReceivePacketFromMacLayer(
    Node *node,
    Message *msg,
    NodeAddress previousHopAddress,
    int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    // STATS DB CODE
#ifdef ADDON_DB
    // Input the fragmented message received from the MAC layer
    HandleNetworkDBEvents(
        node,
        msg,
        incomingInterface,
        "NetworkReceiveFromLower",
        "",
        0,
        0,
        0,
        0);
#endif

#ifdef ADDON_BOEINGFCS
    RospfRedirectMetadata *redirMeta = (RospfRedirectMetadata *)
                MESSAGE_ReturnInfo(msg, INFO_TYPE_ROSPFRedirectMetadata);
    if (redirMeta != NULL)
    {
#ifdef CYBER_CORE
        if (ip->iahepEnabled && ip->iahepData->nodeType == RED_NODE)
        {
            redirMeta->incomingInterface = incomingInterface;
        }
#endif
        ERROR_Assert(redirMeta->incomingInterface != ANY_INTERFACE, 
            "Redirect metadata indicates invalid incoming interface\n");
    }
#endif

    NetworkIpReceivePacket(node,
        msg,
        previousHopAddress,
        incomingInterface);
}


#ifdef CYBER_CORE
BOOL IsMyIsakmpPacket(Node* node, unsigned char ip_p, int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    if (ip->iahepEnabled && ip->iahepData->nodeType == RED_NODE
     && (ip_p == IPPROTO_ISAKMP || ip_p == IPPROTO_ESP || ip_p == IPPROTO_AH)
     /*&& IsIAHEPIahepSecureInterface(node, incomingInterface)*/)
    {
        return TRUE;
    }
    return FALSE;
}
#endif // CYBER_CORE

void NetworkIpReceivePacket(
    Node *node,
    Message *msg,
    NodeAddress previousHopAddress,
    int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    NetworkForwardingTable* rtForward = &(ip->forwardTable);

    if (ip->isIcmpEnable)
    {
        BOOL headerError = NetworkIpHeaderCheck(node,msg,incomingInterface);
        if (headerError)
        {
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                incomingInterface,
                "NetworkPacketDrop",
                "IP Header Error",
                0,
                0,
                0,
                0);
#endif
            MESSAGE_Free(node, msg);
            ip->stats.ipInHdrErrors++;
            return;
        }

    } // if (ip->isIcmpEnable)

    ip_traceroute *ipOption = FindTraceRouteOption(ipHeader);
    if (ipOption)
    {
        if (!IsMyPacket(node, ipHeader->ip_dst))
        {
            if (ipOption->returnHopCount == 0xFFFF)
            {
                ipOption->outboundHopCount++;
                NetworkIcmpGenerateTraceroute(node,
                                              msg,
                                              ipHeader->ip_src,
                                              incomingInterface);
            }
        }
    }

    if (ipHeader->ip_p == IPPROTO_ICMP)
    {
        IcmpHeader *icmpHeader = (IcmpHeader*)
                                ((char *) ipHeader + IpHeaderSize(ipHeader));
        if (icmpHeader->icmpMessageType == ICMP_TRACEROUTE)
        {
            if (!IsMyPacket(node, ipHeader->ip_dst))
            {
                IcmpTraceRouteData *icmpData = (IcmpTraceRouteData*)
                                ((char *) icmpHeader + sizeof(IcmpHeader));
                icmpData->returnHopCount++;
            }
        }
    }

    IpOptionsHeaderType *recordRouteOption =
                                  IpHeaderRecordRouteOptionField(ipHeader);
    if (recordRouteOption)
    {
        if (recordRouteOption->ptr < recordRouteOption->len)
        {
            char *currentAddress = (char *)recordRouteOption;
            currentAddress = currentAddress + recordRouteOption->ptr -1;
            NodeAddress ipAddr = MAPPING_GetInterfaceAddressForInterface(
                                    node, node->nodeId, incomingInterface);
            memcpy (currentAddress, (char *)&ipAddr, sizeof(NodeAddress));
            recordRouteOption->ptr += sizeof(NodeAddress);
        }
    }

    IpOptionsHeaderType *timeStampOption =
                                  IpHeaderTimestampOptionField(ipHeader);
    if (timeStampOption)
    {
        if (timeStampOption->ptr < timeStampOption->len)
        {
            clocktype now;
            int time;
            ip_timestamp_str *timeStamp =
                                       (ip_timestamp_str *)timeStampOption;
            char *pointer = (char *)timeStampOption;
            now = WallClock::getTrueRealTime();
            time = (int)now / MILLI_SECOND;
            pointer = pointer + timeStampOption->ptr -1;
            NodeAddress ipAddr = MAPPING_GetInterfaceAddressForInterface(
                                    node, node->nodeId, incomingInterface);

            if (Ip_timestampGetFlag(timeStamp->flgOflw) == 0)
            {
                memcpy(pointer, &time, sizeof(int));
                timeStampOption->ptr += sizeof(int);
            }
            if (Ip_timestampGetFlag(timeStamp->flgOflw) == 1)
            {
                memcpy(pointer, &ipAddr, sizeof(NodeAddress));
                pointer += sizeof(NodeAddress);
                memcpy(pointer, &time, sizeof(int));
                timeStampOption->ptr += (sizeof(int) + sizeof(NodeAddress));
            }
            if (Ip_timestampGetFlag(timeStamp->flgOflw) == 3)
            {
                NodeAddress addressPresent = *(NodeAddress *)pointer;
                if (addressPresent == ipAddr)
                {
                    pointer += sizeof(NodeAddress);
                    memcpy(pointer, &time, sizeof(int));
                    timeStampOption->ptr += (sizeof(int) +
                                                        sizeof(NodeAddress));
                }
            }

        } // if (timeStampOption->ptr < timeStampOption->len)

    } // if (timeStampOption)

    NetworkType netType = NETWORK_IPV4;
    ActionData acnData;

#ifdef PAS_INTERFACE
    if (PAS_LayerCheck(node, incomingInterface, PACKET_SNIFFER_ETHERNET))
    {
        if (IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) !=
          (unsigned)MESSAGE_ReturnPacketSize(msg))
        {
/*
            if (MESSAGE_ReturnPacketSize(msg) >2044)
            {
                printf(" %d: %d\n",
                IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len),
                MESSAGE_ReturnPacketSize(msg));
            }
*/
            PAS_IPv4(node, ipHeader, previousHopAddress,
                MESSAGE_ReturnPacketSize(msg));
        }
        else
        PAS_IPv4(node, ipHeader, previousHopAddress);

    } // if (PAS_LayerCheck(node, ... )
#endif

#if defined(ADDON_BOEINGFCS)
    HandleNetworkIpStats(node, ip, msg, incomingInterface, TRUE);
#endif

#ifdef ENTERPRISE_LIB
    // check the packet with the access list criteria
    if (ip->interfaceInfo[incomingInterface]->accessListInPointer)
    {
        if (AccessListFilterPacket(
                node,
                msg,
                ip->interfaceInfo[incomingInterface]->accessListInPointer,
                incomingInterface,
                ACCESS_LIST_IN))
        {
            // has matched, so drop and return
            //Trace drop
            acnData.actionType = DROP;
            acnData.actionComment = DROP_ACCESS_LIST;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_NETWORK_LAYER,
                             PACKET_IN,
                             &acnData,
                             netType);

            return;
        }
    }
#endif // ENTERPRISE_LIB

#ifdef CYBER_CORE
    NodeAddress sourceAddress = 0;
    unsigned char ipProtocolNumber;
    unsigned ttl =0;
    TosType priority;

    BOOL packetWasRouted = FALSE;
    RouterFunctionType routerFunction = NULL;
    map<NodeAddress,NodeAddress>::iterator it;

    if (ip->iahepEnabled && ip->iahepData->nodeType == IAHEP_NODE)
    {
        if (IsIAHEPBlackSecureInterface(node, incomingInterface))
        {
            if (ipHeader->ip_p == IPPROTO_ICMP)
            {
                MESSAGE_Free (node, msg);
                return;
            }
            if ((IpHeaderGetIpFragOffset(ipHeader->ipFragment) !=0)
                || IpHeaderGetIpMoreFrag(ipHeader->ipFragment))
            {
                BOOL isReassembled = FALSE;
                Message* joinedMsg = NULL;
                joinedMsg = IpFragmentInput(node, msg, incomingInterface,
                    &isReassembled);
                if (isReassembled)
                {
                    msg = joinedMsg;
                    ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
                }
                else
                {
                    return;
                }
            }
        }

        if ((ip->iahepData->IGMPIsByPassMode)&&(ipHeader->ip_p == IPPROTO_IGMP))
        {
            NodeAddress mappedGrpAddr = 0;
            int outIntf = ANY_INTERFACE;
            IgmpMessage *igmpPkt = (IgmpMessage*) (MESSAGE_ReturnPacket(msg)+
                sizeof(IpHeaderType));

            if (IsIAHEPRedSecureInterface(node, incomingInterface))
            {
                mappedGrpAddr = IAHEPGetMulticastBroadcastAddressMapping(
                                node, ip->iahepData, igmpPkt->groupAddress);
                igmpPkt->groupAddress = mappedGrpAddr;
                outIntf = IAHEPGetIAHEPBlackInterfaceIndex(node);
            }
            else if (IsIAHEPBlackSecureInterface(node, incomingInterface))
            {
                if (igmpPkt->groupAddress)
                {
                    for (it=ip->iahepData->multicastAmdMapping->begin();
                    it != ip->iahepData->multicastAmdMapping->end(); it++)
                    {
                        if ((*it).second == igmpPkt->groupAddress)
                        {
                            mappedGrpAddr = (*it).first;
                            igmpPkt->groupAddress = mappedGrpAddr;
                        }
                    }

                    if (!mappedGrpAddr)
                    {
                        mappedGrpAddr = mappedGrpAddr
                            - DEFAULT_RED_BLACK_MULTICAST_MAPPING;
                        igmpPkt->groupAddress = mappedGrpAddr;
                    }
                }
                outIntf = IAHEPGetIAHEPRedInterfaceIndex(node);
            }

            NetworkIpSendPacketOnInterface(
                node,
                msg,
                CPU_INTERFACE,
                outIntf,
                0);
            return;

        } // if ((ip->iahepData->IGMPIsByPassMode) && ... )

        if (IAHEPProcessingRequired(ipHeader->ip_p))
        {

            routerFunction = NetworkIpGetRouterFunction(node,
                incomingInterface);

            if (routerFunction)
            {
                (routerFunction)(node,
                    msg,
                    ipHeader->ip_dst,
                    previousHopAddress,
                    &packetWasRouted);
            }
            return;
        }

    } // if (ip->iahepEnabled && ... )

    //If required, reassembly is performed prior to ESP/AH processing.
    // Handle packet to security protocol if IpSec enable over
    // this interface
    if ((ip->interfaceInfo[incomingInterface]->spdIN) &&
        (ipHeader->ip_p == IPPROTO_ESP ||
        ipHeader->ip_p == IPPROTO_AH))
    {
        if ((IpHeaderGetIpFragOffset(ipHeader->ipFragment) != 0) ||
            IpHeaderGetIpMoreFrag(ipHeader->ipFragment))
        {
            // first reassemble the packet
            BOOL isReassembled = FALSE;
            Message* joinedMsg = NULL;
            joinedMsg = IpFragmentInput(node,
                                        msg,
                                        incomingInterface,
                                        &isReassembled);
            if (isReassembled)
            {
                msg = joinedMsg;
                ipHeader = (IpHeaderType*) msg->packet;
                if (IPsecRequireProcessing(node,
                                           msg,
                                           incomingInterface))
                {
                    IPsecHandleInboundPacket(node,
                                             msg,
                                             incomingInterface,
                                             previousHopAddress);
                    return;
                }
            }
            else
            {
                return;
            }
        }
        else
        {
            if (ip->interfaceInfo[incomingInterface]->spdIN &&
                IPsecRequireProcessing(node, msg, incomingInterface))
            {
                IPsecHandleInboundPacket(node,
                                         msg,
                                         incomingInterface,
                                         previousHopAddress);

                return;
            }
        }

    } // if ((ip->interfaceInfo[incomingInterface]->spdIN) && ... )

    if (ip->iahepEnabled && ip->iahepData->nodeType == RED_NODE &&
        ipHeader->ip_p == IPPROTO_ESP)
    {
        if (!ip->interfaceInfo[incomingInterface]->spdIN ||
            !IPsecRequireProcessing(
                node,
                msg,
                incomingInterface))
        {
            //This Is Tunnel End Point & Ds Not Have SP:Invalid Configuration
            char errorString[MAX_STRING_LENGTH];
            sprintf(errorString,
                "Node [%d] Is Tunnel End Point,"
                "And Does Not Have SP or SA: Invalid Configuration\n",
                node->nodeId);
            ERROR_ReportWarning(errorString);

#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                incomingInterface,
                "NetworkPacketDrop",
                "No SP or SA At Tunnel End",
                0,
                0,
                0,
                0);
#endif
            MESSAGE_Free(node, msg);
            return;
        }

    } // if (ip->iahepEnabled && ip->iahepData->nodeType == RED_NODE && ... )
#endif //CYBER_CORE

#ifdef STK_INTERFACE
    if (ipHeader->ip_dst != ANY_DEST)
    {
        StkDrawLine(node, -1, previousHopAddress, "blue");
    }
#endif /* STK_INTERFACE */

//GuiStart
    if ((node->guiOption == TRUE))
    {
        BOOL showReceive = TRUE;

        // check the configuration option on whether or not we want to display
        // ROSPF control traffic
#ifdef ADDON_BOEINGFCS
        if (node->guiOption == TRUE &&
            ipHeader->ip_dst != ANY_DEST &&
            !NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
            {
                NodeId sourceId;
                sourceId = MAPPING_GetNodeIdFromInterfaceAddress
                    (node, previousHopAddress);
#ifdef EXATA
                if (msg->isEmulationPacket)
                {
                    GUI_Unicast(sourceId,
                        node->nodeId,
                        GUI_NETWORK_LAYER,
                        GUI_EMULATION_DATA_TYPE,
                        incomingInterface,
                        incomingInterface,
                        getSimTime(node));
                }
                else
                {
                    GUI_Unicast(sourceId,
                        node->nodeId,
                        GUI_NETWORK_LAYER,
                        GUI_DEFAULT_DATA_TYPE,
                        incomingInterface,
                        incomingInterface,
                        getSimTime(node));

                }
#else
                    GUI_Unicast(sourceId,
                        node->nodeId,
                        GUI_NETWORK_LAYER,
                        GUI_DEFAULT_DATA_TYPE,
                        incomingInterface,
                        incomingInterface,
                        getSimTime(node));

#endif
            }// End of if (node->guiOption == TRUE)

        showReceive = RoutingCesRospfShowReceived(node, incomingInterface, msg);
#endif
        if (showReceive)
        {
            NodeAddress previousHopNodeId;

            previousHopNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                                              node,
                                                              previousHopAddress);
            //
            // Receive a packet from MAC, using VT to display.

            // Due to the IPv6 related changes according to the GUI team proposal
            // this function will expect sending interface and receiving interface
            // Right now previousHopAddress is used at sending interface, yet to
            // be decided by GUI team
            //
#ifdef EXATA
            if (msg->isEmulationPacket)
            {
                GUI_Receive(previousHopNodeId,
                    node->nodeId,
                    GUI_NETWORK_LAYER,
                    GUI_EMULATION_DATA_TYPE,
                    MAPPING_GetInterfaceIndexFromInterfaceAddress(
                            node,
                            previousHopAddress),
                    incomingInterface,
                    getSimTime(node) + getSimStartTime(node));
            }
            else
            {
                GUI_Receive(previousHopNodeId,
                    node->nodeId,
                    GUI_NETWORK_LAYER,
                    GUI_DEFAULT_DATA_TYPE,
                    MAPPING_GetInterfaceIndexFromInterfaceAddress(
                            node,
                            previousHopAddress),
                    incomingInterface,
                    getSimTime(node) + getSimStartTime(node));
            }
#else
            GUI_Receive(previousHopNodeId,
                    node->nodeId,
                    GUI_NETWORK_LAYER,
                    GUI_DEFAULT_DATA_TYPE,
                    MAPPING_GetInterfaceIndexFromInterfaceAddress(
                            node,
                            previousHopAddress),
                    incomingInterface,
                    getSimTime(node) + getSimStartTime(node));

#endif
            if (GUI_IsAppHopByHopFlowEnabled())
            {
                NodeId dst = ipHeader->ip_dst;
                NodeId src = MAPPING_GetNodeIdFromInterfaceAddress(node,
                    ipHeader->ip_src);

                if (ipHeader->ip_dst != ANY_DEST &&
                    !NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
                {
                    dst = MAPPING_GetNodeIdFromInterfaceAddress(node,
                        ipHeader->ip_dst);
                }

                GUI_AppHopByHopFlow(msg->originatingProtocol, src, dst,
                    previousHopNodeId, node->nodeId,
                    getSimTime(node) + getSimStartTime(node));
            }
        } // if (showReceive)

    } // if ((node->guiOption == TRUE))
//GuiEnd

    // Increment stat for total number of received IP datagrams from all
    // interfaces.

    ip->stats.ipInReceives++;
    if (node->networkData.networkStats)
    {
        ip->newStats->AddPacketReceivedFromMacDataPoints(
            node,
            msg,
            StatsApiAddrType(node, msg),
            incomingInterface,
            IsDataPacket(msg, ipHeader));
    }
    IpOptionsHeaderType *sourceRouteOption =
                                  IpHeaderSourceRouteOptionField(ipHeader);
    if (sourceRouteOption)
    {
        BOOL packetIsSourceRouted = FALSE;
        packetIsSourceRouted = SourceRouteThePacket(node,
                                                    msg,
                                                    incomingInterface);
        if (packetIsSourceRouted)
        {
            return;
        }
    }

#ifdef ADDON_DB
    //HandleStatsDBNetworkAggregateUpdate(node,
    //    msg,
    //    FALSE,
    //    incomingInterface);

    //HandleStatsDBNetworkSummaryInUpdate(node, msg,
    //        previousHopAddress, incomingInterface) ;

    HandleStatsDBNetworkInUpdate(node, msg,
        previousHopAddress, incomingInterface);
#endif

    // trace recd pkt
    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node,
                     msg,
                     TRACE_NETWORK_LAYER,
                     PACKET_IN,
                     &acnData,
                     netType);

    // Whenever a multicast packet received at a node
    // the membership status of that node with specified group
    // is checked and if required the packet is delivered to
    // the upper layer
    if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
    {
        //For wireless scenarios the received packet may be duplicate
        // thus check the type of multicast protocl running
        // in incoming interface to prevent the duplicate delivery
        // to the upper layer.

        switch (ip->interfaceInfo[incomingInterface]->multicastProtocolType)
        {
#ifdef WIRELESS_LIB
            case MULTICAST_PROTOCOL_ODMRP:
            {
                if (OdmrpCheckIfItIsDuplicatePacket(node, msg))
                {
                    //Trace drop
                    acnData.actionType = DROP;
                    acnData.actionComment = DROP_DUPLICATE_PACKET;
                    TRACE_PrintTrace(node,
                                     msg,
                                     TRACE_NETWORK_LAYER,
                                     PACKET_IN,
                                     &acnData,
                                     netType);
#ifdef ADDON_DB

                    HandleNetworkDBEvents(
                        node,
                        msg,
                        incomingInterface, // use incoming interface here
                        "NetworkPacketDrop",
                        "Duplicate Multicast Packet, ODMRP",
                        0,
                        0,
                        0,
                        0);
#endif
                    // It is a duplicate packet no need to process it
                    MESSAGE_Free(node, msg);
                    return;
                }
                break;
            }
#endif // WIRELESS_LIB
#ifdef ADDON_BOEINGFCS
            case MULTICAST_PROTOCOL_PIM:
            {
                if (MulticastCesRpimCheckIfItIsDuplicatePacket(node,
                    incomingInterface, msg) ||
                    RPimCheckIfItIsDuplicatePacket(node, incomingInterface, msg))
                {
#ifdef ADDON_DB

                    HandleNetworkDBEvents(
                        node,
                        msg,
                        incomingInterface, // use incoming interface here
                        "NetworkPacketDrop",
                        "Duplicate Multicast Packet, RPIM",
                        0,
                        0,
                        0,
                        0);
#endif
                    MESSAGE_Free(node, msg);
                    return;
                }
                break;
            }
#endif
            default:
            {
                break;
            }

        } // switch (ip->interfaceInfo[incomingInterface]->multicastProtocolType)

    } // if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))

    // IsMyPacket() determines whether the packet should be delivered or
    // forwarded.  IsMyPacket() checks multicast subscriptions as well
    // as the host and broadcast addresses of all local interfaces.
    if (IsMyPacket(node, ipHeader->ip_dst) ||
        IsIgmpPacket(node, ipHeader->ip_p)
#ifdef CYBER_CORE
        /*|| IsMyIsakmpPacket(node, ipHeader->ip_p, incomingInterface)*/
#ifdef CYBER_LIB
        // ANODR does not rely on explict IP addresses
        || (ipHeader->ip_dst == ANONYMOUS_IP && IsMyAnodrDataPacket(node, msg))
#endif // CYBER_LIB
#endif // CYBER_CORE
        )
    {
        // Deliver IP packet to node.
        //
        // (We actually deliver a copy of the message instead of the
        // original.  This is in case the packet is multicast, one copy
        // of which is delivered, and the other copy, forwarded.)

        // Need to go through the backplane to the processor first before
        // deliverying data to higher layers...
        BOOL isMulticast = NetworkIpIsMulticastAddress(node, ipHeader->ip_dst);
#ifdef CYBER_CORE
//BROADCAST_IAHEP_START
        BOOL isAppBroadCast = NetworkIpNeedsToForwardAppBroadcast(node,
                                                            msg,
                                                            ipHeader->ip_dst);

        BOOL isDuplicateAppBroadCast = FALSE;
        if (isAppBroadCast)
        {
            isDuplicateAppBroadCast =
                    NetworkIpCheckDuplicateAppBroadcastReceived(node, msg);
        }


        Message* sendMessage = msg;
        if (isMulticast || (isAppBroadCast &&
                            isDuplicateAppBroadCast == FALSE))
        {
//BROADCAST_IAHEP_END
            sendMessage = MESSAGE_Duplicate(node, msg);
        }

        if (isDuplicateAppBroadCast == FALSE)
        {
            NetworkIpSendOnBackplane(node,
                                 sendMessage,
                                 incomingInterface,
                                 CPU_INTERFACE,
                                 previousHopAddress);
        }

#else //CYBER_CORE
        Message* sendMessage = msg;
        if (isMulticast)
        {
            sendMessage = MESSAGE_Duplicate(node, msg);
        }

        NetworkIpSendOnBackplane(node,
                                 sendMessage,
                                 incomingInterface,
                                 CPU_INTERFACE,
                                 previousHopAddress);
#endif //CYBER_CORE

        if (isMulticast)
        {
            // Destination address is multicast address, so pass packet
            // to forwarding process for potential multicast routing.

#ifdef ADDON_BOEINGFCS
            if ((ip->interfaceInfo[incomingInterface]->multicastProtocolType
                == MULTICAST_PROTOCOL_PIM && (MulticastCesRpimDmInterfaceEnabled(node,
                incomingInterface) || MulticastCesRpimActiveOnInterface(node,
                         incomingInterface)))  ||
                (ip->interfaceInfo[incomingInterface]->multicastProtocolType
                == MULTICAST_PROTOCOL_CES_SRW_MOSPF))
            {
                ForwardPacket(node, msg, incomingInterface, previousHopAddress);
            }
            else
            {
                ForwardPacket(node, msg, incomingInterface, ANY_IP);
            }
#else
#ifdef ADDON_DB
            ForwardPacket(node,msg,incomingInterface,previousHopAddress);
#else
            ForwardPacket(node, msg, incomingInterface, ANY_IP);
#endif // ADDON_DB
#endif // ADDON_BOEINGFCS
        } // if (isMulticast)
#ifdef CYBER_CORE
        if (!(ip->iahepEnabled) &&
            (isAppBroadCast && isDuplicateAppBroadCast == FALSE))
        {
            ForwardPacket(node, msg, incomingInterface, ANY_IP);
        }
#endif // CYBER_CORE
    } // if (IsMyPacket(node, ipHeader->ip_dst) || ... )
    else
    {
        // Forward packet.
        ForwardPacket(node, msg, incomingInterface, previousHopAddress);

    }

}

//-----------------------------------------------------------------------------
// MAC-layer packet drop callbacks
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpNotificationOfPacketDrop()
// PURPOSE      Invoke callback functions when a packet is dropped.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message.
//              NodeAddress nextHopAddress,
//                  next hop address of dropped packet.
//              int interfaceIndex
//                  interface that experienced the packet drop.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpNotificationOfPacketDrop(Node *node,
                                  Message *msg,
                                  NodeAddress nextHopAddress,
                                  int interfaceIndex)
{
    // Totally Evil hack under new "subroutine" based layer
    // communication.

    IpHeaderType *ipHeader =
        (IpHeaderType *)MESSAGE_ReturnPacket(msg);
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    if (ip->isIcmpEnable &&
      (icmp->hostUnreachableEnable || icmp->networkUnreachableEnable))
    {
        unsigned short icmpCode = 0;
        BOOL ICMPErrorMsgCreated = FALSE;
        if (NetworkIpGetInterfaceIndexForNextHop(node,ipHeader->ip_dst)
                                                 == -1 &&
                                          icmp->networkUnreachableEnable)
        {
            icmpCode = ICMP_NETWORK_UNREACHABLE;
            ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                  msg,
                                  ipHeader->ip_src,
                                  ANY_INTERFACE,
                                  ICMP_DESTINATION_UNREACHABLE,
                                  icmpCode,
                                  0,
                                  0);
        }
        else if (NetworkIpGetInterfaceIndexForNextHop(node,
                                              ipHeader->ip_dst) != -1 &&
                                            icmp->hostUnreachableEnable)
        {
            icmpCode = ICMP_HOST_UNREACHABLE;
            ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                  msg,
                                  ipHeader->ip_src,
                                  ANY_INTERFACE,
                                  ICMP_DESTINATION_UNREACHABLE,
                                  icmpCode,
                                  0,
                                  0);
        }

        if (ICMPErrorMsgCreated)
        {
            if (icmpCode == ICMP_NETWORK_UNREACHABLE)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                printf("Node %d sending network unreachable message to %s\n",
                                    node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpNetworkUnreacableSent)++;
            }
            else if (icmpCode == ICMP_HOST_UNREACHABLE)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                printf("Node %d sending host unreachable message to %s\n",
                                    node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpHostUnreacableSent)++;
            }
        }
    }
    //if the packet is an ipv6 packet encapsulated on this interface
    // send notification to the tunneling interface also.
    if ((ipHeader->ip_p == IPPROTO_IPV6) &&
                (NetworkIpGetInterfaceAddress(
                        node, interfaceIndex) == ipHeader->ip_src))
    {
        TunnelNotificationOfIPV6PacketDrop(
                node, MESSAGE_Duplicate(node, msg), interfaceIndex);
    }

    MESSAGE_SetLayer(msg, NETWORK_LAYER, ROUTING_PROTOCOL_ALL);
    MESSAGE_SetEvent(msg, MSG_NETWORK_PacketDropped);
    MESSAGE_SetInstanceId(msg, 0);

    // trace for interface Fault
    ActionData acnData;
    acnData.actionType = DROP;
    acnData.actionComment = DROP_INTERFACE_DOWN;
    TRACE_PrintTrace(node,
                    msg,
                    TRACE_NETWORK_LAYER,
                    PACKET_IN,
                    &acnData,
                    NETWORK_IPV4);

    HandleSpecialMacLayerStatusEvents(node,
                                      msg,
                                      nextHopAddress,
                                      interfaceIndex);

}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetMacLayerStatusEventHandlerFunction()
// PURPOSE      Get the status event handler function pointer.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  interface associated with the status handler function.
// RETURN       Status event handler function.
//-----------------------------------------------------------------------------

MacLayerStatusEventHandlerFunctionType
NetworkIpGetMacLayerStatusEventHandlerFunction(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    return ip->interfaceInfo[interfaceIndex]->
                                             macLayerStatusEventHandlerFunction;
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSetMacLayerStatusEventHandlerFunction()
// PURPOSE      Allows the MAC layer to send status messages (e.g.,
//              packet drop, link failure) to a network-layer routing
//              protocol for routing optimization.
// PARAMETERS   Node *node
//                  Pointer to node.
//              MacLayerStatusEventHandlerFunctionType StatusEventHandlerPtr
//                  Status event handler function to call.
//              int interfaceIndex
//                  interface associated with the status event handler.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSetMacLayerStatusEventHandlerFunction(
    Node *node,
    MacLayerStatusEventHandlerFunctionType StatusEventHandlerPtr,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ERROR_Assert(ip->interfaceInfo[interfaceIndex]->
                     macLayerStatusEventHandlerFunction == NULL,
                 "MAC-layer event handler function already set");

    ip->interfaceInfo[interfaceIndex]->macLayerStatusEventHandlerFunction =
                                                         StatusEventHandlerPtr;
}


//---------------------------------------------------------------------------
// Mac layer acknowledgement handlers
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// FUNCTION     NetworkIpGetMacLayerAckHandler
// PURPOSE      Get MAC layer ACK handler
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Interface associated with the ACK handler function.
// RETURN       ACK event handler function.
//---------------------------------------------------------------------------

MacLayerAckHandlerType
NetworkIpGetMacLayerAckHandler(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    return ip->interfaceInfo[interfaceIndex]->macAckHandler;
}


//---------------------------------------------------------------------------
// FUNCTION     NetworkIpReceiveMacAck
// PURPOSE      MAC received an ACK, so call ACK handler function.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Interface associated with the ACK handler function.
//              const Message *msg
//                  Message that was ACKed.
//              NodeAddress nextHop
//                  Next hop that sent the MAC layer ACK.
// RETURN       None
//---------------------------------------------------------------------------

void
NetworkIpReceiveMacAck(
    Node* node,
    int interfaceIndex,
    const Message* msg,
    NodeAddress nextHop)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    if (ip->checkMacAckHandler != FALSE)
    {
        MacLayerAckHandlerType macAckHandler
            = NetworkIpGetMacLayerAckHandler(
                  node, interfaceIndex);

        if (macAckHandler)
        {
            (macAckHandler)(node, interfaceIndex, msg, nextHop);
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     NetworkIpSetMacLayerAckHandler
// PURPOSE      Set MAC layer ACK handler
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Interface associated with the ACK handler function.
// RETURN       None
//---------------------------------------------------------------------------

void
NetworkIpSetMacLayerAckHandler(
    Node *node,
    MacLayerAckHandlerType macAckHandlerPtr,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ERROR_Assert(ip->interfaceInfo[interfaceIndex]->
                     macAckHandler == NULL,
                     "Mac Ack handling function already set");

    ip->interfaceInfo[interfaceIndex]->macAckHandler = macAckHandlerPtr;

    ip->checkMacAckHandler = TRUE;
}


//-----------------------------------------------------------------------------
// MAC-layer promiscuous mode callbacks
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSneakPeekAtMacPacket()
// PURPOSE      Called Directly by the MAC layer, this allows a routing
//              protocol to "sneak a peek" or "tap" messages it would not
//              normally see from the MAC layer.  This function will
//              possibly unfragment such packets and call the function
//              registered by the routing protocol to do the "Peek".
// PARAMETERS   Node *node
//                  Pointer to node.
//              const Message *msg
//                  The message being peeked at from the MAC layer.
//                  Must not be freed or modified!
//              int interface
//                  The interface of which the "peeked" message belongs to.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSneakPeekAtMacPacket(Node *node,
                              const Message *msg,
                              int interfaceIndex,
                              MacHWAddress& prevHopHwAddr)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    IpHeaderType* ipHeader = (IpHeaderType *)MESSAGE_ReturnPacket(msg);

    if (IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len) != IPVERSION4)
    {
        // TBD: NetworkIpv6SneakPeekAtMacPacket(
        // node, msg, interfaceIndex, prevHop);
        return;
    }
   NodeAddress prevHop = MacHWAddressToIpv4Address(node,
                                                      interfaceIndex,
                                                      &prevHopHwAddr);

#ifdef CYBER_LIB
    IpInterfaceInfoType* intf =
        (IpInterfaceInfoType*)ip->interfaceInfo[interfaceIndex];

    // Eavesdropping record
    if (intf->eavesdropFile != NULL)
    {
        IpHeaderType *ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
        char addr1[20];
        char addr2[20];
        char now[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(getSimTime(node), now);
        fprintf(intf->eavesdropFile, "<simtime>%s</simtime>", now);

        fprintf(intf->eavesdropFile, "<ipv4>");

        fprintf(intf->eavesdropFile,
                "%hu %hu %hX %hu %hu",
                IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len),
                IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len),
                IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
                MESSAGE_ReturnPacketSize(msg),
                ipHeader->ip_id);

        fprintf(intf->eavesdropFile,
                " <flags>%hu %hu %hu</flags>",
                IpHeaderGetIpReserved(ipHeader->ipFragment),
                IpHeaderGetIpDontFrag(ipHeader->ipFragment),
                IpHeaderGetIpMoreFrag(ipHeader->ipFragment));

        IO_ConvertIpAddressToString(ipHeader->ip_src, addr1);
        IO_ConvertIpAddressToString(ipHeader->ip_dst, addr2);
        fprintf(intf->eavesdropFile,
                " %hu %hu %hu %hu %s %s",
                IpHeaderGetIpFragOffset(ipHeader->ipFragment),
                ipHeader->ip_ttl,
                ipHeader->ip_p,
                ipHeader->ip_sum,
                addr1,
                addr2);

        fprintf(intf->eavesdropFile,
                "</ipv4>\n");
    }

    // promiscuousMessagePeekFunction doesn't have interfaceIndex,
    // which should be fixed.  Currently let's call CBS directly.
    //if (ip->isSecureCommunityEnabled)
    //{
    //SecureCommunityPeekFunction(node, msg, interfaceIndex, prevHop);
    //}
#ifdef AUTO_IPNE_INTERFACE
    if ((node->macData[interfaceIndex]->isIpneInterface))
    {
        Message* dupMsg = MESSAGE_Duplicate(node, msg);
        /*IpHeaderType* dupHeader = (IpHeaderType *) MESSAGE_ReturnPacket(dupMsg);
        dupHeader->ip_dst = MAPPING_GetInterfaceAddressForInterface(
                                            node,
                                            node->nodeId,
                                            interfaceIndex);*/

        AutoIPNE_ForwardFromNetworkLayer(node, 
                                         interfaceIndex, 
                                         dupMsg, 
                                         prevHop, 
                                         TRUE);
    }
    else if ((node->partitionData->rrInterface->GetReplayMode()) && 
           (node->macData[interfaceIndex]->isReplayInterface))
    {
        Message* dupMsg = MESSAGE_Duplicate(node, msg);
        node->partitionData->rrInterface->
                        ReplayForwardFromNetworkLayer(node, 
                                                      interfaceIndex, 
                                                      dupMsg, 
                                                      TRUE);
    }
#endif
#endif // CYBER_LIB
    if (ip->checkMessagePeekFunction != FALSE)
    {
        PromiscuousMessagePeekFunctionType promiscuousMessagePeekFunction
            = NetworkIpGetPromiscuousMessagePeekFunction(
                  node, interfaceIndex);

        if (promiscuousMessagePeekFunction)
        {
            (promiscuousMessagePeekFunction)(node, msg, prevHop);
        }

    }//if//

}//NetworkIpSneakPeekAtMacPacket//

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetPromiscuousMessagePeekFunction()
// PURPOSE      Returns the network-layer function which will
//              promiscuously inspect packets.
//              See NetworkIpSneakPeekAtMacPacket().
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Interface associated with the peek function.
// RETURN       Peek function.
//-----------------------------------------------------------------------------

PromiscuousMessagePeekFunctionType
NetworkIpGetPromiscuousMessagePeekFunction(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    return ip->interfaceInfo[interfaceIndex]->promiscuousMessagePeekFunction;
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSetPromiscuousMessagePeekFunction()
// PURPOSE      Sets the network-layer function which will
//              promiscuously inspect packets.
//              See NetworkIpSneakPeekAtMacPacket().
// PARAMETERS   Node *node
//                  Pointer to node.
//              PromiscuousMessagePeekFunctionType PeekFunctionPtr
//                  Peek function.
//              int interfaceIndex
//                  Interface associated with the peek function.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSetPromiscuousMessagePeekFunction(
    Node *node,
    PromiscuousMessagePeekFunctionType PeekFunctionPtr,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ERROR_Assert(ip->interfaceInfo[interfaceIndex]->
                     promiscuousMessagePeekFunction == NULL,
                 "Promiscuous function already set");

    ip->interfaceInfo[interfaceIndex]->promiscuousMessagePeekFunction =
                                                               PeekFunctionPtr;

    ip->checkMessagePeekFunction = TRUE;
}

//-----------------------------------------------------------------------------
// Network layer to transport layer
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     SendToUdp()
// PURPOSE      Sends a UDP packet to UDP in the transport layer.
//              The source IP address, destination IP address, and
//              priority of the packet are also sent.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with UDP packet.
//              TosType priority
//                  Priority of UDP packet.
//              NodeAddress sourceAddress
//                  Source IP address.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int incomingInterfaceIndex
//                  interface that received the packet.
// RETURN       None.
//-----------------------------------------------------------------------------

void
SendToUdp(
    Node *node,
    Message *msg,
    TosType priority,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    int incomingInterfaceIndex)
{
    NetworkToTransportInfo *infoPtr;

    MESSAGE_SetEvent(msg, MSG_TRANSPORT_FromNetwork);
    MESSAGE_SetLayer(msg, TRANSPORT_LAYER, TransportProtocol_UDP);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_InfoAlloc(node, msg, sizeof(NetworkToTransportInfo));

    infoPtr = (NetworkToTransportInfo *) MESSAGE_ReturnInfo(msg);

    SetIPv4AddressInfo(&infoPtr->sourceAddr, sourceAddress);
    SetIPv4AddressInfo(&infoPtr->destinationAddr, destinationAddress);

    infoPtr->priority = priority;
    infoPtr->incomingInterfaceIndex = incomingInterfaceIndex;

    MESSAGE_Send(node, msg, PROCESS_IMMEDIATELY);
}

//-----------------------------------------------------------------------------
// FUNCTION     SendToTcp()
// PURPOSE      Same as SendToUdp(), except TCP packet.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with TCP packet.
//              TosType priority
//                  Priority of UDP packet.
//              NodeAddress sourceAddress
//                  Source IP address.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              BOOL aCongestionExperienced
//                  Determine if congestion is experienced (via ECN).
// RETURN       None.
//-----------------------------------------------------------------------------

void
SendToTcp(
    Node *node,
    Message *msg,
    TosType priority,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    BOOL aCongestionExperienced)
{
    NetworkToTransportInfo *infoPtr;

    MESSAGE_SetEvent(msg, MSG_TRANSPORT_FromNetwork);
    MESSAGE_SetLayer(msg, TRANSPORT_LAYER, TransportProtocol_TCP);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_InfoAlloc(node, msg, sizeof(NetworkToTransportInfo));

    infoPtr = (NetworkToTransportInfo *) MESSAGE_ReturnInfo(msg);

    SetIPv4AddressInfo(&infoPtr->sourceAddr, sourceAddress);
    SetIPv4AddressInfo(&infoPtr->destinationAddr, destinationAddress);

    infoPtr->priority = priority;
    infoPtr->isCongestionExperienced = aCongestionExperienced;

    MESSAGE_Send(node, msg, PROCESS_IMMEDIATELY);
}

//-----------------------------------------------------------------------------
// FUNCTION     SendToRsvp()
// PURPOSE      Same as SendToUdp(), except RSVP packet.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with RSVP packet.
//              TosType priority
//                  Priority of UDP packet.
//              NodeAddress sourceAddress
//                  Source IP address.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int interfaceIndex
//                  Incoming interface index
//              unsigned ttl
//                  Receiving TTL
// RETURN       None.
//-----------------------------------------------------------------------------

void
SendToRsvp(
    Node *node,
    Message *msg,
    TosType priority,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    int interfaceIndex,
    unsigned ttl)
{
    NetworkToTransportInfo *infoPtr;

    MESSAGE_SetEvent(msg, MSG_TRANSPORT_FromNetwork);
    MESSAGE_SetLayer(msg, TRANSPORT_LAYER, TransportProtocol_RSVP);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_InfoAlloc(node, msg, sizeof(NetworkToTransportInfo));

    infoPtr = (NetworkToTransportInfo *) MESSAGE_ReturnInfo(msg);

    SetIPv4AddressInfo(&infoPtr->sourceAddr, sourceAddress);
    SetIPv4AddressInfo(&infoPtr->destinationAddr, destinationAddress);

    infoPtr->priority = priority;
    infoPtr->incomingInterfaceIndex = interfaceIndex;
    infoPtr->receivingTtl = ttl;

    MESSAGE_Send(node, msg, PROCESS_IMMEDIATELY);
}

//-----------------------------------------------------------------------------
// FUNCTION     SendToTransport()
// PURPOSE      Same as SendToUdp(), except designer transport protocol packet.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with RSVP packet.
//              TosType priority
//                  Priority of UDP packet.
//              NodeAddress sourceAddress
//                  Source IP address.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int interfaceIndex
//                  Incoming interface index
//              unsigned ttl
//                  Receiving TTL
// RETURN       None.
//-----------------------------------------------------------------------------

void
SendToTransport(
    Node *node,
    Message *msg,
    TosType priority,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    int interfaceIndex,
    unsigned ttl,
    TransportProtocol protocolType)
{
    NetworkToTransportInfo *infoPtr;

    MESSAGE_SetEvent(msg, MSG_TRANSPORT_FromNetwork);
    MESSAGE_SetLayer(msg, TRANSPORT_LAYER, (short)protocolType);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_InfoAlloc(node, msg, sizeof(NetworkToTransportInfo));

    infoPtr = (NetworkToTransportInfo *) MESSAGE_ReturnInfo(msg);

    SetIPv4AddressInfo(&infoPtr->sourceAddr, sourceAddress);
    SetIPv4AddressInfo(&infoPtr->destinationAddr, destinationAddress);

    infoPtr->priority = priority;
    infoPtr->incomingInterfaceIndex = interfaceIndex;
    infoPtr->receivingTtl = ttl;

    MESSAGE_Send(node, msg, PROCESS_IMMEDIATELY);
}


//-----------------------------------------------------------------------------
// IP header
//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpRemoveIpHeader()
// PURPOSE      Removes the IP header from a message while also
//              returning all the fields of the header.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message.
//              NodeAddress *sourceAddress
//                  Storage for source IP address.
//              NodeAddress *destinationAddress
//                  Storage for destination IP address.
//              TosType *priority
//                  Storage for TosType.
//                  (values are not standard for "IP type of service field"
//                  but has correct function)
//              unsigned char *protocol
//                  Storage for IP protocol number.
//              unsigned *ttl
//                  Storage for time to live.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpRemoveIpHeader(
    Node *node,
    Message *msg,
    NodeAddress *sourceAddress,
    NodeAddress *destinationAddress,
    TosType *priority,
    unsigned char *protocol,
    unsigned *ttl)
{
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

    *priority = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
    *ttl = ipHeader->ip_ttl;
    *protocol = ipHeader->ip_p;
    *sourceAddress = ipHeader->ip_src;
    *destinationAddress = ipHeader->ip_dst;

    MESSAGE_RemoveHeader(node, msg, IpHeaderSize(ipHeader), TRACE_IP);
}

//-----------------------------------------------------------------------------
// IP header option field
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     AddIpOptionField()
// PURPOSE      Inserts an option field in the header of an IP packet.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message.
//              int optionCode
//                  The option code
//              int optionSize
//                  Size of the option
// RETURN       None.
//
// NOTES        optionCode should not conflict with standard ones, like
//              the codes for loose and strict source routing.
//              optionSize specifies the size of the option field beyond
//              the 3 byte option header.  Currently optionSize must
//              satisfy (optionSize + 3) % 4 == 0.  Header fields are
//              moved by this operation, so watch out for lingering
//              pointers into the message.
//-----------------------------------------------------------------------------

void
AddIpOptionField(
    Node *node,
    Message *msg,
    int optionCode,
    int optionSize)
{
    IpOptionsHeaderType *newIpOption = NULL;
    int oldHeaderSize = IpHeaderSize((IpHeaderType *) msg->packet);

    // Round up to nearest option size divisable by 4.
    int newIpOptionSize =
        4 * ((((sizeof(IpOptionsHeaderType) + optionSize) - 1) / 4) + 1);
    int newHeaderSize = oldHeaderSize + newIpOptionSize;

    ERROR_Assert(
        FindAnIpOptionField((IpHeaderType *) msg->packet, optionCode) == NULL,
        "Option already exists in IP header");

    ExpandOrShrinkIpHeader(node, msg, newHeaderSize);
    newIpOption =
        (IpOptionsHeaderType *) ((char *) msg->packet + oldHeaderSize);
    if (optionCode == IPOPT_SSRR ||
       optionCode == IPOPT_LSRR ||
       optionCode == IPOPT_RR)
    {
        newIpOption->len = (unsigned char)(newIpOptionSize - 1);
    }
    else
    {
        newIpOption->len = (unsigned char)newIpOptionSize;
    }
    newIpOption->code = (unsigned char) optionCode;
    newIpOption->ptr = IPOPT_MINOFF;
}

//-----------------------------------------------------------------------------
// Source route
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     ExtractIpSourceAndRecordedRoute()
// PURPOSE      Retrieves a copy of the source and recorded route from
//              the options field in the header.
// PARAMETERS   Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress RouteAddresses[]
//                  Storage for source/recorded route.
//              int *NumAddresses
//                  Storage for size of RouteAddresses[] array.
//              int *RouteAddressIndex
//                  The index of the first address of the source route;
//                  before this index is the recorded route.
// RETURN       None.
//-----------------------------------------------------------------------------

void
ExtractIpSourceAndRecordedRoute(
    Message *msg,
    NodeAddress RouteAddresses[],
    int *NumAddresses,
    int *RouteAddressIndex)
{
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    IpOptionsHeaderType *ipOptions = IpHeaderSourceRouteOptionField(ipHeader);
    char *FirstAddress = ((char *) ipOptions + sizeof(IpOptionsHeaderType));

    ERROR_Assert(
        IpHeaderHasSourceRoute(ipHeader),
        "Cannot source route when IP header does not have source route");
    *NumAddresses =
        (ipOptions->len - sizeof(IpOptionsHeaderType) -
         IP_SOURCE_ROUTE_OPTION_PADDING) / sizeof(NodeAddress);
    *RouteAddressIndex =
        (ipOptions->ptr - sizeof(IpOptionsHeaderType) -
         IP_SOURCE_ROUTE_OPTION_PADDING) / sizeof(NodeAddress);
    memmove(RouteAddresses, FirstAddress,
            ((*NumAddresses) *sizeof(NodeAddress)));
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetRouterFunction()
// PURPOSE      Get the router function pointer.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  interface associated with router function.
// RETURN       Router function.
//-----------------------------------------------------------------------------

RouterFunctionType
NetworkIpGetRouterFunction(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    // Validate that we didn't get passed CPU_INTERFACE or ANY_INTERFACE
    ERROR_Assert(interfaceIndex >= 0, "Router functions only exist for numbered interfaces.");

    return ip->interfaceInfo[interfaceIndex]->routerFunction;
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSetRouterFunction()
// PURPOSE      Allows a routing protocol to set the "routing function"
//              (one of its functions) which is called when a packet
//              needs to be routed.
// PARAMETERS   Node *node
//                  Pointer to node.
//              RouterFunctionType RouterFunctionPtr
//                  Router function to set.
//              int interfaceIndex
//                  interface associated with router function.
// RETURN       None.
//
// NOTES        NetworkIpSetRouterFunction() allows a routing protocol
//              to define the routing function.  The routing function
//              is called by the network layer to ask the routing
//              protocol to route the packet.  The routing function is
//              given the packet and its destination.  The routing
//              protocol can route the packet and set "packetWasRouted"
//              to TRUE; or not route the packet and set to FALSE.  If
//              the packet, was not routed, then the network layer will
//              try to use the forwarding table or the source route the
//              source route in the IP header.  This function will also
//              be given packets for the local node the routing
//              protocols can look at packets for protocol reasons.  In
//              this case, the message should not be modified and
//              packetWasRouted must be set to FALSE.
//-----------------------------------------------------------------------------

void
NetworkIpSetRouterFunction(
    Node *node,
    RouterFunctionType routerFunctionPtr,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
/*
    ERROR_Assert(ip->interfaceInfo[interfaceIndex]->routerFunction ==
                 NULL,
                 "Router function already set");
*/
    ip->interfaceInfo[interfaceIndex]->routerFunction = routerFunctionPtr;
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpAddUnicastRoutingProtocolType()
// PURPOSE      Add unicast routing protocol type to interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NetworkRoutingProtocolType routingProtocolType
//                  Router function to add.
//              int interfaceIndex
//                  Interface associated with the router function.
// RETURN       None.
//-----------------------------------------------------------------------------
void
NetworkIpAddUnicastRoutingProtocolType(
    Node *node,
    NetworkRoutingProtocolType routingProtocolType,
    int interfaceIndex,
    NetworkType networkType)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    if (networkType == NETWORK_IPV6)
    {
        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo->
            routerFunction = NULL;
        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo->
            routingProtocolType = routingProtocolType;
        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo->
            routingProtocol = NULL;
        return;
    }

    ip->interfaceInfo[interfaceIndex]->routerFunction = NULL;
    ip->interfaceInfo[interfaceIndex]->routingProtocolType =
                                         routingProtocolType;
    ip->interfaceInfo[interfaceIndex]->routingProtocol = NULL;
}
#ifdef ADDON_BOEINGFCS

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpAddUnicastIntraRegionRoutingProtocolType()
// PURPOSE      Add unicast intra region routing protocol type to interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NetworkRoutingProtocolType routingProtocolType
//                  Router function to add.
//              int interfaceIndex
//                  Interface associated with the router function.
// RETURN       None.
//-----------------------------------------------------------------------------


void
NetworkIpAddUnicastIntraRegionRoutingProtocolType(
    Node *node,
    NetworkRoutingProtocolType routingProtocolType,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ip->interfaceInfo[interfaceIndex]->intraRegionRouterFunction = NULL;
    ip->interfaceInfo[interfaceIndex]->intraRegionRoutingProtocolType =
                                         routingProtocolType;
    ip->interfaceInfo[interfaceIndex]->intraRegionRoutingProtocol = NULL;
}
#endif

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetRoutingProtocol()
// PURPOSE      Get routing protocol structure associated with routing protocol
//              running on this interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NetworkRoutingProtocolType routingProtocolType
//                  Routing protocol to retrieve.
// RETURN       Routing protocol structure requested.
//-----------------------------------------------------------------------------

void *
NetworkIpGetRoutingProtocol(
    Node *node,
    NetworkRoutingProtocolType routingProtocolType,
    NetworkType networkType)
{
    int i;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (NetworkIpGetUnicastRoutingProtocolType(node, i, networkType)
            == routingProtocolType)
        {
            if (ip->interfaceInfo[i]->interfaceType == NETWORK_IPV6
                ||(networkType == NETWORK_IPV6 &&
                   ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL))
            {
                IPv6InterfaceInfo *interfaceInfo;
                interfaceInfo = ip->interfaceInfo[i]->ipv6InterfaceInfo;

                return interfaceInfo->routingProtocol;
            }
            return ip->interfaceInfo[i]->routingProtocol;
        }
    }

    return NULL; // Not reachable.
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetUnicastRoutingProtocolType()
// PURPOSE      Get unicast routing protocol type on this interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  network interface for request
// RETURN       The unicast routing protocol type.
//-----------------------------------------------------------------------------

NetworkRoutingProtocolType
NetworkIpGetUnicastRoutingProtocolType(
    Node *node,
    int interfaceIndex,
    NetworkType networkType)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    if (networkType == NETWORK_IPV4
        && (ip->interfaceInfo[interfaceIndex]->interfaceType == NETWORK_IPV4
            || ip->interfaceInfo[interfaceIndex]->interfaceType == NETWORK_DUAL))
    {
        return ip->interfaceInfo[interfaceIndex]->routingProtocolType;
    }
    else if (networkType == NETWORK_IPV6
        && (ip->interfaceInfo[interfaceIndex]->interfaceType == NETWORK_IPV6
            || ip->interfaceInfo[interfaceIndex]->interfaceType == NETWORK_DUAL))
    {
        IPv6InterfaceInfo *interfaceInfo;
        interfaceInfo = ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

        return interfaceInfo->routingProtocolType;
    }

    return ROUTING_PROTOCOL_NONE;
}


// FUNCTION   NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction
// PURPOSE    Assign unicast routing protocol structure and router
//            function to an interface.  We are only allocating
//            the unicast routing protocol structure and router function
//            once by using pointers to the original structures.
// PARAMETERS node - this node.
//            routingProtocolType - unicast routing protocol to add.
//            interfaceIndex - interface associated with unicast protocol.
// RETURN     None.
void
NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
    Node *node,
    NetworkRoutingProtocolType routingProtocolType,
    int interfaceIndex,
    NetworkType networkType)
{
    int i;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (NetworkIpGetUnicastRoutingProtocolType(node, i, networkType)
            == routingProtocolType)
        {

            if (networkType == NETWORK_IPV6)
            {
                IPv6InterfaceInfo *interfaceInfo1;
                IPv6InterfaceInfo *interfaceInfo2;
                interfaceInfo1 = ip->interfaceInfo[interfaceIndex]
                                ->ipv6InterfaceInfo;

                interfaceInfo2 = ip->interfaceInfo[i]->ipv6InterfaceInfo;

                interfaceInfo1->routerFunction
                                    = interfaceInfo2->routerFunction;
                interfaceInfo1->routingProtocol
                                    = interfaceInfo2->routingProtocol;

                interfaceInfo1->macLayerStatusEventHandlerFunction =
                    interfaceInfo2->macLayerStatusEventHandlerFunction;

                return;
            }

            ip->interfaceInfo[interfaceIndex]->routerFunction =
                            ip->interfaceInfo[i]->routerFunction;

            ip->interfaceInfo[interfaceIndex]->routingProtocol =
                            ip->interfaceInfo[i]->routingProtocol;

            ip->interfaceInfo[interfaceIndex]->
                macLayerStatusEventHandlerFunction =
                      ip->interfaceInfo[i]->macLayerStatusEventHandlerFunction;

            ip->interfaceInfo[interfaceIndex]->
                promiscuousMessagePeekFunction =
                      ip->interfaceInfo[i]->promiscuousMessagePeekFunction;

            return;
        }
    }
    char errStr[MAX_STRING_LENGTH];
    sprintf(errStr,
            "Could not find unicast router function %d\n",
            routingProtocolType);
    ERROR_ReportError(errStr);
}


void NetworkIpSetHsrpOnInterface(Node *node, int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    ip->interfaceInfo[interfaceIndex]->hsrpEnabled = TRUE;
}

BOOL NetworkIpIsHsrpEnabled(Node *node, int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    if (interfaceIndex == ANY_INTERFACE)
    {
        int i;

        for (i = 0; i < node->numberInterfaces; i++)
        {
            if (ip->interfaceInfo[i]->hsrpEnabled)
            {
                return TRUE;
            }
        }

        return FALSE;
    }
    else
    {
        return ip->interfaceInfo[interfaceIndex]->hsrpEnabled;
    }
}

void NetworkIpMibsInit (Node* node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    std::string path;
    char mibsIdPath[MAX_STRING_LENGTH];
    D_Hierarchy *h = &node->partitionData->dynamicHierarchy;

    int i;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        BOOL createPath = FALSE;

        if (h->IsEnabled())
        {
            char ipAddr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(ip->interfaceInfo[i]->ipAddress, ipAddr);

            // create a node path for ipAddrBcast
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "ipAddrBcast",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ipAddrBcast));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf(mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.4.20.1.4.%s",
                    node->nodeId,
                    ipAddr);
                h->AddLink(mibsIdPath, path);
            }

            // create a node path for ipAddrNetMask
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "ipAddrNetMask",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_NodeAddressObj(&ip->interfaceInfo[i]->ipAddrNetMask));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf(mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.4.20.1.3.%s",
                    node->nodeId,
                    ipAddr);
                h->AddLink(mibsIdPath, path);
            }
            // create a node path for ipAddrIfIdx
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "ipAddrIfIdx",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ipAddrIfIdx));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf(mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.4.20.1.2.%s",
                    node->nodeId,
                    ipAddr);
                h->AddLink(mibsIdPath, path);
            }
            // Create a node path for ifDescribtion
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfDescription",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_StringObj(&ip->interfaceInfo[i]->ifDescr));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf(mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.2.2.1.2.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }

            // Create path for ifPhysAddress
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfPhysAddress",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_NodeAddressObj(&ip->interfaceInfo[i]->ipAddress));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf(mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.2.2.1.6.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }

            // Create path for ifInUcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfInUcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifInUcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf(mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.2.2.1.11.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }

            // Create path for ifInNUcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfInNUcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifInNUcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.2.2.1.12.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifOutUcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfOutUcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifOutUcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.2.2.1.17.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifOutNUcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfOutNUcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifOutNUcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.2.2.1.18.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }

            // Create path for ifInDiscards
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfInDiscards",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifInDiscards));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.2.2.1.13.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifInMulticastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfInMulticastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifInMulticastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.2.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifInBroadcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfInBroadcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifInBroadcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.3.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifOutMulticastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfOutMulticastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifOutMulticastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.4.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifOutBroadcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfOutBroadcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifOutBroadcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.5.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifHCInUcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfHCInUcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt64Obj(&ip->interfaceInfo[i]->ifHCInUcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.7.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifHCInMulticastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfHCInMulticastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt64Obj(&ip->interfaceInfo[i]->ifHCInMulticastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.8.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifHCInBroadcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfHCInBroadcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt64Obj(&ip->interfaceInfo[i]->ifHCInBroadcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.9.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifHCOutUcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfHCOutUcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt64Obj(&ip->interfaceInfo[i]->ifHCOutUcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.11.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifHCOutMulticastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfHCOutMulticastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt64Obj(&ip->interfaceInfo[i]->ifHCOutMulticastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.12.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // Create path for ifHCOutBroadcastPkts
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfHCOutBroadcastPkts",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt64Obj(&ip->interfaceInfo[i]->ifHCOutBroadcastPkts));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.31.1.1.1.13.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
            // create path for ifOutDiscards
            createPath =
                h->CreateNodeInterfacePath(
                node,
                i,
                "IfOutDiscards",
                path);
            if (createPath)
            {
                h->AddObject(
                    path,
                    new D_UInt32Obj(&ip->interfaceInfo[i]->ifOutDiscards));

                h->SetWriteable(path, FALSE);
                h->SetExecutable(path, FALSE);
                sprintf (mibsIdPath,
                    "/node/%d/snmp/1.3.6.1.2.1.2.2.1.19.%d",
                    node->nodeId,
                    i);
                h->AddLink(mibsIdPath, path);
            }
        }
#ifdef ADDON_BOEINGFCS
        if (RoutingCesRospfActiveOnInterface(node, i))
        {
            ip->interfaceInfo[i]->ifDescr.Set("WnwRadio");
        }
        else if (NetworkCesIncSincgarsActiveOnInterface(node, i))
        {
            ip->interfaceInfo[i]->ifDescr.Set("SincgarsRadio");
        }
        else if (NetworkCesIncEplrsActiveOnInterface(node, i))
        {
            ip->interfaceInfo[i]->ifDescr.Set("EplrsRadio");
        }
        else if (MacCesWintNcwActiveOnInterface(node, i))
        {
            ip->interfaceInfo[i]->ifDescr.Set("WinTRadio");
        }
        else if (MacCesWintGbsNcwActiveOnInterface(node, i))
        {
            ip->interfaceInfo[i]->ifDescr.Set("WintGbsRadio");
        }
        else if (MacCesWintHnwNcwActiveOnInterface(node, i))
        {
            ip->interfaceInfo[i]->ifDescr.Set("WintHnwRadio");
        }
#endif // ADDON_BOEINGFCS
    }
}

//-----------------------------------------------------------------------------
// Interface creation
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpAddNewInterface()
// PURPOSE      Add new interface to node.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress interfaceIpAddress
//                  Interface to add.
//              int numHostBits
//                  Number of host bits for the interface.
//              int *newInterfaceIndex
//                  The interface number of the new interface.
//              const NodeInput *nodeInput
//                  Provides access to configuration file.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpAddNewInterface(
    Node *node,
    NodeAddress interfaceIpAddress,
    int numHostBits,
    int *newInterfaceIndex,
    const NodeInput *nodeInput,
    BOOL isNewInterface)
{
    BOOL wasFound;
    BOOL typeFound = FALSE;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int interfaceIndex = -1;

    std::string path;
    D_Hierarchy *h = &node->partitionData->dynamicHierarchy;

    if (!ip)
    {
        if (node->adaptationData.endSystem == FALSE &&
                node->adaptationData.genlSwitch == TRUE)
        {
            char str[MAX_STRING_LENGTH];
            sprintf(str,
                    "ATM switch can not have IP interfaces. Please "
                    "configure Node %d to be an ATM End System node",
                    node->nodeId);
            ERROR_ReportError(str);
        }
    }

    char intfString[MAX_STRING_LENGTH];

    if (isNewInterface)
    {
        interfaceIndex = node->numberInterfaces;
        node->numberInterfaces++;

        ip->interfaceInfo[interfaceIndex] = new IpInterfaceInfoType();

        ip->interfaceInfo[interfaceIndex]->interfaceType = NETWORK_IPV4;
    }
    else
    {
        interfaceIndex = node->numberInterfaces - 1;
        ip->interfaceInfo[interfaceIndex]->interfaceType = NETWORK_DUAL;
    }

    if (h->IsEnabled())
    {
        if (h->CreateNetworkPath(
            node,
            interfaceIndex,
            "ip",
            "ipFragUnit",
            path))
        {
            h->AddObject(
                path,
                new D_Int32Obj(&ip->interfaceInfo[interfaceIndex]->ipFragUnit));

            node->partitionData->dynamicHierarchy.SetWriteable(
                path,
                FALSE);

            // AddLink for the Mibs ifMtu
            char mibsIdPath[MAX_STRING_LENGTH];
            sprintf(mibsIdPath,
                "/node/%d/snmp/1.3.6.1.2.1.2.2.1.4.%d",
                node->nodeId,
                interfaceIndex);
            h->AddLink(mibsIdPath, path);
        }
    }

    *newInterfaceIndex = interfaceIndex;

    ERROR_Assert(
        (interfaceIndex >= 0) && (interfaceIndex < MAX_NUM_INTERFACES),
        "Number of interfaces has exceeded MAX_NUM_INTERFACES or is < 0");

    ip->interfaceInfo[interfaceIndex]->ipAddress = interfaceIpAddress;
    ip->interfaceInfo[interfaceIndex]->numHostBits = numHostBits;


    ip->interfaceInfo[interfaceIndex]->routerFunction = NULL;
    ip->interfaceInfo[interfaceIndex]->routingProtocolType =
                                                         ROUTING_PROTOCOL_NONE;
    ip->interfaceInfo[interfaceIndex]->routingProtocol = NULL;

    ip->interfaceInfo[interfaceIndex]->multicastEnabled = FALSE;
    ip->interfaceInfo[interfaceIndex]->multicastRouterFunction = NULL;
    ip->interfaceInfo[interfaceIndex]->multicastProtocolType =
                                                         ROUTING_PROTOCOL_NONE;
    ip->interfaceInfo[interfaceIndex]->multicastRoutingProtocol = NULL;

    ip->interfaceInfo[interfaceIndex]->macLayerStatusEventHandlerFunction =
                                                                          NULL;
    ip->interfaceInfo[interfaceIndex]->promiscuousMessagePeekFunction = NULL;
    ip->interfaceInfo[interfaceIndex]->macAckHandler = NULL;

    ip->interfaceInfo[interfaceIndex]->backplaneStatus =
                                                   NETWORK_IP_BACKPLANE_IDLE;

    ip->interfaceInfo[interfaceIndex]->hsrpEnabled = FALSE;
    ip->interfaceInfo[interfaceIndex]->isUnnumbered = FALSE;

    ip->interfaceInfo[interfaceIndex]->ipAddrNetMask =
        NetworkIpGetInterfaceSubnetMask(node, interfaceIndex);
    ip->interfaceInfo[interfaceIndex]->ipAddrIfIdx = interfaceIndex;
    ip->interfaceInfo[interfaceIndex]->ipAddrBcast = 1;

#ifdef ENTERPRISE_LIB
    // Access list initialization.
    ip->interfaceInfo[interfaceIndex]->accessListInPointer = NULL;
    ip->interfaceInfo[interfaceIndex]->accessListOutPointer = NULL;

    ip->interfaceInfo[interfaceIndex]->
                            accessListStat.packetDroppedByExtdAtIN = 0;
    ip->interfaceInfo[interfaceIndex]->
                            accessListStat.packetDroppedByExtdAtOUT = 0;
    ip->interfaceInfo[interfaceIndex]->
                            accessListStat.packetDroppedByStdAtOut = 0;
    ip->interfaceInfo[interfaceIndex]->
                            accessListStat.packetDroppedByStdAtIN = 0;
    ip->interfaceInfo[interfaceIndex]->
                            accessListStat.packetDroppedForMismatchAtOut = 0;
    ip->interfaceInfo[interfaceIndex]->
                            accessListStat.packetDroppedForMismatchAtIN = 0;

    ip->interfaceInfo[interfaceIndex]->routingTableUpdateFunction = NULL;

    ip->interfaceInfo[interfaceIndex]->rMapForPbr = NULL;

    // for PBR
    ip->interfaceInfo[interfaceIndex]->pbrStat.packetsPolicyRoutedLocal = 0;
    ip->interfaceInfo[interfaceIndex]->pbrStat.packetsNotPolicyRouted = 0;
    ip->interfaceInfo[interfaceIndex]->pbrStat.packetPrecSet = 0;
    ip->interfaceInfo[interfaceIndex]->pbrStat.packetsPolicyRouted = 0;
#endif // ENTERPRISE_LIB
#ifdef CYBER_CORE
    // Initialize Security Structures
    ip->interfaceInfo[interfaceIndex]->spdIN = NULL;
    ip->interfaceInfo[interfaceIndex]->spdOUT = NULL;
#endif //CYBER_CORE
    sprintf(ip->interfaceInfo[interfaceIndex]->interfaceName,
            "interface%d", interfaceIndex);

    IO_ReadStringInstance(
            node->nodeId,
            ANY_DEST,
            nodeInput,
            "INTERFACE-NAME",
            interfaceIndex,    // parameterInstanceNumber
            FALSE,             // fallbackIfNoInstanceMatch
            &wasFound,
            ip->interfaceInfo[interfaceIndex]->interfaceName);

#ifdef ENTERPRISE_LIB
    // For Interface type and interface number follow the exact syntax:
    // [node-id] INTERFACE-TYPE interface-index
    //      interface-type interface-number
    IO_ReadStringInstance(
            node->nodeId,
            ANY_DEST,
            nodeInput,
            "INTERFACE-TYPE",
            interfaceIndex,
            FALSE,
            &typeFound,
            intfString);

    if (typeFound)
    {
        RtParseInterfaceTypeAndNumber(node, interfaceIndex, intfString);
    }
#endif // ENTERPRISE_LIB

}

//-----------------------------------------------------------------------------
// Queue setup
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpInitOutputQueueConfiguration()
// PURPOSE      Initializes queue parameters during startup.
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
//              int interfaceIndex
//                  interface associated with queue.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpInitOutputQueueConfiguration(
    Node *node,
    const NodeInput *nodeInput,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Address address;
    Scheduler *schedulerPtr = NULL;
    char schedulerTypeString[MAX_STRING_LENGTH] = {0};
    BOOL enableSchedulerStat = FALSE;
    int numPriorities = ALL_PRIORITIES;
    int i = 0;
    BOOL wasFound = FALSE;
    BOOL readValue = FALSE;
    char buf[MAX_STRING_LENGTH] = {0};
    char graphDataStr[MAX_STRING_LENGTH] = "NA";
    vector<Queue*> listQueuePtr;

    NetworkType networkType =
        ip->interfaceInfo[interfaceIndex]->interfaceType;

    if (networkType == NETWORK_DUAL)
    {
        networkType = NETWORK_IPV4;
    }
    NetworkGetInterfaceInfo(node, interfaceIndex, &address, networkType);

    // Read Number of Queues under the interface Scheduler
    // that chooses which packet to transmit next.
    IO_ReadInt(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "IP-QUEUE-NUM-PRIORITIES",
        &wasFound,
        &numPriorities);

    if (!wasFound)
    {
        NetworkIpConfigurationError(node,
                                    "IP-QUEUE-NUM-PRIORITIES",
                                    interfaceIndex);
    }

    if ((numPriorities < 1) || (numPriorities > NUM_MAX_IP_QUEUE))
    {
        NetworkIpConfigurationError(node,
                                    "IP-QUEUE-NUM-PRIORITIES",
                                    interfaceIndex);
    }

    // Read if Scheduler Statistics is enabled
    IO_ReadString(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "SCHEDULER-STATISTICS",
            &wasFound,
            buf);

    if (wasFound && (!strcmp(buf, "YES")))
    {
        enableSchedulerStat = TRUE;
    }

    // Initialize the SchedGraphStat Structure for each interface
    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "SCHEDULER-GRAPH-STATISTICS",
        &wasFound,
        buf);

    if (wasFound && strcmp(buf, "YES") == 0)
    {
        BOOL retVal = FALSE;
        char sampleIntervalStr[MAX_STRING_LENGTH] = {0};

        //NetworkIpInterfaceInitForGraph(node, nodeInput, interfaceIndex);
        IO_ReadString(
                node,
                node->nodeId,
                interfaceIndex,
                nodeInput,
                "SAMPLE-INTERVAL",
                &retVal,
                sampleIntervalStr);

        if (retVal)
        {
            char addressString[MAX_ADDRESS_STRING_LENGTH];
            char checkIntervalStr[MAX_STRING_LENGTH] = {0};

            strcpy(checkIntervalStr, sampleIntervalStr);
            IO_ConvertIpAddressToString(&address, addressString);
            strcat(addressString, ".out");

            if ((TIME_ConvertToClock(checkIntervalStr) < 0) ||
                (TIME_ConvertToClock(checkIntervalStr)
                        > TIME_ReturnMaxSimClock(node)))
            {
                NetworkIpConfigurationError(node,
                                        "SAMPLE-INTERVAL",
                                        interfaceIndex);
            }

            // graphDataStr: <sampleInterval> <interfaceAddress.out>
            sprintf(graphDataStr, "%s %s",sampleIntervalStr, addressString);
        }
        else
        {
            ERROR_ReportError("a SAMPLE-INTERVAL value should be specifed"
                " into config file and value must be positive\n");
        }
    }

    // Set the Scheduler
    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "IP-QUEUE-SCHEDULER",
        &wasFound,
        schedulerTypeString);

    if (!wasFound)
    {
        NetworkIpConfigurationError(node,
                                    "IP-QUEUE-SCHEDULER",
                                    interfaceIndex);
    }
    else
    {
        if (!strcmp(schedulerTypeString, "CBQ"))
        {
            NodeInput lsrmInput;
            CBQResourceManager* resrcMngr = NULL;
            char pktSchedulerString[MAX_STRING_LENGTH] = {0};
            char resrcMngrGuideLine[MAX_STRING_LENGTH] = {0};
            int resrcMngrGuideLineLevel = 0;
            int interfaceBandwidth =
                    (int) node->macData[interfaceIndex]->bandwidth;

            ReadCBQResourceManagerConfiguration(node,
                interfaceIndex,
                nodeInput,
                &lsrmInput,
                resrcMngrGuideLine,
                &resrcMngrGuideLineLevel,
                pktSchedulerString);

            RESOURCE_MANAGER_Setup(node,
                                    lsrmInput,
                                    interfaceIndex,
                                    NETWORK_LAYER,
                                    interfaceBandwidth,
                                    &resrcMngr,
                                    resrcMngrGuideLine,
                                    resrcMngrGuideLineLevel,
                                    pktSchedulerString,
                                    enableSchedulerStat,
                                    TRUE,
                                    graphDataStr);

            schedulerPtr = (Scheduler*) resrcMngr;
        }
#ifdef ENTERPRISE_LIB
        else if (!strcmp(schedulerTypeString, "DIFFSERV-ENABLED"))
        {
            char secondSchedTypeString[MAX_STRING_LENGTH] = {0};
            DiffservScheduler* dsSchedulerPtr = NULL;

            ip->diffservEnabled = TRUE;

            ReadDiffservSchedulerConfiguration(node,
                                               interfaceIndex,
                                               nodeInput,
                                               secondSchedTypeString);

            DIFFSERV_SCHEDULER_Setup(&dsSchedulerPtr,
                                     numPriorities,
                                     secondSchedTypeString,
                                     FALSE, // enableSchedulerStat,
                                     graphDataStr);

            schedulerPtr = (Scheduler*) dsSchedulerPtr;
        }
#endif // ENTERPRISE_LIB
        else
        {
            SCHEDULER_Setup(&schedulerPtr,
                            schedulerTypeString,
                            enableSchedulerStat,
                            graphDataStr);
        }

        ip->interfaceInfo[interfaceIndex]->scheduler = schedulerPtr;
    }


#ifdef ADDON_DB

    STATSDB_HandleSchedulerDescTableInsert(node, interfaceIndex,
        "OUTPUT", schedulerTypeString);
#endif


    // This for loop read queue weight and also assigne queue weight if it
    // is not specified by the user
    int unassignQueue = 0;
    double totalWeight = 0.0;
    double* queueWeight;

    queueWeight = (double*) MEM_malloc(sizeof(double) * numPriorities);
    memset(queueWeight, 0, (sizeof(double) * numPriorities));

    for (i = 0, totalWeight = 0.0; i < numPriorities; i++)
    {
        IO_ReadDoubleInstance(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "QUEUE-WEIGHT", // IP-QUEUE-WEIGHT
            i,              // parameterInstanceNumber
            FALSE,          // fallbackIfNoInstanceMatch
            &wasFound,
            &queueWeight[i]);

        if (wasFound)
        {
            if (queueWeight[i] >= 1.0)
            {
                NetworkIpConfigurationError(node, "QUEUE-WEIGHT",
                                                    interfaceIndex);
            }
            totalWeight += queueWeight[i];
        }
        else
        {
            unassignQueue++;
            queueWeight[i] = 1.0;
        }
    }

    ERROR_Assert(totalWeight <= 1.0,"Total queue weight should be <= 1.0\n");
    if (unassignQueue > 0 && unassignQueue != numPriorities)
    {
        for (i = 0; i < numPriorities; i++)
        {
            if (queueWeight[i] == 1.0)
            {
                queueWeight[i] = (1 - totalWeight) / unassignQueue;
            }
        }
    }

    for (i = 0; i < numPriorities; i++)
    {
        Queue* queue = NULL;
        char queueTypeString[MAX_STRING_LENGTH] = {0};
        int queueSize = DEFAULT_NETWORK_OUTPUT_QUEUE_SIZE;
        BOOL enableQueueStat = FALSE;
        int priority = ALL_PRIORITIES;
        int addedQueuePriority = ALL_PRIORITIES;
        void* spConfigInfo = NULL; // Queue Specific configurations.
        clocktype maxPktAge = CLOCKTYPE_MAX; // basically turn off by default.


        IO_ReadStringInstance(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "IP-QUEUE-TYPE",
            i,                 // parameterInstanceNumber
            TRUE,              // fallbackIfNoInstanceMatch
            &wasFound,
            queueTypeString);

        if (!wasFound)
        {
            NetworkIpConfigurationError(
                node, "IP-QUEUE-TYPE", interfaceIndex);
        }

        IO_ReadIntInstance(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "IP-QUEUE-PRIORITY-QUEUE-SIZE", // IP-OUTPUT-QUEUE-SIZE
            i,                 // parameterInstanceNumber
            TRUE,              // fallbackIfNoInstanceMatch
            &wasFound,
            &queueSize);

        if (wasFound && (queueSize <= 0))
        {
            NetworkIpConfigurationError(node,
                                        "IP-QUEUE-PRIORITY-QUEUE-SIZE",
                                        interfaceIndex);
        }

        IO_ReadTimeInstance(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "IP-QUEUE-PRIORITY-QUEUE-MAX-AGE",
            i,                 // parameterInstanceNumber
            TRUE,              // fallbackIfNoInstanceMatch
            &wasFound,
            &maxPktAge);

        if (wasFound && (maxPktAge <= 0))
        {
            NetworkIpConfigurationError(node,
                                        "IP-QUEUE-PRIORITY-QUEUE-MAX-AGE",
                                        interfaceIndex);
        }

        if (!ip->diffservEnabled)
        {
            IO_ReadIntInstance(
                node,
                node->nodeId,
                interfaceIndex,
                nodeInput,
                "IP-QUEUE-PRIORITY",
                i,                 // parameterInstanceNumber
                TRUE,              // fallbackIfNoInstanceMatch
                &wasFound,
                &priority);

            if (wasFound && (priority < 0))
            {
                NetworkIpConfigurationError(
                    node, "IP-QUEUE-PRIORITY", interfaceIndex);
            }
            else if (!wasFound)
            {
                priority = i;
            }
        }

        IO_ReadBool(
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "QUEUE-STATISTICS",
            &wasFound,
            &readValue);

        if (wasFound && readValue)
        {
            enableQueueStat = TRUE;
        }

        if (!strcmp(queueTypeString, "FIFO"))
        {
            // No specific configuration for FIFO
        }
        else if (!strcmp(queueTypeString, "RED"))
        {
            IO_ReadString(
                node,
                node->nodeId,
                interfaceIndex,
                nodeInput,
                "ECN",
                &wasFound,
                buf);

            if (wasFound && (!strcmp(buf, "YES")))
            {
                // Ecn enabled RED
                RedEcnParameters* redParams = NULL;

                ReadRed_EcnConfigurationParameters(node,
                                    interfaceIndex,
                                    nodeInput,
                                    enableQueueStat,
                                    i,
                                    &redParams);
                memset(queueTypeString, 0, MAX_STRING_LENGTH);
                strcpy(queueTypeString, "RED-ECN");
                spConfigInfo = (void*)(redParams);
            }
            else
            {
                RedParameters* redParams = NULL;

                ReadRedConfigurationParameters(node,
                                    interfaceIndex,
                                    nodeInput,
                                    enableQueueStat,
                                    i,
                                    &redParams);

                spConfigInfo = (void*)(redParams);
            }
        }
        else if (!strcmp(queueTypeString, "WRED"))
        {
            RedEcnParameters* redParams = NULL;

            ReadWred_EcnConfigurationThParameters(node,
                                    interfaceIndex,
                                    nodeInput,
                                    enableQueueStat,
                                    i,
                                    &redParams);

            spConfigInfo = (void*)(redParams);
        }
        else if (!strcmp(queueTypeString, "RIO"))
        {
            RioParameters* rioParams = NULL;
            ReadRio_EcnConfigurationThParameters(node,
                            interfaceIndex,
                            nodeInput,
                            enableQueueStat,
                            i,
                            &rioParams);
            spConfigInfo = (void*)(rioParams);
        }
        else
        {
            // Error :Unknown Queue Type
            ERROR_ReportError("Unknown queue type");
        }
        ip->stats.bufferSizeStats = FALSE;


        IO_ReadString(
            node->nodeId,
            &address,
            nodeInput,
            "BUFFER-SIZE-STATISTICS",
            &wasFound,
            buf);

        if (wasFound && (!strcmp(buf, "YES")))
        {
            ip->stats.bufferSizeStats = TRUE;
        }


#ifdef ADDON_BOEINGFCS
        IO_ReadString(
            node->nodeId,
            &address,
            nodeInput,
            "STATS-DB-QUEUE-AGGREGATE-PER-DSCP-STATS-ENABLED",
            &wasFound,
            buf);

        if (wasFound && (!strcmp(buf, "YES")))
        {
            ip->stats.perDscpStats = TRUE;
        }
#endif
        // Initialize Queue depending on queueTypeString specification
        QUEUE_Setup(node,
                    &queue,
                    queueTypeString,
                    queueSize,
                    interfaceIndex,
                    priority,
                    0, // infoFieldSize
                    enableQueueStat,
                    node->guiOption,
                    getSimTime(node) ,
                    spConfigInfo
                    , maxPktAge
#ifdef ADDON_DB
                    ,"Network Output"
#endif
#ifdef ADDON_BOEINGFCS
                    ,ip->stats.perDscpStats
#endif
                    );

        addedQueuePriority = (*schedulerPtr).addQueue(queue,
                                                      priority,
                                                      queueWeight[i]);
        listQueuePtr.push_back(queue);

        //GuiStart++-
        if (node->guiOption == TRUE)
        {
            GUI_AddInterfaceQueue(node->nodeId,
                                  GUI_NETWORK_LAYER,
                                  interfaceIndex,
                                  addedQueuePriority,
                                  queueSize,
                                  getSimTime(node) + getSimStartTime(node));
        }
        //GuiEnd
    }

#if ADDON_DB
    int queueIndex = 0;
    vector<Queue*>::iterator it = listQueuePtr.begin();

    for (; it != listQueuePtr.end(); it++, queueIndex++)
    {
        StatsDb* db = node->partitionData->statsDb;
        if (db && db->statsDescTable->createQueueDescTable)
        {
            StatsDBQueueDesc queueDesc(node->nodeId,
                                       interfaceIndex,
                                       queueIndex,
                                       "Network Output");
            queueDesc.SetQueueDiscipline(
                (std::string) (*it)->getQueueType());
            queueDesc.SetQueueSize((*it)->sizeOfQueue());
            int queuePriority =
                (*schedulerPtr).GetQueuePriority(queueIndex);
            queueDesc.SetQueuePriority(queuePriority);
            queueDesc.m_QueueMetaData = *((*it)->meta_data);

            STATSDB_HandleQueueDescTableInsert(node, queueDesc);
        }
    }
#endif
    if (queueWeight)
    {
        MEM_free(queueWeight);
    }
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpInitCpuQueueConfiguration()
// PURPOSE      Initializes cpu queue parameters during startup.
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
// RETURN       None.
//-----------------------------------------------------------------------------

//static
void
NetworkIpInitCpuQueueConfiguration(
    Node *node,
    const NodeInput *nodeInput)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *cpuSchedulerPtr = NULL;
    Queue* queue = NULL;
    queue = new Queue;
    BOOL enableQueueStat = FALSE;
    BOOL enableSchedulerStat = FALSE;
    char buf[MAX_STRING_LENGTH] = {0};
    BOOL wasFound = FALSE;
    BOOL readValue = FALSE;
    int queueSize = DEFAULT_CPU_QUEUE_SIZE;

    if (ip->backplaneType == BACKPLANE_TYPE_CENTRAL)
    {
        //If router backplane type is CENTRAL then queue size is set as
        //DEFAULT_CPU_QUEUE_SIZE * Total number of interfaces of that node.
        queueSize = DEFAULT_CPU_QUEUE_SIZE * (node->numberInterfaces);
    }

    IO_ReadBool(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "INPUT-QUEUE-STATISTICS",
        &wasFound,
        &readValue);

    if (wasFound && readValue)
    {
        enableQueueStat = TRUE;
    }
#ifdef ADDON_DB
    if (!enableQueueStat)
    {
        if (node->partitionData->statsDb != NULL)
        {
            if (node->partitionData->statsDb->statsAggregateTable->createQueueAggregateTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB QUEUE_Aggregate table requires\n"
                    " INPUT-QUEUE-STATISTICS to be set to YES\n");
            }
            if (node->partitionData->statsDb->statsSummaryTable->createQueueSummaryTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB QUEUE_Summary table requires\n"
                    " INPUT-QUEUE-STATISTICS to be set to YES\n");
            }
            if (node->partitionData->statsDb->statsStatusTable->createQueueStatusTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB QUEUE_Status table requires\n"
                    " INPUT-QUEUE-STATISTICS to be set to YES\n");
            }
        }
    }
#endif
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "INPUT-SCHEDULER-STATISTICS",
        &wasFound,
        buf);

    if (wasFound && (!strcmp(buf, "YES")))
    {
        enableSchedulerStat = TRUE;
    }

    queue->SetupQueue(node,
                      "FIFO",
                      queueSize,
                      0,
                      0,
                      0,
                      enableQueueStat
#ifdef ADDON_DB
                      ,FALSE, 0, NULL, "Network CPU"
#else
                      ,FALSE, getSimTime(node), NULL
#endif
                      );
    if (enableQueueStat)
    {
        queue->stats->SetInterfaceIndex(CPU_INTERFACE);
    }
    SCHEDULER_Setup(&cpuSchedulerPtr,
                    "STRICT-PRIORITY",
                    enableSchedulerStat);

    ip->cpuScheduler = cpuSchedulerPtr;

#ifdef ADDON_DB
    STATSDB_HandleSchedulerDescTableInsert(node, -2,
        "CPU", "STRICT-PRIORITY");
#endif

    // Scheduler add Queue Functionality
    cpuSchedulerPtr->addQueue(queue);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpInitInputQueueConfiguration()
// PURPOSE      Initializes input queue parameters during startup.
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
//              int interfaceIndex
//                  interface associated with queue.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpInitInputQueueConfiguration(
    Node *node,
    const NodeInput *nodeInput,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler* inputSchedulerPtr = NULL;
    int numPriorities = 0;
    int i = 0;
    BOOL enableQueueStat = FALSE;
    BOOL enableSchedulerStat = FALSE;
    char buf[MAX_STRING_LENGTH] = {0};
    BOOL wasFound = FALSE;
    BOOL readValue = FALSE;

    IO_ReadBool(
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "INPUT-SCHEDULER-STATISTICS",
        &wasFound,
        &readValue);

    if (wasFound && readValue)
    {
        enableSchedulerStat = TRUE;
    }

    IO_ReadBool(
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "INPUT-QUEUE-STATISTICS",
        &wasFound,
        &readValue);

    if (wasFound && readValue)
    {
        enableQueueStat = TRUE;
    }
#ifdef ADDON_DB    
    if (!enableQueueStat)
    {
        if (node->partitionData->statsDb != NULL)
        {
            if (node->partitionData->statsDb->statsAggregateTable->createQueueAggregateTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB QUEUE_Aggregate table requires\n"
                    " INPUT-QUEUE-STATISTICS to be set to YES\n");
            }
            if (node->partitionData->statsDb->statsSummaryTable->createQueueSummaryTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB QUEUE_Summary table requires\n"
                    " INPUT-QUEUE-STATISTICS to be set to YES\n");
            }
            if (node->partitionData->statsDb->statsStatusTable->createQueueStatusTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB QUEUE_Status table requires\n"
                    " INPUT-QUEUE-STATISTICS to be set to YES\n");
            }
        }
    }
#endif

    // We assume priority scheduling for input queues.
    SCHEDULER_Setup(&inputSchedulerPtr, "STRICT-PRIORITY",
                        enableSchedulerStat);
    ip->interfaceInfo[interfaceIndex]->inputScheduler =
                        (Scheduler*) inputSchedulerPtr;

#ifdef ADDON_DB

    STATSDB_HandleSchedulerDescTableInsert(node, interfaceIndex,
        "INPUT", "STRICT-PRIORITY");
#endif


    // For input queues,
    // We assume only one FIFO queue for Input buffer.
    numPriorities = 1;

    // Leave for loop just in case we need multiple priority queues
    // later on.
    for (i = 0; i < numPriorities; i++)
    {
        Queue* queue = NULL;
        BOOL wasFound = FALSE;
        int inputQueueSize = DEFAULT_NETWORK_INPUT_QUEUE_SIZE;

        // Input queue size usually matches output queue size.
        IO_ReadIntInstance(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "IP-QUEUE-PRIORITY-INPUT-QUEUE-SIZE", // IP-INPUT-QUEUE-SIZE
            i,                 // parameterInstanceNumber
            TRUE,              // fallbackIfNoInstanceMatch
            &wasFound,
            &inputQueueSize);

        if (wasFound && (inputQueueSize <= 0))
        {
            NetworkIpConfigurationError(node,
                                        "IP-QUEUE-PRIORITY-INPUT-QUEUE-SIZE",
                                        interfaceIndex);
        }

        queue = new Queue; // "FIFO"
        queue->SetupQueue(node,
                          "FIFO",
                          inputQueueSize,
                          interfaceIndex,
                          i,
                          0,
                          enableQueueStat
#ifdef ADDON_DB
                        ,FALSE, 0, NULL, "Network Input"
#else
                          ,FALSE, getSimTime(node), NULL
#endif
                          );

        // Scheduler add Queue Functionality
        (*inputSchedulerPtr).addQueue(queue);

#if ADDON_DB
        // Add this network input queue to the queue description table
        StatsDb* db = node->partitionData->statsDb;
        if (db && db->statsDescTable->createQueueDescTable)
        {
            StatsDBQueueDesc queueDesc(node->nodeId,
                interfaceIndex,
                (*inputSchedulerPtr).numQueue()-1,
                "Network Input");
            queueDesc.SetQueueDiscipline("FIFO");
            queueDesc.SetQueueSize(inputQueueSize);
            int queuePriority =
                (*inputSchedulerPtr).GetQueuePriority
                ((*inputSchedulerPtr).numQueue()-1);
            queueDesc.SetQueuePriority(queuePriority);
            queueDesc.m_QueueMetaData = *(queue->meta_data);

            STATSDB_HandleQueueDescTableInsert(
                node,
                queueDesc);
        }
#endif

    }
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpCreateQueues()
// PURPOSE      Initializes input and output queue parameters during startup
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
//              int interfaceIndex
//                  interface associated with queue.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpCreateQueues(
    Node *node,
    const NodeInput *nodeInput,
    int interfaceIndex)
{
    NetworkIpInitOutputQueueConfiguration(node,
                                          nodeInput,
                                          interfaceIndex);

    NetworkIpInitInputQueueConfiguration(node,
                                         nodeInput,
                                         interfaceIndex);
}


//-----------------------------------------------------------------------------
// Network-layer dequeueing
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpQueueDequeuePacket()
// PURPOSE      Calls the packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              SchedulerType *scheduler
//                  queue to dequeue from.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              MacHWAddress *nexthopmacAddr
//                  Storage for packet's next hop mac address.
//              int outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              TosType *userPriority
//                  Storage for user priority of packet.
//              posInQueue
//                  Position of packet in queue
//                  Added as part of IP-MPLS integration
// RETURN       TRUE if dequeued successfully, FALSE otherwise.
//-----------------------------------------------------------------------------

static
BOOL NetworkIpQueueDequeuePacket(
    Node *node,
    Scheduler *scheduler,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *outgoingInterface,
    int *networkType,
    TosType *userPriority,
    int posInQueue = DEQUEUE_NEXT_PACKET)
{
    QueuePriorityType queuePriority = ALL_PRIORITIES;
    QueuedPacketInfo *infoPtr;

    if ((*scheduler).retrieve(ALL_PRIORITIES,
                          posInQueue,
                          msg,
                          &queuePriority, DEQUEUE_PACKET, getSimTime(node)))
    {
        ERROR_Assert(*msg != NULL, "Cannot dequeue packet");

        infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo((*msg));

        *userPriority = infoPtr->userTos;
        *nextHopAddress = infoPtr->nextHopAddress;

        nexthopmacAddr->hwLength = infoPtr->hwLength;
        nexthopmacAddr->hwType = infoPtr->hwType;
        //Added to avoid double memory allocation and hence memory leak
        if (nexthopmacAddr->byte == NULL)
        {
            nexthopmacAddr->byte = (unsigned char*) MEM_malloc(
                          sizeof(unsigned char)*infoPtr->hwLength);
        }

        memcpy(nexthopmacAddr->byte,infoPtr->macAddress,infoPtr->hwLength);

        *outgoingInterface = infoPtr->outgoingInterface;
        *networkType = infoPtr->networkType;

#ifdef DEBUG_IPV6
        printf("nextHop %x nodeId %d outgoingInterface %d\n",
            infoPtr->nextHopAddress,
            node->nodeId,
            infoPtr->outgoingInterface);
#endif
        return TRUE;
    }

    return FALSE; //Cannot dequeue packet;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpCpuQueueDequeuePacket()
// PURPOSE      Calls the packet scheduler for an interface to retrieve
//              an IP packet from the cpu queue associated with the interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              QueuePriorityType *userPriority
//                  Storage for user priority of packet.
// RETURN       TRUE if dequeued successfully, FALSE otherwise.
//-----------------------------------------------------------------------------

BOOL NetworkIpCpuQueueDequeuePacket(
    Node *node,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *outgoingInterface,
    int *networkType,
    QueuePriorityType *userPriority)

{
    BOOL dequeued = FALSE;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *cpuScheduler;
    TosType userTos = ALL_PRIORITIES;

    cpuScheduler = ip->cpuScheduler;

    dequeued = NetworkIpQueueDequeuePacket(node,
                                           cpuScheduler,
                                           msg,
                                           nextHopAddress,
                                           nexthopmacAddr,
                                           outgoingInterface,
                                           networkType,
                                           &userTos);

    if (dequeued == FALSE) {
        return FALSE;
    }

    *userPriority = (unsigned char) (userTos >> 5);

    return TRUE;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpInputQueueDequeuePacket()
// PURPOSE      Calls the packet scheduler for an interface to retrieve
//              an IP packet from the input queue associated with the interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int incomingInterface
//                  interface to dequeue from.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              QueuePriorityType *userPriority
//                  Storage for priority of packet.
// RETURN       TRUE if dequeued successfully, FALSE otherwise.
//-----------------------------------------------------------------------------

BOOL NetworkIpInputQueueDequeuePacket(
    Node *node,
    int incomingInterface,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *outgoingInterface,
    int *networkType,
    QueuePriorityType *userPriority)

{
    BOOL dequeued = FALSE;

    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *inputScheduler;
    TosType userTos = ALL_PRIORITIES;

    ERROR_Assert(
        incomingInterface >= 0 && incomingInterface < node->numberInterfaces,
        "Invalid interface index");

    inputScheduler = ip->interfaceInfo[incomingInterface]->inputScheduler;

    dequeued = NetworkIpQueueDequeuePacket(node,
                                           inputScheduler,
                                           msg,
                                           nextHopAddress,
                                           nexthopmacAddr,
                                           outgoingInterface,
                                           networkType,
                                           &userTos);

    if (dequeued == FALSE) {
        return FALSE;
    }

    *userPriority = (unsigned char) (userTos >> 5);

    return TRUE;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueDequeuePacket()
// PURPOSE      Calls the packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              MacHWAddress *nexthopmacAddr
//                  Storage for packet's next hop mac address.
//              QueuePriorityType *userPriority
//                  Storage for user priority of packet.
// RETURN       TRUE if dequeued successfully, FALSE otherwise.
//
// NOTES        This function is called by
//              MAC_OutputQueueDequeuePacket() (mac/mac.pc), which itself
//              is called from mac/mac_802_11.pc and other MAC protocol
//              source files.
//
//              This function will assert false if the scheduler cannot
//              return an IP packet for whatever reason.
//-----------------------------------------------------------------------------

BOOL NetworkIpOutputQueueDequeuePacket(
    Node *node,
    int interfaceIndex,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *networkType,
    QueuePriorityType *userPriority)

{
    BOOL dequeued = FALSE;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *scheduler = NULL;
    TosType userTos = ALL_PRIORITIES;
    int outgoingInterface;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    dequeued = NetworkIpQueueDequeuePacket(node,
                                           scheduler,
                                           msg,
                                           nextHopAddress,
                                           nexthopmacAddr,
                                           &outgoingInterface,
                                           networkType,
                                           &userTos);

    if (dequeued)
    {
        // Pass user priority (precedence - 3 bit field) to mac
        *userPriority = (TosType) (userTos >> 5);

        QueuePriorityType  queuePriority = 0;
        queuePriority = (QueuePriorityType) GetQueuePriorityFromUserTos(
                                        node, userTos, (*scheduler).numQueue());
        (*scheduler).collectGraphData(queuePriority,
                        MESSAGE_ReturnPacketSize((*msg)),
                        TIME_getSimTime(node));

        if ((*msg)->headerProtocols[(*msg)->numberOfHeaders-1] == TRACE_LLC)
        {
            MESSAGE_RemoveHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);

            //Trace dequeue
            ActionData acn;
            acn.actionType = DEQUEUE;
            acn.actionComment = NO_COMMENT;
            acn.pktQueue.interfaceID = (unsigned short) interfaceIndex;
            acn.pktQueue.queuePriority = (unsigned char ) queuePriority;
            TRACE_PrintTrace(node,
                            *msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_OUT,
                            &acn,
                            NetworkIpGetInterfaceType(node, interfaceIndex));

           MESSAGE_AddHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);
        }
        else
        {

        //Trace dequeue
        ActionData acn;
        acn.actionType = DEQUEUE;
        acn.actionComment = NO_COMMENT;
        acn.pktQueue.interfaceID = (unsigned short) interfaceIndex;
        acn.pktQueue.queuePriority = (unsigned char ) queuePriority;
            TRACE_PrintTrace(node,
                            *msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_OUT,
                            &acn,
                            NetworkIpGetInterfaceType(node, interfaceIndex));
         }


        //GuiStart
        if (node->guiOption == TRUE)
        {
            unsigned queuePriority = GetQueuePriorityFromUserTos(
                                   node, userTos, (*scheduler).numQueue());
            GUI_QueueDequeuePacket(node->nodeId, GUI_NETWORK_LAYER,
                                   interfaceIndex, queuePriority,
                                   MESSAGE_ReturnPacketSize((*msg)),
                                   getSimTime(node) + getSimStartTime(node));

            if ((*msg)->headerProtocols[(*msg)->numberOfHeaders-1] == TRACE_LLC)
            {
                MESSAGE_RemoveHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);
                if (*networkType == (int) NETWORK_PROTOCOL_IPV6)
                {
                    ip6_hdr* ip6Header = (ip6_hdr*) (*msg)->packet;
                    if (IS_MULTIADDR6(ip6Header->ip6_dst))
                    {
                        GUI_Multicast(node->nodeId,
                                      GUI_NETWORK_LAYER,
                                      GUI_DEFAULT_DATA_TYPE,
                                      interfaceIndex,
                                      getSimTime(node));
                    }
                }
                else if (*networkType == (int) NETWORK_PROTOCOL_IP)
                {
                    IpHeaderType *ipHeader = (IpHeaderType *) (*msg)->packet;
                    if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
                    {
                        GUI_Multicast(node->nodeId,
                                      GUI_NETWORK_LAYER,
                                      GUI_DEFAULT_DATA_TYPE,
                                      interfaceIndex,
                                      getSimTime(node));
                    }
                }
                MESSAGE_AddHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);
            }
            else
            {
                if (*networkType == (int) NETWORK_PROTOCOL_IPV6)
                {
                    ip6_hdr* ip6Header = (ip6_hdr*) (*msg)->packet;
                    if (IS_MULTIADDR6(ip6Header->ip6_dst))
                    {
                        GUI_Multicast(node->nodeId,
                                      GUI_NETWORK_LAYER,
                                      GUI_DEFAULT_DATA_TYPE,
                                      interfaceIndex,
                                      getSimTime(node));
                    }
                }
                else if (*networkType == (int) NETWORK_PROTOCOL_IP)
                {
                    IpHeaderType *ipHeader = (IpHeaderType *) (*msg)->packet;
                    if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
                    {
                        GUI_Multicast(node->nodeId,
                                      GUI_NETWORK_LAYER,
                                      GUI_DEFAULT_DATA_TYPE,
                                      interfaceIndex,
                                      getSimTime(node));
                    }
                }
            }
        }
        //GuiEnd
    }

    return dequeued;
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueDequeuePacketForAPriority()
// PURPOSE      Same as NetworkIpOutputQueueDequeuePacket(), except the
//              packet dequeued is requested by a specific priority,
//              instead of leaving the priority decision up to the
//              packet scheduler.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              QueuePriorityType priority
//                  Priority of packet.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int *networkType
//                  Type of network (IP, Link-16, ...) used to route packet.
//              posInQueue
//                  Position of packet in Queue.
//                  Added as part of IP-MPLS integration
// RETURN       TRUE if dequeued successfully, FALSE otherwise.
//
// NOTES        This function is called by
//              MAC_OutputQueueDequeuePacketForAPriority() (mac/mac.pc),
//              which itself is called from mac/mac_802_11.pc and other
//              MAC protocol source files.
//
//              This function will assert false if the scheduler cannot
//              return an IP packet for whatever reason.
//-----------------------------------------------------------------------------

BOOL NetworkIpOutputQueueDequeuePacketForAPriority(
    Node *node,
    int interfaceIndex,
    QueuePriorityType priority,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *networkType,
    int posInQueue)
{
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;
    Scheduler *scheduler = NULL;
    QueuePriorityType queuePriority = ALL_PRIORITIES;
    QueuedPacketInfo *infoPtr;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    if ((*scheduler).retrieve(priority, posInQueue, msg,
                &queuePriority, DEQUEUE_PACKET, getSimTime(node)))
    {
        ERROR_Assert(*msg != NULL, "Cannot dequeue packet");

        infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo((*msg));

        *nextHopAddress = infoPtr->nextHopAddress;

        nexthopmacAddr->hwLength = infoPtr->hwLength;
        nexthopmacAddr->hwType = infoPtr->hwType;
        //Added to avoid double memory allocation and hence memory leak
        if (nexthopmacAddr->byte == NULL)
        {
            nexthopmacAddr->byte = (unsigned char*) MEM_malloc(
                              sizeof(unsigned char)*infoPtr->hwLength);
        }
        memcpy(nexthopmacAddr->byte,infoPtr->macAddress,infoPtr->hwLength);
        *networkType = infoPtr->networkType;

        if ((*msg)->headerProtocols[(*msg)->numberOfHeaders-1] == TRACE_LLC)
        {
            MESSAGE_RemoveHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);

        //Trace dequeue
        ActionData acn;
        acn.actionType = DEQUEUE;
        acn.actionComment = NO_COMMENT;
        acn.pktQueue.interfaceID = (unsigned short)interfaceIndex;
        acn.pktQueue.queuePriority = (unsigned char) queuePriority;
            TRACE_PrintTrace(node,
                            *msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_OUT,
                            &acn,
                            NetworkIpGetInterfaceType(node, interfaceIndex));

            MESSAGE_AddHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);
        }
        else
        {
            //Trace dequeue
            ActionData acn;
            acn.actionType = DEQUEUE;
            acn.actionComment = NO_COMMENT;
            acn.pktQueue.interfaceID = (unsigned short)interfaceIndex;
            acn.pktQueue.queuePriority = (unsigned char) queuePriority;
            TRACE_PrintTrace(node,
                            *msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_OUT,
                            &acn,
                            NetworkIpGetInterfaceType(node, interfaceIndex));
        }
        (*scheduler).collectGraphData((int) priority,
                                MESSAGE_ReturnPacketSize((*msg)),
                                TIME_getSimTime(node));

        //GuiStart
        if (node->guiOption == TRUE)
        {
            GUI_QueueDequeuePacket(node->nodeId, GUI_NETWORK_LAYER,
                                   interfaceIndex, queuePriority,
                                   MESSAGE_ReturnPacketSize((*msg)),
                                   getSimTime(node) + getSimStartTime(node));
        }
        //GuiEnd
        return TRUE;
    }
    return FALSE;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueDropPacket
// PURPOSE      Drop a packet from the queue.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              Message **msg
//                  Packet to be dropped.
// RETURN       Next hop of dropped packet.
NodeAddress
NetworkIpOutputQueueDropPacket(Node* node,
                               int interfaceIndex,
                               Message **msg,
                               MacHWAddress* nexthopmacAddr)
{
    NodeAddress nextHopAddress;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *scheduler = NULL;
    QueuePriorityType queuePriority = ALL_PRIORITIES;

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    (*scheduler).retrieve(ALL_PRIORITIES,
                        DEQUEUE_NEXT_PACKET,
                        msg,
                        &queuePriority,
                        DISCARD_PACKET,
                        getSimTime(node));


#ifdef ENTERPRISE_LIB
        LlcHeader* llc = NULL;

        if (LlcIsEnabled(node, (int)DEFAULT_INTERFACE))
        {
            if ((*msg)->headerProtocols[(*msg)->numberOfHeaders - 1] ==
                                                                   TRACE_LLC)
            {
               llc = (LlcHeader*) MESSAGE_ReturnPacket((*msg));
            }
        }

        MplsData *mpls = (MplsData *)node->macData[interfaceIndex]->mplsVar;

        if (mpls && llc && llc->etherType == PROTOCOL_TYPE_MPLS)
        {
            return MplsExtractInfoField(
                             node,
                             interfaceIndex,
                             msg, nexthopmacAddr);
        }
#endif // ENTERPRISE_LIB

    nextHopAddress = ((QueuedPacketInfo *)
                     MESSAGE_ReturnInfo((*msg)))->nextHopAddress;


    nexthopmacAddr->hwLength = ((QueuedPacketInfo *)
                                    MESSAGE_ReturnInfo((*msg)))->hwLength;
    nexthopmacAddr->hwType = ((QueuedPacketInfo *)
                                    MESSAGE_ReturnInfo((*msg)))->hwType;
    //Added to avoid double memory allocation and hence memory leak
    if (nexthopmacAddr->byte == NULL)
    {
        nexthopmacAddr->byte = (unsigned char*) MEM_malloc(
                             sizeof(unsigned char)*nexthopmacAddr->hwLength);
    }
    memcpy(nexthopmacAddr->byte,
        ((QueuedPacketInfo *)MESSAGE_ReturnInfo((*msg)))->macAddress,
        ((QueuedPacketInfo *)MESSAGE_ReturnInfo((*msg)))->hwLength);

    return(nextHopAddress);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpQueueDeleteOutboundPacketsToANode()
// PURPOSE      Deletes all packets in the queue going (probably broken),
//              to the specified next hop address.   There is option
//              to return all such packets back to the routing protocols.
//              via the usual mechanism (callback).
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeAddress nextHopAddress
//                  Next hop associated with outbound packets.
//              const NodeAddress destinationAddress
//                  destination associated with outbound packets.
//              const BOOL returnPacketsToRoutingProtocol
//                  Determine whether or not dropped packets should be
//                  returned to the routing protocol for further processing.
// RETURN       None.
//-----------------------------------------------------------------------------

void NetworkIpDeleteOutboundPacketsToANode(
   Node *node,
   const NodeAddress nextHopAddress,
   const NodeAddress destinationAddress,
   const BOOL returnPacketsToRoutingProtocol)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int interfaceIndex;

    //BUG: Should Delete the packets outbound only on the
    //interface on which packet is been dropped.
    for (interfaceIndex = 0;
         interfaceIndex < node->numberInterfaces;
         interfaceIndex++)
    {
        if (TunnelIsVirtualInterface(node, interfaceIndex))
        {
            continue;
        }
        int queueIndex = DEQUEUE_NEXT_PACKET;
        Scheduler *scheduler = NULL;
        QueuedPacketInfo *infoPtr;

        scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

        while (queueIndex < NetworkIpOutputQueueNumberInQueue(
                                node,
                                interfaceIndex,
                                FALSE /* specificPriorityOnly */,
                                ALL_PRIORITIES))
        {
            Message *msg = NULL;
            QueuePriorityType msgPriority = ALL_PRIORITIES;
            NodeAddress currentNextHopAddress;
            NodeAddress currentDestinationAddress;

            if (!scheduler->retrieve(ALL_PRIORITIES,
                                     queueIndex,
                                     &msg,
                                     &msgPriority,
                                     PEEK_AT_NEXT_PACKET,
                                     getSimTime(node)))
            {
                ERROR_ReportError("Cannot retrieve packet");
            }

            infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo(msg);

            msgPriority = infoPtr->userTos;
            currentNextHopAddress = infoPtr->nextHopAddress;

            currentDestinationAddress =
                infoPtr->destinationAddress.ipv4DestAddr;

            if (((nextHopAddress == ANY_IP) ||
                 (currentNextHopAddress == nextHopAddress)) &&
                ((destinationAddress == ANY_IP) ||
                 (currentDestinationAddress == destinationAddress)))
            {
                if (!scheduler->retrieve(ALL_PRIORITIES,
                                         queueIndex,
                                         &msg,
                                         &msgPriority,
                                         DROP_PACKET,
                                         getSimTime(node)))
                {
                    ERROR_ReportError("Cannot retrieve packet");
                }

                msgPriority =
                    ((QueuedPacketInfo *) MESSAGE_ReturnInfo(msg))->userTos;
#ifdef ADDON_DB
                HandleNetworkDBEvents(
                    node,
                    msg,
                    ((QueuedPacketInfo *) MESSAGE_ReturnInfo(msg))->incomingInterface,
                    "NetworkPacketDrop",
                    "Deleting Outbound Packet",
                    0,
                    0,
                    0,
                    0);
#endif

                if (returnPacketsToRoutingProtocol)
                {
                    HandleSpecialMacLayerStatusEvents(node,
                                                      msg,
                                                      nextHopAddress,
                                                      interfaceIndex);
                }
                else
                {
                    MESSAGE_Free(node, msg);
                }
            }
            else
            {
                queueIndex ++;
            }
        }
    }
}

//-----------------------------------------------------------------------------
// Network-layer queue information
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpQueueTopPacket()
// PURPOSE      Same as NetworkIpQueueDequeuePacket(), except the
//              packet is not actually dequeued.  Note that the message
//              containing the packet is not copied; the contents may
//              (inadvertently or not) be directly modified.
// PARAMETERS   Node *node
//                  Pointer to node.
//              SchedulerType *scheduler
//                  queue to get top packet from.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int *outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int *networkType
//                  Whether packet is associated with an IP network, Link-16
//                  nework, etc...
//              QueuePriorityType *priority
//                  Storage for priority of packet.
//              posInQueue
//                  Position of packet in Queue.
//                  Added as part of IP-MPLS integration
// RETURN       TRUE if there is a packet, FALSE otherwise.
//-----------------------------------------------------------------------------

BOOL NetworkIpQueueTopPacket(
    Node *node,
    Scheduler *scheduler,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *outgoingInterface,
    int *networkType,
    QueuePriorityType *priority,
    int posInQueue)
{
    QueuePriorityType notUsed = ALL_PRIORITIES;
    QueuePriorityType queuePriority = ALL_PRIORITIES;
    BOOL isPktRetrieved = FALSE;
    QueuedPacketInfo *infoPtr;

    isPktRetrieved = (*scheduler).retrieve(notUsed,
                                           posInQueue,
                                            msg,
                                            &queuePriority,
                                            PEEK_AT_NEXT_PACKET,
                                            getSimTime(node));

    if (isPktRetrieved)
    {
        ERROR_Assert(*msg != NULL, "Cannot retrieve packet");

        infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo((*msg));

        // Retuning Queue priority
        *priority = queuePriority;
        *nextHopAddress = infoPtr->nextHopAddress;

        nexthopmacAddr->hwLength = infoPtr->hwLength;
        nexthopmacAddr->hwType = infoPtr->hwType;
        //Added to avoid double memory allocation and hence memory leak
        if (nexthopmacAddr->byte == NULL)
        {
            nexthopmacAddr->byte = (unsigned char*) MEM_malloc(
                              sizeof(unsigned char)*infoPtr->hwLength);
        }
        memcpy(nexthopmacAddr->byte,infoPtr->macAddress,infoPtr->hwLength);
        *outgoingInterface = infoPtr->outgoingInterface;
        *networkType = infoPtr->networkType;
    }

    return isPktRetrieved;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpQueueTopPacketForUserPriority()
// PURPOSE      Same as NetworkIpQueueTopPacket(), except the priority
//              value returned is user priority instead of queue priority.
// PARAMETERS   Node *node
//                  Pointer to node.
//              SchedulerType *scheduler
//                  queue to get top packet from.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int *outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int *networkType
//                  Whether packet is associated with an IP network, Link-16
//                  nework, etc...
//              TosType *priority
//                  Storage for user priority of packet.
// RETURN       TRUE if there is a packet, FALSE otherwise.
//-----------------------------------------------------------------------------

BOOL NetworkIpQueueTopPacketForUserPriority(
    Node *node,
    Scheduler *scheduler,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *outgoingInterface,
    int *networkType,
    TosType *priority)
{
    QueuePriorityType notUsed = ALL_PRIORITIES;
    QueuePriorityType queuePriority = ALL_PRIORITIES;
    BOOL isPktRetrieved = FALSE;
    QueuedPacketInfo *infoPtr;

    isPktRetrieved = (*scheduler).retrieve(notUsed,
                                        DEQUEUE_NEXT_PACKET,
                                        msg,
                                        &queuePriority,
                                        PEEK_AT_NEXT_PACKET,
                                        getSimTime(node));
    if (isPktRetrieved)
    {
        ERROR_Assert(*msg != NULL, "Cannot retrieve packet");

        infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo((*msg));

        *priority = infoPtr->userTos;
        *nextHopAddress = infoPtr->nextHopAddress;

         nexthopmacAddr->hwLength = infoPtr->hwLength;
        nexthopmacAddr->hwType = infoPtr->hwType;
        //Added to avoid double memory allocation and hence memory leak
        if (nexthopmacAddr->byte == NULL)
        {
            nexthopmacAddr->byte = (unsigned char*) MEM_malloc(
                             sizeof(unsigned char)*infoPtr->hwLength);
        }
        memcpy(nexthopmacAddr->byte,infoPtr->macAddress,infoPtr->hwLength);
        *outgoingInterface = infoPtr->outgoingInterface;
        *networkType = infoPtr->networkType;
    }

    return isPktRetrieved;
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpCpuQueueTopPacket()
// PURPOSE      Same as NetworkIpCpuQueueDequeuePacket(), except the
//              packet is not actually dequeued.  Note that the message
//              containing the packet is not copied; the contents may
//              (inadvertently or not) be directly modified.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int *outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int *networkType
//                  Whether packet is associated with an IP network, Link-16
//                  nework, etc...
//              QueuePriorityType *priority
//                  Storage for priority of packet.
// RETURN       TRUE if there is a packet, FALSE otherwise.
//-----------------------------------------------------------------------------
BOOL NetworkIpCpuQueueTopPacket(
    Node *node,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *outgoingInterface,
    int *networkType,
    QueuePriorityType *priority)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *cpuScheduler = NULL;

    cpuScheduler = ip->cpuScheduler;

    return NetworkIpQueueTopPacket(node,
                                   cpuScheduler,
                                   msg,
                                   nextHopAddress,
                                   nexthopmacAddr,
                                   outgoingInterface,
                                   networkType,
                                   priority);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpInputQueueTopPacket()
// PURPOSE      Same as NetworkIpInputQueueDequeuePacket(), except the
//              packet is not actually dequeued.  Note that the message
//              containing the packet is not copied; the contents may
//              (inadvertently or not) be directly modified.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int incomingInterface
//                  interface to get top packet from.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int *outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int *networkType
//                  Whether packet is associated with an IP network, Link-16
//                  nework, etc...
//              QueuePriorityType *priority
//                  Storage for priority of packet.
// RETURN       TRUE if there is a packet, FALSE otherwise.
//-----------------------------------------------------------------------------

BOOL NetworkIpInputQueueTopPacket(
    Node *node,
    int incomingInterface,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *outgoingInterface,
    int *networkType,
    QueuePriorityType *priority)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *inputScheduler = NULL;

    ERROR_Assert(
        incomingInterface >= 0 && incomingInterface < node->numberInterfaces,
        "Invalid interface index");

    inputScheduler = ip->interfaceInfo[incomingInterface]->inputScheduler;

    return NetworkIpQueueTopPacket(node,
                                   inputScheduler,
                                   msg,
                                   nextHopAddress,
                                   nexthopmacAddr,
                                   outgoingInterface,
                                   networkType,
                                   priority);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueTopPacket()
// PURPOSE      Same as NetworkIpOutputQueueDequeuePacket(), except the
//              packet is not actually dequeued.  Note that the message
//              containing the packet is not copied; the contents may
//              (inadvertently or not) be directly modified.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int *networkType
//                  Whether packet is associated with an IP network, Link-16
//                  nework, etc...
//              QueuePriorityType *priority
//                  Storage for priority of packet.
// RETURN       TRUE if there is a packet, FALSE otherwise.
//
// NOTES        This function is called by MAC_OutputQueueTopPacket()
//              (mac/mac.pc), which itself is called from
//              mac/mac_802_11.pc and other MAC protocol source files.
//
//              This function will assert false if the scheduler cannot
//              return an IP packet for whatever reason.
//-----------------------------------------------------------------------------

BOOL NetworkIpOutputQueueTopPacket(
    Node *node,
    int interfaceIndex,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress* nexthopmacAddr,
    int* networkType,
    QueuePriorityType *priority)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *scheduler = NULL;
    int outgoingInterface;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    return NetworkIpQueueTopPacket(node,
                                   scheduler,
                                   msg,
                                   nextHopAddress,
                                   nexthopmacAddr,
                                   &outgoingInterface,
                                   networkType,
                                   priority);
}

//---------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueTopPacket()
// PURPOSE      Same as NetworkIpOutputQueueDequeuePacket(), except the
//              packet is not actually dequeued.  Note that the message
//              containing the packet is not copied; the contents may
//              (inadvertently or not) be directly modified.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int *networkType
//                  Whether packet is associated with an IP network, Link-16
//                  nework, etc...
//              QueuePriorityType *priority
//                  Storage for priority of packet.
//              posInQueue : index of packet in queue
// RETURN       TRUE if there is a packet, FALSE otherwise.
//
// NOTES        This function is called by MAC_OutputQueueTopPacket()
//              (mac/mac.pc), which itself is called from
//              mac/mac_802_11.pc and other MAC protocol source files.
//
//              This function will assert false if the scheduler cannot
//              return an IP packet for whatever reason.
//---------------------------------------------------------------------------

BOOL NetworkIpOutputQueueTopPacket(
    Node *node,
    int interfaceIndex,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress* nexthopmacAddr,
    int* networkType,
    QueuePriorityType *priority,
    int posInQueue)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *scheduler = NULL;
    int outgoingInterface;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    return NetworkIpQueueTopPacket(node,
                                   scheduler,
                                   msg,
                                   nextHopAddress,
                                   nexthopmacAddr,
                                   &outgoingInterface,
                                   networkType,
                                   priority,
                                   posInQueue);
}
//---------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueTopPacketForAPriority()
// PURPOSE      Same as NetworkIpOutputQueueDequeuePacketForAPriority(),
//              except the packet is not actually dequeued.  Note that
//              the message containing the packet is not copied; the
//              contents may (inadvertently or not) be directly
//              modified.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              QueuePriorityType priority
//                  Priority of the queue.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              posInQueue
//                  Position of packet in Queue.
//                  Added as part of IP-MPLS integration
// RETURN       TRUE if there is a packet, FALSE otherwise.
//
// NOTES        This function is called by
//              MAC_OutputQueueTopPacketForAPriority() (mac/mac.pc),
//              which itself is called from mac/mac_802_11.pc and other
//              MAC protocol source files.
//
//              This function will assert false if the scheduler cannot
//              return an IP packet for whatever reason.
//-----------------------------------------------------------------------------

BOOL NetworkIpOutputQueueTopPacketForAPriority(
    Node *node,
    int interfaceIndex,
    QueuePriorityType priority,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int posInQueue)
{
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;
    Scheduler *scheduler = NULL;
    QueuePriorityType queuePriority = ALL_PRIORITIES;
    BOOL isPktRetrieved = FALSE;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    isPktRetrieved = (*scheduler).retrieve(priority,
                                            posInQueue,
                                            msg,
                                            &queuePriority,
                                            PEEK_AT_NEXT_PACKET,
                                            getSimTime(node));

    if (isPktRetrieved)
    {
        ERROR_Assert(*msg != NULL, "Cannot retrieve packet");

        *nextHopAddress =
            ((QueuedPacketInfo *)MESSAGE_ReturnInfo((*msg)))->nextHopAddress;


        nexthopmacAddr->hwLength = ((QueuedPacketInfo *)
                                    MESSAGE_ReturnInfo((*msg)))->hwLength;
        nexthopmacAddr->hwType = ((QueuedPacketInfo *)
                                    MESSAGE_ReturnInfo((*msg)))->hwType;
        //Added to avoid double memory allocation and hence memory leak
        if (nexthopmacAddr->byte == NULL)
        {
            nexthopmacAddr->byte = (unsigned char*) MEM_malloc(
                             sizeof(unsigned char)*nexthopmacAddr->hwLength);
        }
        memcpy(nexthopmacAddr->byte,
              ((QueuedPacketInfo *)MESSAGE_ReturnInfo((*msg)))->macAddress,
              ((QueuedPacketInfo *)MESSAGE_ReturnInfo((*msg)))->hwLength);
    }

    return isPktRetrieved;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpQueueIsEmpty()
// PURPOSE      Calls the packet scheduler for an interface to determine
//              whether the interface's cpu queue is empty.
// PARAMETERS   Node *node
//                  Pointer to node.
//              SchedulerType *scheduler
//                  Queue to determine empty from.
// RETURN       TRUE if the scheduler says the interface's cpu queue
//              is empty.
//              FALSE if the scheduler says the interface's cpu queue
//              is not empty.
//-----------------------------------------------------------------------------

static BOOL
NetworkIpQueueIsEmpty(Node *node,
                      Scheduler *scheduler)
{
    return ((*scheduler).isEmpty(ALL_PRIORITIES));
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpCpuQueueIsEmpty()
// PURPOSE      Calls the packet scheduler for an interface to determine
//              whether the interface's cpu queue is empty.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       TRUE if the scheduler says the interface's cpu queue
//              is empty.
//              FALSE if the scheduler says the interface's cpu queue
//              is not empty.
//-----------------------------------------------------------------------------


BOOL
NetworkIpCpuQueueIsEmpty(Node *node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *cpuScheduler = NULL;

    cpuScheduler = ip->cpuScheduler;

    return NetworkIpQueueIsEmpty(node, cpuScheduler);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpInputQueueIsEmpty()
// PURPOSE      Calls the packet scheduler for an interface to determine
//              whether the interface's input queue is empty.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int incomingInterface
//                  Index of interface.
// RETURN       TRUE if the scheduler says the interface's input queue
//              is empty.
//              FALSE if the scheduler says the interface's input queue
//              is not empty.
//-----------------------------------------------------------------------------

BOOL
NetworkIpInputQueueIsEmpty(Node *node, int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *inputScheduler = NULL;

    ERROR_Assert(
        incomingInterface >= 0 && incomingInterface < node->numberInterfaces,
        "Invalid incoming interface");

    inputScheduler = ip->interfaceInfo[incomingInterface]->inputScheduler;

    return NetworkIpQueueIsEmpty(node, inputScheduler);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueIsEmpty()
// PURPOSE      Calls the packet scheduler for an interface to determine
//              whether the interface's output queue is empty.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
// RETURN       TRUE if the scheduler says the interface's output queue
//              is empty.
//              FALSE if the scheduler says the interface's output queue
//              is not empty.
//-----------------------------------------------------------------------------

BOOL
NetworkIpOutputQueueIsEmpty(Node *node, int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

#ifdef ENTERPRISE_LIB
    MplsData *mpls = (MplsData *) node->macData[interfaceIndex]->mplsVar;
    if (mpls)
    {
        return (MplsOutputQueueIsEmpty(node, interfaceIndex));
    }
    else
#endif // ENTERPRISE_LIB
    {
        Scheduler *scheduler = NULL;

        scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

        return NetworkIpQueueIsEmpty(node, scheduler);
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueNumberInQueue()
// PURPOSE      Calls the packet scheduler for an interface to determine
//              how many packets are in a queue.  There may be multiple
//              queues on an interface, so the priority of the desired
//              queue is also provided.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              BOOL specificPriorityOnly
//                  Should we only get the number of packets in queue for
//                  the specified priority only or for all priorities.
//              QueuePriorityType priority
//                  Priority of queue.
// RETURN       Number of packets in queue.
//-----------------------------------------------------------------------------

int
NetworkIpOutputQueueNumberInQueue(
    Node *node,
    int interfaceIndex,
    BOOL specificPriorityOnly,
    QueuePriorityType priority)
{
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;
    Scheduler *scheduler = NULL;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;
    return (*scheduler).numberInQueue(priority);
}


//-----------------------------------------------------------------------------
// FUNCTION: GetQueueNumberFromPriority
// PURPOSE:  Get queue number through which a given user priority
//           will be forwarded.
// PARAMETERS:  TosType userTos
//                  User priority.
//              int numQueues
//                  Maximum number of queue available.
// RETURN: Index of the queue.
//
// Note: This mapping is done based on ip scheduler mapping.
//       If there is any change in that mapping, this mapping
//       should also be changed accordingly.
//-----------------------------------------------------------------------------

unsigned GetQueueNumberFromPriority(
    TosType userTos,
    int numQueues)
{
    int i = 0;

    for (i = numQueues - 1; i >= 0; i--)
    {
        if ((TosType) i <= (userTos >> 5))
        {
            // Return the queue whose priority same as packet priority
            return i;
        }
    }
    return IPTOS_PREC_ROUTINE;
}

static
unsigned GetQueuePriorityFromUserTos(
    Node *node,
    TosType userTos,
    int numQueues)
{
    int i = 0;

    int queuePriority = ReturnPriorityForPHB(node, userTos);

    for (i = numQueues - 1; i >= 0; i--)
    {
        if (i <= queuePriority)
        {
            // Return the queue in or from which
            // packet has been queued or dequeued
            return i;
        }
    }
    return IPTOS_PREC_ROUTINE;
}


//-----------------------------------------------------------------------------
// Per hop behavior (PHB) routing
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     ReturnPriorityForPHB()
// PURPOSE
// PARAMETERS   Node *node
//                  Pointer to node.
//              TosType tos
//
//
// RETURNS
//-----------------------------------------------------------------------------

QueuePriorityType
ReturnPriorityForPHB(
    Node *node,
    TosType tos)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;

#ifdef DEBUG
    printf("#%d: ReturnPriorityForPHB(%d) = ", node->nodeId, tos);
#endif

    for (i = 0; i < ip->numPhbInfo; i++)
    {
        if (ip->phbInfo[i].ds == tos >> 2)
        {
#ifdef DEBUG
    printf("%d\n", ip->phbInfo[i].priority);
#endif
            return ip->phbInfo[i].priority;
        }
    }

#ifdef ENTERPRISE_LIB
    // look for the default priority queue for best effort traffic
    if (ip->diffservEnabled)
    {
        for (i = 0; i < ip->numPhbInfo; i++)
        {
            if (ip->phbInfo[i].ds == DIFFSERV_DS_CLASS_BE)
            {
#ifdef DEBUG
                printf("%d\n", ip->phbInfo[i].priority);
#endif
                return ip->phbInfo[i].priority;
            }
        }
    }
#endif // ENTERPRISE_LIB

#ifdef DEBUG
    printf("%d\n", (QueuePriorityType) tos >> 5);
#endif
    return ((QueuePriorityType) (tos >> 5));
}

//-----------------------------------------------------------------------------
// Routing table (forwarding table)
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkGetInterfaceAndNextHopFromForwardingTable()
// PURPOSE      Do a lookup on the routing table with a destination IP
//              address to obtain a route (index of an outgoing
//              interface and a next hop Ip address).
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int *interfaceIndex
//                  Storage for index of outgoing interface.
//              NodeAddress *nextHopAddress
//                  Storage for next hop IP address.
//                  If no route can be found, *nextHopAddress will be
//                  set to NETWORK_UNREACHABLE.
// RETURN       None.
//-----------------------------------------------------------------------------

void NetworkGetInterfaceAndNextHopFromForwardingTable(
    Node *node,
    NodeAddress destinationAddress,
    int *interfaceIndex,
    NodeAddress *nextHopAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *forwardTable = &(ip->forwardTable);
    int i;

    *interfaceIndex = NETWORK_UNREACHABLE;
    *nextHopAddress = (unsigned) NETWORK_UNREACHABLE;

    //NetworkPrintForwardingTable(node);

    for (i=0; i < forwardTable->size; i++) {
        NodeAddress maskedDestinationAddress =
            MaskIpAddress(
                destinationAddress, forwardTable->row[i].destAddressMask);

        if (forwardTable->row[i].destAddress == maskedDestinationAddress
            && forwardTable->row[i].nextHopAddress !=
            (unsigned) NETWORK_UNREACHABLE
            && forwardTable->row[i].interfaceIsEnabled != FALSE)
        {
            *interfaceIndex = forwardTable->row[i].interfaceIndex;
            *nextHopAddress = forwardTable->row[i].nextHopAddress;
            break;
        }
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkGetInterfaceAndNextHopFromForwardingTable()
// PURPOSE      Do a lookup on the routing table with a destination IP
//              address to obtain a route (index of an outgoing
//              interface and a next hop Ip address).
// PARAMETERS   Node *node
//                  Pointer to node.
//              int currentInterface
//                  The current interface for which we want to find
//                  a route match.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int *interfaceIndex
//                  Storage for index of outgoing interface.
//              NodeAddress *nextHopAddress
//                  Storage for next hop IP address.
//                  If no route can be found, *nextHopAddress will be
//                  set to NETWORK_UNREACHABLE.
// RETURN       None.
//-----------------------------------------------------------------------------

void NetworkGetInterfaceAndNextHopFromForwardingTable(
    Node *node,
    int currentInterface,
    NodeAddress destinationAddress,
    int *interfaceIndex,
    NodeAddress *nextHopAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *forwardTable = &(ip->forwardTable);
    int i;

    *interfaceIndex = NETWORK_UNREACHABLE;
    *nextHopAddress = (unsigned) NETWORK_UNREACHABLE;

    //NetworkPrintForwardingTable(node);

    for (i=0; i < forwardTable->size; i++) {
        NodeAddress maskedDestinationAddress =
            MaskIpAddress(
                destinationAddress, forwardTable->row[i].destAddressMask);

        if (forwardTable->row[i].destAddress == maskedDestinationAddress
            && forwardTable->row[i].nextHopAddress !=
            (unsigned) NETWORK_UNREACHABLE
            && forwardTable->row[i].interfaceIsEnabled != FALSE
            && forwardTable->row[i].interfaceIndex == currentInterface)
        {
            *interfaceIndex = forwardTable->row[i].interfaceIndex;
            *nextHopAddress = forwardTable->row[i].nextHopAddress;
            break;
        }
    }
}
//-----------------------------------------------------------------------------
// FUNCTION     NetworkGetInterfaceAndNextHopFromForwardingTable()
// PURPOSE      Do a lookup on the routing table with a destination IP
//              address to obtain a route (index of an outgoing
//              interface and a next hop Ip address).
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int *interfaceIndex
//                  Storage for index of outgoing interface.
//              NodeAddress *nextHopAddress
//                  Storage for next hop IP address.
//                  If no route can be found, *nextHopAddress will be
//                  set to NETWORK_UNREACHABLE.
//              BOOL *routeType true if forwarding table has entry for
//                    particular destination false if for network.
// RETURN       None.
//-----------------------------------------------------------------------------

void NetworkGetInterfaceAndNextHopFromForwardingTable(
    Node *node,
    NodeAddress destinationAddress,
    int *interfaceIndex,
    NodeAddress *nextHopAddress,
    BOOL *routeType)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *forwardTable = &(ip->forwardTable);
    int i;

    *interfaceIndex = NETWORK_UNREACHABLE;
    *nextHopAddress = (unsigned) NETWORK_UNREACHABLE;

    //NetworkPrintForwardingTable(node);

    for (i=0; i < forwardTable->size; i++) {
        NodeAddress maskedDestinationAddress =
            MaskIpAddress(
                destinationAddress, forwardTable->row[i].destAddressMask);

        if (forwardTable->row[i].destAddress == maskedDestinationAddress
            && forwardTable->row[i].nextHopAddress != (unsigned) NETWORK_UNREACHABLE
            && forwardTable->row[i].interfaceIsEnabled != FALSE)
        {
            if (maskedDestinationAddress == destinationAddress)
            {
                *routeType = TRUE;
            }
            else
            {
                *routeType = FALSE;
            }
            *interfaceIndex = forwardTable->row[i].interfaceIndex;
            *nextHopAddress = forwardTable->row[i].nextHopAddress;
            break;
        }
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkGetInterfaceAndNextHopFromForwardingTable()
// PURPOSE      Do a lookup on the routing table with a destination IP
//              address to obtain a route (index of an outgoing
//              interface and a next hop Ip address).
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int *interfaceIndex
//                  Storage for index of outgoing interface.
//              NodeAddress *nextHopAddress
//                  Storage for next hop IP address.
//                  If no route can be found, *nextHopAddress will be
//                  set to NETWORK_UNREACHABLE.
//              BOOL testType
//                  same protocol's routes if true
//                  different protocol's routes else
//              NetworkRoutingProtocolType type
//                  routing protocol type
// RETURN       None.
//-----------------------------------------------------------------------------
void NetworkGetInterfaceAndNextHopFromForwardingTable
(
    Node *node,
    NodeAddress destinationAddress,
    int *interfaceIndex,
    NodeAddress *nextHopAddress,
    BOOL testType,
    NetworkRoutingProtocolType type)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *forwardTable = &(ip->forwardTable);
    int i;

    *interfaceIndex = NETWORK_UNREACHABLE;
    *nextHopAddress = (unsigned) NETWORK_UNREACHABLE;

    // NetworkPrintForwardingTable(node);

    for (i=0; i < forwardTable->size; i++) {
        NodeAddress maskedDestinationAddress =
            MaskIpAddress(
                destinationAddress,
                forwardTable->row[i].destAddressMask);

        if (forwardTable->row[i].destAddress == maskedDestinationAddress
            && forwardTable->row[i].nextHopAddress !=
            (unsigned) NETWORK_UNREACHABLE
            && forwardTable->row[i].interfaceIsEnabled != FALSE)
        {
            if (testType == TRUE &&
                forwardTable->row[i].protocolType == type)
            {
                *interfaceIndex = forwardTable->row[i].interfaceIndex;
                *nextHopAddress = forwardTable->row[i].nextHopAddress;
                break;
            }
            else if (testType == FALSE && forwardTable->row[i].protocolType
                != type)
            {
                *interfaceIndex = forwardTable->row[i].interfaceIndex;
                *nextHopAddress = forwardTable->row[i].nextHopAddress;
                break;
            }
        }
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkGetInterfaceAndNextHopFromForwardingTable()
// PURPOSE      Do a lookup on the routing table with a destination IP
//              address to obtain a route (index of an outgoing
//              interface and a next hop Ip address).
// PARAMETERS   Node *node
//                  Pointer to node.
//              int operatingInterface
//                  interface currently being
//                  operated on. Routes will only be searched for that
//                  have an outgoing interface that matches the
//                  operating interface.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int *interfaceIndex
//                  Storage for index of outgoing interface.
//              NodeAddress *nextHopAddress
//                  Storage for next hop IP address.
//                  If no route can be found, *nextHopAddress will be
//                  set to NETWORK_UNREACHABLE.
//              BOOL testType
//                  same protocol's routes if true
//                  different protocol's routes else
//              NetworkRoutingProtocolType type
//                  routing protocol type
// RETURN       None.
//-----------------------------------------------------------------------------
void NetworkGetInterfaceAndNextHopFromForwardingTable
(
    Node *node,
    int operatingInterface,
    NodeAddress destinationAddress,
    int *interfaceIndex,
    NodeAddress *nextHopAddress,
    BOOL testType,
    NetworkRoutingProtocolType type)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *forwardTable = &(ip->forwardTable);
    int i;

    *interfaceIndex = NETWORK_UNREACHABLE;
    *nextHopAddress = (unsigned) NETWORK_UNREACHABLE;

    // NetworkPrintForwardingTable(node);

    for (i=0; i < forwardTable->size; i++) {
        NodeAddress maskedDestinationAddress =
            MaskIpAddress(
                destinationAddress,
                forwardTable->row[i].destAddressMask);

        if (forwardTable->row[i].destAddress == maskedDestinationAddress
            && forwardTable->row[i].nextHopAddress !=
            (unsigned) NETWORK_UNREACHABLE
            && forwardTable->row[i].interfaceIsEnabled != FALSE
            && forwardTable->row[i].interfaceIndex == operatingInterface)
        {
            if (testType == TRUE &&
                forwardTable->row[i].protocolType == type)
            {
                *interfaceIndex = forwardTable->row[i].interfaceIndex;
                *nextHopAddress = forwardTable->row[i].nextHopAddress;
                break;
            }
            else if (testType == FALSE && forwardTable->row[i].protocolType
                != type)
            {
                *interfaceIndex = forwardTable->row[i].interfaceIndex;
                *nextHopAddress = forwardTable->row[i].nextHopAddress;
                break;
            }
        }
    }
}



//-----------------------------------------------------------------------------
// FUNCTION     NetworkGetInterfaceAndNextHopFromForwardingTable()
// PURPOSE      Do a lookup on the routing table with a destination IP
//              address to obtain a route (index of an outgoing
//              interface and a next hop Ip address).
// PARAMETERS   Node *node
//                  Pointer to node.
//              int operatingInterface
//                  interface currently being
//                  operated on. Routes will only be searched for that
//                  have an outgoing interface that matches the
//                  operating interface.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int *interfaceIndex
//                  Storage for index of outgoing interface.
//              NodeAddress *nextHopAddress
//                  Storage for next hop IP address.
//                  If no route can be found, *nextHopAddress will be
//                  set to NETWORK_UNREACHABLE.
//              BOOL testType
//                  same protocol's routes if true
//                  different protocol's routes else
//              NetworkRoutingProtocolType type
//                  routing protocol type
// RETURN       None.
//-----------------------------------------------------------------------------
void NetworkGetInterfaceAndNextHopFromForwardingTable
(
    Node *node,
    NodeAddress destinationAddress,
    int *interfaceIndex,
    NodeAddress *nextHopAddress,
    BOOL testType,
    NetworkRoutingProtocolType type,
    BOOL* routeType)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *forwardTable = &(ip->forwardTable);
    int i;

    *interfaceIndex = NETWORK_UNREACHABLE;
    *nextHopAddress = (unsigned) NETWORK_UNREACHABLE;

    // NetworkPrintForwardingTable(node);

    for (i=0; i < forwardTable->size; i++) {
        NodeAddress maskedDestinationAddress =
            MaskIpAddress(
                destinationAddress,
                forwardTable->row[i].destAddressMask);

        if (forwardTable->row[i].destAddress == maskedDestinationAddress
            && forwardTable->row[i].nextHopAddress != (unsigned) NETWORK_UNREACHABLE
            && forwardTable->row[i].interfaceIsEnabled != FALSE)
        {
            if (testType == TRUE &&
                forwardTable->row[i].protocolType == type)
            {

                if (maskedDestinationAddress == destinationAddress)
                {
                    *routeType = TRUE;
                }
                else
                {
                    *routeType = FALSE;
                }

                *interfaceIndex = forwardTable->row[i].interfaceIndex;
                *nextHopAddress = forwardTable->row[i].nextHopAddress;
                break;
            }
            else if (testType == FALSE && forwardTable->row[i].protocolType != type)
            {

                if (maskedDestinationAddress == destinationAddress)
                {
                    *routeType = TRUE;
                }
                else
                {
                    *routeType = FALSE;
                }

                *interfaceIndex = forwardTable->row[i].interfaceIndex;
                *nextHopAddress = forwardTable->row[i].nextHopAddress;
                break;
            }
        }
    }
}

#ifdef ADDON_BOEINGFCS
void NetworkGetInterfaceAndSubnetAddressFromForwardingTable(
    Node *node,
    NodeAddress destinationAddress,
    int *interfaceIndex,
    NodeAddress *subnetMask)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *forwardTable = &(ip->forwardTable);
    int i;

    *interfaceIndex = NETWORK_UNREACHABLE;
    *subnetMask = (unsigned) NETWORK_UNREACHABLE;

    //NetworkPrintForwardingTable(node);

    for (i=0; i < forwardTable->size; i++) {
        NodeAddress maskedDestinationAddress =
            MaskIpAddress(
                destinationAddress, forwardTable->row[i].destAddressMask);

        if (forwardTable->row[i].destAddress == maskedDestinationAddress
            && forwardTable->row[i].nextHopAddress
            != (unsigned) NETWORK_UNREACHABLE
            && forwardTable->row[i].interfaceIsEnabled != FALSE)
        {
            *interfaceIndex = forwardTable->row[i].interfaceIndex;
            *subnetMask = maskedDestinationAddress;
            break;
        }
    }
}
#endif

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetInterfaceIndexForNextHop()
// PURPOSE      This function looks at the network address of each of a
//              node's network interfaces.  When nextHopAddress is
//              matched to a network, the interface index corresponding
//              to the network is returned.
//              (used by NetworkUpdateForwardingTable() and ospfv2.pc)
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress nextHopAddress
//                  IP address
//
// RETURN       Index of outgoing interface, if nextHopAddress is on a
//              directly connected network.
//              -1, otherwise.
//-----------------------------------------------------------------------------

int
NetworkIpGetInterfaceIndexForNextHop(
    Node *node,
    NodeAddress nextHopAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;

    if (nextHopAddress == (unsigned) NETWORK_UNREACHABLE)
    {
        // Return bad value early if the IP address is NETWORK_UNREACHABLE.

        return -1;
    }

    // Given a next hop IP address, return the index of the corresponding
    // outgoing interface.

    for (i = 0; i < node->numberInterfaces; i++)
    {
        NodeAddress subnetMask = NetworkIpGetInterfaceSubnetMask(node, i);
        NodeAddress maskedAddress = MaskIpAddress(nextHopAddress, subnetMask);
        NodeAddress interfaceNetworkAddress =
            MaskIpAddress(ip->interfaceInfo[i]->ipAddress, subnetMask);

        if (maskedAddress == interfaceNetworkAddress)
        {
            return i;
        }
    }

    // Couldn't find IP address on a directly connected network, so
    // return -1 as the interface index.

    return -1;
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkGetInterfaceIndexForDestAddress()
// PURPOSE      Get interface for the destination address.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destAddress
//                  destination associated with the interface.
// RETURN       interface index associated with destination.
//-----------------------------------------------------------------------------

int
NetworkGetInterfaceIndexForDestAddress(
    Node *node,
    NodeAddress destAddress)
{
    int interfaceIndex;
    NodeAddress nextHop;

    if (node->numberInterfaces == 1 || destAddress == ANY_DEST)
    {
        return DEFAULT_INTERFACE;
    }

    NetworkGetInterfaceAndNextHopFromForwardingTable(
        node, destAddress, &interfaceIndex, &nextHop);

    if (nextHop == (unsigned) NETWORK_UNREACHABLE)
    {
        return DEFAULT_INTERFACE;
    }
    else
    {
        return interfaceIndex;
    }
}


// FUNCTION   NetworkIpGetInterfaceIndexFromAddress
// PURPOSE    Get the interface index from an IP address.
// PARAMETERS node - this node.
//            address - address to determine interface index for.
// RETURN     interface index associated with specified address.
int NetworkIpGetInterfaceIndexFromAddress(Node *node, NodeAddress address)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->ipAddress == address)
        {
            return i;
        }
    }

    return -1;
}


// FUNCTION   NetworkIpGetInterfaceIndexFromSubnetAddress
// PURPOSE    Get the interface index from an IP subnet address.
// PARAMETERS node - this node.
//            address - subnet address to determine interface index for.
// RETURN     interface index associated with specified subnet address.
int NetworkIpGetInterfaceIndexFromSubnetAddress(Node *node,
                                                NodeAddress address)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;
    NodeAddress networkAddr, interfaceNetworkAddr;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        networkAddr = MaskIpAddress(address,
                                    ConvertNumHostBitsToSubnetMask(
                                           ip->interfaceInfo[i]->numHostBits));

        interfaceNetworkAddr = MaskIpAddress(ip->interfaceInfo[i]->ipAddress,
                                    ConvertNumHostBitsToSubnetMask(
                                           ip->interfaceInfo[i]->numHostBits));

        if (networkAddr == interfaceNetworkAddr)
        {
            return i;
        }
    }

    return -1;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkGetMetricForDestAddress()
// PURPOSE      Get the cost metric for a destination from the forwarding table.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destAddress
//                  destination to get cost metric from.
// RETURN       Cost metric associated with destination.
//-----------------------------------------------------------------------------

int
NetworkGetMetricForDestAddress(
    Node *node,
    NodeAddress destAddress,
    NetworkRoutingAdminDistanceType *dist)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *forwardTable = &(ip->forwardTable);
    int i;
    int metric = 0xFFFFFFFF;
    if (dist != NULL) {
        *dist = ROUTING_ADMIN_DISTANCE_DEFAULT;
    }

    for (i = 0; i < forwardTable->size; i++) {
        NodeAddress maskedDestinationAddress =
            MaskIpAddress(
                destAddress, forwardTable->row[i].destAddressMask);

        if (forwardTable->row[i].destAddress == maskedDestinationAddress
            && forwardTable->row[i].nextHopAddress !=
            (unsigned) NETWORK_UNREACHABLE
            && forwardTable->row[i].interfaceIsEnabled != FALSE)
        {
            metric = forwardTable->row[i].cost;
            if (dist != NULL)
            {
                *dist = forwardTable->row[i].adminDistance;
            }
            break;
        }
    }
    return metric;
}



//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSetRouteUpdateEventFunction()
// PURPOSE      Set a callback fuction when a route changes from the forwarding
//              table.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NetworkRouteUpdateEventType routeUpdateFunctionPtr)
//                  Route update callback function to set.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpSetRouteUpdateEventFunction(
    Node *node,
    NetworkRouteUpdateEventType routeUpdateFunctionPtr)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ERROR_Assert(ip->routeUpdateFunction == NULL,
                 "Error while setting route update function\n");

    ip->routeUpdateFunction = routeUpdateFunctionPtr;
}



//-----------------------------------------------------------------------------
// FUNCTION     NetworkRouteUpdateEventType()
// PURPOSE      Get the route update callback function.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       Route update function.
//-----------------------------------------------------------------------------

NetworkRouteUpdateEventType
NetworkIpGetRouteUpdateEventFunction(
    Node *node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    return (ip->routeUpdateFunction);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkRoutingGetAdminDistance()
// PURPOSE      Get the administrative distance of a routing protocol.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NetworkRoutingProtocolType type
//                  Type value of routing protocol.
// RETURN       The administrative distance of the routing protocol.
//
// NOTES        These values don't quite match those recommended by
//              Cisco.
//-----------------------------------------------------------------------------

NetworkRoutingAdminDistanceType
NetworkRoutingGetAdminDistance(
    Node *node,
    NetworkRoutingProtocolType type)
{
    switch (type)
    {
        case ROUTING_PROTOCOL_STATIC:
        {
            return ROUTING_ADMIN_DISTANCE_STATIC;
        }

        case ROUTING_PROTOCOL_DEFAULT:
        {
            return ROUTING_ADMIN_DISTANCE_DEFAULT;
        }

        case EXTERIOR_GATEWAY_PROTOCOL_EBGPv4:
        {
#ifdef ADDON_BOEINGFCS
            if (node->networkData.networkVar->ncwHandoff)
            {
                return ROUTING_ADMIN_DISTANCE_EBGPv4_HANDOFF;
            }
            else
            {
#endif
            return ROUTING_ADMIN_DISTANCE_EBGPv4;
#ifdef ADDON_BOEINGFCS
            }
#endif
        }

        case EXTERIOR_GATEWAY_PROTOCOL_IBGPv4:
        {
            return ROUTING_ADMIN_DISTANCE_IBGPv4;
        }

        case EXTERIOR_GATEWAY_PROTOCOL_BGPv4_LOCAL:
        {
            return ROUTING_ADMIN_DISTANCE_BGPv4_LOCAL;
        }

        case ROUTING_PROTOCOL_OSPFv2:
        {
            return ROUTING_ADMIN_DISTANCE_OSPFv2;
        }
#ifdef ADDON_BOEINGFCS
        case ROUTING_PROTOCOL_OSPFv2_EXTERNAL:
        {
            return ROUTING_ADMIN_DISTANCE_OSPFv2_EXTERNAL;
        }
#endif
        case ROUTING_PROTOCOL_OSPFv3:
        {
            return ROUTING_ADMIN_DISTANCE_OSPFv3;
        }

        case ROUTING_PROTOCOL_STAR:
        {
            return ROUTING_ADMIN_DISTANCE_STAR;
        }

        case ROUTING_PROTOCOL_BELLMANFORD:
        {
            return ROUTING_ADMIN_DISTANCE_BELLMANFORD;
        }

        case ROUTING_PROTOCOL_FISHEYE:
        {
            return ROUTING_ADMIN_DISTANCE_FISHEYE;
        }

        case ROUTING_PROTOCOL_SDR:
        {
            return ROUTING_ADMIN_DISTANCE_SDR;
        }

#ifdef ADDON_BOEINGFCS
        case ROUTING_PROTOCOL_CES_SRW:
        {
            return ROUTING_ADMIN_DISTANCE_CES_SRW;
        }

        case ROUTING_PROTOCOL_CES_EPLRS:
        {
            return ROUTING_ADMIN_DISTANCE_ROUTING_CES_SDR;
        }

        case ROUTING_PROTOCOL_CES_SDR:
        {
            return ROUTING_ADMIN_DISTANCE_ROUTING_CES_SDR;
        }
#endif

        case ROUTING_PROTOCOL_OLSR_INRIA:
        {
            return ROUTING_ADMIN_DISTANCE_OLSR;
        }

        case ROUTING_PROTOCOL_OLSRv2_NIIGATA:
        {
            return ROUTING_ADMIN_DISTANCE_OLSRv2_NIIGATA;
        }

        case ROUTING_PROTOCOL_IGRP:
        {
            return ROUTING_ADMIN_DISTANCE_IGRP;
        }

        case ROUTING_PROTOCOL_EIGRP:
        {
            return ROUTING_ADMIN_DISTANCE_EIGRP;
        }
//StartRIP
        case ROUTING_PROTOCOL_RIP:
        {
            return ROUTING_ADMIN_DISTANCE_RIP;
        }
//EndRIP
//StartRIPng
        case ROUTING_PROTOCOL_RIPNG:
        {
            return ROUTING_ADMIN_DISTANCE_RIPNG;
        }
//EndRIPng
//InsertPatch ROUTING_ADMIN_DISTANCE
        case ROUTING_PROTOCOL_FSRL:
        {
            return ROUTING_ADMIN_DISTANCE_FSRL;
        }
        default:
            ERROR_ReportError("Invalid switch value");
            return (NetworkRoutingAdminDistanceType) 0;  // Not reachable.
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkInitForwardingTable()
// PURPOSE      Initialize the IP fowarding table, allocate enough
//              memory for number of rows.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkInitForwardingTable(Node *node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ip->forwardTable.size = 0;
    ip->forwardTable.allocatedSize = 0;
    ip->forwardTable.row = NULL;
#ifdef ADDON_STATS_MANAGER
#ifdef D_LISTENING_ENABLED

    ip->forwardTable.tableStr = new D_String;

    char address[20];
    sprintf(address, "%d\n", node->nodeId);

    ip->forwardTable.tableStr->Set(std::string(address));

    std::string path;
    D_Hierarchy *h = &node->partitionData->dynamicHierarchy;

    if (h->CreateNetworkPath(
            node,
            "ip",
            "ipForwardTable",
            path))
    {
        h->AddObject(
            path,
            new D_StringObj(ip->forwardTable.tableStr));
    }
#endif // D_LISTENING_ENABLED
#endif // ADDON_STATS_MANAGER
}

#ifdef ADDON_STATS_MANAGER
#ifdef D_LISTENING_ENABLED
void NetworkUpdateForwardingTableString(Node* node)
{

// ADD THIS BACK AFTER DEBUGGING!!
#if 0
    if (!node->guiOption)
    {
        // if not using the GUI, this is a waste of
        // processing time.
        return;
    }
#endif

    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *rt = &(ip->forwardTable);

    std::string tblStr = "";
    int i;
    char address[20];

    sprintf(address, "%d\n", node->nodeId);
    tblStr += address;
    //tblStr += "dest|mask|intf|nextHop|protocol|admin|Flag\n";
    //tblStr += "dest|mask|nextHop|protocol\n";

    for (i = 0; i < rt->size; i++)
    {
        IO_ConvertIpAddressToString(rt->row[i].destAddress, address);
        tblStr += address;
        tblStr += "|";
        IO_ConvertIpAddressToString(rt->row[i].destAddressMask, address);
        tblStr += address;
        tblStr += "|";
        //sprintf(address, "%d", rt->row[i].interfaceIndex);
        //tblStr += address;
        //tblStr += "|";
        IO_ConvertIpAddressToString(rt->row[i].nextHopAddress, address);
        tblStr += address;
        tblStr += "|";
        sprintf(address, "%d", rt->row[i].protocolType);
        tblStr += address;
        tblStr += "\n";
        //sprintf(address, "%d", rt->row[i].adminDistance);
        //tblStr += address;
        //tblStr += "|";

        //if (rt->row[i].interfaceIsEnabled) {
        //    tblStr += "U\n";
        //} else {
        //    tblStr += "D\n";
        //}
    }

    rt->tableStr->Set(tblStr);

}
#endif
#endif

//-----------------------------------------------------------------------------
// FUNCTION     NetworkUpdateForwardingTable()
// PURPOSE      Update or add entry to IP routing table.  Search the
//              routing table for an entry with an exact match for
//              destAddress, destAddressMask, and routing protocol.
//              Update this entry with the specified nextHopAddress
//              (the outgoing interface is automatically determined
//              from the nextHopAddress -- see code).  If no matching
//              entry found, then add a new route.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destAddress
//                  IP address of destination network or host.
//              NodeAddress destAddressMask
//                  Netmask.
//              NodeAddress nextHopAddress
//                  Next hop IP address.
//              int cost,
//                  Cost metric associated with the route.
//              NetworkRoutingProtocolType type
//                  Type value of routing protocol.
// RETURN       None.
//
// NOTES        The type field implies that the routing table can
//              simultaneously have entries with the same destination
//              addresses and netmasks, these entries added by different
//              routing protocols.
//
//              This function should have an interfaceIndex field, if
//              the protocol wishes to specify the outgoing interface
//              directly.
//-----------------------------------------------------------------------------

void
NetworkUpdateForwardingTable(
    Node *node,
    NodeAddress destAddress,
    NodeAddress destAddressMask,
    NodeAddress nextHopAddress,
    int interfaceIndex,
    int cost,
    NetworkRoutingProtocolType type)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *forwardTable = &(ip->forwardTable);

    NetworkRoutingProtocolType newType = type;
    NetworkRoutingAdminDistanceType adminDistance;
    int i;

    //loop through to find the first entry where destination address,
    //mask, and type all match.  For ICMP redirect messages, type is
    //obtained from the forwarding table and doesn't need to match.
    for (i = 0; i < forwardTable->size
        && (forwardTable->row[i].destAddress != destAddress
           || forwardTable->row[i].destAddressMask != destAddressMask
           || (forwardTable->row[i].protocolType != type
           && type != ROUTING_PROTOCOL_ICMP_REDIRECT)); i++)
    {
        //loop until match
    }

    if ((type == ROUTING_PROTOCOL_ICMP_REDIRECT) && (i == forwardTable->size))
    {
        newType = ROUTING_PROTOCOL_DEFAULT;
        adminDistance = ROUTING_ADMIN_DISTANCE_DEFAULT;
    }
    else if ((type == ROUTING_PROTOCOL_ICMP_REDIRECT) && (i != forwardTable->size))
    {
        //admin distance and type are retrieved from forwarding table
        adminDistance = forwardTable->row[i].adminDistance;
        newType = forwardTable->row[i].protocolType;
    }
    else
    {
        //adminDistance is obtained from the type
        adminDistance = NetworkRoutingGetAdminDistance(node, type);
    }

    NetworkRouteUpdateEventType routeUpdateFunction = NULL;

    if (interfaceIndex == ANY_INTERFACE)
    {
        if (nextHopAddress == (unsigned) NETWORK_UNREACHABLE)
        {
            interfaceIndex = DEFAULT_INTERFACE;
        }
        else
        {
            interfaceIndex = NetworkIpGetInterfaceIndexForNextHop(
                node,
                nextHopAddress);
        }
    }

    if (interfaceIndex < 0)
    {
        char err[MAX_STRING_LENGTH];
        char addr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(nextHopAddress, addr);
        sprintf(err, "Node %u: Next hop %s is not connected to this node\n",
            node->nodeId, addr);
        ERROR_ReportError(err);
    }

#ifdef ENTERPRISE_LIB
    // Will proceed if Redistribution is enabled
    if (ip->rtRedistributeIsEnabled == TRUE)
    {
        RouteRedistributeAddHook(
            node,
            destAddress,
            destAddressMask,
            nextHopAddress,
            interfaceIndex,
            cost,
            newType);
    }
#endif // ENTERPRISE_LIB

    if (i == forwardTable->size)
    {
        forwardTable->size++;

        if (forwardTable->size > forwardTable->allocatedSize)
        {
            if (forwardTable->allocatedSize == 0)
            {
                forwardTable->allocatedSize = FORWARDING_TABLE_ROW_START_SIZE;
                forwardTable->row = (NetworkForwardingTableRow*)
                    MEM_malloc(
                        forwardTable->allocatedSize *
                        sizeof(NetworkForwardingTableRow));
            }
            else
            {
                int newSize = (forwardTable->allocatedSize * 2);

                NetworkForwardingTableRow* newTableRow =
                    (NetworkForwardingTableRow*)MEM_malloc(
                        newSize * sizeof(NetworkForwardingTableRow));

                memcpy(newTableRow, forwardTable->row,
                       (forwardTable->allocatedSize *
                        sizeof(NetworkForwardingTableRow)));

                MEM_free(forwardTable->row);
                forwardTable->row = newTableRow;
                forwardTable->allocatedSize = newSize;
            }//if//
        }//if//

        while (i > 0 &&
               (destAddress > forwardTable->row[i - 1].destAddress
                || (destAddress == forwardTable->row[i - 1].destAddress
                    && destAddressMask > forwardTable->row[i - 1].
                    destAddressMask)
                || (destAddress == forwardTable->row[i - 1].destAddress
                    && destAddressMask == forwardTable->row[i - 1].
                    destAddressMask
                    &&  adminDistance < forwardTable->row[i - 1].adminDistance)
                || (destAddress == forwardTable->row[i - 1].destAddress
                    && destAddressMask == forwardTable->row[i - 1].
                    destAddressMask
                    && cost == forwardTable->row[i - 1].cost
                    && cost < forwardTable->row[i - 1].cost)))
        {
            forwardTable->row[i] = forwardTable->row[i - 1];
            i--;
        }//while//
    }//if//

    forwardTable->row[i].destAddress = destAddress;
    forwardTable->row[i].destAddressMask = destAddressMask;
    forwardTable->row[i].interfaceIndex = interfaceIndex;
    forwardTable->row[i].nextHopAddress = nextHopAddress;
    forwardTable->row[i].protocolType = newType;
    forwardTable->row[i].adminDistance = adminDistance;

    forwardTable->row[i].cost = cost;

    if (NetworkIpInterfaceIsEnabled(node, interfaceIndex))
    {
        forwardTable->row[i].interfaceIsEnabled = TRUE;
    }
    else
    {
        forwardTable->row[i].interfaceIsEnabled = FALSE;
    }

    routeUpdateFunction = NetworkIpGetRouteUpdateEventFunction(node);

    if (routeUpdateFunction)
    {
        (routeUpdateFunction)(node, destAddress, destAddressMask,
                nextHopAddress, interfaceIndex, cost, adminDistance);
    }
}

// /---------------------------------------------------------------------------
// API        :: NetworkRemoveForwardingTableEntry
// LAYER      :: Network
// PURPOSE    :: Remove single entries in the routing table
// PARAMETERS ::
// + node      : Node*                      : Pointer to node.
// + destAddress            : NodeAddress : IP address of destination
//                                          network or host.
// + destAddressMask        : NodeAddress : Netmask.
// + nextHopAddress         : NodeAddress : Next hop IP address.
// + outgoingInterfaceIndex : int         : outgoing interface.
// RETURN     :: void :
// **/-------------------------------------------------------------------------
void
NetworkRemoveForwardingTableEntry(
    Node *node,
    NodeAddress destAddress,
    NodeAddress destAddressMask,
    NodeAddress nextHopAddress,
    int outgoingInterfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *rt = &ip->forwardTable;

    int i = 0;

    // Go through the routing table...
    while (i < rt->size)
    {
        // Delete entries that corresponds to the routing protocol used
        if ((rt->row[i].destAddress == destAddress) &&
            (rt->row[i].destAddressMask == destAddressMask) &&
            (rt->row[i].nextHopAddress == nextHopAddress) &&
            (rt->row[i].interfaceIndex == outgoingInterfaceIndex) )
        {
            int j = i + 1;

            // Move all other entries down
            while (j < rt->size)
            {
                rt->row[j - 1] = rt->row[j];
                j++;
            }

            // Update forwarding table size.
            rt->size--;
        }
        else
        {
            i++;
        }
    }
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkEmptyFowardingTable()
// PURPOSE      Remove entries in the routing table corresponding to a
//              given routing protocol.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NetworkRoutingProtocolType type
//                  Type of routing protocol whose entries are to be
//                  removed.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkEmptyForwardingTable(
    Node *node,
    NetworkRoutingProtocolType type)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *rt = &ip->forwardTable;

    int i = 0;

    // Go through the routing table...
    while (i < rt->size)
    {
        // Delete entries that corresponds to the routing protocol used
        if (rt->row[i].protocolType == type)
        {
            int j = i + 1;

            // Move all other entries down
            while (j < rt->size)
            {
                rt->row[j - 1] = rt->row[j];
                j++;
            }

            // Update forwarding table size.
            rt->size--;
        }
        else
        {
            i++;
        }
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkPrintForwardingTable()
// PURPOSE      Display all entries in node's routing table.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkPrintForwardingTable(Node *node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *rt = &ip->forwardTable;

    int i;
    char clockStr[MAX_CLOCK_STRING_LENGTH];

    ctoa((getSimTime(node) / SECOND), clockStr);

    printf("Forwarding Table for node %u at time %s\n", node->nodeId, clockStr);
    printf("---------------------------------------------------------------"
        "--------------------\n");
    printf("          dest          mask        intf       nextHop    protocol"
        "    admin    Flag\n");
    printf("---------------------------------------------------------------"
        "--------------------\n");
    for (i = 0; i < rt->size; i++)
    {
        char address[20];
        IO_ConvertIpAddressToString(rt->row[i].destAddress, address);
        printf("%15s  ", address);
        IO_ConvertIpAddressToString(rt->row[i].destAddressMask, address);
        printf("%15s  ", address);
        printf("%5u", rt->row[i].interfaceIndex);
        IO_ConvertIpAddressToString(rt->row[i].nextHopAddress, address);
        printf("%15s   ", address);
        printf("%5u      ", rt->row[i].protocolType);
        printf("%5u", rt->row[i].adminDistance);

        if (rt->row[i].interfaceIsEnabled) {
            printf("       U\n");
        } else {
            printf("       D\n");
        }
    }

    printf ("\n");
}


//-----------------------------------------------------------------------------
// Interface IP addresses
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetInterfaceAddress()
// PURPOSE      Get interface address on this interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  interface to get address from.
// RETURN       Interface address associated with interface.
//-----------------------------------------------------------------------------

NodeAddress
NetworkIpGetInterfaceAddress(
    Node *node,
    int interfaceIndex)
{
    if (INTERFACE_DEBUG) {
        printf("partition %d checking interface %d address for node %d\n",
            node->partitionData->partitionId, interfaceIndex, node->nodeId);
        fflush(stdout);
    }
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    assert(ip != NULL);

    if (interfaceIndex == (int)ANY_INTERFACE)
    {
        return (NodeAddress)ANY_ADDRESS;
    }

    return (ip->interfaceInfo[interfaceIndex]->ipAddress);
}

//needed for parallel mode satcom
NodeAddress
NetworkIpGetLinkLayerAddress(Node* node, int interfaceIndex)
{
    MacHWAddress hwAddr = GetMacHWAddress(node, interfaceIndex);
    return MAC_VariableHWAddressToFourByteMacAddress (node, &hwAddr);
}


int
NetworkIpGetInterfaceIndexFromLinkAddress(Node* node,
                          NodeAddress ownMacAddr)
{
     return MacGetInterfaceIndexFromMacAddress(node, ownMacAddr);
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetInterfaceName()
// PURPOSE      Get interface name on this interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  interface to get address from.
// RETURN       Interface name associated with interface.
//-----------------------------------------------------------------------------

char*
NetworkIpGetInterfaceName(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    return (ip->interfaceInfo[interfaceIndex]->interfaceName);
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetInterfaceNetworkAddress()
// PURPOSE      Get network interface address on this interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  interface to get network address from.
// RETURN       network address associated with interface.
//-----------------------------------------------------------------------------

NodeAddress
NetworkIpGetInterfaceNetworkAddress(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    return (ip->interfaceInfo[interfaceIndex]->ipAddress
            & ConvertNumHostBitsToSubnetMask(
                  ip->interfaceInfo[interfaceIndex]->numHostBits));
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetInterfaceSubnetMask()
// PURPOSE      Get network interface subnet mask on this interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  interface to get subnet mask from
// RETURN       Subnet mask of specified interface.
//-----------------------------------------------------------------------------

NodeAddress
NetworkIpGetInterfaceSubnetMask(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    return (ConvertNumHostBitsToSubnetMask(
                ip->interfaceInfo[interfaceIndex]->numHostBits));
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetInterfaceNumHostBits()
// PURPOSE      Get number of host nits on this interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  interface to get number of host bits from.
// RETURN       Number of host bits associated with the interface.
//-----------------------------------------------------------------------------

int
NetworkIpGetInterfaceNumHostBits(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    return (ip->interfaceInfo[interfaceIndex]->numHostBits);
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpGetInterfaceBroadcastAddress()
// PURPOSE      Get broadcast address on this interface.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  interface to get broadcast address from.
// RETURN       Broadcast address of the interface.
//-----------------------------------------------------------------------------

NodeAddress
NetworkIpGetInterfaceBroadcastAddress(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    //
    // ((sizeof(NodeAddress)*8) - numHostBits) is the number of bits that should
    // be set to '1' for broadcasting
    //
    // ANY_DEST is 0xffffffff: shifting this by the above number of bits
    // provides the basis for the bitwise OR
    //
    // Performing bitwise OR with the above value and the interface IP gives
    // the Interface Broadcast Address
    //

    if (NetworkIpGetInterfaceType(node, interfaceIndex) == NETWORK_IPV6)
    {
        return ANY_DEST;
    }

    if (TunnelIsVirtualInterface(node, interfaceIndex))
    {
        return ANY_DEST;
    }

    int bMaskBits = ((sizeof(NodeAddress)*8)-
                 ip->interfaceInfo[interfaceIndex]->numHostBits);

    if ((unsigned int)bMaskBits >= (sizeof(ANY_DEST)*8))
    {
            return ip->interfaceInfo[interfaceIndex]->ipAddress;
    }
    else
    {
        return (ip->interfaceInfo[interfaceIndex]->ipAddress |
            (ANY_DEST >> bMaskBits));

    }

}

//-----------------------------------------------------------------------------
// Miscellaneous
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpIsMyIP()
// PURPOSE      Calls IsMyPacket().
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress ipAddr
//                  An IP address.
//
// RETURN       Calls IsMyPacket().
//
// NOTES        This is only called by application/mpls_ldp.pc.  Should
//              probably eliminate this function. -Jeff
//-----------------------------------------------------------------------------

BOOL
NetworkIpIsMyIP(Node *node, NodeAddress ipAddress)
{
    return IsMyPacket(node, ipAddress);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpIsLoopbackEnabled()
// PURPOSE      To provide API for other layers to get loopback status.
// PARAMETERS   Node* node
//                  Pointer to node.
//
// RETURN       BOOL.
//-----------------------------------------------------------------------------

BOOL
NetworkIpIsLoopbackEnabled(Node* node)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    return ip->isLoopbackEnabled;
}

//-----------------------------------------------------------------------------
// Debugging
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpConfigurationError()
// PURPOSE      Print out IP configuration error.
// PARAMETERS   Node *node
//                  Pointer to node.
//              char parameterName[]
//                  Error message to print out.
//              int interfaceIndex
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpConfigurationError(
    Node *node,
    const char parameterName[],
    int interfaceIndex)
{
    char buf[MAX_STRING_LENGTH];

    sprintf(buf,
            "node %d (interface %d) cannot find \"%s\" in the CONFIG.IN file"
            " or the value specified is invalid",
            node->nodeId, interfaceIndex, parameterName);
    ERROR_ReportError(buf);
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkPrintIpHeader()
// PURPOSE      Display IP header for message containing an IP header
//              or IP packet.
// PARAMETERS   Message *msg
//                  Pointer to message with IP header or IP packet.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkPrintIpHeader(Message *msg)
{
    IpHeaderType *ipHdr;
    struct ip_options *opt;
    char *dataptr = msg->packet;
    int i;

    ipHdr = (IpHeaderType *) (msg->packet);

    printf("IP header\n");
    printf("totalLength %d headerLength %d moreFragment %d fragmentOffset %d"
           "  timeToLive %d ",
           IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len),
           IpHeaderGetHLen(ipHdr->ip_v_hl_tos_len),
           IpHeaderGetIpMoreFrag(ipHdr->ipFragment),
           IpHeaderGetIpFragOffset(ipHdr->ipFragment),
           ipHdr->ip_ttl);
    printf("protocol %d sourceId %d destId %d identity %d\n",
           ipHdr->ip_p, ipHdr->ip_src, ipHdr->ip_dst, ipHdr->ip_id);

    dataptr += sizeof(IpHeaderType);
    opt = (struct ip_options *) dataptr;

    printf("code %d, len %d, ptr %d\n", opt->code, opt->len, opt->ptr);

    if ((IpHeaderGetHLen(ipHdr->ip_v_hl_tos_len) * 4) > sizeof(IpHeaderType))
    {
        if (opt->code == IPOPT_SSRR)
        {
            for (i = 1; i <= (opt->len - 3) / 4; i++)
            {
                NodeAddress nodePtr;
                memcpy(&nodePtr, (dataptr + i*4 - 1), sizeof(NodeAddress));
                printf("%d, ", nodePtr);

            }
            printf ("\n");
        }
    }

    //printf("payload %s\n", (dataptr + opt->len));
}

//-----------------------------------------------------------------------------
// Statistics
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpRunTimeStat()
// PURPOSE      Print IP runtime statistics.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpRunTimeStat(Node *node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    clocktype      now = getSimTime(node);

    if (ip == NULL)
    {
        return;
    }

    if (node->guiOption) {
        GUI_SendUnsignedData(node->nodeId, ip->stats.ipInReceivesId,
                             ip->stats.ipInReceives, now + getSimStartTime(node));
        GUI_SendUnsignedData(node->nodeId, ip->stats.ipInHdrErrorsId,
                             ip->stats.ipInHdrErrors, now + getSimStartTime(node));
    }
    else {
        printf("Node: %u\n", node->nodeId);
        printf("This time period:\n");

        printf("ipInReceives         -> %u\n",
               ip->stats.ipInReceives -
               ip->stats.ipInReceivesLastPeriod);
        ip->stats.ipInReceivesLastPeriod = ip->stats.ipInReceives;

        printf("ipInHdrErrors        -> %u\n",
               ip->stats.ipInHdrErrors -
               ip->stats.ipInHdrErrorsLastPeriod);
        ip->stats.ipInHdrErrorsLastPeriod = ip->stats.ipInHdrErrors;

        printf("ipInForwardDatagrams -> %u\n",
               ip->stats.ipInForwardDatagrams -
               ip->stats.ipInForwardDatagramsLastPeriod);
        ip->stats.ipInForwardDatagramsLastPeriod =
            ip->stats.ipInForwardDatagrams;

        printf("ipInDelivers         -> %u\n",
               ip->stats.ipInDelivers -
               ip->stats.ipInDeliversLastPeriod);
        ip->stats.ipInDeliversLastPeriod = ip->stats.ipInDelivers;

        printf("ipOutRequests        -> %u\n",
               ip->stats.ipOutRequests -
               ip->stats.ipOutRequestsLastPeriod);
        ip->stats.ipOutRequestsLastPeriod = ip->stats.ipOutRequests;

        printf("ipOutDiscards        -> %u\n",
               ip->stats.ipOutDiscards -
               ip->stats.ipOutDiscardsLastPeriod);
        ip->stats.ipOutDiscardsLastPeriod = ip->stats.ipOutDiscards;

        printf("ipOutNoRoutes        -> %u\n",
               ip->stats.ipOutNoRoutes -
               ip->stats.ipOutNoRoutesLastPeriod);
        ip->stats.ipOutNoRoutesLastPeriod = ip->stats.ipOutNoRoutes;

        printf("ipReasmReqds         -> %u\n",
               ip->stats.ipReasmReqds -
               ip->stats.ipReasmReqdsLastPeriod);
        ip->stats.ipReasmReqdsLastPeriod = ip->stats.ipReasmReqds;

        printf("ipReasmOKs           -> %u\n",
               ip->stats.ipReasmOKs -
               ip->stats.ipReasmOKsLastPeriod);
        ip->stats.ipReasmOKsLastPeriod = ip->stats.ipReasmOKs;

        printf("ipReasmFails         -> %u\n",
               ip->stats.ipReasmFails -
               ip->stats.ipReasmFailsLastPeriod);
        ip->stats.ipReasmFailsLastPeriod = ip->stats.ipReasmFails;

        printf("ipFragOKs            -> %u\n",
               ip->stats.ipFragOKs -
               ip->stats.ipFragOKsLastPeriod);
        ip->stats.ipFragOKsLastPeriod = ip->stats.ipFragOKs;
    }
}



//-----------------------------------------------------------------------------
// Multicast
//-----------------------------------------------------------------------------

// FUNCTION   NetworkIpAddToMulticastGroupList
// PURPOSE    Add group to multicast group list.
// PARAMETERS node - this node.
//            groupAddress - group to add to multicast group list.
// RETURN     None.
void NetworkIpAddToMulticastGroupList(Node *node,
                                      NodeAddress groupAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ListItem *item = ip->multicastGroupList->first;

    NetworkIpMulticastGroupEntry *entry;

    // Go through the group list...
    while (item)
    {
        entry = (NetworkIpMulticastGroupEntry *) item->data;

        // Group already exists, so incrememt member count.
        if (entry->groupAddress == groupAddress)
        {
            entry->memberCount++;
            return;
        }

        item = item->next;
    }

    // Group doesn't exist, so add to multicast group list.

    entry = (NetworkIpMulticastGroupEntry *)
            MEM_malloc(sizeof(NetworkIpMulticastGroupEntry));

    entry->groupAddress = groupAddress;
    entry->memberCount = 1;

    ListInsert(node, ip->multicastGroupList, getSimTime(node), entry);
    // if superapplication server is configured for this multicast address
    // then initialize the super application server if not initialsed
    // and update the time spent out of multicast group for this node.

    if (node->appData.superAppconfigData != NULL)
    {
        SuperApplicationUpdateTimeSpentOutofMulticastGroup(node,
                                                           groupAddress);
    }
}


// FUNCTION   NetworkIpRemoveFromMulticastGroupList
// PURPOSE    Remove group from multicast group list.
// PARAMETERS node - this node.
//            groupAddress - group to remove from multicast group list.
// RETURN     None.
void NetworkIpRemoveFromMulticastGroupList(Node *node,
                                           NodeAddress groupAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ListItem *item = ip->multicastGroupList->first;
    NetworkIpMulticastGroupEntry *entry;

    // seacrh whether any superapplication server is configured for
    // this multicast address; if yes update the timer when node leaves
    // the specified group.
    if (node->appData.superAppconfigData != NULL)
    {
        SuperApplicationUpdateMulticastGroupLeavingTime(node, groupAddress);
    }

    // Go through the multicast group list...
    while (item)
    {
        entry = (NetworkIpMulticastGroupEntry *) item->data;

        // Found it...
        if (entry->groupAddress == groupAddress)
        {
            // If only no one else belongs to the group, remove from group list.
            if (entry->memberCount == 1)
            {
                ListGet(node,
                        ip->multicastGroupList,
                        item,
                        TRUE,
                        FALSE);
            }
            // Someone else also belongs to the group,
            // so decrement member count.
            else if (entry->memberCount > 1)
            {
                entry->memberCount--;
            }
            else
            {
                assert(FALSE);
            }

            return;
        }

        item = item->next;
    }
}


// FUNCTION   NetworkIpPrintMulticastGroupList
// PURPOSE    Print the multicast group list.
// PARAMETERS node - this node.
// RETURN     None.
void NetworkIpPrintMulticastGroupList(Node *node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ListItem *item = ip->multicastGroupList->first;
    NetworkIpMulticastGroupEntry *entry;

    printf("Node %d multicast group list\n", node->nodeId);

    while (item)
    {
        entry = (NetworkIpMulticastGroupEntry *) item->data;

        printf("    group address = %u, member count = %u\n",
                entry->groupAddress, entry->memberCount);

        item = item->next;
    }
}


// FUNCTION   NetworkIpIsPartOfMulticastGroup
// PURPOSE    Check if we are part of the multicast group.
// PARAMETERS node - this node.
//            groupAddress - group to check if node is part of multicast group.
// RETURN     TRUE if node is part of multicast group, FALSE otherwise.
BOOL NetworkIpIsPartOfMulticastGroup(Node *node, NodeAddress groupAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ListItem *item = ip->multicastGroupList->first;
    NetworkIpMulticastGroupEntry *entry;

    // Go through list and see if we belong to this multicast group.
    while (item)
    {
        entry = (NetworkIpMulticastGroupEntry *) item->data;

        // Found it!
        if (entry->groupAddress == groupAddress)
        {
            return TRUE;
        }

        item = item->next;
    }

    // Not part of multicast group...
    return FALSE;
}

#ifdef ADDON_DB

// FUNCTION   NetworkIpIsMyMulticastPacket
// PURPOSE    Check if I am either the receiver of the multicast packet
//            or is a forwarding router for it
// PARAMETERS node - this node.
//            srdAddr - source address who generates this packet
//            dstAddr - shall be the multicast group address
//            prevAddr - shall be the upstream node
//            incomingInterface - incoming interface index
// RETURN     TRUE if node is able to handle this packet, FALSE otherwise.
BOOL NetworkIpIsMyMulticastPacket(Node *node,
                                  NodeAddress srcAddr,
                                  NodeAddress dstAddr,
                                  NodeAddress prevAddr,
                                  int incomingInterface)
{
    // return true if I am the receiver
    if (NetworkIpIsPartOfMulticastGroup(node, dstAddr))
    {
        return TRUE;
    }

    // check if pim is configured
    if (incomingInterface != -1 &&
        !RoutingPimIsPimEnabledInterface(node, incomingInterface))
    {   // the incoming interface is valid and we are not running pim
        // return true, which means we will not use results from
        // this function
        return FALSE ;
    }else if (incomingInterface == -1)
    {
        int i = 0;
        for (; i < node->numberInterfaces; ++i)
        {
            if (RoutingPimIsPimEnabledInterface(node, i))
            {
                break ;
            }
        }
        if (i == node->numberInterfaces) {
            return FALSE ;
        }
    }

    // now check if I am the router to forward the packet.
    // This is a multicast protocol specific

    PimData* pim = (PimData*)
        NetworkIpGetMulticastRoutingProtocol(node, MULTICAST_PROTOCOL_PIM);

#ifdef ISMYPKT_DEBUG
    if (incomingInterface != -1)
    {

        char dstAddrStr[256] ;
        char prevAddrStr[256] ;

        IO_ConvertIpAddressToString(dstAddr, dstAddrStr) ;
        IO_ConvertIpAddressToString(prevAddr, prevAddrStr) ;
        printf("\n\n node %d check pkt to %s with prevAddr %s iif %d \n",
            node->nodeId, dstAddrStr, prevAddrStr, incomingInterface) ;
    }
#endif

    if (pim->modeType == ROUTING_PIM_MODE_DENSE)
    {
        return RoutingPimDmIsMyMulticastPacket(node,
            srcAddr, dstAddr, prevAddr, incomingInterface);

    }
    else
    {
        return RoutingPimSmIsMyMulticastPacket(
            node, srcAddr, dstAddr, prevAddr, incomingInterface);
    }

    return FALSE;
}

#endif

// FUNCTION   NetworkIpJoinMulticastGroup
// PURPOSE    Join a multicast group.
// PARAMETERS node - this node.
//            mcastAddr, multicast group to join.
//            delay - when to join group.
// RETURN     None.
void NetworkIpJoinMulticastGroup(Node* node,
                          NodeAddress mcastAddr,
                          clocktype delay)
{
    char errStr[MAX_STRING_LENGTH];
    char grpStr[MAX_ADDRESS_STRING_LENGTH];
    NodeAddress interfaceAddress;
    Int32 numIntf;
    int intfId;
    IgmpData* igmp = NULL;

    if (mcastAddr < IP_MIN_MULTICAST_ADDRESS
        || mcastAddr > IP_MAX_MULTICAST_ADDRESS)
    {
        IO_ConvertIpAddressToString(mcastAddr, grpStr);
        sprintf(errStr, "Node %u: Unable to set JoinTimer\n"
            "    Group address %s is not a valid multicast address\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else if (mcastAddr <= IP_MAX_RESERVED_MULTICAST_ADDRESS)
    {
        IO_ConvertIpAddressToString(mcastAddr, grpStr);
        sprintf(errStr, "Node %u: Unable to set JoinTimer\n"
            "    Group address %s falls in reserve multicast address "
            "space\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else
    {
        NetworkIpSetMulticastTimer(
            node, MSG_NETWORK_JoinGroup, mcastAddr, delay);


        if (!NetworkIpCheckMulticastRoutingProtocol(
#ifdef ADDON_MAODV
                node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE)
            && !NetworkIpCheckMulticastRoutingProtocol(
                node, MULTICAST_PROTOCOL_MAODV, ANY_INTERFACE))
#else // ADDON_MAODV
                node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE))
#endif // ADDON_MAODV
        {
            numIntf = node->numberInterfaces;
            igmp = IgmpGetDataPtr(node);

            for (intfId = 0; intfId < numIntf; intfId++)
            {
                if (igmp->igmpInterfaceInfo[intfId])
                {
                    // Send group joining request on every interface
                    IgmpJoinGroup(node, intfId, mcastAddr, delay);
                }
            }

#if 0
//#ifdef ADDON_BOEINGFCS
            //CES_HAIPE MULTICAST
            NetworkSecurityCesHaipeSetMulticastGrpTimer(node,
                mcastAddr,
                MSG_NETWORK_IgmpJoinGroupTimer,
                delay);
#endif
        }

    }
}

// FUNCTION   NetworkIpJoinMulticastGroup
// PURPOSE    Join a multicast group.
// PARAMETERS node - this node.
//            mcastAddr, multicast group to join.
//            delay - when to join group.
//            interfaceId - on which interface to join the group
// RETURN     None.
void NetworkIpJoinMulticastGroup(Node* node,
                          Int32 interfaceId,
                          NodeAddress mcastAddr,
                          clocktype delay)
{
    char errStr[MAX_STRING_LENGTH];
    char grpStr[MAX_ADDRESS_STRING_LENGTH];

    if (mcastAddr < IP_MIN_MULTICAST_ADDRESS
        || mcastAddr > IP_MAX_MULTICAST_ADDRESS)
    {
        IO_ConvertIpAddressToString(mcastAddr, grpStr);
        sprintf(errStr, "Node %u: Unable to set JoinTimer\n"
            "    Group address %s is not a valid multicast address\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else if (mcastAddr <= IP_MAX_RESERVED_MULTICAST_ADDRESS)
    {
        IO_ConvertIpAddressToString(mcastAddr, grpStr);
        sprintf(errStr, "Node %u: Unable to set JoinTimer\n"
            "    Group address %s falls in reserve multicast address "
            "space\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else
    {
        NetworkIpSetMulticastTimer(
            node, MSG_NETWORK_JoinGroup, mcastAddr, delay);


        if (!NetworkIpCheckMulticastRoutingProtocol(
#ifdef ADDON_MAODV
                node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE)
            && !NetworkIpCheckMulticastRoutingProtocol(
                node, MULTICAST_PROTOCOL_MAODV, ANY_INTERFACE))
#else // ADDON_MAODV
                node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE))
#endif // ADDON_MAODV
        {
            // Send group joining request
            IgmpJoinGroup(node, interfaceId, mcastAddr, delay);

#if 0
//#ifdef ADDON_BOEINGFCS
            //CES_HAIPE MULTICAST
            NetworkSecurityCesHaipeSetMulticastGrpTimer(node,
                mcastAddr,
                MSG_NETWORK_IgmpJoinGroupTimer,
                delay);
#endif
        }

    }
}


// FUNCTION   NetworkIpLeaveMulticastGroup
// PURPOSE    Leave a multicast group.
// PARAMETERS node - this node.
//            mcastAddr, multicast group to leave.
//            delay - when to leave group.
// RETURN     None.
void NetworkIpLeaveMulticastGroup(Node* node,
                                  NodeAddress mcastAddr,
                                  clocktype delay)
{
    char errStr[MAX_STRING_LENGTH];
    char grpStr[MAX_ADDRESS_STRING_LENGTH];
    NodeAddress interfaceAddress;
    Int32 numIntf;
    int intfId;
    IgmpData* igmp = NULL;

    if (mcastAddr < IP_MIN_MULTICAST_ADDRESS
        || mcastAddr > IP_MAX_MULTICAST_ADDRESS)
    {
        IO_ConvertIpAddressToString(mcastAddr, grpStr);
        sprintf(errStr, "Node %u: Unable to set LeaveTimer\n"
            "    Group address %s is not a valid multicast address\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else if (mcastAddr <= IP_MAX_RESERVED_MULTICAST_ADDRESS)
    {
        IO_ConvertIpAddressToString(mcastAddr, grpStr);
        sprintf(errStr, "Node %u: Unable to set LeaveTimer\n"
            "    Group address %s falls in reserve multicast address "
            "space\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else
    {
        NetworkIpSetMulticastTimer(
            node, MSG_NETWORK_LeaveGroup, mcastAddr, delay);


        if (!NetworkIpCheckMulticastRoutingProtocol(
#ifdef ADDON_MAODV
                node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE)
            && !NetworkIpCheckMulticastRoutingProtocol(
                node, MULTICAST_PROTOCOL_MAODV, ANY_INTERFACE))
#else // ADDON_MAODV
                node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE))
#endif // ADDON_MAODV
        {
            numIntf = node->numberInterfaces;
            igmp = IgmpGetDataPtr(node);
            for (intfId = 0; intfId < numIntf; intfId++)
            {
                if (igmp->igmpInterfaceInfo[intfId])
                {
                    // Send group leaving request
                    IgmpLeaveGroup(node, intfId, mcastAddr, delay);
                }
            }

#if 0
//#ifdef ADDON_BOEINGFCS

            //CES_HAIPE MULTICAST
            NetworkSecurityCesHaipeSetMulticastGrpTimer(node,
                mcastAddr,
                MSG_NETWORK_IgmpLeaveGroupTimer,
                delay);
#endif
        }

    }
}


// FUNCTION   NetworkIpLeaveMulticastGroup
// PURPOSE    Leave a multicast group.
// PARAMETERS node - this node.
//            interfaceId: on which interface it was the member of the group
//            mcastAddr, multicast group to leave.
//            delay - when to leave group.
// RETURN     None.
void NetworkIpLeaveMulticastGroup(Node* node,
                                  Int32 interfaceId,
                                  NodeAddress mcastAddr,
                                  clocktype delay)
{
    char errStr[MAX_STRING_LENGTH];
    char grpStr[MAX_ADDRESS_STRING_LENGTH];

    if (mcastAddr < IP_MIN_MULTICAST_ADDRESS
        || mcastAddr > IP_MAX_MULTICAST_ADDRESS)
    {
        IO_ConvertIpAddressToString(mcastAddr, grpStr);
        sprintf(errStr, "Node %u: Unable to set LeaveTimer\n"
            "    Group address %s is not a valid multicast address\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else if (mcastAddr <= IP_MAX_RESERVED_MULTICAST_ADDRESS)
    {
        IO_ConvertIpAddressToString(mcastAddr, grpStr);
        sprintf(errStr, "Node %u: Unable to set LeaveTimer\n"
            "    Group address %s falls in reserve multicast address "
            "space\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else
    {
        NetworkIpSetMulticastTimer(
            node, MSG_NETWORK_LeaveGroup, mcastAddr, delay);


        if (!NetworkIpCheckMulticastRoutingProtocol(
#ifdef ADDON_MAODV
                node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE)
            && !NetworkIpCheckMulticastRoutingProtocol(
                node, MULTICAST_PROTOCOL_MAODV, ANY_INTERFACE))
#else // ADDON_MAODV
                node, MULTICAST_PROTOCOL_ODMRP, ANY_INTERFACE))
#endif // ADDON_MAODV
        {
            // Send group leaving request
            IgmpLeaveGroup(node, interfaceId, mcastAddr, delay);

#if 0
//#ifdef ADDON_BOEINGFCS

            //CES_HAIPE MULTICAST
            NetworkSecurityCesHaipeSetMulticastGrpTimer(node,
                mcastAddr,
                MSG_NETWORK_IgmpLeaveGroupTimer,
                delay);
#endif
        }

    }
}


// FUNCTION   NetworkIpSetMulticastTimer
// PURPOSE    Set timer to join and leave multicast groups.
// PARAMETERS node - this node.
//            mcastAddr, multicast group to join or leave.
//            delay - when to join or leave group.
// RETURN     None.
void NetworkIpSetMulticastTimer(Node *node,
                          Int32 eventType,
                          NodeAddress mcastAddr,
                          clocktype delay)

{
    Message *msg;
    NodeAddress *info;

    msg = MESSAGE_Alloc(node,
                         NETWORK_LAYER,
                         NETWORK_PROTOCOL_IP,
                         eventType);

    MESSAGE_InfoAlloc(node, msg, sizeof(NodeAddress));

    info = (NodeAddress *) MESSAGE_ReturnInfo(msg);

    memcpy(info, &mcastAddr, sizeof(NodeAddress));

    MESSAGE_Send(node, msg, delay);
}


// FUNCTION   NetworkIpSetMulticastRoutingProtocol
// PURPOSE    Assign a multicast routing protocol structure to an interface.
// PARAMETERS node - this node.
//            multicastRoutingProtocol - multicast routing protocol to set.
//            interfaceIndex - interface associated with multicast protocol.
// RETURN     None.
void
NetworkIpSetMulticastRoutingProtocol(
    Node *node,
    void *multicastRoutingProtocol,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ERROR_Assert(ip->interfaceInfo[interfaceIndex]->multicastRoutingProtocol ==
                 NULL,
                 "Multicast router function already set");

    ip->interfaceInfo[interfaceIndex]->multicastRoutingProtocol=
                                                      multicastRoutingProtocol;
}


// FUNCTION   NetworkIpGetMulticastRoutingProtocol
// PURPOSE    Get the multicast routing protocol structure.
// PARAMETERS node - this node.
//            routingProtcolType - the multicast protocol to get.
// RETURN     Multicast routing protocol structure.
void *
NetworkIpGetMulticastRoutingProtocol(
    Node *node,
    NetworkRoutingProtocolType routingProtocolType)
{
    int i;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->multicastProtocolType
            == routingProtocolType)
        {
            return ip->interfaceInfo[i]->multicastRoutingProtocol;
        }
    }

    return NULL;
}


// FUNCTION   NetworkIpAddMulticastRoutingProtocolType
// PURPOSE    Assign a multicast protocol type to an interface.
// PARAMETERS node - this node.
//            multicastProtcolType - the multicast protocol to add.
//            interfaceIndex - interface associated with multicast protocol.
// RETURN     None
void NetworkIpAddMulticastRoutingProtocolType(
    Node *node,
    NetworkRoutingProtocolType multicastProtocolType,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ip->interfaceInfo[interfaceIndex]->multicastEnabled = TRUE;
    ip->interfaceInfo[interfaceIndex]->multicastRouterFunction = NULL;
    ip->interfaceInfo[interfaceIndex]->multicastProtocolType =
                                                          multicastProtocolType;
    ip->interfaceInfo[interfaceIndex]->multicastRoutingProtocol = NULL;
}


// FUNCTION   NetworkIpSetMulticastRouterFunction
// PURPOSE    Set the multicast router function to an interface.
// PARAMETERS node - this node.
//            routerFunctionPtr - multicast router function to set on this
//                                interface.
//            interfaceIndex - interface associated with multicast protocol.
// RETURN     None.
void
NetworkIpSetMulticastRouterFunction(
    Node *node,
    MulticastRouterFunctionType routerFunctionPtr,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    assert(ip->interfaceInfo[interfaceIndex]->multicastRouterFunction == NULL);

    ip->interfaceInfo[interfaceIndex]->multicastRouterFunction =
                                                              routerFunctionPtr;
}


// FUNCTION   NetworkIpGetMulticastRouterFunction
// PURPOSE    Get the multicast router function from an interface.
// PARAMETERS node - this node.
//            interfaceIndex - interface associated with multicast protocol.
// RETURN     Multicast router function on this interface.
MulticastRouterFunctionType
NetworkIpGetMulticastRouterFunction(
    Node *node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    MulticastRouterFunctionType retVal = NULL;

    if (interfaceIndex >= 0)
    {
        retVal = ip->interfaceInfo[interfaceIndex]->multicastRouterFunction;
    }
    return retVal;
}


// FUNCTION  NetworkIpUpdateMulticastRoutingProtocolAndRouterFunction
// PURPOSE   Assign multicast routing protocol structure and router
//           function to an interface.  We are only allocating
//           the multicast routing protocol structure and router function
//           once by using pointers to the original structures.
void
NetworkIpUpdateMulticastRoutingProtocolAndRouterFunction(
    Node *node,
    NetworkRoutingProtocolType routingProtocolType,
    int interfaceIndex)
{
    int i;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->multicastProtocolType
            == routingProtocolType)
        {
            ip->interfaceInfo[interfaceIndex]->multicastRouterFunction =
                            ip->interfaceInfo[i]->multicastRouterFunction;

            ip->interfaceInfo[interfaceIndex]->multicastRoutingProtocol =
                            ip->interfaceInfo[i]->multicastRoutingProtocol;
            return;
        }
    }
    char errStr[MAX_STRING_LENGTH];
    sprintf(errStr,
            "Could not find multicast router function %d\n",
            routingProtocolType);
    ERROR_ReportError(errStr);
}


// FUNCTION  NetworkIpIsMulticastAddress
// PURPOSE   Check if an address is a multicast address.
// PARAMETERS node - this node.
//            address - address to determine if multicast address.
// RETURN     TRUE if address is multicast address, FALSE, otherwise.
BOOL NetworkIpIsMulticastAddress(Node *node, NodeAddress address)
{
    if (address >= IP_MIN_MULTICAST_ADDRESS &&
        address <= IP_MAX_MULTICAST_ADDRESS)
    {
        return TRUE;
    }

    return FALSE;
}

/*
 *  FUNCTION    NetworkInitMulticastForwardingTable
 *  PURPOSE     initialize the multicast fowarding table, allocate enough
 *              memory for number of rows, used by ip
 *  PARAMETER   node - this node.
 *  RETURN      None.
 */
void NetworkInitMulticastForwardingTable(Node *node)
{
    NetworkDataIp *ip;

    ip = (NetworkDataIp *) node->networkData.networkVar;

    ip->multicastForwardingTable.size = 0;
    ip->multicastForwardingTable.allocatedSize = 0;
    ip->multicastForwardingTable.row = NULL;
}


/*
 *  FUNCTION    NetworkEmptyMulticastFowardingTable
 *  PURPOSE     empty out all the entries in the multicast forwarding table.
 *              basically set the size of table back to 0.
 *  PARAMETER   node - this node.
 *  RETURN      None.
 */
void NetworkEmptyMulticastForwardingTable(Node *node)
{
    NetworkDataIp *ip;
    int i;

    ip = (NetworkDataIp *) node->networkData.networkVar;

    for (i=0; i < ip->multicastForwardingTable.size; i++)
    {
        ListFree(node,
                 ip->multicastForwardingTable.row[i].outInterfaceList,
                 FALSE);
    }

    ip->multicastForwardingTable.size = 0;
}



/*  FUNCTION    NetworkGetOutgoingInterfaceFromMulticastForwardingTable
 *  PURPOSE     get the interface Id node that lead to the
 *              (source, multicast group) pair.
 *  PARAMETER   node - its own node.
 *              sourceAddress - multicast source address.
 *              groupAddress - multicast group address to foward to.
 *  RETURN      interface Id from node to (source, multicast group), or
 *              NETWORK_UNREACHABLE (no such entry is found)
 */
LinkedList* NetworkGetOutgoingInterfaceFromMulticastForwardingTable(
    Node *node,
    NodeAddress sourceAddress,
    NodeAddress groupAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkMulticastForwardingTable *multicastForwardingTable =
                                        &(ip->multicastForwardingTable);
    int i;

    // Look for (source, group) pair.  If exist, use the indicated interface.
    // If not, return NETWORK_UNREACHABLE;
    for (i=0; i < multicastForwardingTable->size; i++) {

        if ((multicastForwardingTable->row[i].sourceAddress ==
            sourceAddress) &&
            (multicastForwardingTable->row[i].multicastGroupAddress ==
            groupAddress))
        {
            return multicastForwardingTable->row[i].outInterfaceList;
            break;
        }
    }

    return NULL;
}


/*  FUNCTION    NetworkUpdateMulticastForwardingTable
 *  PURPOSE     update entry with (sourceAddress, multicastGroupAddress) pair.
 *              search for the row with (sourceAddress, multicastGroupAddress)
 *              and update its interface.
 *              if no row is found, add a new row and increase table size.
 *  PARAMETER   node - its own node.
 *              sourceAddress - multicast source
 *              multicastGroupAddress - multicast group
 *              interfaceIndex - interface to use for
 *                               (sourceAddress, multicastGroupAddress).
 */
void NetworkUpdateMulticastForwardingTable(
                            Node *node,
                            NodeAddress sourceAddress,
                            NodeAddress multicastGroupAddress,
                            int interfaceIndex)
{
    BOOL newInsert = FALSE;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    NetworkMulticastForwardingTable *multicastForwardingTable =
                                        &(ip->multicastForwardingTable);

    int i;

    if (interfaceIndex < 0)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,
                "Error node %u: invalid interface index %d is invalid.\n",
                node->nodeId,
                interfaceIndex);
       ERROR_ReportError(errStr);
    }

    // See if there's a match in the table already and get the index
    // of the table where we want to update (match or new entry).

    for (i=0; i < multicastForwardingTable->size
        && (multicastForwardingTable->row[i].sourceAddress != sourceAddress
            || multicastForwardingTable->row[i].multicastGroupAddress !=
               multicastGroupAddress); i++)
    {
        /* No match. */
    }

    // If where we are going to insert is at the end, make sure the
    // table is big enough.  If not, make it bigger.
    if (i == multicastForwardingTable->size)
    {
        multicastForwardingTable->size++;

        newInsert = TRUE;

        // Increase the table size if we ran out of space.
        if (multicastForwardingTable->size >
            multicastForwardingTable->allocatedSize)
        {
            if (multicastForwardingTable->allocatedSize == 0)
            {
                multicastForwardingTable->allocatedSize =
                                                FORWARDING_TABLE_ROW_START_SIZE;

                multicastForwardingTable->row =
                                (NetworkMulticastForwardingTableRow *)
                                MEM_malloc(
                                    multicastForwardingTable->allocatedSize *
                                    sizeof(NetworkMulticastForwardingTableRow));
            }
            else
            {
                int newSize = (multicastForwardingTable->allocatedSize * 2);

                NetworkMulticastForwardingTableRow* newTableRow =
                        (NetworkMulticastForwardingTableRow*)
                        MEM_malloc(
                          newSize * sizeof(NetworkMulticastForwardingTableRow));

                memcpy(newTableRow,
                       multicastForwardingTable->row,
                       (multicastForwardingTable->allocatedSize *
                                sizeof(NetworkMulticastForwardingTableRow)));

                MEM_free(multicastForwardingTable->row);

                multicastForwardingTable->row = newTableRow;
                multicastForwardingTable->allocatedSize = newSize;
            }//if//
        }//if//

        while (i > 0 &&
               (sourceAddress >
                            multicastForwardingTable->row[i - 1].sourceAddress))
        {
            multicastForwardingTable->row[i] =
                                            multicastForwardingTable->row[i-1];
            i--;
        }//while//

    }//if//

    multicastForwardingTable->row[i].sourceAddress = sourceAddress;
    multicastForwardingTable->row[i].multicastGroupAddress =
                                                        multicastGroupAddress;

    if (newInsert)
    {
        ListInit(node, &multicastForwardingTable->row[i].outInterfaceList);
    }

    // Only insert interface if interface not in the interface list already.
    if (!NetworkInMulticastOutgoingInterface(node,
                         multicastForwardingTable->row[i].outInterfaceList,
                         interfaceIndex))
    {
        int *outInterfaceIndex = (int *) MEM_malloc(sizeof(int));

        *outInterfaceIndex = interfaceIndex;

        ListInsert(node,
                   multicastForwardingTable->row[i].outInterfaceList,
                   getSimTime(node),
                   outInterfaceIndex);
    }
}


/*
 *  FUNCTION    NetworkPrintMulticastForwardingTable
 *  PURPOSE     display all entries in multicast forwarding table of the node.
 *  PARAMETER   node - this node.
 *  RETURN      None.
 */
void NetworkPrintMulticastForwardingTable(Node *node)
{
    int i;
    NetworkDataIp *ip;
    NetworkMulticastForwardingTable *rt;

    ip = (NetworkDataIp *) node->networkData.networkVar;
    rt = &(ip->multicastForwardingTable);

    printf ("Multicast Forwarding Table for node %u\n", node->nodeId);

    for (i=0; i<rt->size; i++) {
        printf("sourceId %u "
               "multicastGroupAddress %u\n",
                rt->row[i].sourceAddress,
                rt->row[i].multicastGroupAddress);

        NetworkPrintMulticastOutgoingInterface(node,
                                               rt->row[i].outInterfaceList);
        printf ("\n");
    }
}


/*
 *  FUNCTION    NetworkPrintMulticastOutgoingInterface
 *  PURPOSE     Print mulitcast outgoing interfaces.
 *  PARAMETER   node - this node.
 *              list - list of outgoing interfaces.
 *  RETURN      None.
 */
void NetworkPrintMulticastOutgoingInterface(Node *node, LinkedList* list)
{
    ListItem *item = list->first;

    printf("    interface =");

    while (item)
    {
        int *interfaceIndex =  (int *)item->data;

        printf(" %u", *interfaceIndex);

        item = item->next;
    }
}


/*
 *  FUNCTION    NetworkInMulticastOutgoingInterface
 *  PURPOSE     Determine if interface is in multicast outgoing interface list.
 *  PARAMETER   node - this node.
 *              list - list of outgoing interfaces.
 *              interfaceIndex - interface to determine if in outgoing
 *              interface list.
 *  RETURN      TRUE if interface is in multicast outgoing interface list,
 *              FALSE otherwise.
 */

BOOL NetworkInMulticastOutgoingInterface(Node *node,
                                         LinkedList* list,
                                         int interfaceIndex)
{
    ListItem *item = list->first;

    while (item)
    {
        int *outInterfaceIndex =  (int *)item->data;

        if (interfaceIndex == *outInterfaceIndex)
        {
            return TRUE;
        }

        item = item->next;
    }

    return FALSE;
}


#if defined(ADDON_BOEINGFCS)
static void HandleNetworkIpStats(
    Node* node,
    NetworkDataIp* ip,
    Message* msg,
    int interfaceIndex,
    BOOL inComingData)
{
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

    if (interfaceIndex != CPU_INTERFACE)
    {
        if (inComingData)
        {
            if ((ipHeader->ip_dst != ANY_DEST) &&
                !NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
            {
                // Unicast packet.
                ip->interfaceInfo[interfaceIndex]->ifInUcastPkts += 1;
                ip->interfaceInfo[interfaceIndex]->ifHCInUcastPkts += 1;
                ip->interfaceInfo[interfaceIndex]->inUcastPacketSize
                    += MESSAGE_ReturnPacketSize(msg);
                if (ip->interfaceInfo[interfaceIndex]->ifInUcastPkts == 1)
                {
                    // First packet.
                    ip->interfaceInfo[interfaceIndex]->firstInUcastPacketTime =
                        getSimTime(node);
                }
                ip->interfaceInfo[interfaceIndex]->lastInUcastPacketTime =
                    getSimTime(node);

                // Check for Data Traffic.
                /*if (msg->originatingProtocol != TRACE_ROUTING_CES_ROSPF &&
                    msg->originatingProtocol != TRACE_OSPFv2 &&
                    msg->originatingProtocol != TRACE_ROUTING_CES_MALSR_ALSU)*/
                if (ipHeader->ip_p == IPPROTO_UDP ||
                    ipHeader->ip_p == IPPROTO_TCP)
                {
                    // These are data packets.
                    ip->interfaceInfo[interfaceIndex]->ifInUcastDataPackets += 1;
                    ip->interfaceInfo[interfaceIndex]->inUcastDataPacketSize +=
                        MESSAGE_ReturnPacketSize(msg);
                    if (ip->interfaceInfo[interfaceIndex]->ifInUcastDataPackets
                        == 1)
                    {
                        ip->interfaceInfo[interfaceIndex]
                        ->firstInUcastDataPacketTime = getSimTime(node);
                    }
                    ip->interfaceInfo[interfaceIndex]
                    ->lastInUcastDataPacketTime = getSimTime(node);
                }
            }
            else if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
            {
                // Not unicast packet
                ip->interfaceInfo[interfaceIndex]->ifInNUcastPkts += 1;
                ip->interfaceInfo[interfaceIndex]->ifInMulticastPkts += 1;
                ip->interfaceInfo[interfaceIndex]->ifHCInMulticastPkts += 1;
                ip->interfaceInfo[interfaceIndex]->inMulticastPacketSize +=
                    MESSAGE_ReturnPacketSize(msg);
                ip->interfaceInfo[interfaceIndex]->inNUcastPacketSize +=
                    MESSAGE_ReturnPacketSize(msg);
                if (ip->interfaceInfo[interfaceIndex]->ifInMulticastPkts == 1)
                {
                    ip->interfaceInfo[interfaceIndex]->firstInMulticastPacketTime
                        = getSimTime(node);
                }
                ip->interfaceInfo[interfaceIndex]->lastInMulticastPacketTime
                    = getSimTime(node);
            }
            else if (ipHeader->ip_dst == ANY_DEST)
            {
                // Not unicast, but is broadcast
                ip->interfaceInfo[interfaceIndex]->ifInBroadcastPkts += 1;
                ip->interfaceInfo[interfaceIndex]->ifHCInBroadcastPkts += 1;
                ip->interfaceInfo[interfaceIndex]->ifInNUcastPkts += 1;
                ip->interfaceInfo[interfaceIndex]->inBroadcastPacketSize +=
                    MESSAGE_ReturnPacketSize(msg);
                ip->interfaceInfo[interfaceIndex]->inNUcastPacketSize +=
                    MESSAGE_ReturnPacketSize(msg);
                if (ip->interfaceInfo[interfaceIndex]->ifInBroadcastPkts == 1)
                {
                    ip->interfaceInfo[interfaceIndex]->firstInBroadcastPacketTime
                        = getSimTime(node);
                }
                ip->interfaceInfo[interfaceIndex]->lastInBroadcastPacketTime
                    = getSimTime(node);
            }

            if (ip->interfaceInfo[interfaceIndex]->ifInNUcastPkts == 1)
            {
                ip->interfaceInfo[interfaceIndex]->firstInNUcastPacketTime
                    = getSimTime(node);
            }
            ip->interfaceInfo[interfaceIndex]->lastInNUcastPacketTime
                = getSimTime(node);
        }

    else
    {
        if (ipHeader->ip_dst != ANY_DEST &&
            !NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
        {
            // We have a outgoing unicast packet.
            ip->interfaceInfo[interfaceIndex]->ifOutUcastPkts += 1;
            ip->interfaceInfo[interfaceIndex]->ifHCOutUcastPkts += 1;
            ip->interfaceInfo[interfaceIndex]->outUcastPacketSize +=
                MESSAGE_ReturnPacketSize(msg);
            if (ip->interfaceInfo[interfaceIndex]->ifOutUcastPkts == 1)
            {
                ip->interfaceInfo[interfaceIndex]->firstOutUcastPacketTime
                    = getSimTime(node);
            }
            ip->interfaceInfo[interfaceIndex]->lastOutUcastPacketTime
                = getSimTime(node);

            /*if (msg->originatingProtocol != TRACE_ROUTING_CES_ROSPF &&
                msg->originatingProtocol != TRACE_OSPFv2 &&
                msg->originatingProtocol != TRACE_ROUTING_CES_MALSR_ALSU)*/
            if (ipHeader->ip_p == IPPROTO_UDP ||
                ipHeader->ip_p == IPPROTO_TCP)
            {
                // we have unicast Data packets
                ip->interfaceInfo[interfaceIndex]->ifOutUcastDataPackets += 1;
                ip->interfaceInfo[interfaceIndex]->outUcastDataPacketSize +=
                    MESSAGE_ReturnPacketSize(msg);
                if (ip->interfaceInfo[interfaceIndex]->ifOutUcastDataPackets == 1)
                {
                    // First packet
                    ip->interfaceInfo[interfaceIndex]->firstOutUcastDataPacketTime
                        = getSimTime(node);
                }
                ip->interfaceInfo[interfaceIndex]->lastOutUcastDataPacketTime
                    = getSimTime(node);
            }
        }
        else if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
        {
            // Non unicast packets but multicast.
            ip->interfaceInfo[interfaceIndex]->ifOutNUcastPkts += 1;
            ip->interfaceInfo[interfaceIndex]->ifOutMulticastPkts += 1;
            ip->interfaceInfo[interfaceIndex]->ifHCOutMulticastPkts += 1;
            ip->interfaceInfo[interfaceIndex]->outMulticastPacketSize +=
                MESSAGE_ReturnPacketSize(msg);
            ip->interfaceInfo[interfaceIndex]->outNUcastPacketSize +=
                MESSAGE_ReturnPacketSize(msg);
            if (ip->interfaceInfo[interfaceIndex]->ifOutMulticastPkts == 1)
            {
                ip->interfaceInfo[interfaceIndex]->firstOutMulticastPacketTime =
                    getSimTime(node);
            }
            ip->interfaceInfo[interfaceIndex]->lastOutMulticastPacketTime =
                getSimTime(node);
        }
        else if (ipHeader->ip_dst == ANY_DEST)
        {
            // Not unicast but Broadcast packet
            ip->interfaceInfo[interfaceIndex]->ifOutBroadcastPkts += 1;
            ip->interfaceInfo[interfaceIndex]->ifHCOutBroadcastPkts += 1;
            ip->interfaceInfo[interfaceIndex]->ifOutNUcastPkts += 1;
            ip->interfaceInfo[interfaceIndex]->outBroadcastPacketSize +=
                MESSAGE_ReturnPacketSize(msg);
            ip->interfaceInfo[interfaceIndex]->outNUcastPacketSize +=
                MESSAGE_ReturnPacketSize(msg);
            if (ip->interfaceInfo[interfaceIndex]->ifOutBroadcastPkts == 1)
            {
                ip->interfaceInfo[interfaceIndex]->firstOutBroadcastPacketTime =
                    getSimTime(node);
            }
            ip->interfaceInfo[interfaceIndex]->lastOutBroadcastPacketTime =
                getSimTime(node);
        }

        if (ip->interfaceInfo[interfaceIndex]->outNUcastPacketSize == 1)
        {
            ip->interfaceInfo[interfaceIndex]->firstOutNUcastPacketTime =
                getSimTime(node);
        }
        ip->interfaceInfo[interfaceIndex]->lastOutNUcastPacketTime =
            getSimTime(node);
    }
}
}
#endif

//-----------------------------------------------------------------------------
// FUNCTIONS WITH INTERNAL LINKAGE
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Packet delivery and forwarding
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     DeliverPacket()
// PURPOSE      Deliver IP packet from MAC layer to the appropriate
//              transport-layer or network-layer protocol.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packket.
//              int interfaceIndex
//                  Index of interface from which packet was received.
//-----------------------------------------------------------------------------

void //inline//
DeliverPacket(Node *node, Message *msg,
              int interfaceIndex, NodeAddress previousHopAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    NodeAddress sourceAddress = 0;
    NodeAddress destinationAddress =0;
    unsigned char ipProtocolNumber;
    unsigned ttl =0;
    TosType priority;
    //interfaceIndex is incomingInterface but the
    //interface mapped to an operational node may be different
    //for nodes with more than one interface
    int mappedInterfaceIndex;
    int outgoingInterfaceToUse;
    NodeAddress outgoingBroadcastAddress;
    NetworkType netType = NETWORK_IPV4;
    ActionData acnData;
    ipHeaderSizeInfo *ipHeaderSize = NULL;

    BOOL aCongestionExperienced = FALSE;

    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

    ipHeaderSize = (ipHeaderSizeInfo *)MESSAGE_AddInfo(node,
                                                       msg,
                                                    sizeof(ipHeaderSizeInfo),
                                                    INFO_TYPE_IpHeaderSize);
    ipHeaderSize->size = IpHeaderSize(ipHeader);


#if defined(ADDON_BOEINGFCS)
    // Ignore loopback stats
    HandleNetworkIpStats(node, ip, msg, interfaceIndex, FALSE);
#endif

#ifdef CYBER_LIB
    if (node->firewallModel &&
            node->firewallModel->isFirewallOn())
    {
            int response;
            response = node->firewallModel->inspect(
                FirewallModel::FILTER_TABLE,
                "INPUT",
                msg,
                interfaceIndex,
                CPU_INTERFACE);
           
            if (response ==  FirewallModel::FIREWALL_ACTION_DROP)
            {
                //printf("Packet dropped\n");
                MESSAGE_Free(node, msg);
                return;
            }
    }

    if (interfaceIndex >= 0)
    {
        IpInterfaceInfoType* intf =
            (IpInterfaceInfoType*)ip->interfaceInfo[interfaceIndex];

        // Auditing record
        if (intf->auditFile != NULL)
        {
            IpHeaderType *ipHeader =
                (IpHeaderType *) MESSAGE_ReturnPacket(msg);
            char addr1[20];
            char addr2[20];
            char now[MAX_STRING_LENGTH];

            TIME_PrintClockInSecond(getSimTime(node), now);
            fprintf(intf->auditFile, "<simtime>%s</simtime>", now);

            fprintf(intf->auditFile, "<ipv4>");

            fprintf(intf->auditFile,
                    "%hu %hu %hX %hu %hu",
                    IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len),
                    IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len),
                    IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
                    MESSAGE_ReturnPacketSize(msg),
                    ipHeader->ip_id);

            fprintf(intf->auditFile,
                    " <flags>%hu %hu %hu</flags>",
                    IpHeaderGetIpReserved(ipHeader->ipFragment),
                    IpHeaderGetIpDontFrag(ipHeader->ipFragment),
                    IpHeaderGetIpMoreFrag(ipHeader->ipFragment));

            IO_ConvertIpAddressToString(ipHeader->ip_src, addr1);
            IO_ConvertIpAddressToString(ipHeader->ip_dst, addr2);
            fprintf(intf->auditFile,
                    " %hu %hu %hu %hu %s %s",
                    IpHeaderGetIpFragOffset(ipHeader->ipFragment),
                    ipHeader->ip_ttl,
                    ipHeader->ip_p,
                    ipHeader->ip_sum,
                    addr1,
                    addr2);

            fprintf(intf->auditFile,
                    "</ipv4>\n");
        }
    }
#endif // CYBER_LIB

     // If the destination node in EXata has more than one interface and is mapped
    // to an operational host on one of its interfaces then interfaceIndex,
    // which is incomingInterface will not work.
    // The code below checks which interface has the destination IP address and
    // references that in the EXata code accordingly.
    if (node->numberInterfaces > 1)
    {
        if ((ipHeader->ip_dst == ANY_DEST) ||
            (IsOutgoingBroadcast(node,
            ipHeader->ip_dst,
            &outgoingInterfaceToUse,
            &outgoingBroadcastAddress)) ||
            (NetworkIpIsMulticastAddress(node,
            ipHeader->ip_dst)))
        {
            mappedInterfaceIndex = interfaceIndex;
        }
        else
        {
            mappedInterfaceIndex = NetworkIpGetInterfaceIndexFromAddress
                (node, ipHeader->ip_dst);
        }
    }
    else
        mappedInterfaceIndex=interfaceIndex;

#ifdef EXATA
    // If this is an external node then send the packet to the
    // operational network if we are doing true emulation
    //
    // In a few abnormal situations we can get to this point in the
    // code with mappedInterfaceIndex == ANY_INTERFACE.  Since this
    // block does not explicitly handle that case, added a check to
    // stop that value from being used as an array index (which causes
    // a seg fault if those situations occur).
    if ((mappedInterfaceIndex != CPU_INTERFACE) &&
        (mappedInterfaceIndex != ANY_INTERFACE) &&
        (node->macData[mappedInterfaceIndex]) &&
        (node->macData[mappedInterfaceIndex]->isIpneInterface))
    {
#ifdef HITL_INTERFACE
        if ((node->isHitlNode == TRUE) 
            && (ipHeader->ip_p !=  IPPROTO_OSPF)
            && (ipHeader->ip_p !=  IPPROTO_PIM)  
            && (ipHeader->ip_p !=  IPPROTO_IGMP) )
        {
            HITL_ForwardToHITL(node, mappedInterfaceIndex, msg);
            return;

        }
        else
#endif
            if (node->partitionData->isAutoIpne)
            {
                if (AutoIPNE_ForwardFromNetworkLayer(node,
                    mappedInterfaceIndex,    
                    msg,     
                    previousHopAddress,      
                    FALSE))
                {
                    return;
                }
#ifdef CYBER_LIB
             //Autoipne_forward has failed, so probably this was a routing protocol      
             //packet meant for the destination      
             if (node->macData[mappedInterfaceIndex]->promiscuousMode)    
             {   
     
                 Message* dupMsg = MESSAGE_Duplicate(node, msg);     
                 AutoIPNE_ForwardFromNetworkLayer(node,      
                                                  mappedInterfaceIndex,      
                                                  dupMsg,    
                                                  previousHopAddress,    
                                                  TRUE);     
             }   
 #endif // CYBER_LIB
            }
    }

     //this code will be called only if this node is not an ipne interface   
     //i.e. replay mode is run without mapping this node as an external      
     //node      
    else if ((mappedInterfaceIndex != CPU_INTERFACE) &&
            (mappedInterfaceIndex != ANY_INTERFACE) &&
            (node->macData[mappedInterfaceIndex]) &&
            (node->macData[mappedInterfaceIndex]->isReplayInterface))
    {
            //if (node->partitionData->isAutoIpne)
            //{

                if (node->partitionData->rrInterface->
                    ReplayForwardFromNetworkLayer(node, 
                                                  mappedInterfaceIndex, 
                                                  msg, 
                                                  FALSE))
                {
                    return;
                }

#ifdef CYBER_LIB
                if (node->macData[mappedInterfaceIndex]->promiscuousMode)
                {   
                    Message* dupMsg = MESSAGE_Duplicate(node, msg);
                    node->partitionData->rrInterface->
                        ReplayForwardFromNetworkLayer(node, 
                                                      mappedInterfaceIndex, 
                                                      dupMsg, 
                                                      TRUE);
                }
#endif // CYBER_LIB
           // }

    }

#endif

    if ((IpHeaderGetIpFragOffset(ipHeader->ipFragment) !=0)
            || IpHeaderGetIpMoreFrag(ipHeader->ipFragment))
    {
        BOOL isReassembled = FALSE;
        Message* joinedMsg = NULL;
        joinedMsg = IpFragmentInput(node, msg, interfaceIndex, &isReassembled);
        if (isReassembled)
        {
            msg = joinedMsg;
            ipHeader = (IpHeaderType *) msg->packet;
#ifdef CYBER_CORE
            if (ip->isIPsecEnabled == TRUE)
            {
                destinationAddress = ipHeader->ip_dst;
                if ((ip->interfaceInfo[interfaceIndex]->spdIN) &&
                    (IPsecRequireProcessing(node,
                                              msg,
                                              interfaceIndex)))
                {
                    IPsecHandleInboundPacket(node,
                                             msg,
                                             interfaceIndex,
                                             previousHopAddress);
                    return;
                }
            }
#endif //CYBER_CORE
        }
        else
        {
            return;
        }
        // STATS DB CODE
#ifdef ADDON_DB
        StatsDBTrimMessageNetworkMsgId(node, msg) ;
#endif
        // ERROR_ReportError("Received fragmented packet. So u need to join it\n");
    }

#ifdef CYBER_CORE
        else
        {
        IAHEPRoutingMsgInfoType *routingInfoType = NULL;

        routingInfoType = (IAHEPRoutingMsgInfoType*)
                            MESSAGE_ReturnInfo(
                            msg,
                            INFO_TYPE_IAHEP_RUTNG);
        if (routingInfoType)
        {
            //Here if the last fragment comes padded, remove padded length
            int padlen = 0;
            if (MESSAGE_ReturnInfo(msg, INFO_TYPE_PadLen) != NULL)
            {
                padlen = *(int*)MESSAGE_ReturnInfo(msg, INFO_TYPE_PadLen);
            }
            msg->virtualPayloadSize = msg->virtualPayloadSize - padlen;
            ipHeader = (IpHeaderType *)MESSAGE_ReturnPacket(msg);

            IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),
                MESSAGE_ReturnPacketSize(msg));
        }
    }
#endif // CYBER_CORE

    ipProtocolNumber = ipHeader->ip_p;

#ifdef ENTERPRISE_LIB
    if (!MplsReturnStateSpace(node))
#endif // ENTERPRISE_LIB
    {
        if ((ipHeader->ip_dst != ANY_DEST) &&
            (interfaceIndex != CPU_INTERFACE) &&
            !NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
        {
            // Let the routing protocol get a look at the original packet
            // before it is given to the transport layer or a
            // routing protocol.

            BOOL packetWasRouted = FALSE;
            BOOL routeThePkt = TRUE;
            RouterFunctionType routerFunction =
                NetworkIpGetRouterFunction(node, interfaceIndex);

            //If packet has IAHEP Header, then 1st IAHEP Processing should
            //be done.Packet cannot be routed by Routing Protocol.

            if (routerFunction && routeThePkt)
            {
                (routerFunction)(node, msg, ipHeader->ip_dst,
                                 previousHopAddress, &packetWasRouted);
            }
            ERROR_Assert(!packetWasRouted,
                         "Router function routed packet it should only "
                         "inspect");
            // The router function may change the header, So we need
            // to reset the IP header pointer
            ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
        }
    }


    if (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) & IPTOS_CE) {
          aCongestionExperienced = TRUE;
    }

#ifdef ADDON_MAODV
    if (FindAnIpOptionField(ipHeader, IPOPT_MAODV) != NULL)
    {
#ifdef ADDON_DB

        HandleNetworkDBEvents(
            node,
            msg,
            interfaceIndex,
            "NetworkPacketDrop",
            "Option Field Not Empty, MAODV",
            0,
            0,
            0,
            0);
#endif
        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_MAODV_OPTION_FIELD;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_IN,
                         &acnData,
                         netType);

        MESSAGE_Free (node, msg);
        return;
    }
#endif // ADDON_MAODV

    if (ipProtocolNumber == IPPROTO_IPV6)
    {
         // When a packet is received with this type of protocol,
         // it means an IPv4-tunneled IPv6 pkt is encapsulated within
         // the IPv4 pkt.
        if (node->networkData.networkProtocol == DUAL_IP)
        {
            TunnelHandleIPv6Pkt(
                node,
                msg,
                interfaceIndex);
        }
        else
        {
            // Since the node is not Dual-IP enabled, drop the packet.
            if (ip->isIcmpEnable && icmp->parameterProblemEnable)
            {
                 BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(
                                              node,
                                              msg,
                                              ipHeader->ip_src,
                                              interfaceIndex,
                                              ICMP_PARAMETER_PROBLEM,
                                              ICMP_PARAMETER_PROBLEM_CODE,
                                              PROBLEM_IN_PROTOCOL,
                                              0);
                 if (ICMPErrorMsgCreated)
                 {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                    printf("Node %d sending parameter problem message"
                           " to %s\n", node->nodeId, srcAddr);
#endif
                     (icmp->icmpErrorStat.icmpParameterProblemSent)++;
                 }
            }
            ip->stats.ipInHdrErrors++;
            if (node->networkData.networkStats)
            {
                ip->newStats->AddPacketDroppedOtherDataPoints(node);
            }
            MESSAGE_Free(node, msg);
        }

        return;
    }



    NetworkIpRemoveIpHeader(
                            node,
                            msg,
                            &sourceAddress,
                            &destinationAddress,
                            &priority,
                            &ipProtocolNumber,
                            &ttl);

    // Increment stat for number of IP datagrams delivered to
    // appropriate protocol module.

    ip->stats.ipInDelivers++;

    // Increment stat for total value of TTLs for packets delivered to
    // this node.  This is used to calculate an "ipInDelivers TTL-based
    // average hop count" metric.

    ip->stats.deliveredPacketTtlTotal += (ttl - IP_TTL_DEC);
    BOOL found = FALSE;

#ifdef ADDON_DB
            // Packet re-assembled and ready to send.
            HandleNetworkDBEvents(
                node,
                msg,
                interfaceIndex,
                "NetworkSendToUpper",
                "",
                sourceAddress,
                destinationAddress,
                priority,
                ipProtocolNumber);
#endif
    switch (ipProtocolNumber)
    {
        // Delivery to transport layer protocols.
        case IPPROTO_UDP:
        {
            // STATS DB CODE

            SendToUdp(node, msg, priority, sourceAddress, destinationAddress,
                      interfaceIndex);
            break;
        }
        case IPPROTO_TCP:
        {

            SendToTcp(node,
                      msg,
                      priority,
                      sourceAddress,
                      destinationAddress,
                      aCongestionExperienced);
            break;
        }
//InsertPatch TRANSPORT_SEND_TO_TRANS

        // Delivery to generic network layer protocols.

        case IPPROTO_IGMP:
        {
            IgmpHandleProtocolPacket(
               node, msg, sourceAddress, destinationAddress, interfaceIndex);
            break;
        }

        case IPPROTO_ICMP:
        {
            if (ip->isIcmpEnable)
            {
                NetworkIcmpHandleProtocolPacket(node,
                                                msg,
                                                sourceAddress,
                                                destinationAddress,
                                                mappedInterfaceIndex);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment = DROP_ICMP_NOT_ENABLE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                interfaceIndex,
                "NetworkPacketDrop",
                "ICMP Not Enabled",
                0,
                0,
                0,
                0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }
#ifdef ADDON_BOEINGFCS
        case IPPROTO_IPIP_ROUTING_CES_MALSR:
        {
            IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

            NetworkIpReceivePacketFromMacLayer(node,
                                               msg,
                                               previousHopAddress,
                                               interfaceIndex);
            break;
        }
        case IPPROTO_IPIP_ROUTING_CES_SRW:
        {
            IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

            NetworkIpReceivePacketFromMacLayer(node,
                                               msg,
                                               previousHopAddress,
                                               interfaceIndex);
            break;
        }
        case IPPROTO_IPIP_CES_SDR:
        {
            IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

            NetworkIpReceivePacketFromMacLayer(node,
                                               msg,
                                               previousHopAddress,
                                               interfaceIndex);
            break;
        }
        case IPPROTO_IPIP_ROUTING_CES_ROSPF:
        {
            IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

            NetworkIpReceivePacketFromMacLayer(node,
                                               msg,
                                               previousHopAddress,
                                               interfaceIndex);
            break;
        }
        case IPPROTO_ROUTING_CES_ROSPF:
        {
            // This case will only occur if we are receiving a simulated hello.
            RoutingCesRospfHandleProtocolPacket(node, msg, interfaceIndex,ipProtocolNumber);
            break;
        }
#endif // ADDON_BOEINGFCS
        // Delivery to network-layer routing protocols.

#ifdef WIRELESS_LIB
        case IPPROTO_AODV:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex) ==
                ROUTING_PROTOCOL_AODV)
            {
                Address srcAddress;
                Address destAddress;

                SetIPv4AddressInfo(&srcAddress, sourceAddress);

                SetIPv4AddressInfo(&destAddress, destinationAddress);

                AodvHandleProtocolPacket(
                    node,
                    msg,
                    srcAddress,
                    destAddress,
                    ttl,
                    interfaceIndex);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, AODV",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }
        case IPPROTO_DYMO:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex) ==
                ROUTING_PROTOCOL_DYMO)
            {
                Address srcAddress;
                Address destAddress;

                SetIPv4AddressInfo(&srcAddress, sourceAddress);
                SetIPv4AddressInfo(&destAddress, destinationAddress);

                DymoHandleProtocolPacket(
                    node,
                    msg,
                    srcAddress,
                    destAddress,
                    interfaceIndex);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, DYMO",
                    0,
                    0,
                    0,
                    0);
#endif
            }
            MESSAGE_Free(node, msg);
            break;
        }

        case IPPROTO_DSR:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex) ==
                ROUTING_PROTOCOL_DSR)
            {
                DsrHandleProtocolPacket(node, msg, sourceAddress,
                    destinationAddress, ttl, previousHopAddress);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, DSR",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }
        case IPPROTO_FSRL:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex) ==
                ROUTING_PROTOCOL_FSRL)
            {
                FsrlHandleProtocolPacket(node, msg, sourceAddress,
                    destinationAddress, interfaceIndex, ttl);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, FSRL",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }
#ifdef ADDON_BOEINGFCS
        case IPPROTO_ROUTING_CES_MALSR:
        {
            RoutingCesMalsrHandleProtocolPacket(node,
                                      msg,
                                      sourceAddress,
                                      destinationAddress,
                                      interfaceIndex,
                                      ttl);

            break;
        }
        case IPPROTO_MI_CES_MULTICAST_MESH:
        {
            MiCesMulticastMeshHandleProtocolPacket(node,
                                      msg,
                                      sourceAddress,
                                      destinationAddress,
                                      interfaceIndex,
                                      ttl);
            break;
        }
        case IPPROTO_NETWORK_CES_REGION:
        {
            NetworkCesRegionHandleProtocolPacket(node,
                                        msg, sourceAddress,
                                        destinationAddress,
                                        interfaceIndex,
                                        ttl);

            break;
        }
        case IPPROTO_CES_EPLRS:
        {
            NetworkCesIncEplrsHandleProtocolPacket(
                   node,
                   msg,
                   previousHopAddress,
                   destinationAddress,
                   interfaceIndex);
            break;
        }
        case IPPROTO_CES_EPLRS_MPR:
        {

            NetworkCesIncEplrsMprHandleProtocolPacket(node,
                        msg,
                        previousHopAddress,
                        destinationAddress,
                        interfaceIndex,
                        ttl);
            break;


        }
        case IPPROTO_ROUTING_CES_MPR:
        {
            if (ip->interfaceInfo[interfaceIndex]->useRoutingCesMpr) {
                RoutingCesMprHandleProtocolPacket(node, msg, sourceAddress,
                                            destinationAddress, ttl,
                                            interfaceIndex);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment
                            = DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, MPR",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }

#endif  // ADDON_BOEINGFCS
#ifdef ADDON_NGCNMS
        case IPPROTO_IPIP_RED:
        {
            NetworkNgcHaipeRemoveHeader(node, msg);

            NetworkNgcHaipeReceivePacketFromMacLayer(node,
                                           msg,
                                           previousHopAddress,
                                           interfaceIndex);

            break;
        }
#endif
        case IPPROTO_LAR1:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex) ==
                ROUTING_PROTOCOL_LAR1)
            {
                Lar1HandleProtocolPacket(node, msg);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, LAR1",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }
        case IPPROTO_STAR:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex) ==
                ROUTING_PROTOCOL_STAR)
            {
                StarHandleProtocolPacket(node, msg, sourceAddress);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, STAR",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }
        case IPPROTO_BRP:
        {
            BrpDeliver(node,
                       msg,
                       sourceAddress,
                       destinationAddress,
                       interfaceIndex,
                       ttl);
            break;
        }
        case IPPROTO_IARP:
        {
            IarpHandleProtocolPacket(node, msg, sourceAddress,
                                     destinationAddress, interfaceIndex,
                                     ttl);
            break;
        }
        case IPPROTO_ZRP:
        {
            ZrpHandleProtocolPacket(node, msg, sourceAddress,
                                    destinationAddress, interfaceIndex,
                                    ttl);
            break;
        }
        case IPPROTO_IERP:
        {
            IerpHandleProtocolPacket(node, msg, sourceAddress,
                                     destinationAddress, interfaceIndex,
                                     ttl);
            break;
        }
        case IPPROTO_ODMRP:
        {
            OdmrpHandleProtocolPacket(node, msg, ipHeader->ip_src,
                ipHeader->ip_dst);
            break;
        }
        case IPPROTO_NDP:
        {
            NdpHandleProtocolPacket(
                node,
                msg,
                sourceAddress,
                interfaceIndex);
            break;
        }
#endif // WIRELESS_LIB
#ifdef ENTERPRISE_LIB
        case IPPROTO_RSVP:
        {
            SendToRsvp(node, msg, priority, sourceAddress,
                       destinationAddress, interfaceIndex, ttl);
            break;
        }
        case IPPROTO_IPIP:
        {
            /*
             * This is for IP in IP encapsulation. When a packet is received
             * with this type of protocol, it means the original IP packet is
             * tunneled. Decapsulate it
             */
             MobileIpDecapsulateDatagram(node, msg);
             break;
        }
        case IPPROTO_MOBILE_IP:
        {
            MobileIpHandleProtocolPacket(node,
                                         msg,
                                         sourceAddress,
                                         destinationAddress,
                                         interfaceIndex);
            break;
        }
        case IPPROTO_OSPF:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex) ==
                ROUTING_PROTOCOL_OSPFv2)
            {
                Ospfv2HandleRoutingProtocolPacket(node,
                                                  msg,
                                                  sourceAddress,
                                                  destinationAddress,
                                                  (unsigned) -1,
                                                  interfaceIndex);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, OSPF",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }
        case IPPROTO_PIM:
        {
            RoutingPimHandleProtocolPacket(node, msg, sourceAddress,
                interfaceIndex);
            break;
        }
        case IPPROTO_IGRP:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex) ==
                ROUTING_PROTOCOL_IGRP)
            {
                 IgrpHandleProtocolPacket(
                     node,
                     msg,
                     sourceAddress,
                     interfaceIndex);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, IGRP",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }
        case IPPROTO_EIGRP:
        {
           EigrpHandleProtocolPacket(
                node,
                msg,
                sourceAddress,
                interfaceIndex,
                previousHopAddress);

            break;
        }
#endif // ENTERPRISE_LIB

#ifdef MILITARY_RADIOS_LIB
        case IPPROTO_ODR:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(
                    node, interfaceIndex) == ROUTING_PROTOCOL_ODR)
            {
                OdrHandleProtocolPacket(node, msg, sourceAddress,
                                            destinationAddress, ttl,
                                            interfaceIndex);
            }

            else
            {
                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment =
                                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData);

                MESSAGE_Free(node, msg);
            }

            break;
        }
        case IPPROTO_IPIP_ODR:
        {
            NetworkIpReceivePacketFromMacLayer(node,
                                               msg,
                                               previousHopAddress,
                                               interfaceIndex);
            break;
        }
        case IPPROTO_SDR:
        {
            if (SdrActiveOnInterface(node, interfaceIndex) == TRUE)
            {
                SdrHandleProtocolPacket(node,
                                        msg,
                                        sourceAddress,
                                        destinationAddress,
                                        interfaceIndex,
                                        ttl);
            }
            else{
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, SDR",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }
#endif // MILITARY_RADIOS_LIB
#ifdef CYBER_LIB
        case IPPROTO_ANODR:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex) ==
                ROUTING_PROTOCOL_ANODR)
            {
                AnodrHandleProtocolPacket(node, msg, sourceAddress,
                                          destinationAddress, ttl,
                                          interfaceIndex);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, ANODR",
                    0,
                    0,
                    0,
                    0);
#endif

                MESSAGE_Free(node, msg);
            }

            break;
        }

        case IPPROTO_SECURE_NEIGHBOR:
        {
            if (ip->isSecureneighborEnabled == TRUE)
            {
                SecureneighborHandleProtocolPacket(
                    node, msg,
                    sourceAddress, destinationAddress,
                    ttl, interfaceIndex);
            }
            else
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment =
                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Protocol Unavailable, SECURE-NEIGHBOR",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
            }

            break;
        }

        //case IPPROTO_SECURE_COMMUNITY:
        //{
        //  if (ip->isSecureCommunityEnabled == TRUE)
        //  {
        //      Address source, dest;
        //      source.networkType = NETWORK_IPV4;
        //      source.interfaceAddr.ipv4 = sourceAddress;
        //      dest.networkType = NETWORK_IPV4;
        //      dest.interfaceAddr.ipv4 = destinationAddress;
        //      SecureCommunityHandleProtocolPacket(
        //          node, msg,
        //          &source, &dest,
        //          ttl, interfaceIndex);
        //  }
        //    else
        //    {
        //        //Trace drop
        //        acnData.actionType = DROP;
        //        acnData.actionComment =
        //            DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
        //        TRACE_PrintTrace(node,
        //                         msg,
        //                         TRACE_NETWORK_LAYER,
        //                         PACKET_IN,
        //                         &acnData,
        //                         netType);
        //
        //        MESSAGE_Free(node, msg);
        //    }
        //
        //    break;
        //}
#endif // CYBER_LIB
#ifdef CYBER_CORE
        case IPPROTO_ISAKMP:
        {
            ISAKMPHandleProtocolPacket(node,
                                       msg,
                                       sourceAddress,
                                       destinationAddress);
            break;
        }
        case IPPROTO_ESP:
        {
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                interfaceIndex,
                "NetworkPacketDrop",
                "Unexpected ESP Packet",
                0,
                0,
                0,
                0);
#endif
            MESSAGE_Free(node, msg);
            break;
        }

        case IPPROTO_AH:
        {
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                interfaceIndex,
                "NetworkPacketDrop",
                "Unexpected AH Packet",
                0,
                0,
                0,
                0);
#endif
            MESSAGE_Free(node, msg);
            break;
        }
#endif // CYBER_CORE
//CES HAIPE
#ifndef CYBER_CORE
        case IPPROTO_ESP:
            {
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Unexpected ESP Packet",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
                break;
            }
        case IPPROTO_AH:
            {
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    interfaceIndex,
                    "NetworkPacketDrop",
                    "Unexpected AH Packet",
                    0,
                    0,
                    0,
                    0);
#endif

                MESSAGE_Free(node, msg);
                break;
            }
#endif //CYBER_CORE

#ifdef ADDON_MAODV
        case IPPROTO_MAODV:
        {
            MaodvHandleProtocolPacket(
                node,
                msg,
                sourceAddress,
                destinationAddress,
                ttl,
                interfaceIndex);

            break;
        }
#endif // ADDON_MAODV

#ifdef CELLULAR_LIB
        case IPPROTO_GSM:
        {
             GsmLayer3ReceivePacketOverIp(node, msg, sourceAddress);
             break;
        }
        case IPPROTO_CELLULAR:
        {
             Address srcAddr;

             SetIPv4AddressInfo(&srcAddr, sourceAddress);
             CellularLayer3ReceivePacketOverIp(node,
                                               msg,
                                               interfaceIndex,
                                               srcAddr);
             break;
        }
#elif UMTS_LIB
        case IPPROTO_CELLULAR:
        {
             Address srcAddr;

             SetIPv4AddressInfo(&srcAddr, sourceAddress);
             CellularLayer3ReceivePacketOverIp(node,
                                               msg,
                                               interfaceIndex,
                                               srcAddr);
             break;
        }
#endif // CELLULAR_LIB

#ifdef ADVANCED_WIRELESS_LIB
        case IPPROTO_DOT16:
        {
            Dot16BackboneReceivePacketOverIp(node, msg, sourceAddress);
             break;
        }
#endif

        case IPPROTO_EXTERNAL:
        {
            EXTERNAL_NetworkLayerPacket packet;
            EXTERNAL_Interface* iface;
            char* info = MESSAGE_ReturnInfo(msg, INFO_TYPE_ExternalData);

            // Get the packet from info
            ERROR_Assert(
                info != NULL,
                "Send info not allocated for network external packet");
            memcpy(
                &packet,
                info,
                sizeof(EXTERNAL_NetworkLayerPacket));

            // Lookup the interface
            iface = EXTERNAL_GetInterfaceByUniqueId(
                &node->partitionData->interfaceList,
                packet.externalId);
            ERROR_Assert(
                iface != NULL,
                "Unknown interface for network external packet");

            EXTERNAL_ForwardData(
                iface,
                node,
                MESSAGE_ReturnPacket(msg),
                MESSAGE_ReturnPacketSize(msg));
            MESSAGE_Free(node, msg);
            break;
        }
#ifdef GATEWAY_INTERFACE
        case IPPROTO_INTERNET_GATEWAY:
        {
            GATEWAY_ForwardToInternetGateway(node, interfaceIndex, msg);
            break;
        }
#endif

        //InsertPatch NETWORK_HANDLE_PACKET
        default:
        {
            if (ip->isIcmpEnable && icmp->protocolUnreachableEnable)
            {
                //Create ICMP protocol unreachable message here.
                //Since IP header has been removed, we need to add back
                //IP header in NetworkIcmpCreateErrorMessage()
                BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(
                                            node,
                                            msg,
                                            ipHeader->ip_src,
                                            interfaceIndex,
                                            ICMP_DESTINATION_UNREACHABLE,
                                            ICMP_PROTOCOL_UNREACHABLE,
                                            0,
                                            0);
                 if (ICMPErrorMsgCreated)
                 {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                     char srcAddr[MAX_STRING_LENGTH];
                     IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                     printf("Node %d sending protocol unreachable message"
                            " to %s\n", node->nodeId, srcAddr);
#endif
                     (icmp->icmpErrorStat.icmpProtocolUnreacableSent)++;
                     ip->stats.ipInUnknownProtos++;
                 }
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                interfaceIndex,
                "NetworkPacketDrop",
                "Protocol Unavailable",
                0,
                0,
                0,
                0);
#endif


                 MESSAGE_Free(node, msg);
            }
            else
            {
                // Updated error message to provide more coherent
                //feedback to user
                char err[MAX_STRING_LENGTH];
                sprintf(err,"Node %d: Invalid protocol: %d",
                                         node->nodeId, ipProtocolNumber);
                ERROR_ReportError(err);
            }
        }

    }//switch//
}//DeliverPacket//


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpUseBackplaneIfPossible()
// PURPOSE      Determine if there's any packet that needs to go through the
//              the backplane and if so, pass the packet through the backplane.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int incomingInterface
//                  Index of interface which packet comes from.
//-----------------------------------------------------------------------------

void
NetworkIpUseBackplaneIfPossible(Node *node,
                                int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int outgoingInterface;
    int networkType = 0;
    NodeAddress hopAddr = 0;
    MacHWAddress hopMacAddr;
    TosType priority = 0;
    Message *newMsg = NULL;
    int packetSize;
    BOOL isEmpty = TRUE;
    NetworkIpBackplaneStatusType *backplaneStatus;

    if (incomingInterface == CPU_INTERFACE ||
        ip->backplaneType == BACKPLANE_TYPE_CENTRAL)
    {
        backplaneStatus = &ip->backplaneStatus;
    }
    else
    {
        backplaneStatus =
                     &ip->interfaceInfo[incomingInterface]->backplaneStatus;
    }

    // If the interface is busy sending on the backplane, then wait...
    if (*backplaneStatus != NETWORK_IP_BACKPLANE_IDLE)
    {
       return;
    }

    // If we are here, then the interface is free to send on
    // the backplane...

    // Get the message information according to the interface queue...
    if (incomingInterface == CPU_INTERFACE ||
        ip->backplaneType == BACKPLANE_TYPE_CENTRAL)
    {
        if (!NetworkIpCpuQueueIsEmpty(node))
        {
            NetworkIpCpuQueueTopPacket(node,
                                 &newMsg,
                                 &hopAddr,
                                 &hopMacAddr,
                                 &outgoingInterface,
                                 &networkType,
                                 &priority);

            isEmpty = FALSE;
        }
    }
    else
    {
        if (!NetworkIpInputQueueIsEmpty(node, incomingInterface))
        {
            NetworkIpInputQueueTopPacket(node,
                                 incomingInterface,
                                 &newMsg,
                                 &hopAddr,
                                 &hopMacAddr,
                                 &outgoingInterface,
                                 &networkType,
                                 &priority);

            isEmpty = FALSE;
        }
    }

    // Only send on backplane if queue is not empty.
    if (!isEmpty)
    {
        Message *backplaneMsg;
        clocktype backplaneDelay;
        NetworkIpBackplaneInfo *backplaneInfo;

        packetSize = MESSAGE_ReturnPacketSize(newMsg);

        if (incomingInterface == CPU_INTERFACE
            || ip->backplaneType == BACKPLANE_TYPE_CENTRAL)
        {
            backplaneDelay = (clocktype) (packetSize * 8 * SECOND /
                                      ip->backplaneThroughputCapacity);
        }
        else
        {
            backplaneDelay = (clocktype) (packetSize * 8 * SECOND /
                ip->interfaceInfo[incomingInterface]->disBackplaneCapacity);
        }

        if (networkType == NETWORK_PROTOCOL_IPV6)
        {
            backplaneMsg = MESSAGE_Alloc(node,
                                         NETWORK_LAYER,
                                         NETWORK_PROTOCOL_IPV6,
                                         MSG_NETWORK_Backplane);
        }
        else
        {
            backplaneMsg = MESSAGE_Alloc(node,
                                     NETWORK_LAYER,
                                     NETWORK_PROTOCOL_IP,
                                     MSG_NETWORK_Backplane);
        }
        MESSAGE_InfoAlloc(node,
                          backplaneMsg,
                          sizeof(NetworkIpBackplaneInfo));

        backplaneInfo = (NetworkIpBackplaneInfo *)
                         MESSAGE_ReturnInfo(backplaneMsg);

        backplaneInfo->incomingInterface = incomingInterface;
        backplaneInfo->hopAddr = hopAddr;
        MAC_CopyMacHWAddress(&backplaneInfo->hopMacAddr,&hopMacAddr);

        *backplaneStatus = NETWORK_IP_BACKPLANE_BUSY;

        MESSAGE_Send(node, backplaneMsg, backplaneDelay);
    }
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpReceiveFromBackplane()
// PURPOSE      Process packets that have passed through the backplane.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg,
//                  packet that just passed through the backplane.
//-----------------------------------------------------------------------------

void
NetworkIpReceiveFromBackplane(Node *node, Message *msg)
{
    Message *queueMsg;
    int outgoingInterface;
    int networkType;
    NodeAddress hopAddr;
    MacHWAddress nextHopMacAddr;
    TosType priority;
    NetworkIpBackplaneStatusType *backplaneStatus;

    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    NetworkIpBackplaneInfo *info = (NetworkIpBackplaneInfo *)
                                   MESSAGE_ReturnInfo(msg);

    if (info->incomingInterface == CPU_INTERFACE
        || ip->backplaneType == BACKPLANE_TYPE_CENTRAL)
    {
        backplaneStatus = &ip->backplaneStatus;

        NetworkIpCpuQueueDequeuePacket(node,
                                 &queueMsg,
                                 &hopAddr,
                                 &nextHopMacAddr,
                                 &outgoingInterface,
                                 &networkType,
                                 &priority);
    }
    else
    {
        backplaneStatus =
                 &ip->interfaceInfo[info->incomingInterface]->backplaneStatus;

        NetworkIpInputQueueDequeuePacket(node,
                                 info->incomingInterface,
                                 &queueMsg,
                                 &hopAddr,
                                 &nextHopMacAddr,
                                 &outgoingInterface,
                                 &networkType,
                                 &priority);
    }

    assert(*backplaneStatus == NETWORK_IP_BACKPLANE_BUSY);

    *backplaneStatus = NETWORK_IP_BACKPLANE_IDLE;

    if (outgoingInterface == CPU_INTERFACE)
    {
        QueuedPacketInfo* packetInfo =
            (QueuedPacketInfo*) MESSAGE_ReturnInfo(queueMsg);

        if (networkType == NETWORK_PROTOCOL_IPV6)
        {
            ip6_hdr* ipv6Header = (ip6_hdr *)MESSAGE_ReturnPacket(queueMsg);

            if (ip->backplaneType == BACKPLANE_TYPE_CENTRAL)
            {
                ip6_deliver(node, queueMsg, 0,
                    packetInfo->incomingInterface, ipv6Header->ip6_nxt);
            }
            else
            {
                ip6_deliver(node, queueMsg, 0,
                    info->incomingInterface, ipv6Header->ip6_nxt);
            }
        }
        else // Ipv4
        {
            if (ip->backplaneType == BACKPLANE_TYPE_CENTRAL)
            {
                DeliverPacket(node, queueMsg,
                    packetInfo->incomingInterface, info->hopAddr);
            }
            else
            {
                DeliverPacket(node, queueMsg,
                    info->incomingInterface, info->hopAddr);
            }
        }
    }
    else
    {
        if (networkType == NETWORK_PROTOCOL_IPV6)
        {
            QueueUpIpv6FragmentForMacLayer(node,
                                     queueMsg,
                                     outgoingInterface,
                                     info->hopMacAddr,
                                     info->incomingInterface);
        }
        else
        {
            QueueUpIpFragmentForMacLayer(node,
                                         queueMsg,
                                         outgoingInterface,
                                         info->hopAddr,
                                         info->incomingInterface);
        }
    }

    NetworkIpUseBackplaneIfPossible(node,
                                    info->incomingInterface);
    MEM_free(info->hopMacAddr.byte);
    info->hopMacAddr.byte = NULL;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendOnBackplane()
// PURPOSE      Simulates packets going to the router backplane before
//              they are further processed.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packket.
//              int incomingInterface
//                  Index of interface from which packet was received.
//              int outgoingInterface
//                  Index of interface packet is to be sent to.
//              NodeAddress hopAddr
//                  address of the next hop node (for forwarding the packet)
//                  or the last hop node (for delivering the packet to upper
//                  layers.
//-----------------------------------------------------------------------------
void //inline//
NetworkIpSendOnBackplane(
     Node *node,
     Message *msg,
     int incomingInterface,
     int outgoingInterface,
     NodeAddress hopAddr)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    IpHeaderType *ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

    // If we assume unlimited backplane throughput,
    // then we skip the backplane overhead altogther.

    if (ip->backplaneThroughputCapacity ==
        NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT)
    {
        if (outgoingInterface == CPU_INTERFACE)
        {
             DeliverPacket(node, msg, incomingInterface, hopAddr);
        }
        else
        {

#ifdef CYBER_CORE
            Int32 temp1 = 0;
            NodeAddress temp2 = 0;

            if (ip->iahepEnabled && ip->iahepData->nodeType == RED_NODE &&
                IsIAHEPRedSecureInterface(node, outgoingInterface) &&
                IAHEPProcessingRequired(ipHeader->ip_p))
            {
                IAHEPAddDestinationRedHeader(node, msg, hopAddr);
                ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
                hopAddr = ANY_DEST;
            }
            /*if (ip->iahepEnabled && ip->iahepData->nodeType == IAHEP_NODE &&
                IsIAHEPBlackSecureInterface(node, outgoingInterface))
            {
                MESSAGE_RemoveInfo (node, msg, INFO_TYPE_IAHEP_RUTNG);
            }*/
#endif //CYBER_CORE
            QueueUpIpFragmentForMacLayer(node,
                                         msg,
                                         outgoingInterface,
                                         hopAddr,
                                         incomingInterface);
        }
    }
    else
    {
        BOOL queueIsFull = FALSE;

        if (incomingInterface == CPU_INTERFACE ||
            ip->backplaneType == BACKPLANE_TYPE_CENTRAL)
        {
            NetworkIpCpuQueueInsert(node,
                               msg,
                               hopAddr,
                               ipHeader->ip_dst,
                               outgoingInterface,
                               NETWORK_PROTOCOL_IP,
                               &queueIsFull,
                               incomingInterface);
        }
        else
        {
            NetworkIpInputQueueInsert(node,
                               incomingInterface,
                               msg,
                               hopAddr,
                               ipHeader->ip_dst,
                               outgoingInterface,
                               NETWORK_PROTOCOL_IP,
                               &queueIsFull);
        }

        // If queue is full, then just drop the packet.  No need to go
        // through the backplane.
        if (queueIsFull)
        {
           // Keep stats on how many packets are dropped due to
           // over backplane throughput limit.
#ifdef ADDON_DB
        // Input the fragmented message received from the MAC layer.
        // Fragment error.
        HandleNetworkDBEvents(
            node,
            msg,
            incomingInterface, // use incoming interface here
            "NetworkPacketDrop",
            "IP Queue Full",
            0,
            0,
            0,
            0);
#endif
           ip->stats.ipNumDroppedDueToBackplaneLimit++;

            //Trace drop
            ActionData acnData;
            acnData.actionType = DROP;
            acnData.actionComment = DROP_QUEUE_OVERFLOW;
            NetworkType netType = NETWORK_IPV4;
            if (outgoingInterface == CPU_INTERFACE)
            {
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData,
                                 netType);
            }
            else
            {
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData,
                                 netType);
            }
            if (ip->isIcmpEnable && icmp->sourceQuenchEnable)
            {
                BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                            msg,
                                            ipHeader->ip_src,
                                            incomingInterface,
                                            ICMP_SOURCE_QUENCH,
                                            ICMP_SOURCE_QUENCH_CODE,
                                            0,
                                            0);
                 if (ICMPErrorMsgCreated)
                 {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                    printf("Node %d sending source quench message to %s\n",
                                        node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpSrcQuenchSent)++;
                }
            }
           MESSAGE_Free(node, msg);
        }
        else
        {
            NetworkIpUseBackplaneIfPossible(node,
                                            incomingInterface);
        }
    }
}


//-----------------------------------------------------------------------------
// FUNCTION     ForwardPacket()
// PURPOSE      Forward IP packet.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packket.
//              int incomingInterface
//                  Index of interface from which packet was received.
//              NodeAddress previousHopAddress
//                  Previous hop of packet.
//
// NOTES        This routine is only called for packets which arrive
//              from the MAC layer.  Packets from a network-layer or
//              transport-layer protocol are not "forwarded", per se.
//-----------------------------------------------------------------------------
#ifndef ADDON_BOEINGFCS
static
#endif
void //inline//
ForwardPacket(
    Node *node,
    Message *msg,
    int incomingInterface,
    NodeAddress previousHopAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader;
    ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
    ActionData acnData;
    NetworkType netType = NETWORK_IPV4;

#ifdef ADDON_MAODV
    BOOL PacketWasRouted = FALSE;
    MulticastRouterFunctionType routerFunction =
               NetworkIpGetMulticastRouterFunction(node, incomingInterface);

    // if multicast router function is defined let it have a look in
    // the packet

    if (routerFunction != NULL
        && NetworkIpIsMulticastAddress(node, ipHeader->ip_dst)
        && !NetworkIpIsMyIP(node, ipHeader->ip_src)
        && ( ip->interfaceInfo[incomingInterface]->multicastProtocolType
        == MULTICAST_PROTOCOL_MAODV))
    {
         (routerFunction)(node,
                         msg,
                         ipHeader->ip_dst,
                         incomingInterface,
                         &PacketWasRouted,
                         previousHopAddress);

        if (PacketWasRouted)
        {
            return;
        }
    }

#endif // ADDON_MAODV

    if (ip->ipForwardingEnabled == FALSE)
    {
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                incomingInterface,
                "NetworkPacketDrop",
                "IP Forwarding Not Enabled",
                0,
                0,
                0,
                0);
#endif
        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_IPFORWARD_NOT_ENABLE;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData,
                         netType);
        if (node->networkData.networkStats)
        {
            ip->newStats->AddPacketDroppedOtherDataPoints(node);
        }
        MESSAGE_Free(node, msg);
        return;
    }

    if (NetworkIpDecreaseTTL(node, msg, incomingInterface))
    {

        if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
        {
#ifdef CYBER_CORE
            if ((ip->iahepEnabled) && (ip->iahepData->nodeType == BLACK_NODE))
            {
                ((NetworkDataIp *) node->networkData.networkVar)
                            ->stats.ipInForwardDatagrams++;
#ifdef ADDON_DB
                HandleNetworkDBEvents(
                    node,
                    msg,
                    incomingInterface,
                    "NetworkForwardPacket",
                    "",
                    0,
                    0,
                    0,
                    0);
#endif

                RoutePacketAndSendToMac(node,
                                        msg,
                                        incomingInterface,
                                        ANY_INTERFACE,
                                        previousHopAddress);
            }
            else
            {
#endif //CYBER_CORE
            /* Self originating packet should not be forwarded */
#if 0
            if (ipHeader->ip_src ==
                    NetworkIpGetInterfaceAddress(node, incomingInterface))
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment = DROP_MULTICAST_ADDR_SELF_PACKET;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    incomingInterface,
                    "NetworkPacketDrop",
                    "Multicast Self Originated Packet",
                    0,
                    0,
                    0,
                    0);
#endif
                /* Free message */
                MESSAGE_Free(node, msg);
            }
            else
#endif
            {
#ifdef ADDON_DB
                HandleNetworkDBEvents(
                    node,
                    msg,
                    incomingInterface,
                    "NetworkForwardPacket",
                    "",
                    0,
                    0,
                    0,
                    0);
#endif
                ((NetworkDataIp *) node->networkData.networkVar)
                        ->stats.ipInForwardDatagrams++;
                RoutePacketAndSendToMac(node,
                                        msg,
                                        incomingInterface,
                                        ANY_INTERFACE,
                                        previousHopAddress);
            }
#ifdef CYBER_CORE
            }
#endif //CYBER_CORE
        }
#ifdef CYBER_CORE
//BROADCAST_IAHEP_START
        else if (!(ip->iahepEnabled) && (ipHeader->ip_dst == ANY_DEST))
        {
            /* Self originating packet should not be forwarded */
            if (ipHeader->ip_src ==
                    NetworkIpGetInterfaceAddress(node, incomingInterface))
            {
                //Trace drop
                acnData.actionType = DROP;
                acnData.actionComment = DROP_DUPLICATE_PACKET;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData,
                                 netType);
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    incomingInterface,
                    "NetworkPacketDrop",
                    "Broadcast Self Originated Packet",
                    0,
                    0,
                    0,
                    0);
#endif

                /* Free message */
                MESSAGE_Free(node, msg);
        }
        else
        {
                BOOL isForwarded = FALSE;
                for (int i = 0; i < node->numberInterfaces; i++)
                {

                    if (i != incomingInterface &&
                        NetworkIpGetUnicastRoutingProtocolType(
                              node, i, NETWORK_IPV4) != ROUTING_PROTOCOL_NONE)
                    {
                         isForwarded = TRUE;
                            NetworkIpSendPacketOnInterface(
                                  node,
                                  MESSAGE_Duplicate(node, msg),
                                  incomingInterface,
                                  i,
                                  ipHeader->ip_dst);
                    }
                }

                if (isForwarded)
                {
                    ((NetworkDataIp *) node->networkData.networkVar)
                        ->stats.ipInForwardDatagrams++;
#ifdef ADDON_DB
                    HandleNetworkDBEvents(
                        node,
                        msg,
                        incomingInterface,
                        "NetworkForwardPacket",
                        "",
                        0,
                        0,
                        0,
                        0);
#endif

        }
        else
        {
#ifdef ADDON_DB

                    HandleNetworkDBEvents(
                        node,
                        msg,
                        incomingInterface,
                        "NetworkPacketDrop",
                        "No Routing Protocol Available",
                        0,
                        0,
                        0,
                        0);
#endif
                }
                /* Free message */
                MESSAGE_Free(node, msg);
           }
        }
//BROADCAST_IAHEP_END
#endif // CYBER_CORE
        else
        {
            ((NetworkDataIp *) node->networkData.networkVar)
                    ->stats.ipInForwardDatagrams++;
#ifdef ADDON_DB
            HandleNetworkDBEvents(
                node,
                msg,
                incomingInterface,
                "NetworkForwardPacket",
                "",
                0,
                0,
                0,
                0);
#endif

             RoutePacketAndSendToMac(node,
                                     msg,
                                     incomingInterface,
                                     ANY_INTERFACE,
                                     previousHopAddress);
        }
    }
}//ForwardPacket//


// STATS DB CODE
#ifdef ADDON_DB
#ifdef ADDON_NGCNMS
void HandleNetworkDBEventsForOtherTables(
    Node* node,
    Message* msg,
    int interfaceIndex,
    BOOL fragment,
    std::string eventType,
    std::string failure,
    NodeAddress srcAddr,
    NodeAddress dstAddr,
    TosType priority,
    unsigned char protocol)
{
    StatsDb* db = node->partitionData->statsDb;

    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    NetworkIpStatsType *stats = &ip->stats;
    std::string protocolType;
    std::string macProtocol;
    int fragId = 0;
    int fragmentUnit = 0;
    MacData* macData = NULL;
    int hopCount = 0;
    char buf[MAX_STRING_LENGTH];
    unsigned short offset = 0;
    double test = 0;


    if (interfaceIndex >= 0)
    {
        macData = (MacData*)node->macData[interfaceIndex];
        fragmentUnit = GetNetworkIPFragUnit(node, interfaceIndex);
    }


    StatsDBNetworkEventParam ipParam;

    if (eventType.compare("NetworkSendToUpper") == 0 ||
        eventType.compare("NetworkReceiveFromUpper") == 0)
    {
        //ipParam.m_SenderAddr = srcAddr;
        //ipParam.m_ReceiverAddr = dstAddr;
        //ipParam.SetPriority(priority);
        //ipParam.SetHdrSize(0);
        if (protocol == IPPROTO_UDP ||
            protocol == IPPROTO_TCP)
        {
            ipParam.SetPktType("Data");
        }
        else
        {
            ipParam.SetPktType("Control");
        }
        NetworkIpConvertIpProtocolNumToString(protocol, &protocolType);
    }
    else
    {
        //ipParam.m_SenderAddr = ipHeader->ip_src;
        //ipParam.m_ReceiverAddr = ipHeader->ip_dst;
        //ipParam.SetPriority(IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len));
        //ipParam.SetHdrSize(IpHeaderSize(ipHeader));
        if (ipHeader->ip_p == IPPROTO_UDP ||
            ipHeader->ip_p == IPPROTO_TCP)
        {
            ipParam.SetPktType("Data");
        }
        else
        {
            ipParam.SetPktType("Control");
        }
        NetworkIpConvertIpProtocolNumToString(ipHeader->ip_p, &protocolType);
    }

    // Hop Count.
    int srcNodeId = MAPPING_GetNodeIdFromInterfaceAddress(node,
        ipParam.m_SenderAddr);
    //int destNodeId = MAPPING_GetNodeIdFromInterfaceAddress(node,
    //    ipParam.m_ReceiverAddr);

    // Check for Multicast Address.
    // This case is for IP Fragmentation cases. If we do not have
    // this then we will have one extra hop count for the IP fragmentation case.
    if (MESSAGE_ReturnPacketSize(msg) > fragmentUnit)
    {
        hopCount = 0;
    }
    else if (srcNodeId == node->nodeId)
    {
        hopCount = 0;
    }
    else if (eventType.compare("NetworkReceiveFromLower") == 0 ||
        eventType.compare("NetworkMalsrForwardPacket") == 0)
    {
        hopCount = 1;
    }
#if 0
    strcpy(ipParam.m_EventType, eventType.c_str());

    // interface Index will always be -1 in case of no IpHeader
    if (fragment && interfaceIndex >= 0)
    {
        offset = IpHeaderGetIpFragOffset(ipHeader->ipFragment);
        offset = (unsigned short) (offset << 3);
        fragId = (int) ceil((double)offset / fragmentUnit);
    }
    ipParam.SetFragNum(fragId);
    if (interfaceIndex >= 0 && macData != NULL)
    {
        NetworkIpConvertMacProtocolTypeToString(macData->macProtocol,
            &macProtocol);
        ipParam.SetMacProtocol((char*) macProtocol.c_str());
    }
    else
    {
        ipParam.SetMacProtocol("");
    }
#endif
    ipParam.SetProtocolType((char*) protocolType.c_str());
#if 0
    if (failure.size() > 0)
    {
        ipParam.SetFailure((char*)failure.c_str());
    }

    // fix 7/26/08
    ipParam.SetInterfaceIndex(interfaceIndex);
#endif

    ipParam.SetHopCount(hopCount);
    HandleStatsDBNetworkEventsInsertionForOtherTables(node,
        msg, MESSAGE_ReturnPacketSize(msg), &ipParam);
}
#endif
static
void HandleNetworkDBEvents(
    Node* node,
    Message* msg,
    int interfaceIndex,
    IpHeaderType *ipHeader,
    const std::string & eventType,
    const std::string & failure,
    NodeAddress srcAddr,
    NodeAddress dstAddr,
    TosType priority,
    unsigned char protocol,
    int ipHdrSize)

{
    StatsDb* db = node->partitionData->statsDb;

    if (db == NULL)
    {
        return ;
    }
#ifdef ADDON_NGCNMS
    if (!db->statsEventsTable->createNetworkEventsTable)
    {
        return HandleNetworkDBEventsForOtherTables(
            node,
            msg,
            interfaceIndex,
            fragment,
            eventType,
            failure,
            srcAddr,
            dstAddr,
            priority,
            protocol) ;
    }

#endif

    HandleStatsDBNetworkEventsInsertion(
        node,
        msg,
        interfaceIndex,
        ipHeader,
        eventType,
        failure,
        srcAddr,
        dstAddr,
        priority,
        protocol,
        ipHdrSize);
    
}

void HandleNetworkDBEventsForPimSm(
    Node* node,
    Message* msg,
    int interfaceIndex,
    //BOOL fragment,
    const std::string & eventType,
    const std::string & failure,
    NodeAddress srcAddr,
    NodeAddress dstAddr,
    TosType priority,
    unsigned char protocol,
    int ipHdrSize)
{
    StatsDb* db = node->partitionData->statsDb;

    if (db == NULL)
    {
        return ;
    }
    RoutingPimSmRegisterPacket* registerPkt =
        (RoutingPimSmRegisterPacket*) MESSAGE_ReturnPacket(msg);

    IpHeaderType* ipHeader = (IpHeaderType*)((char*)registerPkt
                             + sizeof(RoutingPimSmRegisterPacket));

    HandleNetworkDBEvents(
            node,
            msg,
            interfaceIndex,
            ipHeader,
            eventType,
            failure,
            srcAddr,
            dstAddr,
            priority,
            protocol,
            ipHdrSize) ;


}
void HandleNetworkDBEvents(
    Node* node,
    Message* msg,
    int interfaceIndex,
    //BOOL fragment,
    const std::string & eventType,
    const std::string & failure,
    NodeAddress srcAddr,
    NodeAddress dstAddr,
    TosType priority,
    unsigned char protocol,
    int ipHdrSize)
{
    StatsDb* db = node->partitionData->statsDb;

    if (db == NULL)
    {
        return;
    }

#ifdef ADDON_NGCNMS
    if (!db->statsEventsTable->createNetworkEventsTable)
    {
        return HandleNetworkDBEventsForOtherTables(
            node,
            msg,
            interfaceIndex,
            fragment,
            eventType,
            failure,
            srcAddr,
            dstAddr,
            priority,
            protocol) ;
    }

#endif

    if (eventType.compare("NetworkSendToUpper") == 0 ||
        eventType.compare("NetworkReceiveFromUpper") == 0)
    {
        HandleNetworkDBEvents(
            node,
            msg,
            interfaceIndex,
            NULL, // do not pass ipHeader
            eventType,
            failure,
            srcAddr,
            dstAddr,
            priority,
            protocol,
            ipHdrSize) ;
    }else {
        HandleNetworkDBEvents(
            node,
            msg,
            interfaceIndex,
            (IpHeaderType *) msg->packet,
            eventType,
            failure,
            srcAddr,
            dstAddr,
            priority,
            protocol,
            ipHdrSize) ;
    }
}

#endif
//-----------------------------------------------------------------------------
// FUNCTION     RoutePacketAndSendToMac()
// PURPOSE      "Route" a packet by determining the next hop IP address
//              and the outgoing interface.  It is assumed that the IP
//              packet already has an IP header at this point.  Figure
//              out the next hop in the route and send the packet.
//              First the "routing function" is checked and if that fails
//              the default source route or lookup table route is used.
//              [needs updating]
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int incomingInterface
//                  Index of interface on which packet arrived.
//                  [This is different if the packet originated from
//                  the network or transport layers.  This value is only
//                  for multicast packets, currently.]
//              int outgoingInterface
//                  Used only when the application specifies a specific
//                  interface to use to transmit packet.
//-----------------------------------------------------------------------------

void //inline//
RoutePacketAndSendToMac(Node *node,
                        Message *msg,
                        int incomingInterface,
                        int outgoingInterface,
                        NodeAddress previousHopAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable* rt = &(ip->forwardTable);
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    int outgoingInterfaceToUse;
    int interfaceIndex;
    NodeAddress outgoingBroadcastAddress;

    BOOL wasProcessed = FALSE;
    
    assert(incomingInterface != ANY_INTERFACE);
    
    //Call fixed comms for source node only
    if (NetworkIpIsMyIP(node, ipHeader->ip_src))
    {
        if (NetworkIpCheckApplicationDataPacket(node, msg))
        {
            FixedComms_DelayDrop(node, msg, &wasProcessed);
        }

        if (wasProcessed)
        {
            MESSAGE_Free(node, msg);
            return;
        }
    }

#ifdef EXATA
    if (ipHeader->ip_dst != ANY_DEST)
    {
        std::map<int, int>::iterator it, it_end;
        it = node->partitionData->virtualLanGateways->begin();
        it_end = node->partitionData->virtualLanGateways->end();
        for (; it != it_end; ++it)
        {
            if ((ipHeader->ip_dst != (unsigned)it->first) &&
               ((ipHeader->ip_dst & (unsigned)it->second) ==
                (unsigned)(it->first & it->second)))
            {
                unsigned int tos = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);

                AddIpHeader(
                        node,
                        msg,
                        ipHeader->ip_src,
                        it->first,
                        tos,
                        IPPROTO_EXATA_VIRTUAL_LAN,
                        ipHeader->ip_ttl);

                ipHeader = (IpHeaderType *) msg->packet;
                break;
            }
        }
    }


#ifdef GATEWAY_INTERFACE
    /* If the following conditions are true:
        a. The destination address does not belong to any QualNet node
        b. Internet gateway is enabled
        c. There is no entry in teh routing table for the destination host
        Then: send this packet, via IP-in-IP to the gateway router */

    if ((incomingInterface == CPU_INTERFACE) &&
        (node->internetGateway != INVALID_ADDRESS) &&
        (ipHeader->ip_dst != ANY_DEST) &&
        (!NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))&&
        (MAPPING_GetNodeIdFromInterfaceAddress(node, ipHeader->ip_dst)
        == INVALID_MAPPING))
        {
        int tmpInterface;
        NodeAddress tmpAddress;

        NetworkGetInterfaceAndNextHopFromForwardingTable(
            node,
            ipHeader->ip_dst,
            &tmpInterface,
            &tmpAddress);

        if (tmpInterface == NETWORK_UNREACHABLE)
            {
            unsigned int tos = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
            AddIpHeader(
                    node,
                    msg,
                    ipHeader->ip_src,
                    node->internetGateway,
                    tos,
                    IPPROTO_INTERNET_GATEWAY,
                    ipHeader->ip_ttl);
            ipHeader = (IpHeaderType *) msg->packet;
            }
        }
#endif
#endif


    //Variable added for IP-MPLS integration for fragmentation check
    BOOL okToSendThruMpls = TRUE;
    BOOL fragmentedByMpls = FALSE;

    // trace for sending packet
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node,
                    msg,
                    TRACE_NETWORK_LAYER,
                    PACKET_OUT,
                    &acnData,
                    NETWORK_IPV4);

#ifdef EXATA
    //We check if static route is enabled for the node. If it is then it takes
    //precedence and we do not eject the packet out on the EXata interface.
    //However in the case when it is enabled and the node does not belong to
    //the scenario then it means that we need to eject it out on the EXata
    //interface
    BOOL isStaticRoute=false;
    for (int i=0;i<rt->size;i++)
    {
        if (rt->row[i].protocolType == ROUTING_PROTOCOL_STATIC)
    {
            isStaticRoute=true;
            break;
        }
    }



#ifndef AUTO_IPNE_INTERFACE
#ifdef IPNE_INTERFACE
    // If this is an external node then send the packet to the
    // operational network if we are doing true emulation

    if ((incomingInterface != CPU_INTERFACE) &&
        (node->macData[incomingInterface]) &&
        (node->macData[incomingInterface]->isIpneInterface))
    {
        if (IPNE_ForwardFromNetworkLayer(node, incomingInterface, msg))
        {
            return;
        }
    }
#endif
#else
    if ((incomingInterface != CPU_INTERFACE) &&
        (node->macData[incomingInterface]) &&
        (node->macData[incomingInterface]->isIpneInterface))
            {
#ifdef HITL_INTERFACE
        if ((node->isHitlNode == TRUE) 
            && (ipHeader->ip_p !=  IPPROTO_OSPF)
            && (ipHeader->ip_p !=  IPPROTO_PIM)  
            && (ipHeader->ip_p !=  IPPROTO_IGMP) )
        {
            HITL_ForwardToHITL(node, interfaceIndex, msg);
            return;

        }
        else
#endif
        if (!(isStaticRoute))
        {
            if ((NetworkIpGetUnicastRoutingProtocolType(node,incomingInterface)
                == ROUTING_PROTOCOL_NONE)&&(ip->interfaceInfo
                [incomingInterface]->multicastProtocolType
                == ROUTING_PROTOCOL_NONE))
            {
                    if (AutoIPNE_ForwardFromNetworkLayer(node, 
                                                         incomingInterface,
                                                         msg, 
                                                         previousHopAddress, 
                                                         FALSE))
                    {
                        return;
                    }
            }
        }
#ifdef CYBER_LIB
            //routing protocol is running inside
            if (node->macData[incomingInterface]->promiscuousMode)
            {   
                //Broadcast packets never reach here
                if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
                {
                    if (!IsMyPacket(node, ipHeader->ip_dst) &&
                        !IsIgmpPacket(node, ipHeader->ip_p))
                    {
                        Message* dupMsg = MESSAGE_Duplicate(node, msg);
                        AutoIPNE_ForwardFromNetworkLayer(node, 
                                                         incomingInterface, 
                                                         dupMsg, 
                                                         previousHopAddress,
                                                         TRUE);
                    }

                }
                else //unicast
                {
                    Message* dupMsg = MESSAGE_Duplicate(node, msg);
                    AutoIPNE_ForwardFromNetworkLayer(node, 
                                                     incomingInterface, 
                                                     dupMsg, 
                                                     previousHopAddress,
                                                     TRUE);
                }
            }
#endif
    }
    //this code wil be called only if this node is not an ipne interface
    //i.e. replay mode is run without mapping this node as an external 
    //node
    else
    {
        if ((incomingInterface != CPU_INTERFACE) &&
            (node->macData[incomingInterface]) &&
            (node->macData[incomingInterface]->isReplayInterface))
        {
                if (!(isStaticRoute))
                {
                    if ((NetworkIpGetUnicastRoutingProtocolType(node,incomingInterface)
                        == ROUTING_PROTOCOL_NONE)&&(ip->interfaceInfo
                        [incomingInterface]->multicastProtocolType
                        == ROUTING_PROTOCOL_NONE))
                    {
                        if (node->partitionData->rrInterface->
                            ReplayForwardFromNetworkLayer(node, 
                                                          incomingInterface, 
                                                          msg, 
                                                          FALSE))
                        {
                            return;
                        }
                    }
                }
#ifdef CYBER_LIB
                //routing protocol is running inside
                if (node->macData[incomingInterface]->promiscuousMode)
                {   
                    //Broadcast packets never reach here
                    if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
                    {
                        if (!IsMyPacket(node, ipHeader->ip_dst) &&
                            !IsIgmpPacket(node, ipHeader->ip_p))
                        {
                            Message* dupMsg = MESSAGE_Duplicate(node, msg);
                            node->partitionData->rrInterface->
                              ReplayForwardFromNetworkLayer(node, 
                                                              incomingInterface, 
                                                              dupMsg, 
                                                              TRUE);
                        }

                    }
                    else //unicast
                    {
                        Message* dupMsg = MESSAGE_Duplicate(node, msg);
                        node->partitionData->rrInterface->
                          ReplayForwardFromNetworkLayer(node, 
                                                          incomingInterface, 
                                                          dupMsg, 
                                                          TRUE);
                    }
                }
#endif
        }
    }
        
#endif // AUTO_IPNE_INTERFACE
#endif // EXATA

#ifdef CELLULAR_LIB
    if (node->networkData.networkProtocol == CELLULAR)
    {
         // if gateway node, forward packet to cellular network
         if (CellularLayer3IsPacketGateway(node) &&
             CellularLayer3IsPacketForMyPlmn(node,
                                             msg,
                                             incomingInterface,
                                             NETWORK_IPV4))
    {
             // This is a packet from outside to cellular node
             CellularLayer3HandlePacketFromUpperOrOutside(
                          node,
                          msg,
                          incomingInterface,
                 NETWORK_IPV4);
             return;
    }

         // if cellular user device, let cellular layer3 handle it
    }
#elif UMTS_LIB
    if (node->networkData.networkProtocol == CELLULAR)
    {
         // if gateway node, forward packet to cellular network
         if (CellularLayer3IsPacketGateway(node) &&
             CellularLayer3IsPacketForMyPlmn(node,
                                             msg,
                                             incomingInterface,
                                             NETWORK_IPV4))
    {
             // This is a packet from outside to cellular node
             CellularLayer3HandlePacketFromUpperOrOutside(
                 node,
                                      msg,
                                      incomingInterface,
                 NETWORK_IPV4);
             return;
         }

         // if cellular user device, let cellular layer3 handle it
    }
#endif // CELLULAR_LIB

    // Used to determine what routing protocol to use on a interface.
    if (incomingInterface == CPU_INTERFACE)
    {
#ifdef CYBER_CORE
        if (!IsIPsecProcessed(node, msg)
            && ip->interfaceInfo[outgoingInterface]->isISAKMPEnabled
            && ipHeader->ip_src != ANY_DEST
            && ipHeader->ip_dst != ANY_DEST
            && (ipHeader->ip_dst != NetworkIpGetInterfaceBroadcastAddress(node,
            outgoingInterface))
            && !NetworkIpIsMulticastAddress(node, ipHeader->ip_dst)
            && !NetworkIpIsLoopbackInterfaceAddress(ipHeader->ip_dst)
            && ipHeader->ip_p != IPPROTO_ISAKMP)
        {
            BOOL status = TRUE;
            if (IPsecIsMyIP(node, ipHeader->ip_src))
            {
                status = IsISAKMPSAPresent(node,
                                            ipHeader->ip_src,
                                            ipHeader->ip_dst);
                if (status == FALSE)
                {
                    //start ISAKMP Phase-1 exchange here
                   ISAKMPSetUp_Negotiation(node, NULL, NULL,ipHeader->ip_src,
                         ipHeader->ip_dst, INITIATOR, PHASE_1);
                }
            }
            if (status == TRUE)
            {
                ISAKMPNodeConf* nodeconfig = NULL;

                status = IsIPSecSAPresent(node, ipHeader->ip_src,
                    ipHeader->ip_dst, outgoingInterface, nodeconfig);

                if (status == FALSE && nodeconfig != NULL)
                {
                    //start ISAKMP Phase-2 exchange here
                    ISAKMPSetUp_Negotiation(node, nodeconfig, NULL,
                       ipHeader->ip_src, ipHeader->ip_dst, INITIATOR, PHASE_2);
                }
            }
        }
#endif // CYBER_CORE

        // If sent by this node, then routing protocol should be associated
        // with the outgoing interface.
        interfaceIndex = outgoingInterface;
    }
    else
    {
        // If packet is being forwarded, then routing protocol should be
        // associated with the incoming interface.
        interfaceIndex = incomingInterface;
    }

#ifdef ADDON_BOEINGFCS
    HandleNetworkIpStats(node, ip, msg, interfaceIndex, FALSE);
#endif


#ifdef ENTERPRISE_LIB

  if (!(IpHeaderHasSourceRoute(ipHeader) ||
      IpHeaderHasRecordRoute(ipHeader) ||
      IpHeaderHasTimestamp(ipHeader) ||
      (ipHeader->ip_dst == ANY_DEST) ||
      (IsOutgoingBroadcast(node,
                           ipHeader->ip_dst,
                           &outgoingInterfaceToUse,
                           &outgoingBroadcastAddress)) ||
      (NetworkIpIsMulticastAddress(node,
                                   ipHeader->ip_dst)))
      ) // if Source route / record route or timestamp is not true
       // or is not a broadcast/multicast/ANY_DEST packet
  {
    // In IP+MPLS, before routing the packet through mpls,
    // it will be checked if the node is configured as Edge Router
    // or it is itself the source of IP packet.
    BOOL sourceOfPacket = FALSE;
    MplsData *mpls = MplsReturnStateSpace(node);
    if (mpls)
    {
        int i;
        for (i = 0; i < node->numberInterfaces; i++)
        {
            if (ipHeader->ip_src == NetworkIpGetInterfaceAddress(node, i))
            {
                sourceOfPacket = TRUE;
                break;
            }
        }

        if ((mpls->isEdgeRouter) || (sourceOfPacket))
        {
            //Commenting out below code as check using GetNetworkIPFragUnit()
            //can't be put here as in this case outgoingInterface is not
            //available at this time.
            // Is fragmentation required? Check here.
        //if ((MESSAGE_ReturnPacketSize(msg) + (int)
        //     sizeof(Mpls_Shim_LabelStackEntry)) >
        //     GetNetworkIPFragUnit(node, outgoingInterface))
        //    {
        //        if (!(IpHeaderGetIpDontFrag(ipHeader->ipFragment)))
        //        {
        //            //actual fragmentation is delayed till the route finding
        //            // for MPLS
        //        }// end of if dont fragment bit
        //        else
        //        {
        //            // This means that packet will not be fwd via MPLS
        //            okToSendThruMpls = FALSE;
        //        }
        //    } // End fragmentation code.
        //    else
        //    {
        //        // This means that packet can be fwd via MPLS
        //        okToSendThruMpls = TRUE;
        //    }
                okToSendThruMpls = TRUE;
            }
        }
  } // if Source route is true


#endif // ENTERPRISE_LIB

//-------------------------------------------------------------------------//
// Non fragmented packet same as before.
//-------------------------------------------------------------------------//
#ifdef ENTERPRISE_LIB
    if (ip->mobileIpStruct)
    {
        MobileIpEncapsulateDatagram(node, msg);
    }

    // For PBR analysis
    // No particular check is available to ascertain whether its a data
    //  or a control packet(we can do a precedence check, but thats not
    // a foolproof test). So all the packets are policy routed.

    // 15 June, 2004, Added check to avoid (OLSR) control packet matching
    if (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) !=
        IPTOS_PREC_INTERNETCONTROL &&
        !NetworkIpIsLoopbackInterfaceAddress(ipHeader->ip_src) &&
        !NetworkIpIsLoopbackInterfaceAddress(ipHeader->ip_dst))
    {
        if (incomingInterface != CPU_INTERFACE)
        {
            if (!(RtParseIsPktFrmMe(node, ipHeader->ip_src)) &&
                (ip->interfaceInfo[incomingInterface]->rMapForPbr))
            {
                // If the packet is not from me and PBR is enabled
                if (PbrInvoke(
                        node,
                        msg,
                        previousHopAddress,
                        incomingInterface,
                        ip->interfaceInfo[incomingInterface]->rMapForPbr,
                        FALSE,
                        FALSE))
                {
                    return;
                }
             }
        }
        else if ((RtParseIsPktFrmMe(node, ipHeader->ip_src)) &&
                 (ip->local) &&
                 (ip->rMapForPbr))
        {
            // If the packet is from me and local PBR is enabled
            if (PbrInvoke(node, msg, 0, PBR_NO_INTERFACE, ip->rMapForPbr,
                          FALSE, TRUE))
            {
                return;
            }
        }
    }
#endif // ENTERPRISE_LIB

    if (ip->isLoopbackEnabled && (incomingInterface == CPU_INTERFACE) &&
        NetworkIpLoopbackLoopbackUnicastsToSender(node, msg))
    {
        // do nothing. Ip datagram is already Looped back.
    }

    // If broadcast is of type ANY_DEST, then outgoing interface
    // should have already been determined before this.
    else if (ipHeader->ip_dst == ANY_DEST)
    {
        // Datagrams sent to a broadcast address are copied to
        // the loopback interface
        //if (ip->isLoopbackEnabled && (incomingInterface == CPU_INTERFACE))
        //{
        //    NetworkIpLoopbackBroadcastAndMulticastToSender(node, msg);
        //}

#ifdef CYBER_CORE
//BROADCAST_IAHEP_START
        if (!(ip->iahepEnabled) &&
            NetworkIpNeedsToForwardAppBroadcast(node, msg,ipHeader->ip_dst))
        {
            BOOL pktDropped = TRUE;
            for (int i = 0; i < node->numberInterfaces; i++)
            {
                if (NetworkIpGetUnicastRoutingProtocolType(
                          node, i, NETWORK_IPV4) != ROUTING_PROTOCOL_NONE)
                {
                    pktDropped = FALSE;
                    NetworkIpSendPacketOnInterface(
                          node,
                          MESSAGE_Duplicate(node, msg),
                          incomingInterface,
                          i,
                          ipHeader->ip_dst);
                }
            }
            if (pktDropped == TRUE)
            {
#ifdef ADDON_DB

                HandleNetworkDBEvents(
                    node,
                    msg,
                    incomingInterface,
                    "NetworkPacketDrop",
                    "No Routing Protocol Available",
                    0,
                    0,
                    0,
                    0);
#endif
            }
            MESSAGE_Free(node, msg);
        }
        else
        {
//BROADCAST_IAHEP_END
            if (IsOutgoingBroadcast(node,
                ipHeader->ip_dst,
                &outgoingInterfaceToUse,
                &outgoingBroadcastAddress) &&
                msg->originatingProtocol == TRACE_CBR)
            {
                for (int i = 0; i < node->numberInterfaces; i++)
                {
                    NetworkIpSendPacketOnInterface(
                                      node,
                                      MESSAGE_Duplicate(node, msg),
                                      incomingInterface,
                                      i,
                                      ipHeader->ip_dst);
                }
                MESSAGE_Free(node, msg);
            }
            else
            {
        NetworkIpSendPacketOnInterface(
                          node,
                          msg,
                          incomingInterface,
                          outgoingInterface,
                          ipHeader->ip_dst);
    }
        }
#else //CYBER_CORE
        NetworkIpSendPacketOnInterface(
                          node,
                          msg,
                          incomingInterface,
                          outgoingInterface,
                          ipHeader->ip_dst);
#endif //CYBER_CORE
    }
    // Check if it's a broadcast.
    else if (IsOutgoingBroadcast(node,
             ipHeader->ip_dst,
             &outgoingInterfaceToUse,
             &outgoingBroadcastAddress))
    {
        // Datagrams sent to a broadcast address are copied to
        // the loopback interface
        //if (ip->isLoopbackEnabled && (incomingInterface == CPU_INTERFACE))
        //{
        //    NetworkIpLoopbackBroadcastAndMulticastToSender(node, msg);
        //}

        NetworkIpSendPacketOnInterface(node,
                                      msg,
                                      incomingInterface,
                                      outgoingInterfaceToUse,
                                      outgoingBroadcastAddress);

    }
    // Use the multicast forwarding table if we need to
    // send a multicast packet.
    else if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
    {
        BOOL packetWasRouted = FALSE;

        if (ip->isLoopbackEnabled && (incomingInterface == CPU_INTERFACE))
        {
            NetworkIpLoopbackBroadcastAndMulticastToSender(node, msg);
        }

        // Datagrams sent to a broadcast address are copied to
        // the loopback interface

            BOOL originateByMe  = FALSE;
            BOOL isloopbackMulticastPacket = FALSE;

        MulticastRouterFunctionType routerFunction =
                NetworkIpGetMulticastRouterFunction(node, interfaceIndex);

        LinkedList* interfaceList = NULL;

        interfaceList =
            NetworkGetOutgoingInterfaceFromMulticastForwardingTable(
                node,
                ipHeader->ip_src,
                ipHeader->ip_dst);
        /* check if this is a new pkt & the node is the originator of this Pkt */

            int forward = 0;
            int intf = 0;
            for (intf = 0;intf < node->numberInterfaces; intf++)
            {
                if (ipHeader->ip_src ==
                    NetworkIpGetInterfaceAddress(node, intf) &&
                    ipHeader->ip_ttl == 64)
                {
                    originateByMe = TRUE;
#ifdef DEBUG
                    {
                        printf(" I am the source of the packet \n");
                        printf("This is a new Packet \n");
                    }
#endif
                    break;
                }
            }
            if ((originateByMe) &&
               (routerFunction == NULL) &&
               (interfaceList == NULL))
            {
                NodeAddress nextHop = ANY_IP;
#ifdef DEBUG
                {
                    char clockStr[100];

                    ctoa(getSimTime(node), clockStr);
                    printf("Src_Node %u sending m_pkt to DR %x at time %s\n",
                    node->nodeId, nextHop, clockStr);
                }
#endif
                NetworkIpSendPacketToMacLayer(node,
                                          MESSAGE_Duplicate(node, msg),
                                          NetworkIpGetInterfaceIndexFromAddress(
                                          node, ipHeader->ip_src),
                                          nextHop);
                packetWasRouted = TRUE;
#ifdef ADDON_DB
                if (previousHopAddress == ANY_IP
                    && NetworkIpIsMyIP(node, ipHeader->ip_src)
                    && ip->ipMulticastNetSummaryStats)
                {
                    ip->ipMulticastNetSummaryStats->m_NumDataSent++;
                }
#endif
                MESSAGE_Free(node, msg);
            }
#ifndef ADDON_BOEINGFCS
            if (routerFunction != NULL && (!packetWasRouted))
            {
                (routerFunction)(node,
                             msg,
                             ipHeader->ip_dst,
                             interfaceIndex,
                             &packetWasRouted,
                             previousHopAddress);
            }
#else
        BoeingfcsNetworkHandleMulticastPacket(node,
                                              msg,
                                              ipHeader->ip_dst,
                                              interfaceIndex,
                                              incomingInterface,
                                              &packetWasRouted,
                                              previousHopAddress);

#endif

        if (!packetWasRouted)
        {
#ifdef EXATA
            /*
            For interoperability with real-world routing protocols such as
            OSPF, PIM-SM, multicast control packets need to be treated differently.
            For virtual nodes running real routing protocol we must simply send
            (just like a broadcast packet) the multicast packet without
            consulting a forwarding table. This is because the virtual node when
            running a real routing protocol does not maintain a forwarding table
            within the simulator*/

            /* checking if this packet is from outside (physical machine) */

            if (((node->macData[interfaceIndex]->isIpneInterface)||
                ((node->partitionData->rrInterface->GetReplayMode()) &&
                (node->macData[interfaceIndex]->isReplayInterface))) &&
                (msg->isEmulationPacket) )
            {
                NodeAddress nextHop;
                if (NetworkIpGetUnicastRoutingProtocolType
                    (node,interfaceIndex) == ROUTING_PROTOCOL_NONE)
                {
                    nextHop=ANY_DEST;
                    NetworkIpSendPacketOnInterface(
                        node,
                        msg,
                        incomingInterface,
                        outgoingInterface,
                        nextHop);
                }

            }
            else
            {
#ifdef MILITARY_RADIOS_LIB
            if (EplrsActiveOnInterface(node,
                  interfaceIndex))
    {
                EplrsIncRoutePacket(node,
                    interfaceIndex,
                    msg,
                    previousHopAddress,
                    &packetWasRouted);
             }
             else {
#endif
#endif//EXATA
#ifdef ADDON_DB
                if (previousHopAddress != ANY_IP
                    && NetworkIpIsMyIP(node, ipHeader->ip_src))
                {
                    isloopbackMulticastPacket = TRUE;
                }

                if (ip->ipMulticastNetSummaryStats)
                {
                    if (!originateByMe)
                    {
                        ip->ipMulticastNetSummaryStats->m_NumDataRecvd++;
                    }
                    else
                    {
                        if (isloopbackMulticastPacket &&
                            NetworkIpIsPartOfMulticastGroup(node, ipHeader->ip_dst))
                        {
                            ip->ipMulticastNetSummaryStats->m_NumDataRecvd++;
                        }
                    }
                }
#endif

                RouteThePacketUsingMulticastForwardingTable(
                    node,
                    msg,
                    incomingInterface,
                    NETWORK_IPV4);
#ifdef EXATA
            }
#ifdef MILITARY_RADIOS_LIB
             }
#endif
#endif
        }
    }
    else
    {
        // First check if MPLS is enabled, and if so, transfer the packet
        // to MPLS.  Next, try to route with the routing protocol supplied
        // routing function.  If the function doesn't exists or
        // fails to find a route, then try standard lookup table
        // or source routing.

        BOOL packetWasRouted = FALSE;

        /*
         * Check whether the packet comes from Qos application. If so
         * then pass the packet to the Q-OSPF where the path will be
         * calculated (or if the path is calculated previously by other
         * node) and forwarded by Q-OSPF.
         */
#ifdef ENTERPRISE_LIB
        if (NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex)
            == ROUTING_PROTOCOL_OSPFv2 &&
            QospfIsPacketDemandedQos(node, msg))
        {

            IpOptionsHeaderType *ipOptions =
                IpHeaderSourceRouteOptionField((IpHeaderType *) msg->packet);

            if (ipOptions == NULL)
            {
                /*
                 * I.e. address list not yet assigned in IP header's option
                 * field. So call the path calculation algorithm, which will
                 * search the path and if the path can be assigned, it will
                 * be included into the IP header option field and packet
                 * will be forwarded.
                 */

                QospfForwardQosApplicationPacket(node, msg,
                    &packetWasRouted);
            }

        }

        // In IP+MPLS, before routing the packet through mpls,
        // it will be checked if the node is configured as Edge Router
        // or it is itself the source of IP packet.
        MplsData *mpls = MplsReturnStateSpace(node);
        if ((mpls) && (okToSendThruMpls))
        {   if (!IpHeaderHasSourceRoute(ipHeader))
            // if Source route is not true
            {
                int i;
                BOOL sourceOfPacket = FALSE;
                for (i = 0; i < node->numberInterfaces; i++)
                {
                    if (ipHeader->ip_src == NetworkIpGetInterfaceAddress
                                            (node, i))
                    {
                        sourceOfPacket = TRUE;
                        break ;
                    }
                }

                if ((mpls->isEdgeRouter) || (sourceOfPacket))
                {
                    // Changed for adding priority support for FEC
                    // classification
                    MplsRoutePacket(node,
                                    mpls,
                                    msg,
                                    ipHeader->ip_dst,
                                    &packetWasRouted,
                                   IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
                                   incomingInterface,
                                   outgoingInterface);
                }
            }
        }
#endif // ENTERPRISE_LIB

        if (!packetWasRouted)
        {

            /*Unicast router function call is useful for reactive routing protocols, not
            for proactive routing protocols. For proactive routing protocols, the
            forwarding is done using network-ip forwarding tables updated by these routing
            protocols.

            The node having multiple interfaces initializes the router function if
            required.*/

            RouterFunctionType routerFunction = NULL;

            routerFunction = NetworkIpGetRouterFunction(node,
                                                        interfaceIndex);

            if (routerFunction)
            {
                (routerFunction)(node,
                                 msg,
                                 ipHeader->ip_dst,
                                 previousHopAddress,
                                 &packetWasRouted);
                }
#ifdef ADDON_BOEINGFCS

        if (ip->rospfData!= NULL && !packetWasRouted)
        {
            RoutingCesRospfRoutePacket(node,
                             msg,
                             previousHopAddress,
                             interfaceIndex,
                             &packetWasRouted);
        }
#endif // ADDON_BOEINGFCS


            if (!packetWasRouted)
            {
#ifdef MILITARY_RADIOS_LIB
                int i=0;
                BOOL foundEplrs = FALSE;
                for (i = 0; i < node->numberInterfaces; i++)
            {
                    if (foundEplrs)
                {
                        break;
                }
                    else if (EplrsActiveOnInterface(node, i)){
                        if (i != interfaceIndex)
    {
                            NetworkIpAddHeader(node,
                                msg,
                                NetworkIpGetInterfaceAddress(node, i),
                                ipHeader->ip_dst,
                                //ipHeader->ip_tos,
                                IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
                                IPPROTO_IPIP_ODR,
                                ipHeader->ip_ttl);
    }
                        EplrsIncRoutePacket(node,
                            i,
                            msg,
                            previousHopAddress,
                            &packetWasRouted);
                        foundEplrs = TRUE;
            }
        }
                if (!foundEplrs) {
#endif

                    RouteThePacketUsingLookupTable(node,
                                                   msg,
                                                   incomingInterface);

#ifdef MILITARY_RADIOS_LIB
    }
#endif
            }//if//
        }//if//
    }//if//
}//RoutePacketAndSendToMac//


//-----------------------------------------------------------------------------
// FUNCTION     RouteThePacketUsingLookupTable()
// PURPOSE      Tries to route and send the packet using the node's
//              forwarding table.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int incomingInterface
//                  incoming interface of packet.
//-----------------------------------------------------------------------------

void
RouteThePacketUsingLookupTable(Node *node, Message *msg, int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

    int outgoingInterface;
    NodeAddress nextHop;
    BOOL routeType;

    NetworkGetInterfaceAndNextHopFromForwardingTable(
        node, ipHeader->ip_dst, &outgoingInterface, &nextHop, &routeType);

#ifdef NETSNMP_INTERFACE
    if (node->SNMP_TRAP_LINKDOWN_counter == 1 && node->isSnmpEnabled)
    {
        if (msg->originatingProtocol == TRACE_SNMP)
        {

            NetworkForwardingTable *forwardTable = &(ip->forwardTable);
            int i;

            outgoingInterface = NETWORK_UNREACHABLE;
            nextHop = (unsigned) NETWORK_UNREACHABLE;

            for (i=0; i < forwardTable->size; i++) {
                NodeAddress maskedDestinationAddress =
                    MaskIpAddress(
                    ipHeader->ip_dst, forwardTable->row[i].destAddressMask);

                if (forwardTable->row[i].destAddress == maskedDestinationAddress
                    && forwardTable->row[i].nextHopAddress !=
                    (unsigned) NETWORK_UNREACHABLE)
                {
                    outgoingInterface = forwardTable->row[i].interfaceIndex;
                    nextHop = forwardTable->row[i].nextHopAddress;
                    break;
                }
            }

        }
    }
#endif
#if 0 //ifdef ADDON_BOEINGFCS
    if (ip->networkSecurityCesHaipeEnabled)
    {
        destAddr =
        NetworkSecurityCesHaipeGetExitPointAddress(node,
                                                   incomingInterface,
                                                   msg,
                                                   &nextHop,
                                                   &outgoingInterface);
    }
#endif

    if (ip->isIcmpEnable && nextHop != (unsigned)NETWORK_UNREACHABLE)
    {
        NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
        BOOL ICMPErrorMsgCreated;

        if (icmp->redirectEnable && incomingInterface == outgoingInterface &&
            NetworkIpCheckIpAddressIsInSameSubnet
                    (node,outgoingInterface,ipHeader->ip_src)
            && icmp->router == TRUE && !(IpHeaderHasSourceRoute(ipHeader)))
        {
            RedirectCacheInfo* redirectCacheInfo = icmp->redirectCacheInfo;
            bool sendRedirect = true;
            while (redirectCacheInfo != NULL)
            {
                if (redirectCacheInfo->ipSource == ipHeader->ip_src
                    && redirectCacheInfo->destination == ipHeader->ip_dst)
                {
                    sendRedirect = FALSE;
                    break;
                }
                redirectCacheInfo = redirectCacheInfo->next;
            }
            if (sendRedirect)
            {
                // Send ICMP redirect Message
                NetworkIcmpUpdateRedirectCache(node,
                                               ipHeader->ip_src,
                                               ipHeader->ip_dst);

                if (nextHop == 0)
                {
                    ICMPErrorMsgCreated =
                         NetworkIcmpCreateErrorMessage(node,
                                      msg,
                                      ipHeader->ip_src,
                                      incomingInterface,
                                      ICMP_REDIRECT,
                                      1,
                                      0,
                                      ipHeader->ip_dst);
                }
                else
                {
                    ICMPErrorMsgCreated =
                        NetworkIcmpCreateErrorMessage(node,
                              msg,
                              ipHeader->ip_src,
                              incomingInterface,
                              ICMP_REDIRECT,
                              1,
                              0,
                              nextHop);
                }

                if (ICMPErrorMsgCreated)
                {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                    printf("Node %d sending redirect message to %s\n",
                                        node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpRedirctGenerate)++;
                }
            }
        }
    }

    if (nextHop == (unsigned) NETWORK_UNREACHABLE)
    {
        // Increment stat for number of IP packets discarded because no
        // route could be found.
        //
        // Individual routing modules like AODV, LAR1, DSR, and ZRP may
        // or may not increment this value.

        // For PBR analysis
        // No particular check is available to ascertain whether its a data
        //  or a control packet(we can do a precedence check, but thats not
        // a foolproof test). So all the packets are policy routed.

#ifdef ENTERPRISE_LIB
        // 15 June, 2004, Added check to avoid (OLSR) control packet matching
        if (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len)!=
            IPTOS_PREC_INTERNETCONTROL)
        {
            BOOL pbrResult = FALSE;

            // If the packet is not from me.
            if (!RtParseIsPktFrmMe(node, ipHeader->ip_src))
            {
                if ((incomingInterface != CPU_INTERFACE) &&
                    (ip->interfaceInfo[incomingInterface]->rMapForPbr))
                {
                    RouteMap* rMap =
                        ip->interfaceInfo[incomingInterface]->rMapForPbr;

                    if (rMap->hasDefault)
                    {
                        pbrResult = PbrInvoke(node, msg, 0, incomingInterface,
                            rMap,
                            TRUE, FALSE);
                        if (pbrResult)
                        {
                            // the packet is already routed
                            return;
                        }
                    }
                }
            }
            else
            if (ip->local)
            {
                // Packet is from me and local PBR enabled
                RouteMap* rMap = ip->rMapForPbr;

                if (rMap->hasDefault)
                {
                    pbrResult = PbrInvoke(node, msg, 0, PBR_NO_INTERFACE, rMap,
                        TRUE, TRUE);
                    if (pbrResult)
                    {
                        // the packet is already routed
                        return;
                    }
                }
            }
        }
#endif // ENTERPRISE_LIB

#ifdef WIRELESS_LIB
// For dymo gateway
        if (ip->isManetGateway)
        {
            Address temp;

            SetIPv4AddressInfo(
                &temp,
                ipHeader->ip_dst);

            if (DymoIsPrefixMatch(&temp,
                                  &ip->manetPrefixAddr,
                                  ip->manetPrefixlength))
            {
                BOOL packetWasRouted = FALSE;

                Dymo4RouterFunction(
                    node,
                    msg,
                    ipHeader->ip_dst,
                    ANY_DEST,
                    &packetWasRouted);

                if (packetWasRouted) {
                    return;
                }
            }
        }// end of if
// end for dymo gateway
#endif // WIRELESS_LIB

        // added for gateway
        // Check if any default gateway is present for that node

        if (ip->gatewayConfigured)
        {
            // Route the packet thru that default gateway

            NetworkIpRoutePacketThroughGateway(node,
                msg,
                incomingInterface);

            return;
        }

        // end for gateway
        // STATS DB CODE
#ifdef ADDON_DB
        HandleNetworkDBEvents(
            node,
            msg,
            incomingInterface,
            "NetworkPacketDrop",
            "No Route",
            0,
            0,
            0,
            0);
        ip->stats.aggregateStats->ipUnicastOutNoRoutes++ ;
#endif
        ip->stats.ipOutNoRoutes++;

        // Handling of new Stat API for collecting unicast and broadcast packets 
        // dropped seperately
        if (node->networkData.networkStats)
        {
            STAT_DestAddressType type;
            type = StatsApiAddrType(node, msg);
            if (type == STAT_Unicast)
            {
                ip->newStats->AddPacketDroppedNoRouteDataPointsUnicast(node);
            }
            else if (type == STAT_Multicast)
            {
                ip->newStats->AddPacketDroppedNoRouteDataPointsMulticast(node);
            }
            ip->newStats->AddPacketDroppedNoRouteDataPoints(node);
        }
        //Trace drop
        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_NO_ROUTE;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData,
                         NETWORK_IPV4);

        if (ip->isIcmpEnable &&
          (icmp->hostUnreachableEnable || icmp->networkUnreachableEnable))
        {
            unsigned short icmpCode = 0;
            BOOL ICMPErrorMsgCreated = FALSE;
            if (NetworkIpGetInterfaceIndexForNextHop(node,ipHeader->ip_dst)
                                                     == -1 &&
                                              icmp->networkUnreachableEnable)
            {
                icmpCode = ICMP_NETWORK_UNREACHABLE;
                ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                      msg,
                                      ipHeader->ip_src,
                                      incomingInterface,
                                      ICMP_DESTINATION_UNREACHABLE,
                                      icmpCode,
                                      0,
                                      0);
            }
            else if (NetworkIpGetInterfaceIndexForNextHop(node,
                                                  ipHeader->ip_dst) != -1 &&
                                                icmp->hostUnreachableEnable)
            {
                icmpCode = ICMP_HOST_UNREACHABLE;
                ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                      msg,
                                      ipHeader->ip_src,
                                      incomingInterface,
                                      ICMP_DESTINATION_UNREACHABLE,
                                      icmpCode,
                                      0,
                                      0);
            }

            if (ICMPErrorMsgCreated)
            {
                if (icmpCode == ICMP_NETWORK_UNREACHABLE)
                {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                    printf("Node %d sending network unreachable message"
                           " to %s\n", node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpNetworkUnreacableSent)++;
                }
                else if (icmpCode == ICMP_HOST_UNREACHABLE)
                {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                    printf("Node %d sending host unreachable message"
                        " to %s\n", node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpHostUnreacableSent)++;
                }
            }
        }
        // Free message.

        MESSAGE_Free(node, msg);

        return;
    }

#ifdef MILITARY_RADIOS_LIB
    if ((outgoingInterface != CPU_INTERFACE) &&
        (ipHeader->ip_p != IPPROTO_SDR) &&
        IsSincgarsGateway(node, outgoingInterface))
    {
        BOOL sincgars_packetWasRouted = FALSE;
        SdrRouterFunction(node,
            msg,
            ipHeader->ip_dst,
            NetworkIpGetInterfaceAddress(node, outgoingInterface),
            &sincgars_packetWasRouted);
        return;
    }


#endif // MILITARY_RADIOS_LIB
    // Found route (outgoing interface and next hop address) in
    // forwarding table.  Queue packet on interface with next hop
    // address.

    // nextHop == 0 for switched ethernet routes
    if (nextHop == 0)
    {
        NetworkIpSendPacketOnInterface(
            node,
            msg,
            incomingInterface,
            outgoingInterface,
            ipHeader->ip_dst);
    }
    else
    {
        NetworkIpSendPacketOnInterface(node,
                                      msg,
                                      incomingInterface,
                                      outgoingInterface,
                                      nextHop);
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     QueueUpIpFragmentForMacLayer()
// PURPOSE      Called by NetworkIpSendPacketOnInterface().  Checks if
//              the output queue(s) for the specified interface is empty
//              or full, and calls NetworkIpOutputQueueInsert() to queue
//              the IP packet.  Drops packet if the queue was full.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int interfaceIndex
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop address.
//
// NOTES        This is one of the places where
//              MAC_NetworkLayerHasPacketToSend() may be called,
//              which starts the MAC packet-sending process.  See the
//              comments for the necessary state.
//
//              MAC_NetworkLayerHasPacketToSend() is also called
//              in mpls.pc.
//-----------------------------------------------------------------------------

static void //inline//
QueueUpIpFragmentForMacLayer(
    Node *node,
    Message *msg,
    int interfaceIndex,
    NodeAddress nextHop,
    int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;
    IpHeaderType* ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    BOOL queueIsFull;
    BOOL queueWasEmpty;
    ActionData acnData;
    NetworkType netType = NETWORK_IPV4;

#ifdef ENTERPRISE_LIB
    MplsData *mpls = (MplsData *) node->macData[interfaceIndex]->mplsVar;

    // If the Diffserv Multi-Field Traffic Conditioner is Enabled
    if (ip->isEdgeRouter == TRUE)
    {
        // Check whether or not the Diffserv Multi-Field Traffic Conditioner
        // will drop this packet
        DIFFSERV_TrafficConditionerProfilePacketAndMarkOrDrop(
            node,
            ip,
            msg,
            incomingInterface,
            //interfaceIndex,
            &queueIsFull);

        if (queueIsFull)
        {
            // DiffServ Multi-Field Traffic Conditioner dropped this packet
            // Free message and return early.

            // Increment stat for number of output IP packets discarded
            // because of a lack of buffer space.

            ip->stats.ipOutDiscards++;
            if (node->networkData.networkStats)
            {
                ip->newStats->AddPacketDroppedQueueOverflowDataPoints(node);
            }
            if (ip->isIcmpEnable && icmp->sourceQuenchEnable)
            {
                 BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                            msg,
                                            ipHeader->ip_src,
                                            incomingInterface,
                                            ICMP_SOURCE_QUENCH,
                                            ICMP_SOURCE_QUENCH_CODE,
                                            0,
                                            0);
                 if (ICMPErrorMsgCreated)
                 {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                     char srcAddr[MAX_STRING_LENGTH];
                     IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                     printf("Node %d sending source quench message to %s\n",
                                        node->nodeId, srcAddr);
#endif
                     (icmp->icmpErrorStat.icmpSrcQuenchSent)++;
                 }
            }
#ifdef ADDON_DB
            // STATS DB CODE
            HandleNetworkDBEvents(
                node,
                msg,
                incomingInterface, // incoming Interface
                "NetworkPacketDrop",
                "Ip Queue Full",
                0,
                0,
                0,
                0);
#endif
            //Trace drop
            acnData.actionType = DROP;
            acnData.actionComment = DROP_QUEUE_OVERFLOW;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_NETWORK_LAYER,
                             PACKET_OUT,
                             &acnData,
                             netType);

            MESSAGE_Free(node, msg);

// GuiStart
            if (node->guiOption == TRUE)
            {
                unsigned int priority = GetQueuePriorityFromUserTos(
                                            node,
                                            IpHeaderGetTOS(
                                            ipHeader->ip_v_hl_tos_len),
                                            (*scheduler).numQueue());
                GUI_QueueDropPacket(node->nodeId, GUI_NETWORK_LAYER,
                                    interfaceIndex, priority,
                                    getSimTime(node) + getSimStartTime(node));
            }
//GuiEnd

            return;
        }
    }

    // Check the emptiness of the interface's output queue(s) before
    // attempting to queue packet.
    if (mpls)
    {
        queueWasEmpty = MplsOutputQueueIsEmpty(node, interfaceIndex);
    }
    else
#endif // ENTERPRISE_LIB
    {
        queueWasEmpty = NetworkIpOutputQueueIsEmpty(node, interfaceIndex);
    }

    // Queue packet on output queue of interface.

    NetworkIpOutputQueueInsert(node,
                               interfaceIndex,
                               msg,
                               nextHop,
                               ipHeader->ip_dst,
                               NETWORK_PROTOCOL_IP,
                               &queueIsFull);

// GuiStart
    if (!queueIsFull && node->guiOption == TRUE)
    {
        unsigned int priority = GetQueuePriorityFromUserTos(
                                    node,
                                    IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
                                    (*scheduler).numQueue());

        GUI_QueueInsertPacket(node->nodeId, GUI_NETWORK_LAYER,
                              interfaceIndex, priority,
                              MESSAGE_ReturnPacketSize(msg),
                              getSimTime(node) + getSimStartTime(node));
    }
//GuiEnd

    if (queueIsFull)
    {
        // Increment stat for number of output IP packets discarded
        // because of a lack of buffer space.

        ip->stats.ipOutDiscards++;
        if (node->networkData.networkStats)
        {
            ip->newStats->AddPacketDroppedQueueOverflowDataPoints(node);
        }
#ifdef ADDON_DB
// STATS DB CODE
            HandleNetworkDBEvents(
                node,
                msg,
                interfaceIndex, // incoming Interface
                "NetworkPacketDrop",
                "Ip Queue Full",
                0,
                0,
                0,
                0);
#endif

        if (ip->isIcmpEnable && icmp->sourceQuenchEnable)
        {
             BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                        msg,
                                        ipHeader->ip_src,
                                        incomingInterface,
                                        ICMP_SOURCE_QUENCH,
                                        ICMP_SOURCE_QUENCH_CODE,
                                        0,
                                        0);

             if (ICMPErrorMsgCreated)
             {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                 char srcAddr[MAX_STRING_LENGTH];
                 IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                 printf("Node %d sending source quench message to %s\n",
                                    node->nodeId, srcAddr);
#endif
                 (icmp->icmpErrorStat.icmpSrcQuenchSent)++;
             }
        }

        // Free message and return early.

// GuiStart
        if (node->guiOption == TRUE)
        {
            int priority = GetQueuePriorityFromUserTos(
                                node,
                                IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
                                (*scheduler).numQueue());

            GUI_QueueDropPacket(node->nodeId, GUI_NETWORK_LAYER,
                                interfaceIndex, priority,
                                getSimTime(node) + getSimStartTime(node));
        }
//GuiEnd
        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_QUEUE_OVERFLOW;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData,
                         netType);

        MESSAGE_Free(node, msg);
        return;
    }

    // Did not have to drop packet because of lack of buffer space.
    //
    // Start the MAC packet-sending process if the interface's output
    // queue(s) was empty, and after the insert attempt, now has a
    // packet to send.

    if (queueWasEmpty)
    {
#ifdef ENTERPRISE_LIB
        if (mpls)
        {
            if (!MplsOutputQueueIsEmpty(node, interfaceIndex))
            {
                MAC_NetworkLayerHasPacketToSend(node, interfaceIndex);
            }
        }
        else
#endif // ENTERPRISE_LIB
        {
            if (!NetworkIpOutputQueueIsEmpty(node, interfaceIndex))
            {
#ifdef ADDON_BOEINGFCS
                if (!NetworkCesIncSincgarsActiveOnInterface(node, interfaceIndex))
                {
                    MAC_NetworkLayerHasPacketToSend(node, interfaceIndex);
                }
#else
                MAC_NetworkLayerHasPacketToSend(node, interfaceIndex);
#endif
            }
        }
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     ProcessDelayedSendToMac()
// PURPOSE
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//-----------------------------------------------------------------------------

static void //inline//
ProcessDelayedSendToMac(Node *node, Message *msg)
{
    DelayedSendToMacLayerInfoType *info =
        (DelayedSendToMacLayerInfoType *) MESSAGE_ReturnInfo(msg);

    NetworkIpSendPacketOnInterface(
        node,
        msg,
        info->incomingInterface,
        info->outgoingInterface,
        info->nextHop);
}

//-----------------------------------------------------------------------------
// Source route
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     IpHeaderSourceRouteOptionField()
// PURPOSE      Returns the source route contained in IP packet.
// PARAMETERS   IpHeaderType *ipHeader
//                  Pointer to IP header.
// RETURNS      Pointer to header of source route option field, if
//              source route is present.
//              NULL, if source route is not present.
//-----------------------------------------------------------------------------

IpOptionsHeaderType * //inline//
IpHeaderSourceRouteOptionField(IpHeaderType *ipHeader)
{
    return (FindAnIpOptionField(ipHeader, IPOPT_SSRR));
}

//---------------------------------------------------------------------------
// FUNCTION     IpHeaderRecordRouteOptionField()
// PURPOSE      Returns the record route contained in IP packet.
// PARAMETERS   IpHeaderType *ipHeader
//                  Pointer to IP header.
// RETURNS      Pointer to header of record route option field, if
//              record route is present.
//              NULL, if record route is not present.
//---------------------------------------------------------------------------

IpOptionsHeaderType * //inline//
IpHeaderRecordRouteOptionField(IpHeaderType *ipHeader)
{
    return (FindAnIpOptionField(ipHeader, IPOPT_RR));
}

//---------------------------------------------------------------------------
// FUNCTION     IpHeaderTimestampRouteOptionField()
// PURPOSE      Returns the Timestamp contained in IP packet.
// PARAMETERS   IpHeaderType *ipHeader
//                  Pointer to IP header.
// RETURNS      Pointer to header of Timestamp option field, if
//              Timestamp is present.
//              NULL, if Timestamp is not present.
//---------------------------------------------------------------------------

IpOptionsHeaderType * //inline//
IpHeaderTimestampOptionField(IpHeaderType *ipHeader)
{
    return (FindAnIpOptionField(ipHeader, IPOPT_TS));
}
//-----------------------------------------------------------------------------
// FUNCTION     SourceRouteThePacket()
// PURPOSE      Extract the next hop IP address from a packet with a
//              source route in the IP header, and call
//              NetworkIpSendPacketOnInterface().
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int incomingInterface
//-----------------------------------------------------------------------------

static BOOL //inline//
SourceRouteThePacket(Node *node, Message *msg, int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    IpOptionsHeaderType *ipOptions =
                                   IpHeaderSourceRouteOptionField(ipHeader);
    int outgoingInterface;
    int interfaceIndex;
    NodeAddress nextHop;
    BOOL isItSource = FALSE;

    if (ipOptions->ptr >= ipOptions->len)
    {
        //packet has reached its ultimate destination. So no need to
        //source route the packet any further.Return from here and let
        //NetworkIpReceive packet process the packet further.

        return FALSE;
    }


    for (interfaceIndex = 0; interfaceIndex < node->numberInterfaces;
         interfaceIndex++)
    {
        if (NetworkIpGetInterfaceAddress(node,interfaceIndex)
                                                         == ipHeader->ip_src)
        {
            isItSource = TRUE;
            break;
        }
    }

    if (!isItSource && !NetworkIpDecreaseTTL(node, msg, incomingInterface))
        return TRUE;

    if (isItSource)
    {
        //calculate outgoing interface to route the packet
        memcpy((char *)&nextHop, (char *)&ipHeader->ip_dst,
                                                       sizeof(NodeAddress));
        outgoingInterface = NetworkIpGetInterfaceIndexForNextHop(node,
                                                                 nextHop);
    }
    else
    {
            //calculate outgoing interface to route the packet
        memcpy((char *)&nextHop, (char *)ipOptions + ipOptions->ptr - 1,
                                                       sizeof(NodeAddress));
        outgoingInterface = NetworkIpGetInterfaceIndexForNextHop(node,
                                                                 nextHop);
    }



    if (outgoingInterface == -1)
    {
        if (ip->isIcmpEnable && icmp->sourceRouteFailedEnable)
        {
            // send ICMP packet with Source Route Failed type
            BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(
                                       node,
                                       msg,
                                       ipHeader->ip_src,
                                       incomingInterface,
                                       ICMP_DESTINATION_UNREACHABLE,
                                       ICMP_SOURCE_ROUTE_FAILED,
                                       0,
                                       0);
           if (ICMPErrorMsgCreated)
           {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                printf("Node %d sending source route failed"
                       " message to %s\n", node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpSourceRouteFailedSent)++;
            }
        }
#ifdef ADDON_DB
        HandleNetworkDBEvents(
            node,
            msg,
            incomingInterface,
            "NetworkPacketDrop",
            "No Route",
            0,
            0,
            0,
            0);
#endif
        // Free message.
        MESSAGE_Free(node, msg);
        return(TRUE);
    }

    if (!isItSource)
    {
        NodeAddress nextEntryInRoute =
                                      NetworkIpGetInterfaceAddress(node,
                                                      outgoingInterface);

        char *nextDestination = (char *)ipOptions + ipOptions->ptr - 1;

        //replace the destination address in IP Header with the
        //address in source route pointed by the pointer.

        memcpy(&ipHeader->ip_dst, nextDestination,
                                                 sizeof(NodeAddress));

        // Record Route (replace the address in the source route
        // pointed by pointer with the outgoing interface of this node)

        memcpy((char *)ipOptions + ipOptions->ptr - 1,
                         (char *)&nextEntryInRoute, sizeof(NodeAddress));

        //increment the pointer by 4

        ipOptions->ptr += sizeof(NodeAddress);

        ip->stats.ipInReceives++;
        ip->stats.ipInForwardDatagrams++;
        
        if (node->networkData.networkStats)
        {
            ip->newStats->AddPacketReceivedFromMacDataPoints(
                node,
                msg,
                StatsApiAddrType(node, msg),
                incomingInterface,
                IsDataPacket(msg, ipHeader));
        }
#ifdef ADDON_DB
            HandleNetworkDBEvents(
                node,
                msg,
                incomingInterface,
                "NetworkForwardPacket",
                "",
                0,
                0,
                0,
                0);
#endif
    }

    NetworkIpSendPacketOnInterface(node,
                                   msg,
                                   incomingInterface,
                                   outgoingInterface,
                                   nextHop);

    //packet is routed
    return(TRUE);
}

//-----------------------------------------------------------------------------
// Boolean utility routines for packet forwarding process
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     IsMyPacket()
// PURPOSE      Determines from the destination IP address whether a
//              packet should be delivered (instead of forwarded).
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destAddress
//                  An IP packet's destination IP address.
// RETURNS      TRUE if packet should be delivered to node.
//              FALSE if packet should not be delivered to node.
//
// NOTES        TRUE is returned if destAddress matches any local
//              interface's IP address or broadcast address.  TRUE is
//              also returned if destAddress is 255.255.255.255
//              (ANY_DEST).
//
//              If destAddress is a multicast address, it's checked
//              against any multicast groups the node is subscribed to.
//              [BSD has interfaces subscribing to multicast groups;
//              QualNet has nodes subscribing.]
//-----------------------------------------------------------------------------

BOOL //inline
IsMyPacket(Node *node, NodeAddress destAddress)
{
    int i;

    if (destAddress == ANY_DEST)
    {
        return TRUE;
    }

    // Check if we are registered for any multicast group.
    // If we are, then accept this packet.

    if (NetworkIpIsMulticastAddress(node, destAddress))
    {
        if (NetworkIpIsPartOfMulticastGroup(node, destAddress))
        {
            return TRUE;
        }

        return FALSE;
    }

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (destAddress == NetworkIpGetInterfaceAddress(node, i)
            || destAddress == NetworkIpGetInterfaceBroadcastAddress(node, i))
        {
            return TRUE;
        }
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// FUNCTION     IsOutgoingBroadcast()
// PURPOSE
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destAddress
//                  An IP packet's destination IP address.
//              int *outgoingInterface
//                  Outgoing interface index.
//              NodeAddress *outgoingBroadcastAddress
//
// RETURNS
//-----------------------------------------------------------------------------

BOOL
IsOutgoingBroadcast(
    Node *node,
    NodeAddress destAddress,
    int *outgoingInterface,
    NodeAddress *outgoingBroadcastAddress)
{
    int i;

    ERROR_Assert(
        outgoingInterface && outgoingBroadcastAddress,
        "NULL pointer passed to IsOutgoingBroadcast()");

    if (destAddress == ANY_DEST)
    {
        *outgoingInterface = DEFAULT_INTERFACE;
        *outgoingBroadcastAddress = ANY_DEST;
        return TRUE;
    }

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (destAddress == NetworkIpGetInterfaceBroadcastAddress(node, i))
        {
            *outgoingInterface = i;
            *outgoingBroadcastAddress = ANY_DEST;
            return TRUE;
        }
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// Per hop behavior (PHB)
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     IpInitPerHopBehaviors()
// PURPOSE
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//
// RETURN       None.
//-----------------------------------------------------------------------------

//static
void //inline//
IpInitPerHopBehaviors(
    Node *node,
    const NodeInput *nodeInput)
{
#ifdef ENTERPRISE_LIB
    NodeInput phbInput;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i, items;
    BOOL retVal;

    IO_ReadCachedFile(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "PER-HOP-BEHAVIOR-FILE",
        &retVal,
        &phbInput);

    ip->numPhbInfo = 0;


    if (retVal != TRUE)
    {
        return;
    }

    ip->phbInfo = (IpPerHopBehaviorInfoType *)
                  MEM_malloc(sizeof(IpPerHopBehaviorInfoType) *
                         NUM_INITIAL_PHB_INFO_ENTRIES);
    ip->maxPhbInfo = NUM_INITIAL_PHB_INFO_ENTRIES;

    for (i = 0; i < phbInput.numLines; i++)
    {
        char identifier[MAX_STRING_LENGTH];
        int tempDs = 0;
        int tempPriority = 0;
        unsigned char ds = 0;
        QueuePriorityType priority = 0;

        sscanf(phbInput.inputStrings[i], "%s", identifier);

        if (strcmp(identifier, "DS-TO-PRIORITY-MAP") == 0)
        {
            items = sscanf(phbInput.inputStrings[i], "%*s %d %d",
                       &tempDs, &tempPriority);

            if (items != 2)
            {
                ERROR_ReportError("DS-TO-PRIORITY-MAP expects <ds> <prio>\n");
            }
            ds = (unsigned char) tempDs;
        }
        else
        if (strcmp(identifier, "DEFAULT-DS-TO-PRIORITY-MAP") == 0)
        {
            items = sscanf(phbInput.inputStrings[i], "%*s %d",&tempPriority);

            if (items != 1)
            {
                ERROR_ReportError("DEFAULT-DS-TO-PRIORITY-MAP expects only"
                    " default priority queue <prio>\n");
            }

            ds = (unsigned char) DIFFSERV_DS_CLASS_BE;
        }
        priority = (QueuePriorityType) tempPriority;

        AddPHBEntry(node, ds, priority);
    }
#endif // ENTERPRISE_LIB
}

//-----------------------------------------------------------------------------
// FUNCTION     AddPHBEntry()
// PURPOSE
// PARAMETERS   Node *node
//                  Pointer to node.
//              unsigned char ds
//
//              QueuePriorityType priority
//
// RETURN       None.
//-----------------------------------------------------------------------------

static void //inline//
AddPHBEntry(
    Node *node,
    unsigned char ds,
    QueuePriorityType priority)
{
#ifdef ENTERPRISE_LIB
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    if (ip->numPhbInfo == ip->maxPhbInfo)
    {
        IpPerHopBehaviorInfoType* newPhbInfo =
            (IpPerHopBehaviorInfoType*)
            MEM_malloc(sizeof(IpPerHopBehaviorInfoType) *
                (ip->maxPhbInfo + NUM_INITIAL_PHB_INFO_ENTRIES));

        memcpy(newPhbInfo, ip->phbInfo,
               sizeof(IpPerHopBehaviorInfoType) * ip->numPhbInfo);

        ip->maxPhbInfo += NUM_INITIAL_PHB_INFO_ENTRIES;
        MEM_free(ip->phbInfo);
        ip->phbInfo = newPhbInfo;
    }

    ip->phbInfo[ip->numPhbInfo].ds = ds;
    ip->phbInfo[ip->numPhbInfo].priority = priority;

#ifdef DEBUG
    printf("#%d: Add PHB for ds %d => prio %d\n", node->nodeId, ds, priority);
#endif
    ip->numPhbInfo++;
#endif // ENTERPRISE_LIB
}

//-----------------------------------------------------------------------------
// Callbacks into IP made by the MAC layer, helper functions
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     HandleSpecialMacLayerStatusEvents()
// PURPOSE      Give the routing protocol the special status messages
//              that come from the MAC layer that notify when special
//              events at that level occur.  Used by the routing protocols
//              for routing optimization.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with MAC-layer event.
//              int interfaceIndex
//                  interface associated with MAC events.
// RETURN       None.
//-----------------------------------------------------------------------------

static void //inline//
HandleSpecialMacLayerStatusEvents(Node *node,
                                  Message *msg,
                                  const NodeAddress nextHopAddress,
                                  int interfaceIndex)
{

    MacLayerStatusEventHandlerFunctionType macLayerStatusEventHandlerFunction
        = NetworkIpGetMacLayerStatusEventHandlerFunction(
              node, interfaceIndex);

    if (macLayerStatusEventHandlerFunction)
    {
        (macLayerStatusEventHandlerFunction)(node,
                                             msg,
                                             nextHopAddress,
                                             interfaceIndex);
    }//if//
    MESSAGE_Free(node, msg);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpRemoveOutputQueue()
// PURPOSE
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Interface associated with queue.
//              QueuePriorityType priority
//                  Priority queue to remove packet from.
// RETURN       None.
//-----------------------------------------------------------------------------

/*void
NetworkIpRemoveOutputQueue(
    Node *node,
    int interfaceIndex,
    QueuePriorityType priority)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *schedulerPtr =
        ip->interfaceInfo[interfaceIndex]->scheduler;
    int i;

    for (i = 0; i < schedulerPtr->numQueues; i++)
    {
        if (schedulerPtr->queue[i].priority == priority)
        {
            int afterEntries = schedulerPtr->numQueues - (i + 1);

            if (afterEntries > 0)
            {
                memmove(&schedulerPtr->queue[i], &schedulerPtr->queue[i+1],
                        afterEntries);
            }
            schedulerPtr->numQueues--;
            return;
        }
    }
}

*/
//-----------------------------------------------------------------------------
// Network-layer enqueueing
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpQueueInsert()
// PURPOSE      Calls the packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int incomingInterface
//                  interface of input queue.
//              Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress nextHopAddress
//                  Packet's next hop address.
//              NodeAddress destinationAddress
//                  Packet's destination address.
//              int outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int networkType
//                  Type of network packet is using (IP, Link-16, ...)
//              BOOL *queueIsFull
//                  Storage for boolean indicator.
//                  If TRUE, packet was not queued because scheduler
//                  reported queue was (or queues were) full.
//              int incomingInterface
//                  Incoming interface, Default argument used by backplane.
// RETURN       None.
//-----------------------------------------------------------------------------


void
NetworkIpQueueInsert(
    Node *node,
    Scheduler *scheduler,
    Message *msg,
    NodeAddress nextHopAddress,
    NodeAddress destinationAddress,
    int outgoingInterface,
    int networkType,
    BOOL *queueIsFull,
    int incomingInterface,
    BOOL isOutputQueue)
{

#ifdef nADDON_BOEINGFCS
    if (ModeCesWnwReceiveOnlyReturnCurrentState(node,  outgoingInterface))
    {
#ifdef CYBER_CORE
        NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
        ModeCesDataWnwReceiveOnly *rcvOnly=
            ip->interfaceInfo[outgoingInterface]->receiveOnlyData;

        /*
        if (IsIAHEPIahepSecureInterface(node, outgoingInterface))
        {
            if (ip->iahepData->nodeType == RED_NODE)
            {//check red node
                ModeCesWnwReceiveOnlyUpdateStats( rcvOnly,
                    NETWORK_LAYER);
#ifdef ADDON_DB
                HandleNetworkDBEvents(
                    node,
                    msg,
                    outgoingInterface,
                    "NetworkPacketDrop",
                    "IAHEP Receive Only Node",
                    0,
                    0,
                    0,
                    0);
#endif
                MESSAGE_Free(node, msg);
                return;
            }
        }
            */
        }
#endif
    }
    /*if (!MAC_InterfaceIsEnabled(node, outgoingInterface))
    {
        MESSAGE_Free(node,msg);
        return;
    }*/
#endif
    int queueIndex = ALL_PRIORITIES;
    IpHeaderType *ipHeader = NULL;
    QueuedPacketInfo *infoPtr;
    BOOL isResolved = FALSE;

    ipHeader = (IpHeaderType*) MESSAGE_ReturnPacket(msg);

    // Tack on the nextHopAddress to the message using the insidious "info"
    // field.

    MacHWAddress hwAddr ;
    if (isOutputQueue && (outgoingInterface != CPU_INTERFACE))
    {
        if (ArpIsEnable(node, outgoingInterface))
        {
            if (node->macData[outgoingInterface]->macProtocol !=
                        MAC_PROTOCOL_802_3)
            {
                ERROR_Assert(LlcIsEnabled(node,outgoingInterface),
                    "LLC Should be enabled, when ARP is used"
                    "in protocol other than 802.3");
            }

            isResolved = ArpTTableLookup(node,
                                         outgoingInterface,
                                         PROTOCOL_TYPE_IP,
                                         IpHeaderGetTOS(
                                         ipHeader->ip_v_hl_tos_len),
                                         nextHopAddress,
                                         &hwAddr,
                                         &msg,
                                         incomingInterface,
                                         networkType);
            if (!isResolved)
            {
                *queueIsFull = FALSE;
                return;
            }
        }
        else
        {
            isResolved = IPv4AddressToHWAddress(node,
                                                outgoingInterface,
                                                msg,
                                                nextHopAddress,
                                                &hwAddr);
        }
    }


    MESSAGE_InfoAlloc(node, msg, sizeof(QueuedPacketInfo));

    infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo(msg);

    infoPtr->nextHopAddress = nextHopAddress;
    infoPtr->destinationAddress.ipv4DestAddr = destinationAddress;
    if (outgoingInterface != CPU_INTERFACE)
    {
#ifdef ADDON_DB
        StatsDBAddMessageNextPrevHop(
            node,
            msg,
            nextHopAddress,
            NetworkIpGetInterfaceAddress(node, outgoingInterface));
#endif
    }

    memcpy(infoPtr->macAddress,hwAddr.byte,hwAddr.hwLength);
    infoPtr->hwLength = hwAddr.hwLength;
    infoPtr->hwType = hwAddr.hwType;



    infoPtr->outgoingInterface = outgoingInterface;
    infoPtr->networkType = networkType;
    infoPtr->userTos = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
    infoPtr->incomingInterface = incomingInterface;

    //Trace Enqueue
    ActionData acn;
    acn.actionType = ENQUEUE;
    acn.actionComment = NO_COMMENT;
    NetworkType netType = NETWORK_IPV4;
    acn.pktQueue.interfaceID = (unsigned short) outgoingInterface;
    acn.pktQueue.queuePriority = (unsigned char)
        IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);

   if (outgoingInterface != CPU_INTERFACE)
    {
        TRACE_PrintTrace(node,
                        msg,
                        TRACE_NETWORK_LAYER,
                        PACKET_OUT,
                        &acn,
                        netType);
    }
    else
    {
        TRACE_PrintTrace(node,
                        msg,
                        TRACE_NETWORK_LAYER,
                        PACKET_IN,
                        &acn,
                        netType);
    }

    if (isOutputQueue &&
         ( outgoingInterface != CPU_INTERFACE ) &&
            LlcIsEnabled(node, outgoingInterface))
    {

         LlcAddHeader(node, msg, PROTOCOL_TYPE_IP);
    }

    // Call the Scheduler "insertFunction"
    queueIndex = GenericPacketClassifier(scheduler,
        (int) ReturnPriorityForPHB(node,
        IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len)));

    (*scheduler).insert(node,
                        outgoingInterface,
                        msg,
                        queueIsFull,
                        queueIndex,
                        NULL, //const void* infoField,
                        getSimTime(node));
    // Check the Queue threshold for the MI Queues.
#ifdef ADDON_BOEINGFCS

    if (NetworkCesIncEplrsActiveOnInterface(node, outgoingInterface) 
        && ipHeader->ip_p != IPPROTO_IGMP)
    {
        NetworkCesIncHasPacketToSendToEplrs(node,
            outgoingInterface);
            return;
    }

    if (ModeCesWnwReceiveOnlyReturnCurrentState(node,  outgoingInterface))
    {
        return;
    }
    else
    {
        RoutingCesMalsrCheckMiQueueThreshold(node, outgoingInterface);
    }
#endif
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpCpuQueueInsert()
// PURPOSE      Calls the cpu packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress nextHopAddress
//                  Packet's next hop address.
//              NodeAddress destinationAddress
//                  Packet's destination address.
//              int outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int networkType
//                  Type of network packet is using (IP, Link-16, ...)
//              BOOL *queueIsFull
//                  Storage for boolean indicator.
//                  If TRUE, packet was not queued because scheduler
//                  reported queue was (or queues were) full.
//              int incomingInterface
//                  Incoming interface of packet.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpCpuQueueInsert(
    Node *node,
    Message *msg,
    NodeAddress nextHopAddress,
    NodeAddress destinationAddress,
    int outgoingInterface,
    int networkType,
    BOOL *queueIsFull,
    int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *cpuScheduler = ip->cpuScheduler;

    NetworkIpQueueInsert(
                        node,
                        cpuScheduler,
                        msg,
                        nextHopAddress,
                        destinationAddress,
                        outgoingInterface,
                        networkType,
                        queueIsFull,
                        incomingInterface);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpInputQueueInsert()
// PURPOSE      Calls the input packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int incomingInterface
//                  interface of input queue.
//              Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress nextHopAddress
//                  Packet's next hop address.
//              NodeAddress destinationAddress
//                  Packet's destination address.
//              int outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int networkType
//                  Type of network packet is using (IP, Link-16, ...)
//              BOOL *queueIsFull
//                  Storage for boolean indicator.
//                  If TRUE, packet was not queued because scheduler
//                  reported queue was (or queues were) full.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpInputQueueInsert(
    Node *node,
    int incomingInterface,
    Message *msg,
    NodeAddress nextHopAddress,
    NodeAddress destinationAddress,
    int outgoingInterface,
    int networkType,
    BOOL *queueIsFull)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *inputScheduler = NULL;

    ERROR_Assert(
        incomingInterface >= 0 && incomingInterface < node->numberInterfaces,
        "Invalid incoming interface");

    inputScheduler = ip->interfaceInfo[incomingInterface]->inputScheduler;
    NetworkIpQueueInsert(
                        node,
                        inputScheduler,
                        msg,
                        nextHopAddress,
                        destinationAddress,
                        outgoingInterface,
                        networkType,
                        queueIsFull);
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueInsert()
// PURPOSE      Calls the output packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int outgoingInterface
//                  interface of output queue.
//              Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress nextHopAddress
//                  Packet's next hop address.
//              NodeAddress destinationAddress
//                  Packet's destination address.
//              int networkType
//                  Type of network packet is using (IP, Link-16, ...)
//              BOOL *queueIsFull
//                  Storage for boolean indicator.
//                  If TRUE, packet was not queued because scheduler
//                  reported queue was (or queues were) full.
// RETURN       None.
// NOTES        Called by QueueUpIpFragmentForMacLayer().
//-----------------------------------------------------------------------------

void
NetworkIpOutputQueueInsert(
    Node *node,
    int outgoingInterface,
    Message *msg,
    NodeAddress nextHopAddress,
    NodeAddress destinationAddress,
    int networkType,
    BOOL *queueIsFull)
{
#ifdef ADDON_BOEINGFCS
     if (!MAC_InterfaceIsEnabled(node, outgoingInterface))
     {
         //MESSAGE_Free(node, msg);
     *queueIsFull = TRUE;
         return;
     }
#endif
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    Scheduler *scheduler = NULL;

    ERROR_Assert(
        outgoingInterface >= 0 && outgoingInterface < node->numberInterfaces,
        "Invalid outgoing interface");

#ifdef CYBER_LIB
    if (node->macData[outgoingInterface]->macProtocol ==
                                                      MAC_PROTOCOL_WORMHOLE)
    {
        // Drop message as Warmhole does not generate any traffic.
        // These messages will be counted as ipOutDiscards on wormhole nodes.
       *queueIsFull = TRUE;
        return;
    }
#endif //CYBER_LIB

    {

#if 0 //#ifdef ADDON_BOEINGFCS
        if (!ip->networkSecurityCesHaipeEnabled)
        {
            NodeAddress* nextHopInfo = (NodeAddress*)
            MESSAGE_AddInfo(node,
                            msg,
                            sizeof(NodeAddress),
                            INFO_TYPE_HaipeNextHop);

            *nextHopInfo = nextHopAddress;
        }
#endif

        scheduler = ip->interfaceInfo[outgoingInterface]->scheduler;

        NetworkIpQueueInsert(node,
                             scheduler,
                             msg,
                             nextHopAddress,
                             destinationAddress,
                             outgoingInterface,
                             networkType,
                             queueIsFull,
                             ANY_INTERFACE,
                             TRUE);
    }

}



#ifdef ADDON_LINK16

void
NetworkQueueInsert(
    Node *node,
    Scheduler *scheduler,
    Message *msg,
    NodeAddress nextHopAddress,
    NodeAddress destinationAddress,
    int outgoingInterface,
    int networkType,
    BOOL *queueIsFull,
    int incomingInterface = ANY_INTERFACE)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    QueuedPacketInfo *infoPtr;

    // Tack on the nextHopAddress to the message using the insidious "info"
    // field.

    MESSAGE_InfoAlloc(node, msg, sizeof(QueuedPacketInfo));

    infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo(msg);

    infoPtr->nextHopAddress = nextHopAddress;
    infoPtr->destinationAddress.ipv4DestAddr = destinationAddress;
    infoPtr->outgoingInterface = outgoingInterface;
    infoPtr->networkType = networkType;
    infoPtr->userTos = (TosType) IPTOS_PREC_ROUTINE;
    infoPtr->incomingInterface = incomingInterface;
#ifdef ADDON_DB
    StatsDBAddMessageNextPrevHop(
        node,
        msg,
        infoPtr->nextHopAddress,
        NetworkIpGetInterfaceAddress(node, outgoingInterface));
#endif
    // Call the "insert" function
    int queueIndex = GenericPacketClassifier(scheduler,
            (int) ReturnPriorityForPHB(node, (TosType) IPTOS_PREC_ROUTINE));
    (*scheduler).insert(node,
        outgoingInterface,
        msg,
        queueIsFull,
        queueIndex,
        NULL, //infoField,
        getSimTime(node));

    //Trace Enqueue
    if (!(*queueIsFull))
    {
        IpHeaderType *ipHeader
                    = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

        //Trace Enqueue
        ActionData acn;
        acn.actionType = ENQUEUE;
        acn.actionComment = NO_COMMENT;
        acn.pktQueue.interfaceID = outgoingInterface;
        acn.pktQueue.queuePriority = (TosType) ipHeader->ip_tos;
        TRACE_PrintTrace(node,
                        msg,
                        TRACE_NETWORK_LAYER,
                        PACKET_IN,
                        &acn,
                        NETWORK_IPV4);
    }
}


void
NetworkOutputQueueInsert(
    Node *node,
    int outgoingInterface,
    Message *msg,
    NodeAddress nextHopAddress,
    NodeAddress destinationAddress,
    int networkType,
    BOOL *queueIsFull)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    Scheduler *scheduler = NULL;

    ERROR_Assert(
        outgoingInterface >= 0 && outgoingInterface < node->numberInterfaces,
        "Invalid outgoing interface");

    scheduler = ip->interfaceInfo[outgoingInterface]->scheduler;
    NetworkQueueInsert(
                       node,
                       scheduler,
                       msg,
                       nextHopAddress,
                       destinationAddress,
                       outgoingInterface,
                       networkType,
                       queueIsFull,
                       ANY_INTERFACE);
}

#endif // ADDON_LINK16


//-----------------------------------------------------------------------------
// IP header
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpAddHeader()
// PURPOSE      Add an IP packet header to a message.
//              Just calls AddIpHeader.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message.
//              NodeAddress sourceAddress
//                  Source IP address.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              TosType priority
//                  Currently a TosType.
//                  (values are not standard for "IP type of service field"
//                  but has correct function)
//              unsigned char protocol
//                  IP protocol number.
//              unsigned ttl
//                  Time to live.
//                  If 0, uses default value IPDEFTTL, as defined in
//                  include/ip.h.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpAddHeader(
    Node *node,
    Message *msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    TosType priority,
    unsigned char protocol,
    unsigned ttl)
{
    AddIpHeader(node,
                msg,
                sourceAddress,
                destinationAddress,
                priority,
                protocol,
                ttl);
}


//-----------------------------------------------------------------------------
// FUNCTION     AddIpHeader()
// PURPOSE      Add an IP packet header to a message.
//              The new message has an IP packet.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message.
//              NodeAddress sourceAddress
//                  Source IP address.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              TosType priority
//                  Currently a TosType.
//                  (values are not standard for "IP type of service field"
//                  but has correct function)
//              unsigned char protocol
//                  IP protocol number.
//              unsigned ttl
//                  Time to live.
//                  If 0, uses default value IPDEFTTL, as defined in
//                  include/ip.h.
// RETURN       None.
//-----------------------------------------------------------------------------

void
AddIpHeader(
    Node *node,
    Message *msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    TosType priority,
    unsigned char protocol,
    unsigned ttl)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader;
    int hdrSize = sizeof(IpHeaderType);

    MESSAGE_AddHeader(node, msg, hdrSize, TRACE_IP);

    ipHeader = (IpHeaderType *) msg->packet;
    memset(ipHeader, 0, hdrSize);

    IpHeaderSetVersion(&(ipHeader->ip_v_hl_tos_len), IPVERSION4) ;
    ipHeader->ip_id = ip->packetIdCounter;
    ip->packetIdCounter++;
    ipHeader->ip_src = sourceAddress;
    ipHeader->ip_dst = destinationAddress;

#ifdef ADDON_DB
    StatsDBAddMessageAddrInfo(node, msg, sourceAddress, destinationAddress);
#endif // ADDON_DB
    if (ttl == 0)
    {
        ipHeader->ip_ttl = IPDEFTTL;
    }
    else
    {
        ipHeader->ip_ttl = (unsigned char) ttl;
    }

    // TOS field (8 bit) in the IPV4 header
    IpHeaderSetTOS(&(ipHeader->ip_v_hl_tos_len), priority);


    if (ip->isPacketEcnCapable)
    {
        // Bits 6 and 7 of TOS field in the IPV4 header are used by ECN
        // and proposed respectively for the ECT and CE bits.
        // So before assign the value of priority to ip_tos, leave bits 6 and 7.

        if (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) & 0x03)
        {
            // User TOS specification conflicts with an ~enabled~ ECN
            char errorString[MAX_STRING_LENGTH];
            sprintf(errorString,
                    "~enabled~ ECN!!! ECN bits of TOS field in"
                    " application Input should contain zero values\n");
            ERROR_ReportError(errorString);
        }

        IpHeaderSetTOS(&(ipHeader->ip_v_hl_tos_len),
            (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) | IPTOS_ECT));
        ip->isPacketEcnCapable = FALSE;
    }
#ifdef ECN_DEBUG_TEST
    {
        /*
         * Mark the CE bit of some specific data packets (for testing)
         */
        int markCount = ECN_TEST_PKT_MARK;
        UInt32 markValues[] = { 14002};
        static int markFlag[] = { 1};
        struct tcphdr *aTcpHdr = (struct tcphdr *)((char*)ipHeader +
                                                    hdrSize);
        if (markCount) {
            int counter;
            for (counter = 0; counter < markCount; counter++) {
                if (aTcpHdr->th_seq == markValues[counter]
                            && markFlag[counter]) {
                    markFlag[counter]--;
                    ipHeader->ip_tos |=  IPTOS_CE;
                    printf ("\nSequence number of CE (specific for test)"
                             " marked packet is %u\n\n",
                             (unsigned) aTcpHdr->th_seq);
                }
            }
        }
    }
#endif /* ECN_DEBUG_TEST */

    ipHeader->ip_p = protocol;

    ERROR_Assert(MESSAGE_ReturnPacketSize(msg) <= IP_MAXPACKET,
                 "IP datagram (including header) exceeds IP_MAXPACKET bytes");

        IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),
            MESSAGE_ReturnPacketSize(msg));
        unsigned int hdrSize_temp= hdrSize/4;
        IpHeaderSetHLen(&(ipHeader->ip_v_hl_tos_len), hdrSize_temp);
        //original code
        //SetIpHeaderSize(ipHeader, hdrSize);


}

//-----------------------------------------------------------------------------
// FUNCTION     ExpandOrShrinkIpHeader()
// PURPOSE      Increases the size of an IP header so as to allow for
//              adding a new source route or other options.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message.
//              int newHeaderSize
//                  New IP header size in bytes.
//                  (This value is checked.)
// RETURN       None.
//-----------------------------------------------------------------------------

void //inline//
ExpandOrShrinkIpHeader(
    Node *node,
    Message *msg,
    int newHeaderSize)
{
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

    ERROR_Assert(newHeaderSize <= IP_MAX_HEADER_SIZE,
                 "IP header exceeds IP_MAX_HEADER_SIZE bytes");

    if (IpHeaderSize(ipHeader) != (unsigned) newHeaderSize)
    {
        IpHeaderType *origIpHeader = ipHeader;
        int oldIpHeaderSize = IpHeaderSize(ipHeader);

        MESSAGE_RemoveHeader(node, msg, oldIpHeaderSize, TRACE_IP);

        MESSAGE_AddHeader(node, msg, newHeaderSize, TRACE_IP);

        ipHeader = (IpHeaderType *) msg->packet;
        memmove((char *) ipHeader, (char *) origIpHeader,
                MIN(oldIpHeaderSize, newHeaderSize));
       IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),
           MESSAGE_ReturnPacketSize(msg));
       unsigned int newHeaderSize_temp = newHeaderSize/4;
       IpHeaderSetHLen(&(ipHeader->ip_v_hl_tos_len), newHeaderSize_temp);

    }//if//
}

//-----------------------------------------------------------------------------
// IP header option field
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     ExpandOrShrinkIpOptionField()
// PURPOSE
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message.
//              const int int optionCode
//                  option code
//              const int newIpOptionSize
//                  size of option
// RETURN       None.
//-----------------------------------------------------------------------------

static void //inline//
ExpandOrShrinkIpOptionField(
    Node *node,
    Message *msg,
    const int optionCode,
    const int newIpOptionSize)
{
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    IpOptionsHeaderType *ipOption = FindAnIpOptionField(ipHeader, optionCode);
    int oldHeaderSize = IpHeaderSize(ipHeader);
    int oldIpOptionSize = ipOption->len + 1;
    int deltaOptionSize = newIpOptionSize - oldIpOptionSize;
    int newHeaderSize = oldHeaderSize + deltaOptionSize;
    int bytesAfterOption = (int) (((char *) ipHeader + oldHeaderSize) -
                                  ((char *) ipOption + oldIpOptionSize));

    ERROR_Assert(newIpOptionSize % 4 == 0,
                 "IP option size must be a multiple of 4 bytes in QualNet");

    ExpandOrShrinkIpHeader(node, msg, newHeaderSize);

    ipHeader = (IpHeaderType *) msg->packet;
    ipOption = FindAnIpOptionField(ipHeader, optionCode);
    ipOption->len = (unsigned char)(newIpOptionSize - 1);

    // Move the header data after this option field to make room for
    // the new option data.

    memmove(((char *) ipOption + newIpOptionSize),
            ((char *) ipOption + oldIpOptionSize), bytesAfterOption);
}

//-----------------------------------------------------------------------------
// Statistics
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpInitStats()
// PURPOSE      Initialize statistics.
// PARAMETERS   Node* node
//              NetworkIpStatsType *stats
//                  Pointer to stats struct.
// RETURN       None.
//-----------------------------------------------------------------------------

static void //inline//
NetworkIpInitStats(Node* node, NetworkIpStatsType *stats)
{
    stats->deliveredPacketTtlTotal = 0;

    if (node->guiOption) {
        stats->ipInReceivesId = GUI_DefineMetric("IP In Receives",
                                                 node->nodeId,
                                                 GUI_NETWORK_LAYER, 0,
                                                 GUI_UNSIGNED_TYPE,
                                                 GUI_CUMULATIVE_METRIC);

        stats->ipInHdrErrorsId = GUI_DefineMetric("IP Header Errors",
                                                  node->nodeId,
                                                  GUI_NETWORK_LAYER, 0,
                                                  GUI_UNSIGNED_TYPE,
                                                  GUI_CUMULATIVE_METRIC);
    }

    stats->ipInReceives = 0;
    stats->ipInHdrErrors = 0;
    stats->ipInAddrErrors = 0;
    stats->ipInForwardDatagrams = 0;
    stats->ipInDiscards = 0;
    stats->ipInDelivers = 0;
    stats->ipOutRequests = 0;
    stats->ipOutDiscards = 0;
    stats->ipOutNoRoutes = 0;
    stats->ipReasmReqds = 0;
    stats->ipReasmOKs = 0;
    stats->ipReasmFails = 0;
    stats->ipFragOKs = 0;

    stats->ipInReceivesLastPeriod = 0;
    stats->ipInHdrErrorsLastPeriod = 0;
    stats->ipInAddrErrorsLastPeriod = 0;
    stats->ipInForwardDatagramsLastPeriod = 0;
    stats->ipInDiscardsLastPeriod = 0;
    stats->ipInDeliversLastPeriod = 0;
    stats->ipOutRequestsLastPeriod = 0;
    stats->ipOutDiscardsLastPeriod = 0;
    stats->ipOutNoRoutesLastPeriod = 0;
    stats->ipReasmReqdsLastPeriod = 0;
    stats->ipReasmOKsLastPeriod = 0;
    stats->ipReasmFailsLastPeriod = 0;
    stats->ipFragOKsLastPeriod = 0;

    stats->ipNumDroppedDueToBackplaneLimit = 0;

    // Fragmentation statistics.
    stats->ipFragsCreated = 0;
    stats->ipPacketsAfterFragsReasm = 0;
    stats->ipFragsInBuff = 0;

    //ATM : statistics added for gateway
    stats->ipRoutePktThruGt = 0;
    stats->ipSendPktToOtherNetwork = 0;
    stats->ipRecvdPktFromOtherNetwork = 0;
    //ATM

    stats->ipCommsDropped = 0;
    stats->ipPktsWarmupDropped = 0;
    stats->ipPktsWarmupDelay = 0;
    
#ifdef ADDON_DB
    // Initialize the Network Aggregate Stats
    stats->aggregateStats = new StatsDBNetworkAggregate;
    InitializeStatsDbNetworkAggregateStats(stats->aggregateStats);
#endif
}

static clocktype GetLeastTime(
    Node* node,
    clocktype time1,
    clocktype time2,
    clocktype time3,
    clocktype time4)
{
    clocktype leastTime = getSimTime(node);
    if (leastTime > time1 && time1 != 0)
    {
        leastTime = time1;
    }
    if (leastTime > time2 && time2 != 0)
    {
        leastTime = time2;
    }
    if (leastTime > time3 && time3 != 0)
    {
        leastTime = time3;
    }
    if (leastTime > time4 && time4 != 0)
    {
        leastTime = time4;
    }
    return leastTime;
}

static clocktype GetLargestTime(
    clocktype time1,
    clocktype time2,
    clocktype time3,
    clocktype time4)
{
    clocktype leastTime = 0;
    if (leastTime < time1)
    {
        leastTime = time1;
    }
    if (leastTime < time2)
    {
        leastTime = time2;
    }
    if (leastTime < time3)
    {
        leastTime = time3;
    }
    if (leastTime < time4)
    {
        leastTime = time4;
    }
    return leastTime;
}
//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpPrintStats()
// PURPOSE      Print IP statistics using IO_PrintStat().
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpPrintStats(Node *node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    NetworkIpStatsType *stats = &ip->stats;
    char buf[MAX_STRING_LENGTH];
    char clockStr[MAX_STRING_LENGTH];
    char ipAddr[MAX_STRING_LENGTH];
    double averageHopCount;

    sprintf(buf, "ipInHdrErrors = %u", stats->ipInHdrErrors);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);
    sprintf(buf, "ipInDelivers = %u", stats->ipInDelivers);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);

    // Rich-Merge, commented out to simplify stats comparison
    //sprintf(buf, "ipCommsDropped = %u", stats->ipCommsDropped);
    //IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);

    //sprintf(buf, "ipPktsWarmupDelayed = %u", stats->ipPktsWarmupDelay);
    //IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);

    //sprintf(buf, "ipPktsWarmupDropped = %u", stats->ipPktsWarmupDropped);
    //IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);

    if (ip->isIcmpEnable && icmp->fragmentationNeededEnable)
    {
        sprintf(buf, "ipFragFails = %u", (UInt32)stats->ipFragFails);
        IO_PrintStat(node, "Network", "IP", ANY_DEST,
                     -1 /* instance Id */, buf);
    }
    if (ip->isIcmpEnable && icmp->protocolUnreachableEnable)
    {
        sprintf(buf, "ipInUnknownProtos = %u",
                                           (UInt32)stats->ipInUnknownProtos);
        IO_PrintStat(node, "Network", "IP", ANY_DEST,
                     -1 /* instance Id */, buf);
    }
    sprintf(buf, "Packets fragmented = %u", stats->ipFragOKs);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);
    sprintf(buf, "Fragments created = %u", (UInt32) stats->ipFragsCreated);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1, buf);
    sprintf(buf, "Fragments received = %u", (UInt32) stats->ipReasmReqds);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);
    sprintf(buf, "Fragments dropped = %u", stats->ipReasmFails);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);
    sprintf(buf, "Fragments in Buffer = %u", stats->ipFragsInBuff);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1, buf);
    sprintf(buf, "Fragments reassembled = %u", stats->ipReasmOKs);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);
    sprintf(buf, "Packets created after reassembling = %u",
        stats->ipPacketsAfterFragsReasm);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1, buf);
    sprintf(buf, "ipInDelivers TTL sum = %u", stats->deliveredPacketTtlTotal);
    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);

    // ATM : statistics added for gateway
    if (ip->gatewayConfigured)
    {
        sprintf(buf, "ipRoutePktThruGt = %u",
        stats->ipRoutePktThruGt);
        IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);

        sprintf(buf, "Send pkt to Other Net = %u",
        stats->ipSendPktToOtherNetwork);
        IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);

        sprintf(buf, "Recvd pkt from Other Net  = %u",
        stats->ipRecvdPktFromOtherNetwork);
        IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);
    }
    //ATM

    // Report TTL-based average hop count.  Note that the average hop
    // count is not accurate at all when there are many IP packets with
    // initial TTLs not equal to IPDEFTTL, as defined in include/ip.h.
    // This inaccuracy is present for AODV, for example, since many
    // AODV packets have an initial TTL of 1.

    if (stats->ipInDelivers == 0)
    {
        averageHopCount = 0;
    }
    else
    {
        averageHopCount =
            (double)
            ((IPDEFTTL * stats->ipInDelivers) - stats->deliveredPacketTtlTotal)
            / stats->ipInDelivers;
    }

    sprintf(buf, "ipInDelivers TTL-based average hop count = %.2f",
            floor(averageHopCount * 100 + 0.5) / 100);

    IO_PrintStat(node, "Network", "IP", ANY_DEST, -1 /* instance Id */, buf);

    if (ip->backplaneThroughputCapacity !=
        NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT)
    {
        sprintf(buf, "ipNumDroppedDueToBackplaneLimit = %u",
                stats->ipNumDroppedDueToBackplaneLimit);
        IO_PrintStat(node, "Network", "IP", ANY_DEST, -1, buf);
    }

    // Rich-Merge - dont print out statistics unless CES is enabled??

#ifdef ADDON_BOEINGFCS
    // Print the interface based IP stats.
    for (int i = 0; i < node->numberInterfaces; i++)
    {
        IO_ConvertIpAddressToString(ip->interfaceInfo[i]->ipAddress, ipAddr);
        double inUnicastPacketTput = 0;
        double inNUnicastPacketTput = 0;
        double inMulticastPacketTput = 0;
        double inBroadcastPacketTput = 0;
        double outUnicastPacketTput = 0;
        double outNUnicastPacketTput = 0;
        double outMulticastPacketTput = 0;
        double outBroadcastPacketTput = 0;
        double totalInTput = 0;
        double totalOutTput = 0;
        double inUcastDataPacketTput = 0;
        double outUcastDataPacketTput = 0;
        int totalInPacketSize = 0;
        int totalOutPacketSize = 0;
        clocktype firstInPacketTime = 0;
        clocktype lastInPacketTime = 0;
        clocktype firstOutPacketTime = 0;
        clocktype lastOutPacketTime = 0;
        sprintf(buf, "IfDescription = %s",
                 (const char*)ip->interfaceInfo[i]->ifDescr);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfPhysAddress = %s", ipAddr);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfInUnicastPkts = %d",
                (UInt32)ip->interfaceInfo[i]->ifInUcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "ifInUcastDataPackets = %d",
                (UInt32)ip->interfaceInfo[i]->ifInUcastDataPackets);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfInNUnicastPkts = %d",
                (UInt32)ip->interfaceInfo[i]->ifInNUcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfInDiscards = %d",
                (UInt32)ip->interfaceInfo[i]->ifInDiscards);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfOutDiscards = %d",
                (UInt32)ip->interfaceInfo[i]->ifOutDiscards);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfOutUnicastPkts = %d",
                (UInt32)ip->interfaceInfo[i]->ifOutUcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "ifOutUcastDataPackets = %d",
                (UInt32)ip->interfaceInfo[i]->ifOutUcastDataPackets);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfOutNUnicastPkts = %d",
                (UInt32)ip->interfaceInfo[i]->ifOutNUcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfInMulticastPkts = %d",
                (UInt32)ip->interfaceInfo[i]->ifInMulticastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfInBroadcastPkts = %d",
                (UInt32)ip->interfaceInfo[i]->ifInBroadcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfOutMulticastPkts = %d",
                (UInt32)ip->interfaceInfo[i]->ifOutMulticastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfOutBroadcastPkts = %d",
                (UInt32)ip->interfaceInfo[i]->ifOutBroadcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfHCInUnicastPkts = %d",
                (UInt64)ip->interfaceInfo[i]->ifHCInUcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfHCInMulticastPkts = %d",
                (UInt64)ip->interfaceInfo[i]->ifHCInMulticastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfHCInBroadcastPkts = %d",
                (UInt64)ip->interfaceInfo[i]->ifHCInBroadcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfHCOutUnicastPkts = %d",
                (UInt64)ip->interfaceInfo[i]->ifHCInUcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfHCOutMulticastPkts = %d",
                (UInt64)ip->interfaceInfo[i]->ifHCOutMulticastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfHCOutBroadcastPkts = %d",
                (UInt64)ip->interfaceInfo[i]->ifHCOutBroadcastPkts);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IfMtu = %d",
                (Int32)ip->interfaceInfo[i]->ipFragUnit);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        sprintf(buf, "IpAddrIfIdx = %d",
                (UInt32)ip->interfaceInfo[i]->ipAddrIfIdx);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        char netMaskStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(ip->interfaceInfo[i]->ipAddrNetMask,
            netMaskStr);
        sprintf (buf, "IpAddrNetMask = %s", netMaskStr);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "IpAddrBcast = %d",
                (UInt32)ip->interfaceInfo[i]->ipAddrBcast);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        // NAIL STATS.
        sprintf(buf, "Incoming Unicast Data Packets = %d",
                (UInt32)ip->interfaceInfo[i]->ifInUcastDataPackets);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "OutGoing Unicast Data Packets = %d",
                (UInt32)ip->interfaceInfo[i]->ifOutUcastDataPackets);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "Incoming Unicast Data Packets size (in bytes) = %d",
                (UInt32)ip->interfaceInfo[i]->inUcastDataPacketSize);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        sprintf(buf, "OutGoing Unicast Data Packets size (in bytes) = %d",
                (UInt32)ip->interfaceInfo[i]->outUcastDataPacketSize);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        TIME_PrintClockInSecond(ip->interfaceInfo[i]->firstInUcastDataPacketTime,
            clockStr);
        sprintf(buf, "First incoming Unicast Data Packet received at "
            "(in seconds) = %s",clockStr);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        TIME_PrintClockInSecond(ip->interfaceInfo[i]->lastInUcastDataPacketTime,
            clockStr);
        sprintf(buf, "Last incoming Unicast Data Packet received at "
            "(in seconds) = %s",clockStr);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        TIME_PrintClockInSecond(ip->interfaceInfo[i]->firstOutUcastDataPacketTime,
            clockStr);
        sprintf(buf, "First outgoing Unicast Data Packet sent at (in seconds) = %s",
                clockStr);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
        TIME_PrintClockInSecond(ip->interfaceInfo[i]->lastOutUcastDataPacketTime,
            clockStr);
        sprintf(buf, "Last outgoing Unicast Data Packet sent at (in seconds) =%s",
                clockStr);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);


        // Throughput for Unicast Data packets on an interface
        if (ip->interfaceInfo[i]->lastInUcastDataPacketTime >
            ip->interfaceInfo[i]->firstInUcastDataPacketTime)
        {
            inUcastDataPacketTput = ((ip->interfaceInfo[i]->
                inUcastDataPacketSize * 8 * SECOND) /
                (ip->interfaceInfo[i]->lastInUcastDataPacketTime -
                ip->interfaceInfo[i]->firstInUcastDataPacketTime));
        }
        sprintf(buf,
                "Throughput for Unicast DATA packets received by "
                " Network Layer (bits/s) = %f",
                (double)inUcastDataPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        if (ip->interfaceInfo[i]->lastOutUcastDataPacketTime >
            ip->interfaceInfo[i]->firstOutUcastDataPacketTime)
        {
            outUcastDataPacketTput = ((ip->interfaceInfo[i]->
                outUcastDataPacketSize * 8 * SECOND) /
                (ip->interfaceInfo[i]->lastOutUcastDataPacketTime -
                ip->interfaceInfo[i]->firstOutUcastDataPacketTime));
        }
        sprintf(buf,
                "Throughput for Unicast DATA packets sent out of Network Layer "
                " (bits/s) = %f",
                (double)outUcastDataPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        // Througput for Unicast packets on an interface.
        if (ip->interfaceInfo[i]->lastInUcastPacketTime >
            ip->interfaceInfo[i]->firstInUcastPacketTime)
        {
            inUnicastPacketTput = ((ip->interfaceInfo[i]->inUcastPacketSize
                * 8 * SECOND) / (ip->interfaceInfo[i]->lastInUcastPacketTime
                - ip->interfaceInfo[i]->firstInUcastPacketTime));
        }
        sprintf(buf,
                "Throughput for Unicast packets received by Network Layer "
                "(bits/s) = %f",
                (double)inUnicastPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        if (ip->interfaceInfo[i]->lastOutUcastPacketTime >
            ip->interfaceInfo[i]->firstOutUcastPacketTime)
        {
            outUnicastPacketTput = ((ip->interfaceInfo[i]->outUcastPacketSize
                * 8 * SECOND) /(ip->interfaceInfo[i]->lastOutUcastPacketTime -
                ip->interfaceInfo[i]->firstOutUcastPacketTime));
        }
        sprintf(buf,
                "Throughput for Unicast packets sent out of Network Layer"
                " (bits/s) = %f",
                (double)outUnicastPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        // Througput for Non-unicast packets on an interface.
        if (ip->interfaceInfo[i]->lastInNUcastPacketTime >
            ip->interfaceInfo[i]->firstInNUcastPacketTime)
        {
            inNUnicastPacketTput = ((ip->interfaceInfo[i]->inNUcastPacketSize
                * 8 * SECOND) / (ip->interfaceInfo[i]->lastInNUcastPacketTime
                - ip->interfaceInfo[i]->firstInNUcastPacketTime));
        }
        sprintf(buf,
               "Throughput for Non-Unicast packets received by Network Layer"
               "(bits/s) = %f",
               (double)inNUnicastPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        if (ip->interfaceInfo[i]->lastOutNUcastPacketTime >
            ip->interfaceInfo[i]->firstOutNUcastPacketTime)
        {
            outNUnicastPacketTput = ((ip->interfaceInfo[i]->outNUcastPacketSize
                * 8 * SECOND) / (ip->interfaceInfo[i]->lastOutNUcastPacketTime
                - ip->interfaceInfo[i]->firstOutNUcastPacketTime));
        }
        sprintf(buf,
               "Throughput for Non-Unicast packets sent out of Network Layer"
               "(bits/s) = %f",
               (double)outNUnicastPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        // Througput for Multicast packets on an interface.
        if (ip->interfaceInfo[i]->lastInMulticastPacketTime >
            ip->interfaceInfo[i]->firstInMulticastPacketTime)
        {
            inMulticastPacketTput = ((ip->interfaceInfo[i]->inMulticastPacketSize
                * 8 * SECOND) /(ip->interfaceInfo[i]->lastInMulticastPacketTime
                - ip->interfaceInfo[i]->firstInMulticastPacketTime));
        }
        sprintf(buf,
                "Throughput for Multicast packets received by Network Layer"
                "(bits/s) = %f",
                (double)inMulticastPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        if (ip->interfaceInfo[i]->lastOutMulticastPacketTime >
            ip->interfaceInfo[i]->firstOutMulticastPacketTime)
        {
            outMulticastPacketTput = ((ip->interfaceInfo[i]->outMulticastPacketSize
                * 8 * SECOND) /
                (ip->interfaceInfo[i]->lastOutMulticastPacketTime -
                ip->interfaceInfo[i]->firstOutMulticastPacketTime));
        }
        sprintf(buf,
                "Throughput for Multicast packets sent out of Network Layer"
                "(bits/s) = %f",
                (double)outMulticastPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        // Througput for Broadcast packets on an interface.
        if (ip->interfaceInfo[i]->lastInBroadcastPacketTime >
            ip->interfaceInfo[i]->firstInBroadcastPacketTime)
        {
            inBroadcastPacketTput = ((ip->interfaceInfo[i]->inBroadcastPacketSize
                * 8 * SECOND) / (ip->interfaceInfo[i]->lastInBroadcastPacketTime
                - ip->interfaceInfo[i]->firstInBroadcastPacketTime));
        }
        sprintf(buf,
                "Throughput for Broadcast packets received by Network Layer"
                "(bits/s) = %f",
                (double)inBroadcastPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        if (ip->interfaceInfo[i]->lastOutBroadcastPacketTime >
            ip->interfaceInfo[i]->firstOutBroadcastPacketTime)
        {
            outBroadcastPacketTput = ((ip->interfaceInfo[i]->outBroadcastPacketSize
                * 8 * SECOND) /(ip->interfaceInfo[i]->lastOutBroadcastPacketTime
                - ip->interfaceInfo[i]->firstOutBroadcastPacketTime));
        }
        sprintf(buf,
                "Throughput for Broadcast packets sent out of Network Layer"
                "(bits/s) = %f",
                (double)outBroadcastPacketTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        // Total through put.
        firstInPacketTime = GetLeastTime(node,
            ip->interfaceInfo[i]->firstInUcastPacketTime,
            ip->interfaceInfo[i]->firstInNUcastPacketTime,
            ip->interfaceInfo[i]->firstInMulticastPacketTime,
            ip->interfaceInfo[i]->firstInBroadcastPacketTime);
        lastInPacketTime = GetLargestTime(ip->interfaceInfo[i]->
            lastInUcastPacketTime,ip->interfaceInfo[i]->lastInNUcastPacketTime,
            ip->interfaceInfo[i]->lastInMulticastPacketTime,
            ip->interfaceInfo[i]->lastInBroadcastPacketTime);
        if (lastInPacketTime > firstInPacketTime)
        {
            totalInPacketSize = ip->interfaceInfo[i]->inNUcastPacketSize +
                                ip->interfaceInfo[i]->inUcastPacketSize;
            totalInTput = ((totalInPacketSize * 8 * SECOND) /
                (lastInPacketTime - firstInPacketTime));
        }
        sprintf(buf,
                "Overall Throughput for packets received by Network Layer"
                "(bits/s) = %f",(double)totalInTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);

        firstOutPacketTime = GetLeastTime(node,
            ip->interfaceInfo[i]->firstOutUcastPacketTime,
            ip->interfaceInfo[i]->firstOutNUcastPacketTime,
            ip->interfaceInfo[i]->firstOutMulticastPacketTime,
            ip->interfaceInfo[i]->firstOutBroadcastPacketTime);
        lastOutPacketTime = GetLargestTime(ip->interfaceInfo[i]->
            lastOutUcastPacketTime,ip->interfaceInfo[i]->lastOutNUcastPacketTime,
            ip->interfaceInfo[i]->lastOutMulticastPacketTime,
            ip->interfaceInfo[i]->lastOutBroadcastPacketTime);
        if (lastOutPacketTime > firstOutPacketTime)
        {
            totalOutPacketSize = ip->interfaceInfo[i]->outNUcastPacketSize +
                                ip->interfaceInfo[i]->outUcastPacketSize;
            totalOutTput = ((totalOutPacketSize * 8 * SECOND) /
                (lastOutPacketTime - firstOutPacketTime));
        }
        sprintf(buf,
                "Overall Throughput for packets sent out of Network Layer"
                "(bits/s) = %f",(double)totalOutTput);
        IO_PrintStat(node, "NETWORK", "IP", ipAddr, i, buf);
    }
#endif

    ip->newStats->Print(node, "Network", "IP", ANY_DEST, -1);
}

//-----------------------------------------------------------------------------
// Multicast
//-----------------------------------------------------------------------------

// /**
// API                 :: RouteThePacketUsingMulticastForwardingTable
// LAYER               :: Network
// PURPOSE             :: Tries to route the multicast packet using the
//                        multicast forwarding table.
// PARAMETERS          ::
// + node               : Node*     : this node
// + msg                : Message*  : Pointer to Message
// + incomingInterface  : int       : Incomming Interface
// RETURN              :: void      : NULL.
// **/
void
RouteThePacketUsingMulticastForwardingTable(
    Node* node,
    Message *msg,
    int incomingInterface,
    NetworkType netType)
{
    IpHeaderType* ipHeader = NULL;
    ip6_hdr* ipv6Header = NULL;
    NodeAddress nextHop;
    LinkedList* interfaceList;
    ListItem *item;

    if (netType == NETWORK_IPV4)
    {
        ipHeader = (IpHeaderType* ) MESSAGE_ReturnPacket(msg);

        // Get all the interfaces that we must use to forward the
        // multicast packets.
        interfaceList =
            NetworkGetOutgoingInterfaceFromMulticastForwardingTable(
                node,
                ipHeader->ip_src,
                ipHeader->ip_dst);
    }
    else
    {
        ipv6Header = (ip6_hdr* ) MESSAGE_ReturnPacket(msg);

        if (ipv6Header->ip6_hlim < IPTTLDEC)
        {
            MESSAGE_Free(node, msg);

            return;
        }

        ipv6Header->ip6_hlim -= IPTTLDEC;

        // Get all the interfaces that we must use to forward the
        // multicast packets.
        interfaceList = Ipv6GetOutgoingInterfaceFromMulticastTable(
                            node,
                            ipv6Header->ip6_src,
                            ipv6Header->ip6_dst);
    }

    // No interfaces for multicast packet, so drop...
    if (interfaceList == NULL)
    {
        IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;

        // Packet Trace for IPv6 not supported
        if (netType == NETWORK_IPV4)
        {
            NetworkDataIp* ip = (NetworkDataIp *)
                                node->networkData.networkVar;
            ip->stats.ipOutNoRoutes++;

            // Handling of new Stat API for collecting unicast and multicast packets 
            // dropped seperately
            if (node->networkData.networkStats)
            {
                STAT_DestAddressType type;
                type = StatsApiAddrType(node, msg);
                if (type == STAT_Unicast)
                {
                    ip->newStats->AddPacketDroppedNoRouteDataPointsUnicast(node);
                }
                else if (type == STAT_Multicast)
                {
                    ip->newStats->AddPacketDroppedNoRouteDataPointsMulticast(node);
                }
                ip->newStats->AddPacketDroppedNoRouteDataPoints(node);
            }
#ifdef ADDON_DB
            ip->stats.aggregateStats->ipMulticastOutNoRoutes++ ;
            if (!NetworkIpIsPartOfMulticastGroup(node, ipHeader->ip_dst)
                && ip->ipMulticastNetSummaryStats)
            {
                ip->ipMulticastNetSummaryStats->m_NumDataDiscarded++;
            }
#endif
            //Trace drop
            ActionData acnData;
            acnData.actionType = DROP;
            acnData.actionComment = DROP_NO_ROUTE;
            TRACE_PrintTrace(node,
                            msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_OUT,
                            &acnData,
                            netType);
#ifdef ADDON_DB
        HandleNetworkDBEvents(
            node,
            msg,
            incomingInterface,
            "NetworkPacketDrop",
            "No Route",
            0,
            0,
            0,
            0);
#endif

        }
        else
        {
            ipv6->ip6_stat.ip6s_noroute++;
        }

        MESSAGE_Free(node, msg);

        return;
    }


    // Send packet out to each interface that we need to forward onto.

    item = interfaceList->first;

    while (item)
    {
        int *outgoingInterface = (int *) item->data;

        nextHop = ANY_DEST;

        if (netType == NETWORK_IPV4)
        {
            NetworkIpSendPacketOnInterface(
                node,
                MESSAGE_Duplicate(node, msg),
                incomingInterface,
                *outgoingInterface,
                nextHop);
#ifdef ADDON_DB
            NetworkDataIp* ip = (NetworkDataIp *)
                                node->networkData.networkVar;
            if (ip->ipMulticastNetSummaryStats)
            {
                ip->ipMulticastNetSummaryStats->m_NumDataForwarded++;
            }
#endif
        }
        else
        {
            route rt;

            COPY_ADDR6(ipv6Header->ip6_dst, rt.ro_dst);

            ip6_output(
                node,
                MESSAGE_Duplicate(node, msg),
                (optionList*)NULL,
                &rt,
                0,
                (ip_moptions*)NULL,
                incomingInterface,
                *outgoingInterface);
        }

        item = item->next;
    }

    MESSAGE_Free(node, msg);
}

//---------------------------------------------------------------------------
//-------------------------------------------------------------------------//
//          IP FRAGMENTATION IS END-TO-END ONLY.
//-------------------------------------------------------------------------//

//---------------------------------------------------------------------------
// FUNCTION             : IpFragmentPacket
// PURPOSE             :: Fragment an IP packet
// PARAMETERS          ::
// +node                : Node* node: pointer to Node
// +msg                 : Message* msg: Pointer to Message Structure
// +mtu                 : int mtu: Maximum Transmission Unit of the circuit.
//                                  list header.
//                      : BOOL fragmentForMpls:Fragment an IP packet for MPLS
// RETURN               : int : status of fragmentation.
// NOTES                : IP fragmented packet processing function
//---------------------------------------------------------------------------
int
IpFragmentPacket(
    Node* node,
    Message* msg,
    int mtu,
    ipFragmetedMsg** fragmentHead,
    BOOL fragmentForMpls)
{
    int off;
    int hlen;
    int fragmentedLen;
    int remaining_packetSize = 0;
    IpHeaderType* originalIpHdr = NULL;
    IpHeaderType *ipHeader = NULL;

    Message* tmpMsg = NULL;
    ipFragmetedMsg* fragmentChain = NULL;

    char* tempPayload = NULL;
    unsigned short offset;
    unsigned int curPayloadLen;

    char*  payload = MESSAGE_ReturnPacket(msg);
    int packetLen = 0;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    NodeAddress sourceAddress;
    NodeAddress destinationAddress;
    TosType priority = 0;
    unsigned char protocol;
    unsigned hLim;

    int originalIpId;
    BOOL originalFragmented = FALSE;
    int origFragOffSet;


    ipHeader = (IpHeaderType*) payload;
    if ((IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4) >
        sizeof(IpHeaderType))
    {
        return FALSE;
    }
    hlen = sizeof(IpHeaderType);



    originalIpId = ipHeader->ip_id;
    originalFragmented = IpHeaderGetIpMoreFrag(ipHeader->ipFragment);
    origFragOffSet = IpHeaderGetIpFragOffset(ipHeader->ipFragment);


    // Now Calculate the fragmentedLen
    // The Fragmentable Part of the original packet is divided into
    // fragments, each, except possibly the last one,
    // being an integer multiple of 8 octets long.
    if (!fragmentForMpls)
    {
        fragmentedLen = ((int)(mtu - hlen) / 8) * 8;
    }
    else
    {
#ifdef ENTERPRISE_LIB
        // Size of mpls header added while fragmentation
        fragmentedLen = ((int)(mtu - (hlen + sizeof(Mpls_Shim_LabelStackEntry
                            ))) / 8) * 8;
#endif // ENTERPRISE_LIB
    }

    // Get the copy of the ip header.
    originalIpHdr = (IpHeaderType*) MEM_malloc(sizeof(IpHeaderType));

    memcpy(originalIpHdr, payload, sizeof(IpHeaderType));

    packetLen = IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len);

#ifdef SENSOR_NETWORKS_LIB
    ZigbeeAppInfo* zigbeeAppInfo = NULL;
    zigbeeAppInfo = (ZigbeeAppInfo*)MESSAGE_ReturnInfo(msg, INFO_TYPE_ZigbeeApp_Info);
#endif // SENSOR_NETWORKS_LIB

    // Remove the Ip header from the original packet.
    NetworkIpRemoveIpHeader(
        node,
        msg,
        &sourceAddress,
        &destinationAddress,
        &priority,
        &protocol,
        &hLim);

    // Get the new payload after removing the ip header.
    payload = MESSAGE_ReturnPacket(msg);


    // Make the first fragment Packet.
    tmpMsg = MESSAGE_Alloc(node,
                           NETWORK_LAYER,
                           NETWORK_PROTOCOL_IP,
                           MSG_NETWORK_Ip_Fragment);

    // allocate packet for fragmented part by taking care of original
    // packet and virtual packet.
    if (msg->packetSize >= fragmentedLen)
    {
        MESSAGE_PacketAlloc(
            node,
            tmpMsg,
            fragmentedLen ,
            TRACE_IP);

        // Now Make the fragmented Packet. with out virtual packet
        tempPayload = MESSAGE_ReturnPacket(tmpMsg);
        memcpy(tempPayload, payload, fragmentedLen);
        remaining_packetSize = msg->packetSize - fragmentedLen;
    }
    else
    {
        MESSAGE_PacketAlloc(
            node,
            tmpMsg,
            msg->packetSize,
            TRACE_IP);

            tempPayload = MESSAGE_ReturnPacket(tmpMsg);
            memcpy(tempPayload, payload, msg->packetSize);

            // Now Make the fragmented Packet. with virtual packet.
            MESSAGE_AddVirtualPayload(
                node,
                tmpMsg,
                fragmentedLen - msg->packetSize);
    }

    //------------------------------------------------------------------------//
    // QUALNET'S EXTRA OVERHEAD TO MANAGE BROKEN MESSAGE.
    //------------------------------------------------------------------------//
    tmpMsg->sequenceNumber = msg->sequenceNumber;
    tmpMsg->originatingProtocol = msg->originatingProtocol;
    tmpMsg->originatingNodeId = msg->originatingNodeId;
    tmpMsg->protocolType = msg->protocolType;
    tmpMsg->layerType = msg->layerType;
    tmpMsg->numberOfHeaders = msg->numberOfHeaders;
    tmpMsg->packetCreationTime = msg->packetCreationTime;
    tmpMsg->originatingNodeId = msg->originatingNodeId;
    tmpMsg->instanceId = msg->instanceId;
    tmpMsg->naturalOrder = msg->naturalOrder;

    for (int headerCounter = 0;
        headerCounter < msg->numberOfHeaders;
        headerCounter++)
    {
        tmpMsg->headerProtocols[headerCounter] =
            msg->headerProtocols[headerCounter];
        tmpMsg->headerSizes[headerCounter] = msg->headerSizes[headerCounter];
    }
    MESSAGE_CopyInfo(node, tmpMsg, msg);
    //------------------------------------------------------------------------//
    // END OF QUALNET SPECIFIC WORK.
    //------------------------------------------------------------------------//

    // Unfragmented part added here first fragment header and then ipv6 header

    NetworkIpAddHeader(
        node,
        tmpMsg,
        sourceAddress,
        destinationAddress,
        priority,
        protocol,
        hLim);



    ipHeader = (IpHeaderType *)MESSAGE_ReturnPacket(tmpMsg);
    IpHeaderSetIpMoreFrag(&(ipHeader->ipFragment), 1);
    ipHeader->ip_id = (UInt16)originalIpId;

    IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len), fragmentedLen + hlen);
    IpHeaderSetIpFragOffset(&(ipHeader->ipFragment), (UInt16)origFragOffSet);

#ifdef ADDON_BOEINGFCS
    // needed for distinguishing SDR control packets from others
    // in SINCGARS
    IpHeaderSetIpReserved(&ipHeader->ipFragment, IpHeaderGetIpReserved
      (originalIpHdr->ipFragment));
    ipHeader->ip_sum = originalIpHdr->ip_sum;
#endif
    ip->stats.ipFragsCreated++;

     // Now put it into the fragmented list.

    (*fragmentHead) = (ipFragmetedMsg*) MEM_malloc(sizeof(ipFragmetedMsg));
    (*fragmentHead)->next = NULL;
    (*fragmentHead)->msg = tmpMsg;
    fragmentChain = (*fragmentHead);

    // Loop through length of segment after first fragment,
    // make new header and copy data of each part and link onto chain.
    for (off = fragmentedLen;
        off < (packetLen - hlen); off += fragmentedLen)
    {
        BOOL ip_more_fragments = FALSE;
        tmpMsg = MESSAGE_Alloc(
                    node,
                    NETWORK_LAYER,
                    NETWORK_PROTOCOL_IP,
                    MSG_NETWORK_Ip_Fragment);

        offset = (unsigned short) off;
        offset = (unsigned short) (offset >> 3);
        if ((packetLen - hlen) <= off + fragmentedLen)
        {
            curPayloadLen = packetLen - hlen - off;
        }
        else
        {
            ip_more_fragments = TRUE;
            curPayloadLen = fragmentedLen;
        }

        // packet to curPayloadLen - hlen, because fragment and V6 header
        // size are allocated later but it will allocated when there is
        // no virtual packet else 0 byte is allocated
        // virtual packet is added.
        if (remaining_packetSize > curPayloadLen)
        {
            MESSAGE_PacketAlloc(node, tmpMsg,
                curPayloadLen,
                TRACE_IP);
            // Now Make the fragmented Packet. with out virtual packet
            tempPayload = MESSAGE_ReturnPacket(tmpMsg);
            memcpy(tempPayload, payload + off, curPayloadLen);
            remaining_packetSize = remaining_packetSize - curPayloadLen;
        }
        else
        {
            MESSAGE_PacketAlloc(node, tmpMsg,
                remaining_packetSize,
                TRACE_IP);
            if (remaining_packetSize > 0)
            {
                tempPayload = MESSAGE_ReturnPacket(tmpMsg);
                memcpy(tempPayload, payload + off, remaining_packetSize);

                // Now Make the fragmented Packet. with virtual packet.
                MESSAGE_AddVirtualPayload(
                    node,
                    tmpMsg,
                    curPayloadLen - remaining_packetSize);
                remaining_packetSize = 0;
            }
            else
            {
                // Now Make the fragmented Packet. with virtual packet.
                MESSAGE_AddVirtualPayload(
                    node,
                    tmpMsg,
                    curPayloadLen);
            }
        }

        // unfragmented part added here first fragment header and then ipv6 header

        NetworkIpAddHeader(
                node,
                tmpMsg,
                sourceAddress,
                destinationAddress,
                priority,
                protocol,
                hLim);



        // Set the ip headers fragment option porperly.
        ipHeader = (IpHeaderType *)MESSAGE_ReturnPacket(tmpMsg);

        if (ip_more_fragments || originalFragmented)
        {
           IpHeaderSetIpMoreFrag(&(ipHeader->ipFragment), TRUE);
        }
        ipHeader->ip_id = (UInt16)originalIpId;

        IpHeaderSetIpFragOffset (&(ipHeader->ipFragment),
                                 offset + origFragOffSet);

        IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),
                            curPayloadLen + hlen);



#ifdef ADDON_BOEINGFCS
        // needed for distinguishing SDR control packets from others
        // in SINCGARS
        IpHeaderSetIpReserved(&(ipHeader->ipFragment),
            IpHeaderGetIpReserved(originalIpHdr->ipFragment));
        ipHeader->ip_sum = originalIpHdr->ip_sum;
#endif
#ifdef ADDON_DB
        // Adding the info fields for the Fragmented message
        MESSAGE_CopyInfo(node, tmpMsg, msg);
#endif

#ifdef SENSOR_NETWORKS_LIB
        // Add the info in each fragment if its not already there
        if (zigbeeAppInfo)
        {
            ZigbeeAppInfo* tempZigbeeAppInfo = NULL;

            // check if the info is present in each fragment
            tempZigbeeAppInfo = (ZigbeeAppInfo*)
                           MESSAGE_ReturnInfo(tmpMsg,
                                              INFO_TYPE_ZigbeeApp_Info);
            if (!tempZigbeeAppInfo)
            {
                // info not present. Add the info in each fragment
                tempZigbeeAppInfo = (ZigbeeAppInfo*)MESSAGE_AddInfo(
                                                    node,
                                                    tmpMsg,
                                                    sizeof(ZigbeeAppInfo),
                                                    INFO_TYPE_ZigbeeApp_Info);
                memcpy(tempZigbeeAppInfo, zigbeeAppInfo, sizeof(ZigbeeAppInfo));
            }
        }
#endif // SENSOR_NETWORKS_LIB

        // Now put it in the fragment chain.
        fragmentChain->next = (ipFragmetedMsg*)
                                MEM_malloc(sizeof(ipFragmetedMsg));
        fragmentChain = fragmentChain->next;
        fragmentChain->msg = tmpMsg;
        fragmentChain->next = NULL;

        ip->stats.ipFragsCreated++;
        // QUALNET'S EXTRA OVERHEAD TO MANAGE BROKEN MESSAGE.
        tmpMsg->sequenceNumber = msg->sequenceNumber;

    } // end of creating all fragments

    MEM_free(originalIpHdr);
    ip->ipFragmentId++;
    ip->stats.ipFragOKs++;
    return TRUE;
} // end of fragmentation.


//---------------------------------------------------------------------------
// FUNCTION             : IpDeleteFragmentedPacket
// PURPOSE             :: This function deletes all the fragmented packet.
// PARAMETERS          ::
// +node                : Node* node    : Pointer to node
// +ipv6                : NetworkDataIp* ip: Ip data pointer of node.
// +prevFp              : IpFragQueue** prevFp: Pointer to the pointer of
//                                      previous fragment queue.
// +fp                  : IpFragQueue** fp: Pointer to the pointer of
//                                      fragment queue.
// RETURN               : None
// NOTES                : fragmented header processing function
//---------------------------------------------------------------------------

static void
IpDeleteFragmentedPacket(
    Node* node,
    NetworkDataIp* ip,
    IpFragQueue** prevFp,
    IpFragQueue** fp
#ifdef ADDON_DB
    , int interfaceIndex
#endif
    )
{
    IpFragQueue* tempFp = NULL;
    IpFragData* tempFrg = (*fp)->firstMsg;
    IpFragData* grbFrg = NULL;

    while (tempFrg)
    {
#ifdef ADDON_DB
        // Input the fragmented message received from the MAC layer.
        // Fragment error.
        HandleNetworkDBEvents(
            node,
            tempFrg->msg,
            interfaceIndex,
            "NetworkPacketDrop",
            "Fragment Hold Timer Expired",
            0,
            0,
            0,
            0);
#endif
        grbFrg = tempFrg;
        tempFrg = tempFrg->nextMsg;
#ifdef CYBER_LIB
        if (node->resourceManager)
        {
            node->resourceManager->packetFree(grbFrg->msg);
        }
#endif
        MESSAGE_Free(node, grbFrg->msg);
        MEM_free(grbFrg);
        ip->stats.ipReasmFails++;
        ip->stats.ipFragsInBuff--;
    }
    if ((*prevFp))
    {
        (*prevFp)->next = (*fp)->next;
    }
    else
    {
        ip->fragmentListFirst = (*fp)->next;
    }
    tempFp = (*fp);
    (*fp) = (*fp)->next;
    MEM_free(tempFp);
}


//---------------------------------------------------------------------------
// FUNCTION             : IpFragmentInput
// PURPOSE             :: Fragment header input processing
// PARAMETERS          ::
// +node                : Node* node    : Pointer to node
// +msg                 : Message* msg  : Pointer to Message Structure
// +interfaceId         : int interfaceId  : Value of the Interface index
//
// RETURN               : None
// NOTES                : fragmented header processing function
//---------------------------------------------------------------------------

Message*
IpFragmentInput(Node* node, Message* msg, int interfaceId, BOOL* isReassembled)
{
    char* payload = MESSAGE_ReturnPacket(msg);

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;

    IpHeaderType* ipHeader = (IpHeaderType *) payload;
    int packetLen = IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len);

    IpFragQueue* prevFp = NULL;
    IpFragQueue* fp = ip->fragmentListFirst;

    ActionData acnData;
    NetworkType netType = NETWORK_IPV4;
    Message* joinedMsg = NULL;

    ip->stats.ipReasmReqds++;

    // Reassemble, first pullup headers.
    if ((unsigned) packetLen < sizeof(IpHeaderType))
    {
        // STATS DB CODE
#ifdef ADDON_DB
        // Input the fragmented message received from the MAC layer.
        // Fragment error.
        HandleNetworkDBEvents(
            node,
            msg,
            interfaceId,
            "NetworkPacketDrop",
            "Fragments Reassemble Error",
            0,
            0,
            0,
            0);
#endif
        // Fragment Error.
            if (ip->isIcmpEnable && icmp->parameterProblemEnable)
            {
                 BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(
                                              node,
                                              msg,
                                              ipHeader->ip_src,
                                              interfaceId,
                                              ICMP_PARAMETER_PROBLEM,
                                              ICMP_PARAMETER_PROBLEM_CODE,
                                              PROBLEM_IN_TOTAL_LENGTH,
                                              0);
                 if (ICMPErrorMsgCreated)
                 {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                     char srcAddr[MAX_STRING_LENGTH];
                     IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                     printf("Node %d sending parameter problem message"
                            " to %s\n", node->nodeId, srcAddr);
#endif
                     (icmp->icmpErrorStat.icmpParameterProblemSent)++;
                 }
            }
        ip->stats.ipReasmFails++;
        *isReassembled = FALSE;
        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_START_FRAG_LENG_LESSTHAN_IPHEDEARTYPE;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_IN,
                         &acnData,
                         netType);

        MESSAGE_Free(node, msg);
//DERIUS
  //                ERROR_ReportError("during assembling\n");
//DERIUS

        return NULL;
    }

    // Make sure that fragments have a data length
    // that's a non-zero multiple of 8 bytes.
    if ((IpHeaderGetIpMoreFrag(ipHeader->ipFragment)) &&
        ((IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) <=
        sizeof(IpHeaderType)) || (((packetLen + sizeof(IpHeaderType))) & 0x7)
        != 0))
    {
        // STATS DB CODE
#ifdef ADDON_DB
        // Input the fragmented message received from the MAC layer.
        // Fragment error.
        HandleNetworkDBEvents(
            node,
            msg,
            interfaceId,
            "NetworkPacketDrop",
            "Fragments Reassemble Error",
            0,
            0,
            0,
            0);
#endif
         // Fragmentation Error.
        if (ip->isIcmpEnable && icmp->parameterProblemEnable)
        {
             BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(
                                          node,
                                          msg,
                                          ipHeader->ip_src,
                                          interfaceId,
                                          ICMP_PARAMETER_PROBLEM,
                                          ICMP_PARAMETER_PROBLEM_CODE,
                                          PROBLEM_IN_TOTAL_LENGTH,
                                          0);
             if (ICMPErrorMsgCreated)
             {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                 char srcAddr[MAX_STRING_LENGTH];
                 IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                 printf("Node %d sending parameter problem message to %s\n",
                                    node->nodeId, srcAddr);
#endif
                 (icmp->icmpErrorStat.icmpParameterProblemSent)++;
             }
        }
         ip->stats.ipReasmFails++;
         *isReassembled = FALSE;
        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_MORE_FRAG_IPLENG_LESSEQ_IPHEDEARTYPE;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_IN,
                         &acnData,
                         netType);

         MESSAGE_Free(node, msg);
//DERIUS
  //                ERROR_ReportError("during assembling\n");
//DERIUS
         return NULL;
    }

    while (fp)
    {
        // Look for queue of fragments of this datagram.
        if (ipHeader->ip_id == fp->ipFrg_id &&
            (ipHeader->ip_src == fp->ipFrg_src) &&
            (ipHeader->ip_dst == fp->ipFrg_dst))
        {
            break;
        }
        // Delete all the fragmented packets whose time has expired.
        if (getSimTime(node) >= fp->fragHoldTime)
        {
            //send the first fragment msg to generate the icmp error msg
            if (ip->isIcmpEnable && icmp->fragmentsReassemblyTimeoutEnable)
            {
                BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(
                                           node,
                                           fp->firstMsg->msg,
                                           fp->ipFrg_src,
                                           ANY_INTERFACE,
                                           ICMP_TIME_EXCEEDED,
                                           ICMP_FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
                                           0,
                                           0);
                if (ICMPErrorMsgCreated)
                {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(fp->ipFrg_src, srcAddr);
                    printf("Node %d sending fragment reassembly timeout"
                           " message to %s\n", node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpFragReassemblySent)++;
                }
            }
            IpDeleteFragmentedPacket(node, ip, &prevFp, &fp
#ifdef ADDON_DB
                , interfaceId
#endif
                );
        }// end of deleting.
        else
        {
            prevFp = fp;
            fp = fp->next;
        }
    }

    // Now add the fragment in the buffer.
    IpFragData* newFragMsg = NULL;
    if (fp)
    {
        if (getSimTime(node) >= fp->fragHoldTime)
        {
            //send the first fragment msg to generate the icmp error msg
            if (ip->isIcmpEnable && icmp->fragmentsReassemblyTimeoutEnable)
            {
                BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(
                                           node,
                                           fp->firstMsg->msg,
                                           fp->ipFrg_src,
                                           interfaceId,
                                           ICMP_TIME_EXCEEDED,
                                           ICMP_FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
                                           0,
                                           0);
                if (ICMPErrorMsgCreated)
                {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(fp->ipFrg_src, srcAddr);
                    printf("Node %d sending fragment reassembly timeout"
                           " message to %s\n", node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpFragReassemblySent)++;
                }
            }
            IpDeleteFragmentedPacket(node, ip, &prevFp, &fp
#ifdef ADDON_DB
                , interfaceId
#endif
                );

            return NULL;
        }
        IpFragData* temp = fp->firstMsg;
        char* tempPayload = MESSAGE_ReturnPacket(temp->msg);
        IpHeaderType* tempIpHeader = (IpHeaderType *)tempPayload;
        int msgFragOff = IpHeaderGetIpFragOffset(ipHeader->ipFragment) << 3;
        int currentFragOff =
            IpHeaderGetIpFragOffset(tempIpHeader->ipFragment)<< 3;

        // if this fragment offset is less than the starting fragment
        // offset so put it in the front
        if (currentFragOff > msgFragOff)
        {
            newFragMsg = (IpFragData*) MEM_malloc(sizeof(IpFragData));
            newFragMsg->nextMsg = fp->firstMsg;
            fp->firstMsg = newFragMsg;
        }
        else
        {
            IpFragData* prevTemp = temp;
            for (;
                temp != NULL; temp = temp->nextMsg)
               {
                   tempPayload = MESSAGE_ReturnPacket(temp->msg);
                   tempIpHeader = (IpHeaderType *)tempPayload;
                   msgFragOff = IpHeaderGetIpFragOffset(
                       ipHeader->ipFragment) << 3;
                   currentFragOff = IpHeaderGetIpFragOffset(
                       tempIpHeader->ipFragment) << 3;

                   if (currentFragOff == msgFragOff)
                   {
#ifdef ADDON_DB

                       HandleNetworkDBEvents(
                           node,
                           msg,
                           interfaceId,
                           "NetworkReceivePacketDrop",
                           "Duplicate Fragment",
                           0,
                           0,
                           0,
                           0);
#endif
                       MESSAGE_Free(node, msg);
                       return NULL;
                   }

                   if (currentFragOff > msgFragOff)
                   {
                       break;
                   }
                   prevTemp = temp;
               }
               newFragMsg = (IpFragData*) MEM_malloc(sizeof(IpFragData));
               newFragMsg->nextMsg = prevTemp->nextMsg;
               prevTemp->nextMsg = newFragMsg;
         }

    }
    else
    {
        if (!prevFp)
        {
            ip->fragmentListFirst =
                (IpFragQueue*) MEM_malloc(sizeof(IpFragQueue));
            fp = ip->fragmentListFirst;
        }
        else
        {
            prevFp->next =
                (IpFragQueue*) MEM_malloc(sizeof(IpFragQueue));
            fp = prevFp->next;
        }

        fp->firstMsg = (IpFragData*) MEM_malloc(sizeof(IpFragData));
        fp->firstMsg->nextMsg = NULL;
        newFragMsg = fp->firstMsg;
        fp->ipFrg_id = ipHeader->ip_id;
        fp->ipFrg_src = ipHeader->ip_src;
        fp->ipFrg_dst = ipHeader->ip_dst;
        fp->actualacketSize = 0;

        fp->totalFragmentSize = 0;

        fp->fragHoldTime = getSimTime(node) + ip->ipFragHoldTime;
        fp->next = NULL;
    }

    ip->stats.ipFragsInBuff++;
    newFragMsg->msg = msg;

#ifdef CYBER_LIB
    if (node->resourceManager)
    {
        node->resourceManager->packetAllocated(msg);
    }
#endif

    int mff = IpHeaderGetIpMoreFrag(ipHeader->ipFragment);
    if (!mff)
    {
        fp->actualacketSize =
            (IpHeaderGetIpFragOffset(ipHeader->ipFragment) << 3) +
            IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len);
    }

    fp->totalFragmentSize += IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) -
                             (sizeof(IpHeaderType));

    // Not all the fragment packet received yet so wait for all to
    // come till atleast hold time
    if (!fp->actualacketSize ||
        ((fp->actualacketSize - (sizeof(IpHeaderType))) != fp->totalFragmentSize))
    {
          *isReassembled = FALSE;
          return NULL;
    }
    else // This is the last fragment packet so try to ressemble it.
    {
        if (fp)
        {
            // Join all the  fragmented packets then return.
            joinedMsg = IpFragementReassamble(node, msg, fp, interfaceId);

            // Delete the fragment queue head
            if (ip->fragmentListFirst == fp)
            {
                ip->fragmentListFirst = fp->next;
            }
            else
            {
                prevFp->next = fp->next;
            }
            MEM_free(fp);

            if (!joinedMsg)
            {
                *isReassembled = FALSE;
                return NULL;
            }
        }

    }
    ip->stats.ipPacketsAfterFragsReasm++;
    *isReassembled = TRUE;
    return joinedMsg;
}


//---------------------------------------------------------------------------
// FUNCTION             : IpFragementReassamble
// PURPOSE             :: Take incoming datagram fragment and try to
//                        reassemble it into whole datagram.  If a chain for
//                        reassembly of this datagram already exists, then it
//                        is given as fp; otherwise have to make a chain.
// PARAMETERS          ::
// +node                : Node* node    : Pointer to Node
// +msg                 : Message* msg  : Pointer to Message Sturcture
// +fp                  : Ipv6FragQueue* fp: Pointer to fragmentation queue.
// RETURN               : Message*  : Pointer to the Message Structure
// NOTES                : Ressambling message function
//---------------------------------------------------------------------------

Message*
IpFragementReassamble(Node* node, Message* msg, IpFragQueue* fp, int interfaceId)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    char* payload = NULL;
    int packetLen = 0;

    int totalLength = 0;
    int totalVirtualPackeLength = 0;
    int assemblePacketLength = 0;
    char* joinedPayload = NULL;
    int lengthToCopy = 0;
    int reassError = 0;
    int hLen = sizeof(IpHeaderType);
    int originalIpId;

    IpFragData* tempFragData = NULL;
    IpFragData* prevFragData = NULL;
    Message* joinedMsg = NULL;

    NodeAddress sourceAddress;
    NodeAddress destinationAddress;
    TosType priority = 0;
    unsigned char protocol;
    unsigned int hLim;

    ActionData acnData;
    NetworkType netType = NETWORK_IPV4;
#ifdef ADDON_BOEINGFCS
    BOOL ipReserved = 0;
    unsigned short ipSum = 0;
#endif

    // First calculate the total packet length to produce the large packet.

    tempFragData = fp->firstMsg;
    // Calculate the first fragment Information.
    payload = MESSAGE_ReturnPacket(tempFragData->msg);
    IpHeaderType* ipHeader = (IpHeaderType*)payload;

    originalIpId = ipHeader->ip_id;
#ifdef ADDON_BOEINGFCS
    // keep a copy of the first frag's reserveBit and ip_sum for SDR
    ipReserved = IpHeaderGetIpReserved(ipHeader->ipFragment);
    ipSum = ipHeader->ip_sum;
#endif
    // Starting fragment offset should be zero.
    if (((IpHeaderGetIpFragOffset(ipHeader->ipFragment)) << 3) != 0)
    {
        reassError = 1;
        //drop all the fragment packets and return
        tempFragData = fp->firstMsg;
        while (tempFragData)
        {
            // STATS DB CODE
#ifdef ADDON_DB
            // Fragment error.
            HandleNetworkDBEvents(
                node,
                tempFragData->msg,
                interfaceId,
                "NetworkPacketDrop",
                "Fragments Reassemble Error",
                0,
                0,
                0,
                0);
#endif
            prevFragData = tempFragData;
            tempFragData = tempFragData->nextMsg;
            ip->stats.ipReasmFails++;
            ip->stats.ipFragsInBuff--;

            //Trace drop
            acnData.actionType = DROP;
            acnData.actionComment = DROP_START_FRAGMENT_OFFSET_NOT_ZERO;
            TRACE_PrintTrace(node,
                             prevFragData->msg,
                             TRACE_NETWORK_LAYER,
                             PACKET_IN,
                             &acnData,
                             netType);
            if (ip->isIcmpEnable && icmp->parameterProblemEnable)
            {
                 BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(
                                              node,
                                              prevFragData->msg,
                                              ipHeader->ip_src,
                                              interfaceId,
                                              ICMP_PARAMETER_PROBLEM,
                                              ICMP_PARAMETER_PROBLEM_CODE,
                                              PROBLEM_IN_FLAGS_OR_FRAGOFFSET,
                                              0);
                 if (ICMPErrorMsgCreated)
                 {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                     char srcAddr[MAX_STRING_LENGTH];
                     IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                     printf("Node %d sending parameter problem message"
                            " to %s\n", node->nodeId, srcAddr);
#endif
                     (icmp->icmpErrorStat.icmpParameterProblemSent)++;
                 }
            }


#ifdef CYBER_LIB
            if (node->resourceManager)
            {
                node->resourceManager->packetFree(prevFragData->msg);
            }
#endif
            MESSAGE_Free(node, prevFragData->msg);
            MEM_free(prevFragData);
        }
        return NULL;
    }

    totalLength = 0;
    totalVirtualPackeLength = 0;

    // Then calculate packetsize rest of the fragmented packets.
    while (tempFragData->nextMsg != NULL)
    {
        payload = MESSAGE_ReturnPacket(tempFragData->msg);
        ipHeader = (IpHeaderType*)payload;
        int currentFragOff =
            IpHeaderGetIpFragOffset(ipHeader->ipFragment) << 3;

        // Check for the proper offset.
        if (currentFragOff != (totalLength + totalVirtualPackeLength))
        {
            reassError = 1;
            break;
        }

        totalLength += tempFragData->msg->packetSize - (sizeof(IpHeaderType));

        totalVirtualPackeLength += tempFragData->msg->virtualPayloadSize;

        assemblePacketLength += IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len)
                                - (sizeof(IpHeaderType));
        tempFragData = tempFragData->nextMsg;
    }

    // Now add the last packet and virtual packet length
    payload = MESSAGE_ReturnPacket(tempFragData->msg);
    ipHeader = (IpHeaderType*)payload;

    if ((int) (IpHeaderGetIpFragOffset(ipHeader->ipFragment) << 3) !=
        (assemblePacketLength))
    {
        reassError = 1;
    }
    // Last fragment should have more faragment flag as zero.
    int mff = IpHeaderGetIpMoreFrag(ipHeader->ipFragment);
    if (mff)
    {
        reassError = 1;
    }

    totalLength += tempFragData->msg->packetSize - (sizeof(IpHeaderType));
    totalVirtualPackeLength += tempFragData->msg->virtualPayloadSize;
    assemblePacketLength += IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) -
                            (sizeof(IpHeaderType));

    if (reassError)
    {
        // Drop all the fragment packets and return
        tempFragData = fp->firstMsg;
        while (tempFragData)
        {
            // STATS DB CODE
#ifdef ADDON_DB
            // Fragment error.
            HandleNetworkDBEvents(
                node,
                tempFragData->msg,
                interfaceId,
                "NetworkPacketDrop",
                "Fragments Reassemble Error",
                0,
                0,
                0,
                0);
#endif
            prevFragData = tempFragData;
            tempFragData = tempFragData->nextMsg;
            ip->stats.ipReasmFails++;
            ip->stats.ipFragsInBuff--;
            //Trace drop
            acnData.actionType = DROP;
            acnData.actionComment = DROP_ALLFRAGMENT_NOT_COLLECTED;
            TRACE_PrintTrace(node,
                             prevFragData->msg,
                             TRACE_NETWORK_LAYER,
                             PACKET_IN,
                             &acnData,
                             netType);
            if (ip->isIcmpEnable && icmp->parameterProblemEnable)
            {
                 BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(
                                              node,
                                              prevFragData->msg,
                                              ipHeader->ip_src,
                                              interfaceId,
                                              ICMP_PARAMETER_PROBLEM,
                                              ICMP_PARAMETER_PROBLEM_CODE,
                                              PROBLEM_IN_FLAGS_OR_FRAGOFFSET,
                                              0);
                 if (ICMPErrorMsgCreated)
                 {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                     char srcAddr[MAX_STRING_LENGTH];
                     IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                     printf("Node %d sending parameter problem message"
                            " to %s\n", node->nodeId, srcAddr);
#endif
                     (icmp->icmpErrorStat.icmpParameterProblemSent)++;
                 }
            }

#ifdef CYBER_LIB
            if (node->resourceManager)
            {
                node->resourceManager->packetFree(prevFragData->msg);
            }
#endif
            MESSAGE_Free(node, prevFragData->msg);
            MEM_free(prevFragData);
        }
        return NULL;
    }

    //Now allocate joined Message data;
    joinedMsg = MESSAGE_Alloc(node,
                           NETWORK_LAYER,
                           NETWORK_PROTOCOL_IP,
                           MSG_NETWORK_Ip_Fragment);

    MESSAGE_PacketAlloc(node, joinedMsg, totalLength, TRACE_IP);

    // Now Make the reassemble Packet. with virtual packet.
    MESSAGE_AddVirtualPayload(node, joinedMsg, totalVirtualPackeLength);

    joinedPayload = MESSAGE_ReturnPacket(joinedMsg);

    // Now copy all the messages.
    tempFragData = fp->firstMsg;

    // Remove the Ip header from the original packet.
    NetworkIpRemoveIpHeader(
        node,
        tempFragData->msg,
        &sourceAddress,
        &destinationAddress,
        &priority,
        &protocol,
        &hLim);

    payload = MESSAGE_ReturnPacket(tempFragData->msg);
    //packetLen = MESSAGE_ReturnPacketSize(tempFragData->msg);
    packetLen = tempFragData->msg->packetSize;

    lengthToCopy = packetLen;
    memcpy(joinedPayload, payload, lengthToCopy);
    ip->stats.ipReasmOKs++;
    ip->stats.ipFragsInBuff--;
//------------------------------------------------------------------------//
// QUALNET'S EXTRA OVERHEAD TO MANAGE TO JOIN MESSAGE.
//------------------------------------------------------------------------//
    joinedMsg->sequenceNumber = tempFragData->msg->sequenceNumber;
    joinedMsg->originatingProtocol = tempFragData->msg->originatingProtocol;
    joinedMsg->originatingNodeId = tempFragData->msg->originatingNodeId;
    joinedMsg->protocolType = tempFragData->msg->protocolType;
    joinedMsg->layerType = tempFragData->msg->layerType;
    joinedMsg->numberOfHeaders = tempFragData->msg->numberOfHeaders;
    joinedMsg->packetCreationTime = tempFragData->msg->packetCreationTime;
    joinedMsg->originatingNodeId = tempFragData->msg->originatingNodeId;
    joinedMsg->instanceId = tempFragData->msg->instanceId;
    joinedMsg->naturalOrder = tempFragData->msg->naturalOrder;

    for (int headerCounter = 0;
        headerCounter < tempFragData->msg->numberOfHeaders;
        headerCounter++)
    {
        joinedMsg->headerProtocols[headerCounter] =
            tempFragData->msg->headerProtocols[headerCounter];
        joinedMsg->headerSizes[headerCounter] =
            tempFragData->msg->headerSizes[headerCounter];

    }
    MESSAGE_CopyInfo(node, joinedMsg, tempFragData->msg);
//------------------------------------------------------------------------//
// END OF QUALNET SPECIFIC WORK.
//------------------------------------------------------------------------//

    // Go for next processing.
    joinedPayload += lengthToCopy;
    prevFragData = tempFragData;
    tempFragData = tempFragData->nextMsg;

#ifdef CYBER_LIB
    if (node->resourceManager)
    {
        node->resourceManager->packetFree(prevFragData->msg);
    }
#endif

    MESSAGE_Free(node, prevFragData->msg);
    MEM_free(prevFragData);

    while (tempFragData != NULL)
    {
         payload = MESSAGE_ReturnPacket(tempFragData->msg);

         packetLen = tempFragData->msg->packetSize;
         lengthToCopy = packetLen - hLen;

         if (lengthToCopy > 0)
         {
             memcpy(joinedPayload, payload + hLen, lengthToCopy);
             joinedPayload += lengthToCopy;
         }

         ip->stats.ipReasmOKs++;
         ip->stats.ipFragsInBuff--;
         prevFragData = tempFragData;
         tempFragData = tempFragData->nextMsg;

#ifdef CYBER_LIB
         if (node->resourceManager)
         {
             node->resourceManager->packetFree(prevFragData->msg);
         }
#endif // CYBER_LIB
         MESSAGE_Free(node, prevFragData->msg);
         MEM_free(prevFragData);
    }

    NetworkIpAddHeader(
        node,
        joinedMsg,
        sourceAddress,
        destinationAddress,
        priority,
        protocol,
        hLim);

    ipHeader = (IpHeaderType*)MESSAGE_ReturnPacket(joinedMsg);
    ipHeader->ip_id = (UInt16)originalIpId;

#ifdef ADDON_BOEINGFCS
    // for SDR to distiguish SDRcontrol packet or routed packet
    // so restore the original value for REserve bit and ip_sum
    IpHeaderSetIpReserved(&(ipHeader->ipFragment), ipReserved);
    ipHeader->ip_sum = ipSum;
#endif
    //MESSAGE_Free(node, msg);
    return joinedMsg;
}

//-----------------------------------------------------------------------------
// End of fragmentation related code.
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpQueuePeekWithIndex()
// PURPOSE      Like NetworkIpQueueTopPacket(), except a index to the
//            . packet to peek at is given. Note that the message
//              containing the packet is not copied; the contents may
//              (inadvertently or not) be directly modified.
// PARAMETERS   Node *node
//                  Pointer to node.
//              SchedulerType *scheduler
//                  queue to get top packet from.
//              int msgIndex
//                  index to message
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int *outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int *networkType
//                  Whether packet is associated with an IP network, Link-16
//                  nework, etc...
//              QueuePriorityType *priority
//                  Storage for priority of packet.
//              interfaceIndex : Parameter added for checking LLC
//                 enabled. This has beem done as part of IP-MPLS integration
// RETURN       TRUE if there is a packet, FALSE otherwise.
//-----------------------------------------------------------------------------

BOOL NetworkIpQueuePeekWithIndex(
    Node *node,
    Scheduler *scheduler,
    int msgIndex,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nextHopMacAddr,
    int *outgoingInterface,
    int *networkType,
    QueuePriorityType *priority,
    int interfaceIndex)
{
    QueuePriorityType queuePriority = ALL_PRIORITIES;
    BOOL isPktRetrieved = FALSE;
    QueuedPacketInfo *infoPtr;

    isPktRetrieved = (*scheduler).retrieve(ALL_PRIORITIES,
                                            msgIndex,
                                            msg,
                                            &queuePriority,
                                            PEEK_AT_NEXT_PACKET,
                                            getSimTime(node));

    if (isPktRetrieved)
    {
        ERROR_Assert(*msg != NULL, "Cannot retrieve packet");
        // Retuning Queue priority
        *priority = queuePriority;
        // This code has been aded as part of IP-MPLS integration
#ifdef ENTERPRISE_LIB
        if (LlcIsEnabled(node, interfaceIndex))
        {
                LlcHeader* llc;
                llc = (LlcHeader*) MESSAGE_ReturnPacket((*msg));
                if (llc->etherType == PROTOCOL_TYPE_MPLS)
                {
                    TackedOnInfoWhileInMplsQueueType* infoPtr = NULL;
                    infoPtr = (TackedOnInfoWhileInMplsQueueType*)
                                                  (MESSAGE_ReturnInfo(*msg));

                    // Copying Next Hop Mac Address
                    *nextHopAddress = infoPtr->nextHopAddress;

                    // Copying Next Hop Mac Address byte, type, length.
                    if (nextHopMacAddr->byte == NULL)
                    {
                        nextHopMacAddr->byte =
                              (unsigned char*) MEM_malloc(infoPtr->hwLength);
                    }
                    memcpy(nextHopMacAddr->byte,
                           infoPtr->macAddress,
                           infoPtr->hwLength);
                    nextHopMacAddr->hwLength = infoPtr->hwLength;
                    nextHopMacAddr->hwType = infoPtr->hwType;
                    return isPktRetrieved ;
                }
         }
#endif // ENTERPRISE_LIB
        infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo((*msg));

        // Retuning Queue priority
        *priority = queuePriority;
        *nextHopAddress = infoPtr->nextHopAddress;

        nextHopMacAddr->hwLength = infoPtr->hwLength;
        nextHopMacAddr->hwType = infoPtr->hwType;
        //Added to avoid double memory allocation and hence memory leak
        if (nextHopMacAddr->byte == NULL)
        {
            nextHopMacAddr->byte = (unsigned char*) MEM_malloc(
                          sizeof(unsigned char)*infoPtr->hwLength);
        }
        memcpy(nextHopMacAddr->byte,infoPtr->macAddress,infoPtr->hwLength);
        *outgoingInterface = infoPtr->outgoingInterface;
        *networkType = infoPtr->networkType;
    }

    return isPktRetrieved;
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueuePeekWithIndex()
// PURPOSE      Like NetworkIpQueueTopPacket(), except a index to the
//            . packet to peek at is given. Note that the message
//              containing the packet is not copied; the contents may
//              (inadvertently or not) be directly modified.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              int msgIndex
//                  Index of message in queue.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              QueuePriorityType *priority
//                  Storage for priority of packet.
// RETURN       TRUE if there is a packet, FALSE otherwise.
//
// NOTES        This function is called by MAC_OutputQueueTopPacket()
//              (mac/mac.pc), which itself is called from
//              mac/mac_802_11.pc and other MAC protocol source files.
//
//              This function will assert false if the scheduler cannot
//              return an IP packet for whatever reason.
//-----------------------------------------------------------------------------

BOOL NetworkIpOutputQueuePeekWithIndex(
    Node *node,
    int interfaceIndex,
    int msgIndex,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nextHopMacAddr,
    QueuePriorityType *priority)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *scheduler = NULL;
    int outgoingInterface;
    int networkType;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    return NetworkIpQueuePeekWithIndex(node,
                                   scheduler,
                                   msgIndex,
                                   msg,
                                   nextHopAddress,
                                   nextHopMacAddr,
                                   &outgoingInterface,
                                   &networkType,
                                   priority,
                                   interfaceIndex);
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueDequeuePacketWithIndex()
// PURPOSE      Same as NetworkIpOutputQueueDequeuePacket(), except the
//              packet dequeued is specified by an index,
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              int msgIndex
//                  Index of packet.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              int *networkType
//                  Type of network (IP, Link-16, ...) used to route packet.
// RETURN       TRUE if dequeued successfully, FALSE otherwise.
//
// NOTES        This function is called by
//              MAC_OutputQueueDequeuePacketWithIndex() (mac/mac.pc),
//              which itself is called from mac/mac_802_11.pc and other
//              MAC protocol source files.
//
//              This function will assert false if the scheduler cannot
//              return an IP packet for whatever reason.
//-----------------------------------------------------------------------------

BOOL NetworkIpOutputQueueDequeuePacketWithIndex(
    Node *node,
    int interfaceIndex,
    int msgIndex,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nextHopMacAddr,
    int *networkType)
{
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;
    Scheduler *scheduler = NULL;
    QueuePriorityType queuePriority = ALL_PRIORITIES;
    QueuedPacketInfo *infoPtr;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    if ((*scheduler).retrieve(ALL_PRIORITIES, msgIndex, msg,
                &queuePriority, DEQUEUE_PACKET, getSimTime(node)))
    {
        ERROR_Assert(*msg != NULL, "Cannot dequeue packet");

        infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo((*msg));

        *nextHopAddress = infoPtr->nextHopAddress;

         nextHopMacAddr->hwLength = infoPtr->hwLength;
        nextHopMacAddr->hwType = infoPtr->hwType;

        //Added to avoid double memory allocation and hence memory leak
        if (nextHopMacAddr->byte == NULL)
        {
            nextHopMacAddr->byte = (unsigned char*) MEM_malloc(
                             sizeof(unsigned char)*infoPtr->hwLength);
        }
        memcpy(nextHopMacAddr->byte,infoPtr->macAddress,infoPtr->hwLength);
        *networkType = infoPtr->networkType;

        if ((*msg)->headerProtocols[(*msg)->numberOfHeaders-1] == TRACE_LLC)
        {
            MESSAGE_RemoveHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);

        //Trace dequeue
        ActionData acn;
        acn.actionType = DEQUEUE;
        acn.actionComment = NO_COMMENT;
        acn.pktQueue.interfaceID = (unsigned short) interfaceIndex;
        acn.pktQueue.queuePriority = (unsigned char) queuePriority;
            TRACE_PrintTrace(node,
                            *msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_OUT,
                            &acn,
                            NetworkIpGetInterfaceType(node, interfaceIndex));


            MESSAGE_AddHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);
        }

        else
        {
            //Trace dequeue
            ActionData acn;
            acn.actionType = DEQUEUE;
            acn.actionComment = NO_COMMENT;
            acn.pktQueue.interfaceID = (unsigned short) interfaceIndex;
            acn.pktQueue.queuePriority = (unsigned char) queuePriority;
            TRACE_PrintTrace(node,
                            *msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_OUT,
                            &acn,
                            NetworkIpGetInterfaceType(node, interfaceIndex));
         }

        (*scheduler).collectGraphData((int) queuePriority,
                                MESSAGE_ReturnPacketSize((*msg)),
                                TIME_getSimTime(node));

#if 0
        //GuiStart
        if (node->guiOption == TRUE)
        {
            GUI_QueueDequeuePacket(node->nodeId, GUI_NETWORK_LAYER,
                                   interfaceIndex, queuePriority,
                                   MESSAGE_ReturnPacketSize((*msg)),
                                   getSimTime(node) + getSimStartTime(node));
        }
        //GuiEnd
#endif
        return TRUE;
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// Network-layer dequeueing
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpOutputQueueDequeuePacket()
// PURPOSE      Calls the packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
//              Addded function for IP+MPLS
// PARAMETERS   Node *node
//                  Pointer to node.
//              int interfaceIndex
//                  Index of interface.
//              Message **msg
//                  Storage for pointer to message with IP packet.
//              NodeAddress *nextHopAddress
//                  Storage for packet's next hop address.
//              QueuePriorityType *userPriority
//                  Storage for user priority of packet.
//              posInQueue
//                  Position of packet in Queue.
//                  Added as part of IP-MPLS integration
// RETURN       TRUE if dequeued successfully, FALSE otherwise.
//
// NOTES        This function is called by
//              MAC_OutputQueueDequeuePacket() (mac/mac.pc), which itself
//              is called from mac/mac_802_11.pc and other MAC protocol
//              source files.
//
//              This function will assert false if the scheduler cannot
//              return an IP packet for whatever reason.
//-----------------------------------------------------------------------------

BOOL NetworkIpOutputQueueDequeuePacket(
    Node *node,
    int interfaceIndex,
    Message **msg,
    NodeAddress *nextHopAddress,
    MacHWAddress *nexthopmacAddr,
    int *networkType,
    QueuePriorityType *userPriority,
    int posInQueue)

{
    BOOL dequeued = FALSE;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *scheduler = NULL;
    TosType userTos = ALL_PRIORITIES;
    int outgoingInterface;

    ERROR_Assert(
        interfaceIndex >= 0 && interfaceIndex < node->numberInterfaces,
        "Invalid interface index");

    scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    dequeued = NetworkIpQueueDequeuePacket(node,
                                           scheduler,
                                           msg,
                                           nextHopAddress,
                                           nexthopmacAddr,
                                           &outgoingInterface,
                                           networkType,
                                           &userTos,
                                           posInQueue);
    if (dequeued)
    {
        // Pass user priority (precedence - 3 bit field) to mac
        *userPriority = (TosType) (userTos >> 5);

        QueuePriorityType  queuePriority = 0;
        queuePriority = (QueuePriorityType) GetQueuePriorityFromUserTos(
                                     node, userTos, (*scheduler).numQueue());
        (*scheduler).collectGraphData(queuePriority,
                        MESSAGE_ReturnPacketSize((*msg)),
                        TIME_getSimTime(node));

         if ((*msg)->headerProtocols[(*msg)->numberOfHeaders-1] == TRACE_LLC)
        {
            MESSAGE_RemoveHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);

        //Trace dequeue
        ActionData acn;
        acn.actionType = DEQUEUE;
        acn.actionComment = NO_COMMENT;
            acn.pktQueue.interfaceID = (unsigned short) interfaceIndex;
            acn.pktQueue.queuePriority = (unsigned char) queuePriority;
            TRACE_PrintTrace(node,
                            *msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_OUT,
                            &acn,
                            NetworkIpGetInterfaceType(node, interfaceIndex));
            MESSAGE_AddHeader(node, *msg, LLC_HEADER_SIZE, TRACE_LLC);
        }
        else
        {
             //Trace dequeue
            ActionData acn;
            acn.actionType = DEQUEUE;
            acn.actionComment = NO_COMMENT;
            acn.pktQueue.interfaceID = (unsigned short) interfaceIndex;
            acn.pktQueue.queuePriority = (unsigned char) queuePriority;
            TRACE_PrintTrace(node,
                            *msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_OUT,
                            &acn,
                            NetworkIpGetInterfaceType(node, interfaceIndex));
        }

        //GuiStart
        if (node->guiOption == TRUE)
        {
            unsigned queuePriority = GetQueuePriorityFromUserTos(
                                   node, userTos, (*scheduler).numQueue());
            GUI_QueueDequeuePacket(node->nodeId, GUI_NETWORK_LAYER,
                                   interfaceIndex, queuePriority,
                                   MESSAGE_ReturnPacketSize((*msg)),
                                   getSimTime(node));
        }
        //GuiEnd
    }

    return dequeued;
}



// /**
// API                 :: NetworkIpGetBandwidth
// LAYER               :: Network
// PURPOSE             :: getting the bandwidth information
// PARAMETERS          ::
// + node               : Node*   : the node who's bandwidth is needed.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: Int64: inverted bandwidth
// ASSUMPTION   :     Bandwidth read from interface is in from of bps unit.
//                    To invert the bandwidth we use the equation
//                    10000000 / bandwidth. Where bandwidth is in Kbps unit.
// **/
Int64 NetworkIpGetBandwidth(Node* node, int interfaceIndex)
{
    ERROR_Assert((interfaceIndex >= 0) &&
                 (interfaceIndex <= node->numberInterfaces),
                 "Invalid Interface Index !!!");

    if (TunnelIsVirtualInterface(node, interfaceIndex))
    {
        return getTunnelBandwidth(node, interfaceIndex);
    }
    else
    {
        return node->macData[interfaceIndex]->bandwidth;
    }
}

// /**
// API                 :: NetworkIpGetPropDelay
// LAYER               :: Network
// PURPOSE             :: getting the propagation delay information
// PARAMETERS          ::
// + node               : Node*   : the node who's bandwidth is needed.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: clocktype: propagation delay
// ASSUMPTION           : Array is exactly 3-byte long.
// **/
clocktype NetworkIpGetPropDelay(Node* node, int interfaceIndex)
{
    ERROR_Assert((interfaceIndex >= 0) &&
                 (interfaceIndex <= node->numberInterfaces),
                 "Invalid Interface Index !!!");

    if (TunnelIsVirtualInterface(node, interfaceIndex))
    {
        return getTunnelPropDelay(node, interfaceIndex);
    }
    else
    {
        return node->macData[interfaceIndex]->propDelay;
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpParseAndSetRoutingProtocolType()
// PURPOSE      Parse ROUTING-PROTOCOL parameter and set routingProtocolType.
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
//-----------------------------------------------------------------------------
void NetworkIpParseAndSetRoutingProtocolType(
    Node* node,
    const NodeInput* nodeInput)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    BOOL retVal;
    char protocolString[MAX_STRING_LENGTH];
    int i;

    NetworkRoutingProtocolType routingProtocolType;
    NetworkRoutingProtocolType multicastProtocolType;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (NetworkIpGetInterfaceType(node, i) == NETWORK_IPV4
            || NetworkIpGetInterfaceType(node, i) == NETWORK_DUAL)
        {

            routingProtocolType = ROUTING_PROTOCOL_BELLMANFORD;

            IO_ReadString(
                node->nodeId,
                NetworkIpGetInterfaceAddress(node, i),
                nodeInput,
                "ROUTING-PROTOCOL",
                &retVal,
                protocolString);

            if (retVal)
            {
#ifdef WIRELESS_LIB
                if (strcmp(protocolString, "LAR1") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_LAR1;
                }
                else if (strcmp(protocolString, "AODV") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_AODV;
                }
                else if (strcmp(protocolString, "DYMO") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_DYMO;
                }
                else if (strcmp(protocolString, "DSR") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_DSR;
                }
                else
                if (strcmp(protocolString, "FSRL") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_FSRL;
                }
                else
                if (strcmp(protocolString, "STAR") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_STAR;
                }
                else if (strcmp(protocolString, "IARP") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_IARP;
                }
                else if (strcmp(protocolString, "ZRP") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_ZRP;
                }
                else if (strcmp(protocolString, "IERP") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_IERP;
                }
#else // WIRELESS_LIB
                if ((strcmp(protocolString, "LAR1") == 0) ||
                    (strcmp(protocolString, "AODV") == 0) ||
                    (strcmp(protocolString, "DYMO") == 0) ||
                    (strcmp(protocolString, "DSR") == 0) ||
                    (strcmp(protocolString, "FSRL") == 0) ||
                    (strcmp(protocolString, "STAR") == 0) ||
                    (strcmp(protocolString, "IARP") == 0) ||
                    (strcmp(protocolString, "ZRP") == 0) ||
                    (strcmp(protocolString, "IERP") == 0))
                {
                    ERROR_ReportMissingLibrary(protocolString, "Wireless");
                }
#endif // WIRELESS_LIB
#ifdef ENTERPRISE_LIB
                else if (strcmp(protocolString, "OSPFv2") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_OSPFv2;
                }
                else
                if (strcmp(protocolString, "IGRP") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_IGRP;
                }
                else
                if (strcmp(protocolString, "EIGRP") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_EIGRP;
                }
#else // ENTERPRISE_LIB
                else if ((strcmp(protocolString, "OSPFv2") == 0) ||
                    (strcmp(protocolString, "IGRP") == 0) ||
                    (strcmp(protocolString, "EIGRP") == 0))
                {
                    ERROR_ReportMissingLibrary(protocolString,
                        "multimedia_enterprise");
                }
#endif // ENTERPRISE_LIB
#ifdef ADDON_BOEINGFCS
                else if ((strcmp(protocolString, "ROUTING-CES-SRW") == 0)
                            ||(strcmp(protocolString, "SRW-ROUTING") == 0))
                {
                    routingProtocolType = ROUTING_PROTOCOL_CES_SRW;
                }
                else
                if (strcmp(protocolString, "ROUTING-CES-ROSPF") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_OSPFv2;
                }
                else
                if (strcmp(protocolString, "ROUTING-CES-SDR") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_CES_SDR;
                }
#endif
                else if (retVal && strcmp(protocolString, "ODR") == 0)
                {
#ifdef MILITARY_RADIOS_LIB
                    routingProtocolType = ROUTING_PROTOCOL_ODR;
#else // MILITARY_RADIOS_LIB
                    ERROR_ReportMissingLibrary(protocolString,
                                                    "Military Radios\n");
#endif // MILITARY_RADIOS_LIB
        }
                else if (retVal && strcmp(protocolString, "SDR") == 0)
                {
#ifdef MILITARY_RADIOS_LIB
                    routingProtocolType = ROUTING_PROTOCOL_SDR;
#else // MILITARY_RADIOS_LIB
                    ERROR_ReportMissingLibrary(protocolString,
                                                    "Military Radios\n");
#endif // MILITARY_RADIOS_LIB
                }
#ifdef CYBER_LIB
                else
                if (strcmp(protocolString, "ANODR") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_ANODR;
                }
#else //CYBER_LIB
                else if (strcmp(protocolString, "ANODR") == 0)
                {
                    ERROR_ReportMissingLibrary(protocolString, "CYBER_LIB");
                }
#endif // CYBER_LIB
                else if (strcmp(protocolString, "BELLMANFORD") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_BELLMANFORD;
                }
#ifdef WIRELESS_LIB
                else if (strcmp(protocolString, "FISHEYE") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_FISHEYE;
                }
                else if (strcmp(protocolString, "OLSR-INRIA") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_OLSR_INRIA;
                }
                else if (strcmp(protocolString, "OLSRv2-NIIGATA") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_OLSRv2_NIIGATA;
                }
#else // WIRELESS_LIB
                else if ((strcmp(protocolString, "FISHEYE") == 0) ||
                    (strcmp(protocolString, "OLSR-INRIA") == 0) ||
                    (strcmp(protocolString, "OLSRv2-NIIGATA") == 0))
                {
                    ERROR_ReportMissingLibrary(protocolString, "Wireless");
                }
#endif // WIRELESS_LIB
                else if (strcmp(protocolString, "RIP") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_RIP;
                }
                else
                if (strcmp(protocolString, "NONE") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_NONE;
                    // Allow a node to specify explicitly that routing
                    // protocols are not used.
                }
                else
                {
                    char buff[MAX_STRING_LENGTH];
                    sprintf(buff, "%s is not a valid IPv4 ROUTING-PROTOCOL"
                            " specified on interfaceIndex %d of node %d,"
                            " BELLMAN-FORD is used by default.\n",
                            protocolString, i, node->nodeId);
                    ERROR_ReportWarning(buff);
                }
            }
            else if (IPV4_ROUTING_DISABLED_WARNING)
            {
                char buff[MAX_STRING_LENGTH];
                sprintf(buff, "No IPv4 ROUTING-PROTOCOL is "
                "specified on interfaceIndex %d of node %d,"
                "BELLMAN-FORD is used by default.\n",
                i, node->nodeId);
                ERROR_ReportWarning(buff);
            }

            NetworkIpAddUnicastRoutingProtocolType(
                node,
                routingProtocolType,
                i,
                NETWORK_IPV4);

            IO_ReadString(node->nodeId,
                 NetworkIpGetInterfaceAddress(node, i),
                 nodeInput,
                 "GROUP-MANAGEMENT-PROTOCOL",
                 &retVal,
                 protocolString);

            if (retVal)
            {
                if (strcmp(protocolString, "IGMP") == 0)
                {
                    ip->isIgmpEnable = TRUE;
                }
            }

            multicastProtocolType = ROUTING_PROTOCOL_NONE;

            IO_ReadString(
                 node->nodeId,
                 NetworkIpGetInterfaceAddress(node, i),
                 nodeInput,
                 "MULTICAST-PROTOCOL",
                 &retVal,
                 protocolString);

            if (retVal)
            {

#ifdef ADDON_BOEINGFCS
                if (strcmp(protocolString, "CES-SRW-MOSPF") == 0)
                {
                    multicastProtocolType = MULTICAST_PROTOCOL_CES_SRW_MOSPF;
                }
                else
#endif // ADDON_BOEINGFCS

#ifdef ENTERPRISE_LIB
                if (strcmp(protocolString, "DVMRP") == 0)
                {
                    multicastProtocolType = MULTICAST_PROTOCOL_DVMRP;
                }
                else if (strcmp(protocolString, "MOSPF") == 0)
                {
                    if (routingProtocolType == ROUTING_PROTOCOL_NONE)
                    {
                        NetworkIpAddUnicastRoutingProtocolType(
                                node,
                                ROUTING_PROTOCOL_OSPFv2,
                                i,
                                NETWORK_IPV4);
                        routingProtocolType = ROUTING_PROTOCOL_OSPFv2;
                    }
                    else
                    if (routingProtocolType != ROUTING_PROTOCOL_OSPFv2)
                    {
                        ERROR_ReportError("Need OSPFv2 as the underlying "
                            "unicast routing protocol to run MOSPF.\n");
                    }

                    multicastProtocolType = MULTICAST_PROTOCOL_MOSPF;
                }
                else if (strcmp(protocolString, "PIM") == 0)
                {
                    multicastProtocolType = MULTICAST_PROTOCOL_PIM;
                }
#else //ENTERPRISE_LIB
                if ((strcmp(protocolString, "DVMRP") == 0) ||
                    (strcmp(protocolString, "MOSPF") == 0) ||
                    (strcmp(protocolString, "PIM") == 0))
                {
                    ERROR_ReportMissingLibrary(protocolString,
                        "ENTERPRISE_LIB");
                }
#endif // ENTERPRISE_LIB
#ifdef WIRELESS_LIB
                else if (strcmp(protocolString, "ODMRP") == 0)
                {
                    multicastProtocolType = MULTICAST_PROTOCOL_ODMRP;
                }
#else //WIRELESS_LIB
                else if (strcmp(protocolString, "ODMRP") == 0)
                {
                    ERROR_ReportMissingLibrary(protocolString,
                        "WIRELESS_LIB");
                }
#endif // WIRELESS_LIB

#ifdef ADDON_MAODV
                else if (strcmp(protocolString, "MAODV") == 0)
                {
                    multicastProtocolType = MULTICAST_PROTOCOL_MAODV;
                }
#else // ADDON_MAODV
                else if (strcmp(protocolString, "MAODV") == 0)
                {
                    ERROR_ReportMissingLibrary(protocolString,
                        "ADDON_MAODV");
                }
#endif // ADDON_MAODV

                else if (strcmp(protocolString, "NONE") == 0)
                {
                    multicastProtocolType = ROUTING_PROTOCOL_NONE;
                }
                else
                {
                    char errorString[MAX_STRING_LENGTH];
                    sprintf(errorString,
                            "Unknown MULTICAST-PROTOCOL %s\n",
                            protocolString);
                    ERROR_ReportError(errorString);
                }


                NetworkIpAddMulticastRoutingProtocolType(
                        node,
                        multicastProtocolType,
                        i);
            } // if (retval)

#ifdef ADDON_DB
            // After the routing and multicast protocols are known,
            //we can record this interface in the Interface Status table
            StatsDb* db = node->partitionData->statsDb;
            if (db != NULL && db->statsDescTable->createInterfaceDescTable)
            {
                ip->interfaceInfo[i]->metaData = new MetaDataStruct;
                ip->interfaceInfo[i]->metaData->AddInterfaceMetaData(node, i,
                    node->partitionData, nodeInput);
                StatsDBInterfaceDesc interfaceDesc(node->nodeId, i);

                char interfaceAddrStr[100];
                char interfaceSubnetMaskStr[100];
                NetworkIpGetInterfaceAddressString(node, i, interfaceAddrStr);
                IO_ConvertIpAddressToString(NetworkIpGetInterfaceSubnetMask
                    (node, i),
                    interfaceSubnetMaskStr);
                std::string routingProtocolString;
                std::string multicastProtocolString;
                NetworkIpConvertProtocolTypeToString(routingProtocolType,
                    &routingProtocolString);
                NetworkIpConvertProtocolTypeToString(multicastProtocolType,
                    &multicastProtocolString);

                interfaceDesc.SetInterfaceAddr((std::string) interfaceAddrStr);
                interfaceDesc.SetSubnetMask((std::string) interfaceSubnetMaskStr);
                interfaceDesc.SetNetworkType(routingProtocolString);
                interfaceDesc.SetMulticastProtocol(multicastProtocolString);
                interfaceDesc.SetInterfaceName(
                    (std::string) NetworkIpGetInterfaceName(node, i));
                interfaceDesc.m_InterfaceMetaData = *(ip->interfaceInfo[i]->
                    metaData);
#ifdef ADDON_BOEINGFCS
                interfaceDesc.SetSubnetId(NetworkCesSubnetGetId(node, i));
#endif
                STATSDB_HandleInterfaceDescTableInsert(node, interfaceDesc);
            }
            else {
                ip->interfaceInfo[i]->metaData = NULL;
            }

            STATSDB_HandleInterfaceStatusTableInsert(node, FALSE, i);
#endif
        }
    }
}

//-----------------------------------------------------------------------------
// FUNCTION     IpRoutingInit()
// PURPOSE      Initialization function for network layer.
//              Initializes IP.
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
//-----------------------------------------------------------------------------
void
IpRoutingInit(Node *node,
                     const NodeInput *nodeInput)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    BOOL retVal;
    char protocolString[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    int i;

    // In second Pass initialize the routing Protocols on each interface
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (NetworkIpGetInterfaceType(node, i) == NETWORK_IPV4
            || NetworkIpGetInterfaceType(node, i) == NETWORK_DUAL)
        {
            switch (ip->interfaceInfo[i]->routingProtocolType)
            {
    #ifdef WIRELESS_LIB
                case ROUTING_PROTOCOL_LAR1:
                {
                    if (!NetworkIpGetRoutingProtocol(
                                            node, ROUTING_PROTOCOL_LAR1))
                    {
                        Lar1Init(
                         node,
                        (Lar1Data **) &ip->interfaceInfo[i]->routingProtocol,
                         nodeInput,
                         i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node,
                            ROUTING_PROTOCOL_LAR1,
                            i);
                    }
                    break;
                }
                case ROUTING_PROTOCOL_AODV:
                {
                    if (!NetworkIpGetRoutingProtocol(node,
                        ROUTING_PROTOCOL_AODV))
                    {
                        AodvInit(
                          node,
                          (AodvData**)&ip->interfaceInfo[i]->routingProtocol,
                          nodeInput,
                          i,
                          ROUTING_PROTOCOL_AODV);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node,
                            ROUTING_PROTOCOL_AODV,
                            i);
                    }
                    break;
                }
                case ROUTING_PROTOCOL_DYMO:
                {
                    if (!NetworkIpGetRoutingProtocol(node,
                        ROUTING_PROTOCOL_DYMO))
                    {
                        DymoInit(
                          node,
                          (DymoData**)&ip->interfaceInfo[i]->routingProtocol,
                          nodeInput,
                          i,
                          ROUTING_PROTOCOL_DYMO);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node,
                            ROUTING_PROTOCOL_DYMO,
                            i);
                    }
                    break;
                }
                case ROUTING_PROTOCOL_DSR:
                {
                    if (!NetworkIpGetRoutingProtocol(
                                                node, ROUTING_PROTOCOL_DSR))
                    {
                        DsrInit(
                            node,
                            (DsrData **) &ip->interfaceInfo[i]
                                                        ->routingProtocol,
                            nodeInput,
                            i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                                                  node,
                                                  ROUTING_PROTOCOL_DSR,
                                                  i);
                    }
                    break;
                }
                case ROUTING_PROTOCOL_FSRL:
                {
                    if (!NetworkIpGetRoutingProtocol(node,
                                                     ROUTING_PROTOCOL_FSRL))
                    {
                        FsrlInit(
                            node,
                            (FsrlData **) &ip->interfaceInfo[i]
                                                        ->routingProtocol,
                            nodeInput,
                            i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                                                  node,
                                                  ROUTING_PROTOCOL_FSRL,
                                                  i);
                    }
                    break;
                }

                case ROUTING_PROTOCOL_STAR:
                {
                    if (!NetworkIpGetRoutingProtocol(
                                                node, ROUTING_PROTOCOL_STAR))
                    {
                        StarInit(
                            node,
                            (StarData **) &ip->interfaceInfo[i]
                                                        ->routingProtocol,
                            nodeInput,
                            i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                                                  node,
                                                  ROUTING_PROTOCOL_STAR,
                                                  i);
                    }
                    break;
                }
    //StartIARP
                case ROUTING_PROTOCOL_IARP:
                {
                    if (!NetworkIpGetRoutingProtocol(
                                                node, ROUTING_PROTOCOL_IARP))
                    {
                        IarpInit(node,
                            (IarpData**) &ip->interfaceInfo[i]
                                                        ->routingProtocol,
                            nodeInput,
                            i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node, ROUTING_PROTOCOL_IARP, i);
                    }
                    break;
                }
    //EndIARP
    //StartZRP
                case ROUTING_PROTOCOL_ZRP:
                {
                    if (!NetworkIpGetRoutingProtocol(
                                                node, ROUTING_PROTOCOL_ZRP))
                    {
                        ZrpInit(node,
                            (ZrpData**) &ip->interfaceInfo[i]
                                                        ->routingProtocol,
                             nodeInput,
                             i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node, ROUTING_PROTOCOL_ZRP, i);
                    }
                    break;
                }
    //EndZRP
    //StartIERP
                case ROUTING_PROTOCOL_IERP:
                {
                    if (!NetworkIpGetRoutingProtocol(
                                                node, ROUTING_PROTOCOL_IERP))
                    {
                        IerpInit(node,
                            (IerpData**) &ip->interfaceInfo[i]->routingProtocol,
                            nodeInput,
                            i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node, ROUTING_PROTOCOL_IERP, i);
                    }
                    break;
                }
    //EndIERP
    #endif // WIRELESS_LIB
    #ifdef ENTERPRISE_LIB
                case ROUTING_PROTOCOL_OSPFv2:
                {
                    MAC_SetInterfaceStatusHandlerFunction(
                                            node,
                                            i,
                                            &Ospfv2InterfaceStatusHandler);

                    if (!NetworkIpGetRoutingProtocol(
                                            node, ROUTING_PROTOCOL_OSPFv2))
                    {
                        Ospfv2Init(
                            node,
                            (Ospfv2Data **) &ip->interfaceInfo[i]
                                                        ->routingProtocol,
                            nodeInput,
                            FALSE,
#ifdef ADDON_NGCNMS
                            FALSE,
#endif
                            i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                                                  node,
                                                  ROUTING_PROTOCOL_OSPFv2,
                                                  i);
                    }
                    break;
                }
                case ROUTING_PROTOCOL_IGRP:
                {
                    if (!NetworkIpGetRoutingProtocol(
                                            node, ROUTING_PROTOCOL_IGRP))
                    {
                        IgrpInit(
                            node,
                            (RoutingIgrp **)
                            &ip->interfaceInfo[i]->routingProtocol,
                            nodeInput,
                            i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node,
                            ROUTING_PROTOCOL_IGRP,
                            i);
                    }
                    break;
                }
                case ROUTING_PROTOCOL_EIGRP:
                {
                    MAC_SetInterfaceStatusHandlerFunction(
                        node,
                        i,
                        EigrpInterfaceStatusHandler);

                    if (!NetworkIpGetRoutingProtocol(
                                        node, ROUTING_PROTOCOL_EIGRP))
                    {
                        EigrpInit(
                            node,
                            (RoutingEigrp **)
                            &ip->interfaceInfo[i]->routingProtocol,
                            nodeInput,
                            i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node,
                            ROUTING_PROTOCOL_EIGRP,
                            i);
                    }
                    break;
                }
#endif // ENTERPRISE_LIB
#ifdef MILITARY_RADIOS_LIB
                case ROUTING_PROTOCOL_ODR:
    {
                    if (!NetworkIpGetRoutingProtocol(
                                            node, ROUTING_PROTOCOL_ODR))
        {
                        OdrInit(
                            node,
                            (OdrData **) &ip->interfaceInfo[i]
                                                        ->routingProtocol,
                            nodeInput,
                            i);
        }
                    else
{
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node,
                            ROUTING_PROTOCOL_ODR,
                            i);
    }
                    break;
}
#endif // MILITARY_RADIOS_LIB
                case ROUTING_PROTOCOL_SDR:
                {
#ifdef MILITARY_RADIOS_LIB
                    if (!NetworkIpGetRoutingProtocol(
                                            node, ROUTING_PROTOCOL_SDR))
                    {
                        SdrInit(node, nodeInput, i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node,
                            ROUTING_PROTOCOL_SDR,
                            i);
                    }
                    break;
#else // MILITARY_RADIOS_LIB
                    ERROR_ReportMissingLibrary(
                                        protocolString, "Military Radios\n");
#endif // MILITARY_RADIOS_LIB
                }
#ifdef CYBER_LIB
                case ROUTING_PROTOCOL_ANODR:
                {
                    if (!NetworkIpGetRoutingProtocol(
                                            node, ROUTING_PROTOCOL_ANODR))
                    {
                        AnodrInit(
                            node,
                            (AnodrData **) &ip->interfaceInfo[i]
                                                    ->routingProtocol,
                            nodeInput,
                            i);
                    }
                    else
                    {
                        NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                                                  node,
                                                  ROUTING_PROTOCOL_ANODR,
                                                  i);
                    }
                    break;
                }
#endif // CYBER_LIB
                default:
                {
                    break;
                }
            }

            if (ip->isIgmpEnable
                && !TunnelIsVirtualInterface(node, i))
            {
                IgmpInit(node,
                        nodeInput,
                        &ip->igmpDataPtr,
                        i);
            }

            switch (ip->interfaceInfo[i]->multicastProtocolType)
            {
#ifdef ENTERPRISE_LIB
                case MULTICAST_PROTOCOL_DVMRP:
                {
                    if (!NetworkIpGetMulticastRoutingProtocol(node,
                                                MULTICAST_PROTOCOL_DVMRP))
                    {
                        RoutingDvmrpInit(node, nodeInput, i);
                    }
                    else
                    {
                        NetworkIpUpdateMulticastRoutingProtocolAndRouterFunction(
                                                  node,
                                                  MULTICAST_PROTOCOL_DVMRP,
                                                  i);

                        /* Inform IGMP about multicast routing protocol */
                        if (ip->isIgmpEnable == TRUE
                            && !TunnelIsVirtualInterface(node, i))
                        {
                            IgmpSetMulticastProtocolInfo(
                                    node,
                                    i,
                                    &RoutingDvmrpLocalMembersJoinOrLeave);
                        }
                    }
                    break;
                }
                case MULTICAST_PROTOCOL_MOSPF:
                {
                    if (!NetworkIpGetMulticastRoutingProtocol(node,
                                                MULTICAST_PROTOCOL_MOSPF))
                    {
                        MospfInit(node, nodeInput, i);
                    }
                    else
                    {
                        NetworkIpUpdateMulticastRoutingProtocolAndRouterFunction(
                                                  node,
                                                  MULTICAST_PROTOCOL_MOSPF,
                                                  i);

                        /* Inform IGMP about multicast routing protocol */

                        if (ip->isIgmpEnable == TRUE
                            && !TunnelIsVirtualInterface(node, i))
                        {
                            IgmpSetMulticastProtocolInfo(
                                           node,
                                           i,
                                           &MospfLocalMembersJoinOrLeave);
                        }
                    }
                    break;
                }
                case MULTICAST_PROTOCOL_PIM:
                {
                    if (!NetworkIpGetMulticastRoutingProtocol(node,
                                                    MULTICAST_PROTOCOL_PIM))
                    {
                        RoutingPimInit(node, nodeInput, i);
                    }
                    else
                    {
                        NetworkIpUpdateMulticastRoutingProtocolAndRouterFunction(
                                                  node,
                                                  MULTICAST_PROTOCOL_PIM,
                                                  i);

                        /* Inform IGMP about multicast routing protocol */
                        if (ip->isIgmpEnable == TRUE
                            && !TunnelIsVirtualInterface(node, i))
                        {
                            IgmpSetMulticastProtocolInfo(
                                        node,
                                        i,
                                        &RoutingPimLocalMembersJoinOrLeave);
                        }
                    }
                    break;
                }
#endif // ENTERPRISE_LIB
#ifdef WIRELESS_LIB
                case MULTICAST_PROTOCOL_ODMRP:
                {
                    if (!NetworkIpGetMulticastRoutingProtocol(node,
                                                MULTICAST_PROTOCOL_ODMRP))
                    {
                        OdmrpInit(node, nodeInput, i);
                    }
                    else
                    {
                        NetworkIpUpdateMulticastRoutingProtocolAndRouterFunction(
                                                  node,
                                                  MULTICAST_PROTOCOL_ODMRP,
                                                  i);
                    }
                    break;
                }
    #endif // WIRELESS_LIB

    #ifdef ADDON_MAODV
                case MULTICAST_PROTOCOL_MAODV:
                {
                    if (!NetworkIpGetMulticastRoutingProtocol(
                        node,
                        MULTICAST_PROTOCOL_MAODV))
                    {
                        MaodvInit(node, nodeInput, i);
                    }
                    else
                    {
                        NetworkIpUpdateMulticastRoutingProtocolAndRouterFunction(
                            node,
                            MULTICAST_PROTOCOL_MAODV,
                            i);
                    }
                    break;
                }
    #endif // ADDON_MAODV
                default:
                {
                    break;
                }
            } // switch
        }
    }

     IO_ReadString(node->nodeId,
                     ANY_ADDRESS,
                     nodeInput,
                     "ICMP",
                     &retVal,
                     protocolString);

    if (!retVal ||
        (retVal && !strcmp(protocolString, "YES")))
    {
        NetworkIcmpInit(node, nodeInput);
    }
    else if (strcmp(protocolString, "NO"))
    {
        ERROR_ReportError("ICMP: must be YES or NO!\n");
    }

    IO_ReadString(
             node->nodeId,
             ANY_ADDRESS,
             nodeInput,
             "MULTICAST-STATIC-ROUTE",
             &retVal,
             protocolString);

    if (retVal == TRUE && strcmp(protocolString, "YES") == 0)
    {
        RoutingMulticastStaticInit(
                    node,
                    nodeInput);
    }


#ifdef ENTERPRISE_LIB
    MobileIpInit(node, nodeInput);
    IpInitPerHopBehaviors(node, nodeInput);
#endif // ENTERPRISE_LIB

    ip->mftcInfo = NULL;
    ip->numMftcInfo = 0;
    ip->maxMftcInfo = 0;
    ip->ipMftcParameter = NULL;
    ip->numIpMftcParameters = 0;
    ip->maxIpMftcParameters = 0;
    ip->isEdgeRouter = FALSE;
    ip->mftcStatisticsEnabled = FALSE;

    // Read this node collect Diffserv statistics or not
    // The <variant> is one of YES | NO
    // Format is: DIFFSERV-EDGE-ROUTER-STATISTICS <variant>, for example
    //            DIFFSERV-EDGE-ROUTER-STATISTICS YES
    //            DIFFSERV-EDGE-ROUTER-STATISTICS NO
    // If not specified, default is NO

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "DIFFSERV-EDGE-ROUTER-STATISTICS",
        &retVal,
        buf);

    if (retVal && strcmp(buf, "YES") == 0)
    {
        ip->mftcStatisticsEnabled = TRUE;
    }

#ifdef ENTERPRISE_LIB
    // Read whether this node is Diffserv enabled Edge router or not
    // The <variant> is one of YES | NO
    // Format is: DIFFSERV-ENABLE-EDGE-ROUTER <variant>, for example
    //            DIFFSERV-ENABLE-EDGE-ROUTER YES
    //            DIFFSERV-ENABLE-EDGE-ROUTER NO
    //            [3 5]  DIFFSERV-ENABLE-EDGE-ROUTER YES
    // If not specified, default is NO

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "DIFFSERV-ENABLE-EDGE-ROUTER",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            ip->isEdgeRouter = TRUE;
            DIFFSERV_MFTrafficConditionerInit(node, nodeInput);
        }
        else if (strcmp(buf, "NO") == 0)
        {
            ip->isEdgeRouter = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "DIFFSERV-ENABLE-EDGE-ROUTER: Unknown variant"
                " in configuration file.\n");
        }
    }

    // Initializing access list
    AccessListInit(node, nodeInput);

    // Initializing route map.  Make sure that it is initialized after the
    // access list initialization is over.
    RouteMapInit(node, nodeInput);

    // Initializing of PBR
    PbrInit(node, nodeInput);

    //Initialization of Route Redistribution.
    RouteRedistributeInit(node, nodeInput);


#endif // ENTERPRISE_LIB
#ifdef CYBER_LIB
    SecureneighborInit(node, nodeInput);

    //SecureCommunityInit(node, nodeInput);
#endif // CYBER_LIB
}

// /**
// API                 :: IsIPV4RoutingEnabledOnInterface
// LAYER               :: Network
// PURPOSE             :: To check if IPV4 Routing is enabled on interface?
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: BOOL
// **/
BOOL IsIPV4RoutingEnabledOnInterface(Node* node,
                                 int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    if (ip->interfaceInfo[interfaceIndex]->routingProtocolType !=
        ROUTING_PROTOCOL_NONE)
    {
        return TRUE;
    }
    return FALSE;
}

// /**
// API                 :: IsIPV4MulticastEnabledOnInterface
// LAYER               :: Network
// PURPOSE             :: To check if IPV4 Multicast is enabled on interface?
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: BOOL
// **/
BOOL IsIPV4MulticastEnabledOnInterface(Node* node,
                                 int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    if (ip->interfaceInfo[interfaceIndex]->multicastEnabled == TRUE
        && ip->interfaceInfo[interfaceIndex]->multicastProtocolType !=
                                        ROUTING_PROTOCOL_NONE)
    {
        return TRUE;
    }
    return FALSE;
}

// /**
// API                 :: NetworkIpInterfaceIsEnabled
// LAYER               :: Network
// PURPOSE             :: To check the interface is enabled or not?
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: BOOL
// **/
BOOL NetworkIpInterfaceIsEnabled(Node* node, int interfaceIndex)
{
    if (TunnelIsVirtualInterface(node, interfaceIndex))
    {
        return TunnelInterfaceIsEnabled(node, interfaceIndex);
    }
    else
    {
        return MAC_InterfaceIsEnabled(node, interfaceIndex);
    }
}

// /**
// API                 :: NetworkIpIsWiredNetwork
// LAYER               :: Network
// PURPOSE             :: Determines if an interface is a wired interface.
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: BOOL
// **/
BOOL
NetworkIpIsWiredNetwork(Node *node, int interfaceIndex)
{
    if (TunnelIsVirtualInterface(node, interfaceIndex))
    {
        return FALSE;
    }
    else
    {
        return MAC_IsWiredNetwork(node, interfaceIndex);
    }
}

// /**
// API                 :: NetworkIpIsPointToPointNetwork
// LAYER               :: Network
// PURPOSE             :: Determines if an interface is a point-to-point.
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: BOOL
// **/
BOOL
NetworkIpIsPointToPointNetwork(Node *node, int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    if (ip->interfaceInfo[interfaceIndex]->isVirtualInterface
        || ip->interfaceInfo[interfaceIndex]->isUnnumbered)
    {
        return TRUE;
    }
    else
    {
        return MAC_IsPointToPointNetwork(node, interfaceIndex);
    }
}

// /**
// API                 :: NetworkIpIsWiredBroadcastNetwork
// LAYER               :: Network
// PURPOSE             :: Determines if an interface is a wired interface.
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: BOOL
// **/
BOOL
NetworkIpIsWiredBroadcastNetwork(Node *node, int interfaceIndex)
{
    if (TunnelIsVirtualInterface(node, interfaceIndex))
    {
        return FALSE;
    }
    else
    {
        return MAC_IsWiredBroadcastNetwork(node, interfaceIndex);
    }
}

//---------------------------------------------------------------------------
// FUNCTION             : NetworkIpGetNetworkProtocolType:
// PURPOSE              : Get Network Protocol Type for the node:
// PARAMETERS           ::
// + node               : Node *node:
// + nodeId             : NodeAddress nodeId:
// RETURN               : NetworkProtocolType:
//---------------------------------------------------------------------------
NetworkProtocolType
NetworkIpGetNetworkProtocolType(Node* node, NodeAddress nodeId)
{
    if (node->nodeId == nodeId)
    {
        return node->networkData.networkProtocol;
    }
    else
    {
        return MAPPING_GetNetworkProtocolTypeForNode(node, nodeId);
    }
}

// -----------------------------------------------------------------------------
// API :: ResolveNetworkTypeFromSrcAndDestNodeId
// PURPOSE :: Resolve the NetworkType from source and destination node id's.
// PARAMETERS ::
// + node : Node* : Pointer to the Node
// + sourceNodeId : NodeId
// + destNodeId : NodeId
// RETURN :: NetworkType
// -----------------------------------------------------------------------------
NetworkType
ResolveNetworkTypeFromSrcAndDestNodeId(
    Node* node,
    NodeId sourceNodeId,
    NodeId destNodeId)
{
    NetworkProtocolType sourcetype;
    NetworkProtocolType desttype;

    sourcetype = NetworkIpGetNetworkProtocolType(node, sourceNodeId);
    desttype = NetworkIpGetNetworkProtocolType(node, destNodeId);

    if (sourcetype == IPV4_ONLY)
    {
        if (desttype == IPV4_ONLY || desttype == DUAL_IP)
        {
            return NETWORK_IPV4;
        }
        else if (desttype == GSM_LAYER3 || desttype == CELLULAR)
        {
            // Currently GSM does not suport IPv4 to GSM layer3
            // UMTS does
            // IPv4 is default right now
            return NETWORK_IPV4;
        }
        else
        {
            ERROR_ReportError(
                "Source and destination Address type mismatch\n");
        }
    }
    else if (sourcetype == IPV6_ONLY)
    {
        if (desttype == IPV6_ONLY || desttype == DUAL_IP)
        {
            return NETWORK_IPV6;
        }
        else
        {
            ERROR_ReportError(
                "Source and destination Address type mismatch\n");
        }
    }
    else if (sourcetype == DUAL_IP)
    {
        if (desttype == IPV4_ONLY || desttype == DUAL_IP)
        {
            return NETWORK_IPV4;
        }
        else if (desttype == IPV6_ONLY)
        {
            return NETWORK_IPV6;
        }
        else
        {
            ERROR_ReportError(
                "destination INVALID_NETWORK_TYPE \n");
        }
    }
    else if (sourcetype == ATM_NODE)
    {
        if (desttype == ATM_NODE)
        {
            return NETWORK_ATM;
        }
        else if (desttype == IPV4_ONLY || desttype == DUAL_IP)
        {
            return NETWORK_IPV4;
        }
        else if (desttype == IPV6_ONLY)
        {
            return NETWORK_IPV6;
        }
        else
        {
            ERROR_ReportError(
                "destination INVALID_NETWORK_TYPE \n");
        }
    }
    else if (sourcetype == GSM_LAYER3 || sourcetype == CELLULAR)
    {
        // for cellular type network
        // IPv4 is default right now
        return NETWORK_IPV4;
    }

    return NETWORK_INVALID;
} //ResolveDestNetworkType

// -----------------------------------------------------------------------------
// API :: GetDefaultInterfaceIndex
// PURPOSE :: Returns Default Interface index of depending on network type
// PARAMETERS ::
// + node : Node* : Pointer to the Node
// + sourceNodeId : NodeId
// + networkType : NetoworkType
// RETURN :: int
// -----------------------------------------------------------------------------
int
GetDefaultInterfaceIndex(
    Node* node,
    NetworkType netType)
{

    int i = 0;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    for (; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->interfaceType == netType ||
            ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL)
        {
            return i;
        }
    }

    return -1;

}


#ifdef ADDON_DB
void NetworkIpConvertIpProtocolNumToString(
    unsigned char type,
    std::string* protocolString)
{
    switch(type)
    {
        case IPPROTO_IP:
            *protocolString = "IPPROTO_IP";
            break;

        case IPPROTO_ICMP:
            *protocolString = "IPPROTO_ICMP";
            break;

        case IPPROTO_IGMP:
            *protocolString = "IPPROTO_IGMP";
            break;

        case IPPROTO_IPIP:
            *protocolString = "IPPROTO_IPIP";
            break;

        case IPPROTO_TCP:
            *protocolString = "IPPROTO_TCP";
            break;

        case IPPROTO_UDP:
            *protocolString = "IPPROTO_UDP";
            break;

        case IPPROTO_IPV6:
            *protocolString = "IPPROTO_IPV6";
            break;

        case IPPROTO_SDR:
            *protocolString = "IPPROTO_SDR";
            break;

        case IPPROTO_RSVP:
            *protocolString = "IPPROTO_RSVP";
            break;

#ifdef ADDON_BOEINGFCS
        case IPPROTO_RPIM:
            *protocolString = "IPPROTO_RPIM";
            break;

        case IPPROTO_NETWORK_CES_CLUSTER:
            *protocolString = "IPPROTO_NETWORK_CES_CLUSTER";
            break;

        case IPPROTO_ROUTING_CES_MALSR:
            *protocolString = "IPPROTO_ROUTING_CES_MALSR";
            break;

        case IPPROTO_ROUTING_CES_ROSPF:
            *protocolString = "IPPROTO_ROUTING_CES_ROSPF";
            break;

        case IPPROTO_IPIP_ROUTING_CES_MALSR:
            *protocolString = "IPPROTO_IPIP_ROUTING_CES_MALSR";
            break;

        case IPPROTO_IPIP_ROUTING_CES_ROSPF:
            *protocolString = "IPPROTO_IPIP_ROUTING_CES_ROSPF";
            break;

        case IPPROTO_NETWORK_CES_REGION:
            *protocolString = "IPPROTO_NETWORK_CES_REGION";
            break;

        case IPPROTO_ROUTING_CES_MPR:
            *protocolString = "IPPROTO_ROUTING_CES_MPR";
            break;

        case IPPROTO_ROUTING_CES_SRW:
            *protocolString = "IPPROTO_ROUTING_CES_SRW";
            break;

        case IPPROTO_IPIP_ROUTING_CES_SRW:
            *protocolString = "IPPROTO_IPIP_ROUTING_CES_SRW";
            break;

        case IPPROTO_IPIP_SDR:
            *protocolString = "IPPROTO_IPIP_SDR";
            break;

        case IPPROTO_IPIP_CES_SDR:
            *protocolString = "IPPROTO_IPIP_CES_SDR";
            break;
#endif // ADDON_BOEINGFCS

        case IPPROTO_MOBILE_IP:
            *protocolString = "IPPROTO_MOBILE_IP";
            break;

        case IPPROTO_ESP:
            *protocolString = "IPPROTO_ESP";
            break;

        case IPPROTO_AH:
            *protocolString = "IPPROTO_AH";
            break;

        case IPPROTO_OSPF:
            *protocolString = "IPPROTO_OSPF";
            break;

        case IPPROTO_PIM:
            *protocolString = "IPPROTO_PIM";
            break;

#ifdef ADDON_BOEINGFCS
        case IPPROTO_CES_EPLRS:
            *protocolString = "IPPROTO_CES_EPLRS";
            break;
#endif
        case IPPROTO_IGRP:
            *protocolString = "IPPROTO_IGRP";
            break;

        case IPPROTO_EIGRP:
            *protocolString = "IPPROTO_EIGRP";
            break;

        case IPPROTO_BELLMANFORD:
            *protocolString = "IPPROTO_BELLMANFORD";
            break;

        case IPPROTO_FISHEYE:
            *protocolString = "IPPROTO_FISHEYE";
            break;

        case IPPROTO_FSRL:
            *protocolString = "IPPROTO_FSRL";
            break;

        case IPPROTO_AODV:
            *protocolString = "IPPROTO_AODV";
            break;

        case IPPROTO_DYMO:
            *protocolString = "IPPROTO_DYMO";
            break;

        case IPPROTO_DSR:
            *protocolString = "IPPROTO_DSR";
            break;

        case IPPROTO_ODMRP:
            *protocolString = "IPPROTO_ODMRP";
            break;

        case IPPROTO_LAR1:
            *protocolString = "IPPROTO_LAR1";
            break;

        case IPPROTO_STAR:
            *protocolString = "IPPROTO_STAR";
            break;

        case IPPROTO_DAWN:
            *protocolString = "IPPROTO_DAWN";
            break;

        case IPPROTO_DVMRP:
            *protocolString = "IPPROTO_DVMRP";
            break;

        case IPPROTO_EXTERNAL:
            *protocolString = "IPPROTO_EXTERNAL";
            break;

        case IPPROTO_NDP:
            *protocolString = "IPPROTO_NDP";
            break;

        case IPPROTO_CELLULAR:
            *protocolString = "IPPROTO_CELLULAR";
            break;

        case IPPROTO_BRP:
            *protocolString = "IPPROTO_BRP";
            break;

        case IPPROTO_ZRP:
            *protocolString = "IPPROTO_ZRP";
            break;

        case IPPROTO_IERP:
            *protocolString = "IPPROTO_IERP";
            break;

        case IPPROTO_IARP:
            *protocolString = "IPPROTO_IARP";
            break;

#ifdef ADVANCED_WIRELESS_LIB
        case IPPROTO_DOT16:
            *protocolString = "IPPROTO_DOT16";
            break;
#endif

#ifdef ADDON_MAODV
        case IPPROTO_MAODV:
            *protocolString = "IPPROTO_MAODV";
            break;
#endif

#ifdef CELLULAR_LIB
        case IPPROTO_GSM:
            *protocolString = "IPPROTO_GSM";
            break;
#endif

#ifdef CYBER_CORE
        case IPPROTO_ISAKMP:
            *protocolString = "IPPROTO_ISAKMP";
            break;

        case NETWORK_PROTOCOL_ISAKMP:
            *protocolString = "ISAKMP";
            break;
#endif // CYBER_CORE

#ifdef CYBER_LIB
        case IPPROTO_SECURE_NEIGHBOR:
            *protocolString = "IPPROTO_SECURE_NEIGHBOR";
            break;

        case IPPROTO_ANODR:
            *protocolString = "IPPROTO_ANODR";
            break;

        case IPPROTO_SECURE_COMMUNITY:
            *protocolString = "IPPROTO_SECURE_COMMUNITY";
            break;

#endif // CYBER_LIB

#ifdef ADDON_NGCNMS
        case IPPROTO_IPIP_RED:
            *protocolString = "IPPROTO_IPIP_RED";
            break;
#endif

        default:
            *protocolString = "Unknown";
            break;
    }
}
void NetworkIpConvertProtocolTypeToString(
    NetworkRoutingProtocolType type,
    std::string *protocolString)
{
    switch (type)
    {
        case NETWORK_PROTOCOL_IP:
            *protocolString = "IP";
            break;

        case NETWORK_PROTOCOL_IPV6:
            *protocolString = "IPv6";
            break;

        case NETWORK_PROTOCOL_MOBILE_IP:
            *protocolString = "MobileIP";
            break;

        case NETWORK_PROTOCOL_NDP:
            *protocolString = "NDP";
            break;

        case NETWORK_PROTOCOL_SPAWAR_LINK16:
            *protocolString = "Link16";
            break;
        case NETWORK_PROTOCOL_ICMP:
            *protocolString = "ICMP";
            break;

        case ROUTING_PROTOCOL_AODV:
            *protocolString = "AODV";
            break;

        case ROUTING_PROTOCOL_DSR:
            *protocolString = "DSR";
            break;

        case ROUTING_PROTOCOL_FSRL:
            *protocolString = "FSRL";
            break;

#ifdef ADDON_BOEINGFCS
        case ROUTING_PROTOCOL_CES_MALSR:
            *protocolString = "CES_MALSR";
            break;

        case ROUTING_PROTOCOL_CES_SRW:
            *protocolString = "CES_SRW";
            break;

        case ROUTING_PROTOCOL_CES_ROSPF:
            *protocolString = "CES_ROSPF";
            break;

        case NETWORK_CES_REGION:
            *protocolString = "CES_Region";
            break;

        case ROUTING_PROTOCOL_CES_MPR:
            *protocolString = "CES_MPR";
            break;

        case NETWORK_PROTOCOL_NETWORK_CES_INC_SINCGARS:
            *protocolString = "CES_SINCGARS";
            break;

        case ROUTING_PROTOCOL_CES_SDR:
            *protocolString = "CES_SDR";
            break;

        case NETWORK_PROTOCOL_CES_EPLRS:
            *protocolString = "CES_EPRLS";
            break;

        case ROUTING_PROTOCOL_CES_EPLRS:
            *protocolString = "ROUTING_CES_EPRLS";
            break;

        case MULTICAST_PROTOCOL_CES_SRW_MOSPF:
            *protocolString = "SRW_MOSPF";
            break;
#endif // ADDON_BOEINGFCS

        case ROUTING_PROTOCOL_STAR:
            *protocolString = "STAR";
            break;

        case ROUTING_PROTOCOL_LAR1:
            *protocolString = "LAR1";
            break;

        case ROUTING_PROTOCOL_ODMRP:
            *protocolString = "ODMRP";
            break;

        case ROUTING_PROTOCOL_OSPF:
            *protocolString = "OPSPF";
            break;

        case ROUTING_PROTOCOL_OSPFv2:
            *protocolString = "OSPFv2";
            break;

#ifdef ADDON_BOEINGFCS
        case ROUTING_PROTOCOL_OSPFv2_EXTERNAL:
            *protocolString = "OSPFv2_EXTERNAL";
            break;
#endif
        case ROUTING_PROTOCOL_SDR:
            *protocolString = "SDR";
            break;

        case ROUTING_PROTOCOL_BELLMANFORD:
            *protocolString = "BELLMANFORD";
            break;

        case ROUTING_PROTOCOL_STATIC:
            *protocolString = "STATIC";
            break;

        case ROUTING_PROTOCOL_DEFAULT:
            *protocolString = "DEFAULT";
            break;

        case ROUTING_PROTOCOL_FISHEYE:
            *protocolString = "FISHEYE";
            break;

        case ROUTING_PROTOCOL_OLSR_INRIA:
            *protocolString = "OLSR_INRIA";
            break;

        case ROUTING_PROTOCOL_IGRP:
            *protocolString = "IGRP";
            break;

        case ROUTING_PROTOCOL_EIGRP:
            *protocolString = "EIGRP";
            break;

        case ROUTING_PROTOCOL_BRP:
            *protocolString = "BRP";
            break;

        case ROUTING_PROTOCOL_RIP:
            *protocolString = "RIP";
            break;

        case ROUTING_PROTOCOL_RIPNG:
            *protocolString = "RIPNG";
            break;

        case ROUTING_PROTOCOL_IARP:
            *protocolString = "IARP";
            break;

        case ROUTING_PROTOCOL_ZRP:
            *protocolString = "ZRP";
            break;

        case ROUTING_PROTOCOL_IERP:
            *protocolString = "IERP";
            break;

        case EXTERIOR_GATEWAY_PROTOCOL_EBGPv4:
            *protocolString = "EBGPv4";
            break;

        case EXTERIOR_GATEWAY_PROTOCOL_IBGPv4:
            *protocolString = "IBGPv4";
            break;

        case EXTERIOR_GATEWAY_PROTOCOL_BGPv4_LOCAL:
            *protocolString = "BGPv4_LOCAL";
            break;

        case GROUP_MANAGEMENT_PROTOCOL_IGMP:
            *protocolString = "IGMP";
            break;

        case LINK_MANAGEMENT_PROTOCOL_CBQ:
            *protocolString = "CBQ";
            break;

        case MULTICAST_PROTOCOL_STATIC:
            *protocolString = "MULTICAST_STATIC";
            break;

        case MULTICAST_PROTOCOL_DVMRP:
            *protocolString = "DVMRP";
            break;

        case MULTICAST_PROTOCOL_MOSPF:
            *protocolString = "MOSPF";
            break;

        case MULTICAST_PROTOCOL_ODMRP:
            *protocolString = "OSMRP";
            break;

        case MULTICAST_PROTOCOL_PIM:
            *protocolString = "PIM";
            break;

        case MULTICAST_PROTOCOL_MAODV:
            *protocolString = "MAODV";
            break;

        case NETWORK_PROTOCOL_GSM:
            *protocolString = "GSM";
            break;

        case NETWORK_PROTOCOL_ARP:
            *protocolString = "ARP";
            break;

        case ROUTING_PROTOCOL_OSPFv3:
            *protocolString = "OSPFv3";
            break;

        case ROUTING_PROTOCOL_OLSRv2_NIIGATA:
            *protocolString = "OLSRv2_NIIGATA";
            break;

        /*case ROUTING_PROTOCOL_GENERIC_LS:
            *protocolString = "GENERIC_LS";
            break;*/

        case ROUTING_PROTOCOL_ALL:
            *protocolString = "ALL";
            break;

        case NETWORK_PROTOCOL_CELLULAR:
            *protocolString = "CELLULAR";
            break;

        case ROUTING_PROTOCOL_AODV6:
            *protocolString = "AODV6";
            break;

        case ROUTING_PROTOCOL_DYMO:
            *protocolString = "DYMO";
            break;
        case ROUTING_PROTOCOL_DYMO6:
            *protocolString = "DYMO6";
            break;

#ifdef CYBER_LIB
        case ROUTING_PROTOCOL_ANODR:
            *protocolString = "ANODR";
            break;

        case NETWORK_PROTOCOL_SECURENEIGHBOR:
            *protocolString = "SECURENEIGHBOR";
            break;

        case NETWORK_PROTOCOL_SECURECOMMUNITY:
            *protocolString = "SECURECOMMUNITY";
            break;
#endif // CYBER_LIB

#ifdef CYBER_CORE
        case NETWORK_PROTOCOL_IPSEC_AH:
            *protocolString = "IPSEC_AH";
            break;

        case NETWORK_PROTOCOL_IPSEC_ESP:
            *protocolString = "IPSEC_ESP";
            break;

        case NETWORK_PROTOCOL_ISAKMP:
            *protocolString = "ISAKMP";
            break;
#endif // CYBER_CORE

#ifdef ADDON_NGCNMS
        case NETWORK_PROTOCOL_NGC_HAIPE:
            *protocolString = "HAIPE";
            break;
#endif
        default:
            *protocolString = "NONE";
            break;
    }
}

void NetworkIpConvertAdminDistanceToString(
    NetworkRoutingAdminDistanceType type,
    std::string adminString)
{
    switch (type)
    {
        case ROUTING_ADMIN_DISTANCE_STATIC:
            adminString = "IP";
            break;

#ifdef ADDON_BOEINGFCS
        case ROUTING_ADMIN_DISTANCE_EBGPv4_HANDOFF:
            adminString = "IPv6";
            break;
#endif
        case ROUTING_ADMIN_DISTANCE_EBGPv4:
            adminString = "MobileIP";
            break;

        case ROUTING_ADMIN_DISTANCE_BGPv4_LOCAL:
            adminString = "NDP";
            break;
    }
}

void NetworkIpConvertMacProtocolTypeToString(
    MAC_PROTOCOL type,
    std::string *protocolString)
{
    switch (type)
    {
        case MAC_PROTOCOL_MPLS:
            *protocolString = "MPLS";
            break;

        case MAC_PROTOCOL_CSMA:
            *protocolString = "CSMA";
            break;

        case MAC_PROTOCOL_FCSC_CSMA:
            *protocolString = "FCSC_CSMA";
            break;

        case MAC_PROTOCOL_MACA:
            *protocolString = "MACA";
            break;

        case MAC_PROTOCOL_FAMA:
            *protocolString = "FAMA";
            break;
        case MAC_PROTOCOL_802_11:
            *protocolString = "802.11";
            break;

        case MAC_PROTOCOL_802_3:
            *protocolString = "802.3";
            break;

        case MAC_PROTOCOL_DAWN:
            *protocolString = "DAWN";
            break;

        case MAC_PROTOCOL_LINK:
            *protocolString = "LINK";
            break;

        case MAC_PROTOCOL_ALOHA:
            *protocolString = "ALOHA";
            break;

        case MAC_PROTOCOL_GENERICMAC:
            *protocolString = "GENERICMAC";
            break;

        case MAC_PROTOCOL_SWITCHED_ETHERNET:
            *protocolString = "SWITCHED_ETHERNET";
            break;

        case MAC_PROTOCOL_TDMA:
            *protocolString = "TDMA";
            break;

        case MAC_PROTOCOL_GSM:
            *protocolString = "GSM";
            break;

        case MAC_PROTOCOL_SPAWAR_LINK16:
            *protocolString = "SPAWAR_LINK16";
            break;

        case MAC_PROTOCOL_TADIL_LINK11:
            *protocolString = "TADIL_LINK11";
            break;

        case MAC_PROTOCOL_TADIL_LINK16:
            *protocolString = "TADIL_LINK16";
            break;

        case MAC_PROTOCOL_ALE:
            *protocolString = "ALE";
            break;

        case MAC_PROTOCOL_SATTSM:
            *protocolString = "SATTSM";
            break;

        case MAC_PROTOCOL_SATCOM:
            *protocolString = "SATCOM";
            break;

        case MAC_PROTOCOL_USAP:
            *protocolString = "USAP";
            break;

        case MAC_PROTOCOL_SATELLITE_BENTPIPE:
            *protocolString = "SATELLITE_BENTPIPE";
            break;

        case MAC_SWITCH:
            *protocolString = "MAC_SWITCH";
            break;

        case MAC_PROTOCOL_GARP:
            *protocolString = "GARP";
            break;

        case MAC_PROTOCOL_DOT11:
            *protocolString = "DOT11";
            break;

        case MAC_PROTOCOL_DOT16:
            *protocolString = "DOT16";
            break;

        case MAC_PROTOCOL_ABSTRACT:
            *protocolString = "ABSTRACT";
            break;

        case MAC_PROTOCOL_CELLULAR:
            *protocolString = "CELLULAR";
            break;

        case MAC_PROTOCOL_ANE:
            *protocolString = "ANE";
            break;

        case MAC_PROTOCOL_WORMHOLE:
            *protocolString = "WORMHOLE";
            break;

        case MAC_PROTOCOL_ANODR:
            *protocolString = "ANODR";
            break;

        case MAC_PROTOCOL_802_15_4:
            *protocolString = "802.15.4";
            break;

#ifdef ADDON_BOEINGFCS
        case MAC_PROTOCOL_CES_WINTNCW:
            *protocolString = "CES_WINT_NCW";
            break;

        case MAC_PROTOCOL_CES_WINTHNW:
            *protocolString = "CES_WINT_HNW";
            break;

        case MAC_PROTOCOL_CES_WINTGBS:
            *protocolString = "CES_WINT_GBS";
            break;

        case MAC_PROTOCOL_CES_WNW_MDL:
            *protocolString = "CES_WNW_MDL";
            break;

        case MAC_PROTOCOL_BOEING_GENERICMAC:
            *protocolString = "BOEING_GENERICMAC";
            break;

        case MAC_PROTOCOL_CES_SRW:
            *protocolString = "CES_SRW";
            break;
        case MAC_PROTOCOL_CES_EPLRS:
            *protocolString = "CES_EPLRS";
            break;
#endif // ADDON_BOEINGFCS

        default:
            *protocolString = "Unknown";
            break;
    }
}

#endif

// FUNCTION            :: NetworkIpIsUnnumberedInterface
// LAYER               :: Network
// PURPOSE             :: checking for unnumbered Interface.
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + intIndex        ::   int     :.Interface Index
// RETURN              :: BOOL
// **/
BOOL NetworkIpIsUnnumberedInterface(Node* node, int intIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    return ip->interfaceInfo[intIndex]->isUnnumbered;
}


//support fix for ticket#1087 start
// FUNCTION            :: NetworkIpGetIpAddressForUnnumberedInterface
// LAYER               :: Network
// PURPOSE             :: getting IP address for unnumbered Interface.
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + intIndex        ::   int     :.Interface Index
// RETURN              :: NodeAddress
// **/
NodeAddress NetworkIpGetIpAddressForUnnumberedInterface(Node* node,
                                                        int intIndex)
{
    int i = 0;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    NodeAddress borrowedAddress = ANY_ADDRESS;
    BOOL isCentralizedIp = TRUE;

    // find first non-unnumbered ipv4 interface
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if ((ip->interfaceInfo[i]->interfaceType == NETWORK_IPV4
            || ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL)
            && ip->interfaceInfo[i]->isUnnumbered == FALSE)
        {
            borrowedAddress = NetworkIpGetInterfaceAddress(node, i);
            isCentralizedIp = FALSE;
            break;
        }
    }

    // All ipv4 interfaces are unnumbered
    if (isCentralizedIp == TRUE)
    {
        //find first ipv4 interface
        for (i = 0; i < node->numberInterfaces; i++)
        {
            if ((ip->interfaceInfo[i]->interfaceType == NETWORK_IPV4
                || ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL))
            {
                borrowedAddress = NetworkIpGetInterfaceAddress(node, i);
            break;
            }
        }
    }
    return borrowedAddress;
}
//support fix for ticket#1087 end

// -------------------------------------------------------------------------
// API :: GetDefaultIPv4InterfaceAddress
// PURPOSE :: Returns Default ipv4 Interface address
// PARAMETERS ::
// + node : Node* : Pointer to the Node
// RETURN :: NodeAddress
// ------------------------------------------------------------------------
NodeAddress GetDefaultIPv4InterfaceAddress(Node* node)
{
    int i = 0;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    for (; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->interfaceType == NETWORK_IPV4 ||
            ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL)
        {
            return ip->interfaceInfo[i]->ipAddress;
        }
    }

    return ANY_ADDRESS;
}

#ifdef ADDON_BOEINGFCS
QueuePerDscpStats* QueueGetPerDscpStatEntry(Message *msg,
                                            QueuePerDscpMap *dscpStats)
{
    IpHeaderType *ipHeader;
    ipHeader = (IpHeaderType *) msg->packet;
    unsigned int tos = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
    int prio = tos>>2;
    QueuePerDscpMapIter queuePerDscpMapIter = dscpStats->find(prio);

    QueuePerDscpStats *statsEntry = NULL;

    if (queuePerDscpMapIter == dscpStats->end())
    {
        (*dscpStats)[prio] = new QueuePerDscpStats;
        statsEntry = (*dscpStats)[prio];
        statsEntry->numPacketsQueued = 0;
        statsEntry->numPacketsDequeued = 0;
        statsEntry->numPacketsDropped = 0;
    }
    else
    {
        statsEntry = (*queuePerDscpMapIter).second;
    }
    return statsEntry;
}

#endif
//---------------------------------------------------------------------------
// FUNCTION     NetworkIpHeaderCheck()
// PURPOSE      To check the header of incoming packet for errors in case
//              ICMP is senabled
// PARAMETERS   Node *node - Pointer to node.
//              Message *msg - Message pointer
//              int incomingInterface - incoming interface
// RETURN       BOOL.
//---------------------------------------------------------------------------

BOOL NetworkIpHeaderCheck(
    Node *node,
    Message *msg,
    int incomingInterface)
{

    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    IpHeaderType *ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
    unsigned short pointer = 0;
    BOOL param = FALSE;

    if (IpHeaderSize(ipHeader) > sizeof(IpHeaderType))
    {
        char *option = (char *)ipHeader;
        option = option + (sizeof(IpHeaderType) + 1);
        if (*option == 0)
        {
            if (icmp->parameterProblemEnable)
            {
                pointer=PROBLEM_IN_OPTION;
                param = TRUE;
            }
            else
            {
                ERROR_Assert(FALSE, "Problem in IP Option Length\n");
            }
        }
    }

    if (IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len)<5)
    {
        if (icmp->parameterProblemEnable)
        {
            pointer = PROBLEM_IN_HEADER_LENGTH;
            param = TRUE;
        }
        else
        {
            ERROR_Assert(FALSE, "Problem in IP Header Length......\n");
        }
    }
    else if (IpHeaderGetIpDontFrag(ipHeader->ipFragment)==1 &&
             IpHeaderGetIpMoreFrag(ipHeader->ipFragment==1))
    {
        if (icmp->parameterProblemEnable)
        {
            pointer = PROBLEM_IN_FLAGS_OR_FRAGOFFSET;
            param = TRUE;
        }
        else
        {
            ERROR_Assert(FALSE, "Problem in IP Header Flags......\n");
        }
    }

    if (param)
    {
         BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                      msg,
                                      ipHeader->ip_src,
                                      incomingInterface,
                                      ICMP_PARAMETER_PROBLEM,
                                      ICMP_PARAMETER_PROBLEM_CODE,
                                      pointer,
                                      0);
         if (ICMPErrorMsgCreated)
         {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
             char srcAddr[MAX_STRING_LENGTH];
             IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
             printf("Node %d sending parameter problem message to %s\n",
                                node->nodeId, srcAddr);
#endif
             (icmp->icmpErrorStat.icmpParameterProblemSent)++;
         }
         return TRUE;
    }
    return FALSE;
}



// /**
// API        :: FindTraceRouteOption
// LAYER      :: Network
// PURPOSE    :: Searches the IP header for the Traceroute option field ,
//               and returns a pointer to traceroute header.
// PARAMETERS ::
// + ipHeader  : const IpHeaderType*  : Pointer to an IP header.
// RETURN     :: ip_traceroute* : pointer to the header of the traceroute
//               option field. NULL if no option fields, or the desired
//               option field cannot be found.
// **/

ip_traceroute *FindTraceRouteOption(const IpHeaderType *ipHeader)
{
    IpOptionsHeaderType *currentOption;
    ip_traceroute *traceRouteOption;

    // If the passed in IP header is the minimum size, return NULL.
    // (no option in IP header)
    if (IpHeaderSize(ipHeader) == sizeof(IpHeaderType))
    {
        return NULL;
    }

    // Move pointer over 20 bytes from start of IP header,
    // so currentOption points to first option.
    currentOption = (IpOptionsHeaderType *)
                    ((char *) ipHeader + sizeof(IpHeaderType));
    traceRouteOption = (ip_traceroute *)currentOption;

    // Loop until an option code matches optionKey.
    while (traceRouteOption->type != IPOPT_TRCRT)
    {
        if (traceRouteOption->type == IPOPT_NOP)
        {
            // Move pointer over 1 byte from start of options field, so
            // currentOption points to next option, if the current
            // option is a NOP.
            currentOption = (IpOptionsHeaderType*)
                            ((char*) currentOption + 1);
            traceRouteOption = (ip_traceroute*)currentOption;

            continue;
        }
        // Options should never report their length as 0.
        if (currentOption->len == 0)
        {
            return NULL;
        }
        /* Current option code doesn't match;
           move pointer over to next option */
        currentOption =
            (IpOptionsHeaderType *) ((char *) currentOption +
                                                         currentOption->len);

        traceRouteOption = (ip_traceroute *)currentOption;

        // If we've run out of options, return NULL.
        if ((char *) currentOption
                >= (char *) ipHeader + IpHeaderSize(ipHeader)||
            *((char *) currentOption) == IPOPT_EOL)
        {
            return NULL;
        }
    }

    // Found tracerote option, Return pointer to option.

    return traceRouteOption;
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpAddHeaderWithOptions()
// PURPOSE      Add an IP packet header to a message.
//              The new message has an IP packet.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message.
//              NodeAddress sourceAddress
//                  Source IP address.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              TosType priority
//                  Currently a TosType.
//                  (values are not standard for "IP type of service field"
//                  but has correct function)
//              unsigned char protocol
//                  IP protocol number.
//              unsigned ttl
//                  Time to live.
//                  If 0, uses default value IPDEFTTL, as defined in
//                  include/ip.h.
// RETURN       None.
//-----------------------------------------------------------------------------

void
NetworkIpAddHeaderWithOptions(
    Node *node,
    Message *msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    TosType priority,
    unsigned char protocol,
    unsigned ttl,
    int ipHeaderLength,
    char *ipOptions)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader;
    int hdrSize = ipHeaderLength;
    char *options;

    MESSAGE_AddHeader(node, msg, hdrSize, TRACE_IP);

    ipHeader = (IpHeaderType *) msg->packet;
    memset(ipHeader, 0, hdrSize);
    if ((unsigned)ipHeaderLength > sizeof(IpHeaderType))
    {
        options = (char *)ipHeader;
        options = options + sizeof(IpHeaderType);
        memcpy(options, ipOptions, ipHeaderLength - sizeof(IpHeaderType));
    }
    IpHeaderSetVersion(&(ipHeader->ip_v_hl_tos_len), IPVERSION4) ;
    ipHeader->ip_id = ip->packetIdCounter;
    ip->packetIdCounter++;
    ipHeader->ip_src = sourceAddress;
    ipHeader->ip_dst = destinationAddress;

    if (ttl == 0)
    {
        ipHeader->ip_ttl = IPDEFTTL;
    }
    else
    {
        ipHeader->ip_ttl = (unsigned char) ttl;
    }

    // TOS field (8 bit) in the IPV4 header
    IpHeaderSetTOS(&(ipHeader->ip_v_hl_tos_len), priority);


    if (ip->isPacketEcnCapable)
    {
        // Bits 6 and 7 of TOS field in the IPV4 header are used by ECN
        // and proposed respectively for the ECT and CE bits.
        // So before assign the value of priority to ip_tos, leave bits 6 and 7.

        if (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) & 0x03)
        {
            // User TOS specification conflicts with an ~enabled~ ECN
            char errorString[MAX_STRING_LENGTH];
            sprintf(errorString,
                    "~enabled~ ECN!!! ECN bits of TOS field in"
                    " application Input should contain zero values\n");
            ERROR_ReportError(errorString);
        }

        IpHeaderSetTOS(&(ipHeader->ip_v_hl_tos_len),
            (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) | IPTOS_ECT));
        ip->isPacketEcnCapable = FALSE;
    }
#ifdef ECN_DEBUG_TEST
    {
        /*
         * Mark the CE bit of some specific data packets (for testing)
         */
        int markCount = ECN_TEST_PKT_MARK;
        UInt32 markValues[] = { 14002};
        static int markFlag[] = { 1};
        struct tcphdr *aTcpHdr = (struct tcphdr *)((char*)ipHeader +
                                                    hdrSize);
        if (markCount) {
            int counter;
            for (counter = 0; counter < markCount; counter++) {
                if (aTcpHdr->th_seq == markValues[counter]
                            && markFlag[counter]) {
                    markFlag[counter]--;
                    ipHeader->ip_tos |=  IPTOS_CE;
                    printf ("\nSequence number of CE (specific for test)"
                             " marked packet is %u\n\n",(unsigned) aTcpHdr->th_seq);
                }
            }
        }
    }
#endif /* ECN_DEBUG_TEST */

    ipHeader->ip_p = protocol;

    ERROR_Assert(MESSAGE_ReturnPacketSize(msg) <= IP_MAXPACKET,
                 "IP datagram (including header) exceeds IP_MAXPACKET bytes");

        IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),
            MESSAGE_ReturnPacketSize(msg));
        unsigned int hdrSize_temp= hdrSize/4;
        IpHeaderSetHLen(&(ipHeader->ip_v_hl_tos_len), hdrSize_temp);
        //original code
        //SetIpHeaderSize(ipHeader, hdrSize);
}

#ifdef CYBER_CORE
// FUNCTION            :: NetworkIpRemoveBroadcastForwardMappingEntries
// LAYER               :: Network
// PURPOSE             :: Remove entries from map created for recived packets
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + msg               :: Message* :.Pointer to packet message

// RETURN              :: BOOL
// **/
static void NetworkIpRemoveBroadcastForwardMappingEntries(
    Node* node,
    Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    map<Int64, clocktype>::iterator it;
    map<Int64, clocktype>::iterator tempIt;


    it = ip->broadcastAppMapping->begin() ;
    while (it != ip->broadcastAppMapping->end())
    {
        if ((getSimTime(node) - it->second) >= ip->broadcastForwardingTimeout)
          {
            tempIt= it;
            it++;
            ip->broadcastAppMapping->erase(tempIt);
        }
        else
        {
            it++;
        }
    }

    MESSAGE_Send(node, msg, ip->broadcastForwardingTimeout);
}
#endif //CYBER_CORE

// -----------------------------------------------------------------------
//FUNCTION            :: IsIgmpPacket
// PURPOSE            :: Checks whether this packet is an IGMP packet and
//                       whether IGMP is enabled for this node.
// PARAMETERS ::
// + node : Node*     : Pointer to the Node
// + ipHeader->ip_p   : ip protocol in the ip header of this message.
// -----------------------------------------------------------------------
bool
IsIgmpPacket(Node* node, unsigned char ip_protocol)
{
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;

    if (ip->isIgmpEnable && ip_protocol == IPPROTO_IGMP)
    {
        return TRUE;
    }

    return FALSE;
}

#ifdef CYBER_CORE
// FUNCTION            :: NetworkIpNeedsToForwardAppBroadcast
// LAYER               :: Network
// PURPOSE             :: checking requirement of forwarding the broadcast
//                     ::   application packets
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + msg               :: Message* :.Pointer to packet message
// + destAddress       :: NodeAdddress : Ipv4 destination address
// RETURN              :: BOOL
// **/

static BOOL NetworkIpNeedsToForwardAppBroadcast(Node* node,
                                     Message *msg,
                                     NodeAddress destAddress)
{

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    if (destAddress == ANY_ADDRESS && ip->isAppBroadcastForwardingEnabled)
    {
        // originating protocol can be safely used
        //as TCP does not support broadcast of application data packets
        switch(msg->originatingProtocol)
        {
            case TRACE_CBR:
                {
                    return TRUE;
                }

            default:
                return FALSE;
        }

    }

    return FALSE;

}

// FUNCTION            :: NetworkIpCheckDuplicateAppBroadcastReceived
// LAYER               :: Network
// PURPOSE             :: check whether packet received is a duplicate
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + msg               :: Message* :.Pointer to packet message

// RETURN              :: BOOL
// **/

static BOOL NetworkIpCheckDuplicateAppBroadcastReceived(
    Node* node,
    Message *msg)
{

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    map<Int64, clocktype>::iterator it;

    Int64 tempId = msg->originatingNodeId;
    tempId = tempId << 32;
    tempId = tempId | msg->sequenceNumber;

    it = ip->broadcastAppMapping->find(tempId);

    if (it != ip->broadcastAppMapping->end())
    {
        return TRUE;
    }

    // insert is required as node may not forward packet to any interface.
    ip->broadcastAppMapping->insert(pair<Int64, clocktype>(tempId,
                                                          getSimTime(node)));

    return FALSE;
}

#endif
// -----------------------------------------------------------------------
//FUNCTION            :: NetworkIpDecreaseTTL
// PURPOSE            :: Checks whether this packet is an IGMP packet and
//                       whether IGMP is enabled for this node.
// PARAMETERS ::
// + node : Node*     : Pointer to the Node
// + msg  : Message*  : Pointer to message
// + incomingInterface  : int  : Incoming interface
// -----------------------------------------------------------------------
static BOOL
NetworkIpDecreaseTTL(Node *node, Message *msg, int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    ActionData acnData;
    NetworkType netType = NETWORK_IPV4;

    BOOL isPacketTTL=false;
    BOOL isPacketOut=false;
    if (ipHeader->ip_ttl <= IP_TTL_DEC)
        isPacketTTL = true;

    if (isPacketTTL)
    {
#ifdef EXATA
        /*
        For TTL 1 we must not generate a TTL exceeded when we have a routing
        protocol running on an operational host. The operational host will
        take care of it. This is true for unicast data packets, multicast
        control packets for unicast and multicast routing protocols
        */
        if ((incomingInterface != CPU_INTERFACE) &&
           (node->macData[incomingInterface])
           && ((node->macData[incomingInterface]->isIpneInterface) ||
           ((node->partitionData->rrInterface->GetReplayMode()) && 
           (node->macData[incomingInterface]->isReplayInterface))))
        {
            if ((NetworkIpGetUnicastRoutingProtocolType(node,incomingInterface)
                == ROUTING_PROTOCOL_NONE)&&(ip->interfaceInfo
                [incomingInterface]->multicastProtocolType
                == ROUTING_PROTOCOL_NONE))
            {
               isPacketOut=true;
            }
        }
#endif //EXATA

        // Increment stat for number of IP datagrams discarded because
        // of header errors (e.g., checksum error, version number
        // mismatch, TTL exceeded, etc.).

        // STATS DB CODE
        if (!isPacketOut)
        {
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                incomingInterface,

                "NetworkPacketDrop",
                "Zero TTL",
                0,
                0,
                0,
                0);

#endif
            if (!NetworkIpIsMulticastAddress(node, ipHeader->ip_dst) &&
                ipHeader->ip_dst != ANY_DEST )
            {
                ip->stats.ipInHdrErrors++;
            }
            if (node->networkData.networkStats)
            {
                ip->newStats->AddPacketDroppedTtlExpiredDataPoints(node);
            }
            //Trace drop
            acnData.actionType = DROP;
            acnData.actionComment = DROP_TTL_ZERO;
            TRACE_PrintTrace(node,
                msg,
                TRACE_NETWORK_LAYER,
                PACKET_OUT,
                &acnData,
                netType);
            if (ip->isIcmpEnable && icmp->TTLExceededEnable)
            {
                // send ICMP packet with time exceeded type
                BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                          msg,
                                          ipHeader->ip_src,
                                          incomingInterface,
                                          ICMP_TIME_EXCEEDED,
                                          ICMP_TTL_EXPIRED_IN_TRANSIT,
                                          0,
                                          0);
                if (ICMPErrorMsgCreated)
                {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                    printf("Node %d sending TTL expired message to %s\n",
                        node->nodeId, srcAddr);
#endif
                   (icmp->icmpErrorStat.icmpTTLExceededSent)++;
                }
            }
            // Free message.
            MESSAGE_Free(node, msg);
            return FALSE;
        }
        else
            return TRUE;
    }
    else
    {
        //according to rfc 791, the TTL should be decreased at the
        //time of forwarding the packet.
        ipHeader->ip_ttl = (unsigned char) (ipHeader->ip_ttl - IP_TTL_DEC);
        return TRUE;
    }
}

BOOL
IsDuplicatePacket(Node* node,
        int interfaceIndex,
        Message* msg)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    BOOL result = FALSE;

    switch (ip->interfaceInfo[interfaceIndex]->
        multicastProtocolType)
    {
#ifdef WIRELESS_LIB
        case MULTICAST_PROTOCOL_ODMRP:
        {
            if (OdmrpCheckIfItIsDuplicatePacket(node, msg))
            {
                // It is a duplicate packet no need to process it
                result = TRUE;
            }
            break;
        }
#endif // WIRELESS_LIB
#ifdef ADDON_BOEINGFCS
        case MULTICAST_PROTOCOL_PIM:
        {
            if (MulticastCesRpimCheckIfItIsDuplicatePacket(node,
                    interfaceIndex, msg) ||
                RPimCheckIfItIsDuplicatePacket(node, interfaceIndex, msg))
            {
                result = TRUE;
            }
            break;
        }
#endif
    }

    return result;
}

BOOL 
NetworkIpCheckApplicationDataPacket(Node* node, Message * msg)
{
    int IpHeaderlen;

    IpHeaderType* ipHeader = (IpHeaderType*)MESSAGE_ReturnPacket(msg);
    if (IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len) == 4)
    {
        IpHeaderlen = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len)*4;
        if (ipHeader->ip_p == IPPROTO_TCP)
        {
            struct tcphdr* tcpHdr;
            tcpHdr = (tcphdr*)(MESSAGE_ReturnPacket(msg)+ IpHeaderlen);
            switch (tcpHdr->th_sport)
            {
            case APP_EXTERIOR_GATEWAY_PROTOCOL_BGPv4:
                return FALSE;
            default:
                return TRUE;
            }
        }
        else if (ipHeader->ip_p == IPPROTO_UDP)
        {
            TransportUdpHeader* udpHdr = (TransportUdpHeader*)(MESSAGE_ReturnPacket(msg)
            + IpHeaderlen); 
            switch (udpHdr->sourcePort)
            {
            case APP_ROUTING_BELLMANFORD:
            case APP_ROUTING_FISHEYE:
            case APP_ROUTING_RIP:
            case APP_ROUTING_RIPNG:
            case APP_ROUTING_OLSRv2_NIIGATA:
            case APP_ROUTING_HSRP:
            case APP_ROUTING_STATIC:
#ifdef EXATA
                if (msg->isEmulationPacket)
                {
                    return TRUE;
                }
#endif
                return FALSE;
            case APP_ROUTING_OLSR_INRIA:
                return FALSE;
            default:
                return TRUE;
            }
        }
        else//Neither UDP nor TCP packet
        {
            return TRUE;

        }
    }
    else
    {
        return FALSE;
    }
}

#ifdef ADDON_DB
void HandleStatsDBIpMulticastNetSummaryTableInsertion(Node* node)
{
    StatsDb* db = node->partitionData->statsDb;
    PartitionData* partition = node->partitionData;
    Node* traverseNode = node;
    NetworkDataIp *ip = NULL;

    // Check if the Table exists.
    if (!db || !db->statsSummaryTable ||
        !db->statsSummaryTable->createMulticastNetSummaryTable)
    {
        // Table does not exist
        return;
    }

    while (traverseNode != NULL)
    {
        if (traverseNode->partitionId != partition->partitionId)
        {
            traverseNode = traverseNode->nextNodeData;
            continue;
        }

        //getting network ip data
        ip = (NetworkDataIp *) traverseNode->networkData.networkVar;

        if (!ip)
        {
            traverseNode = traverseNode->nextNodeData;
            continue;
        }

        StatsDBMulticastNetworkSummaryContent stats;
        
        if (ip->ipMulticastNetSummaryStats->m_NumDataSent != 0
            || ip->ipMulticastNetSummaryStats->m_NumDataRecvd != 0
            || ip->ipMulticastNetSummaryStats->m_NumDataForwarded != 0
            || ip->ipMulticastNetSummaryStats->m_NumDataDiscarded != 0)
        {
            strcpy(stats.m_ProtocolType,"OTHER");
            stats.m_NumDataSent =
                                ip->ipMulticastNetSummaryStats->m_NumDataSent;
            stats.m_NumDataRecvd =
                               ip->ipMulticastNetSummaryStats->m_NumDataRecvd;
            stats.m_NumDataForwarded =
                           ip->ipMulticastNetSummaryStats->m_NumDataForwarded;
            stats.m_NumDataDiscarded =
                           ip->ipMulticastNetSummaryStats->m_NumDataDiscarded;

            // At this point we have the overall stats per node. Insert into
            // the database now.
            STATSDB_HandleMulticastNetSummaryTableInsert(traverseNode,stats);

            //Init the stats variables again for peg count over time period
            //strcpy(ip->ipMulticastNetSummaryStats->m_ProtocolType,"");
            ip->ipMulticastNetSummaryStats->m_NumDataSent = 0;
            ip->ipMulticastNetSummaryStats->m_NumDataRecvd = 0;
            ip->ipMulticastNetSummaryStats->m_NumDataForwarded = 0;
            ip->ipMulticastNetSummaryStats->m_NumDataDiscarded = 0;
        }
       
        //next node
        traverseNode = traverseNode->nextNodeData;
    }
}
#endif
