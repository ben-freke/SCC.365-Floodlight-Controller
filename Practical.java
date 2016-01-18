 package net.floodlightcontroller.practical;

 import java.io.IOException;
 import java.util.ArrayList;
 import java.util.Collection;
 import java.util.Collections;
 import java.util.Map;
 import java.util.HashMap;
 import java.util.Arrays;
 import java.util.Iterator;
 import java.util.List;

 import net.floodlightcontroller.core.FloodlightContext;
 import net.floodlightcontroller.core.IFloodlightProviderService;
 import net.floodlightcontroller.core.IOFMessageListener;
 import net.floodlightcontroller.core.IOFSwitch;
 import net.floodlightcontroller.core.module.FloodlightModuleContext;
 import net.floodlightcontroller.core.module.FloodlightModuleException;
 import net.floodlightcontroller.core.module.IFloodlightModule;
 import net.floodlightcontroller.core.module.IFloodlightService;
 import net.floodlightcontroller.packet.Ethernet;
 import net.floodlightcontroller.packet.IPv4;
 import net.floodlightcontroller.packet.ICMP;
 import net.floodlightcontroller.util.MACAddress;


 import org.openflow.protocol.OFMessage;
 import org.openflow.protocol.OFMatch;
 import org.openflow.protocol.OFFlowMod;
 import org.openflow.protocol.OFPacketIn;
 import org.openflow.protocol.OFPacketOut;
 import org.openflow.protocol.OFPort;
 import org.openflow.protocol.OFType;
 import org.openflow.protocol.action.OFAction;
 import org.openflow.protocol.action.OFActionOutput;
 import org.openflow.protocol.action.OFActionNetworkLayerSource;
 import org.openflow.protocol.action.OFActionTransportLayerSource;
 import org.openflow.protocol.action.OFActionNetworkLayerDestination;
 import org.openflow.protocol.action.OFActionTransportLayerDestination;
 import org.openflow.protocol.action.OFActionDataLayerSource;
 import org.openflow.protocol.action.OFActionDataLayerDestination;
 import org.openflow.util.U16;
 import org.openflow.util.HexString;
 import org.slf4j.Logger;
 import org.slf4j.LoggerFactory;



/**
* @author Ben Freke
* SCC365 router coursework - Static routers with ICMP response capability
*
* This is a skeleton class
*/


public class Practical implements IFloodlightModule, IOFMessageListener {

	protected static Logger log = LoggerFactory.getLogger(Practical.class);
	protected IFloodlightProviderService floodlightProvider;
	private HashMap<Long, RouterData> routers = new HashMap<Long, RouterData>();
	private int noFlowMods = 0;
	
	@Override
	public String getName() {
		return "practical";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
		new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		log = LoggerFactory.getLogger(Practical.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	/* Handle a packet message - called every time a packet is received */
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		/**
		 * The receive command. This handles incoming packets.
		 */

		/**
		 * Set up the variables that are used in the packet inspection.
		 * Set up the RouteTable and ARPTable objects to be used for packet forwarding
		 */

		OFPacketIn pi = (OFPacketIn) msg;
		OFMatch match = new OFMatch(); 
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		RouteTable routeTable = null;
		ARPTable arpTable = null;
		System.out.println("Packet Received");
		System.out.println(match.getDataLayerType());


		/**
		 * If the OpenFlow Controller hasn't dealt with this router before, add the router to the routers HashMap
		 */

		if (!routers.containsKey(sw.getId()))
		{
			routers.put(sw.getId(), new RouterData(sw));
			//If the router doesn't exist in the Router Map, add it to the Router Map.
			System.out.println("Router Added");
		}


		/**
		 * Now the controller is interfacing with a known switch, retreive the routing table and arp table,
		 * and store them in the variables created above.
		 */
		routeTable = routers.get(sw.getId()).routeTable();
		arpTable = routers.get(sw.getId()).arpTable();

		/**
		 * Create an array of OFActions, for actions to be pushed to and ultimately to be sent to the OF Switch
		 */

		ArrayList<OFAction> actionsArray = new ArrayList<OFAction>();

		/**
		 * Decode the OFMatch object to determine the IP Source and Destination Addresses
		 */

		String ip[] = match.toString().split(",");
    	String ipParts[] = ip[7].split("=");
    	String ipSrc = ipParts[1];
    	ipParts = ip[6].split("=");
    	String ipDst = ipParts[1];

		/**
		 * Test that the packet is IPv4 - if it isn't, drop it.
		 */

		if (match.getDataLayerType() != 2048){

			/**
			 * Packet is not IPv4
			 */

			System.out.println("Not IPv4");

			/**
			 * Generate a OFActionOutput with a null port to drop the packet
			 */

			OFActionOutput actionOutput = new OFActionOutput();
			actionOutput.setPort(OFPort.OFPP_NONE.getValue());
			actionsArray.add(actionOutput);

			/**
			 * Generate an OF Match for the entire data layer type (e.g. all ARP packets)
			 */

			OFMatch newMatch = new OFMatch();
			newMatch.fromString("dl_type=0x" + Integer.toHexString(match.getDataLayerType()));

			/**
			 * Push the FlowMod to the OpenFlow Switch, causing it to drop all future packets to for this DL type.
			 */

			System.out.println("Flow Added");
			installFlowMod(sw, pi, newMatch, actionsArray, 0, 0, 1, cntx);

			/**
			 * Write the packet to the port and continue processing. Don't run anything else on the receive command.
			 */

			writePacketToPort(sw, pi, actionsArray, cntx);
			return Command.CONTINUE;


		}

		/**
		 * Test if the packet is coming to the router and if it's ICMP
		 * If it is, get the MAC Address of the source, and create and send an ICMP reply to that MAC Address
		 */

    	if(routeTable.nextHop(ipSrc).equals(routeTable.nextHop(ipDst)) && match.getNetworkProtocol() == 1)
    	{

    		System.out.println("It's coming to me, the router");
    		String mac = arpTable.mac(ipSrc);
    		String[] macParts = mac.split(":");

    		// convert hex string to byte values
    		byte[] macBytes = new byte[6];
    		for(int i=0; i<6; i++){
    		    Integer hex = Integer.parseInt(macParts[i], 16);
    		    macBytes[i] = hex.byteValue();
    		}
  
    		writeICMPReplyToPort(sw, pi, ipSrc, match.getDataLayerSource(), ipDst, match.getDataLayerDestination(), pi.getInPort(), cntx);
    	}

		/**
		 * If it's not coming to the router, but the router has the MAC address in its ARP table, the desintation
		 * node is on the router's own network (for example, a router connected to this router).
		 */

    	else if (arpTable.hasARP(ipDst))
    	{
    		System.out.println("Has the ARP, so it's on my network");

			/**
			 * Get the MAC Address of the destination
			 */

    		String mac = arpTable.mac(ipDst);
    		String[] macParts = mac.split(":");

    		// convert hex string to byte values
    		byte[] macBytes = new byte[6];
    		for(int i=0; i<6; i++){
    		    Integer hex = Integer.parseInt(macParts[i], 16);
    		    macBytes[i] = hex.byteValue();
    		}

			/**
			 * Create a desintation action to send the packet to, and give it the MAC address derived above
			 */
    		
    		OFActionDataLayerDestination actionDestination = new OFActionDataLayerDestination();
    		actionDestination.setDataLayerAddress(macBytes);
    		actionsArray.add(actionDestination);

			/**
			 * Create an output action to send the packet to a port
			 */

    		OFActionOutput actionOutput = new OFActionOutput();
        	actionOutput.setPort(routeTable.outPort(ipDst));
        	actionsArray.add(actionOutput);

			/**
			 * Create a new match with the correct data layer type and destination IP address
			 */

        	OFMatch newMatch = new OFMatch();
        	newMatch.fromString("dl_type=0x0800,nw_dst=" + ipDst);

			/**
			 * Push the flow to the switch
			 */

        	System.out.println("Flow Added");
        	installFlowMod(sw, pi, newMatch, actionsArray, 0, 0, 1, cntx);
        	noFlowMods++;
        	System.out.println("Number of Flow Mods:" + noFlowMods);
    	}

		/**
		 * If the router has the next hop (but it doesn't have the device on its network)
		 */

    	else if (routeTable.nextHop(ipDst) != null)
    	{

			System.out.println("Does not have the ARP, so it's going to a different network");

			/**
			 * Parse the MAC Address
			 */

    		String mac = arpTable.mac(routeTable.nextHop(ipDst));
    		String[] macParts = mac.split(":");

    		// convert hex string to byte values
    		byte[] macBytes = new byte[6];
    		for(int i=0; i<6; i++){
    		    Integer hex = Integer.parseInt(macParts[i], 16);
    		    macBytes[i] = hex.byteValue();
    		}

			/**
			 * Create a desintation action to send the packet to, and give it the MAC address derived above
			 */
    		
    		OFActionDataLayerDestination actionDestination = new OFActionDataLayerDestination();
    		actionDestination.setDataLayerAddress(macBytes);
    		actionsArray.add(actionDestination);

			/**
			 * Create an output action to send the packet to a port
			 */

    		OFActionOutput actionOutput = new OFActionOutput();
        	actionOutput.setPort(routeTable.outPort(ipDst));
        	actionsArray.add(actionOutput);

			/**
			 * The subnet is changing, so IP Destinations can be pushed to the switch as a subnet instead of a whole IP
			 * Parse the IP Destination, and generate the genetic subnet
			 */


        	String[] ipDstParts = ipDst.split("\\.");
        	String ipDstNet = ipDstParts[0] + "." + ipDstParts[1] + "." + ipDstParts[2] + ".0/24";
        	System.out.println(ipDstNet);

			/**
			 * Create a new OFMatch with the IP Destination subnet in.
			 */
        	OFMatch newMatch = new OFMatch();
        	newMatch.fromString("dl_type=0x0800,nw_dst=" + ipDstNet);

			/**
			 * Install the flow to the OpenFlow Switch
			 */
        	System.out.println("Flow Added");
        	installFlowMod(sw, pi, newMatch, actionsArray, 0, 0, 1, cntx);
        	noFlowMods++;
        	System.out.println("Number of Flow Mods:" + noFlowMods);
        }

		/**
		 * Print out some debugging information
		 */

		System.out.println("Destination: " + String.valueOf(match.getNetworkDestination()));
		System.out.println("Out Port: " + String.valueOf(routeTable.outPort(ipDst)));
		System.out.println("Next Hop: " + String.valueOf(routeTable.nextHop(ipDst)));
		System.out.println("Switch: " + String.valueOf(sw.getId()));

		/**
		 * If the next hop returns null, this means the IP Address is not in the routers ARP or Next Hop table, so
		 * the router does not have a route to this node.
		 */

		if (routeTable.nextHop(ipDst) == null){


			System.out.println("Destination Unreachable");

			/**
			 * Generate a OFActionOutput with a null port to drop the packet
			 */

			OFActionOutput actionOutput = new OFActionOutput();
			actionOutput.setPort(OFPort.OFPP_NONE.getValue());
			actionsArray.add(actionOutput);

			/**
			 * Generate an OF Match for the entire subnet (as the routing table works on a per subnet basis, so if
			 * it can't match a packet the entire subnet is unreachable
			 */

			String[] ipDstParts = ipDst.split("\\.");
			String ipDstNet = ipDstParts[0] + "." + ipDstParts[1] + "." + ipDstParts[2] + ".0/24";
			OFMatch newMatch = new OFMatch();
			newMatch.fromString("dl_type=0x0800,nw_dst=" + ipDstNet);

			/**
			 * Push the FlowMod to the OpenFlow Switch, causing it to drop all future packets to this subnet.
			 */

			System.out.println("Flow Added");
			installFlowMod(sw, pi, newMatch, actionsArray, 0, 0, 1, cntx);
		}

		/**
		 * Finally, write the packet to the port so the packet that came to the OpenFlow controller is not lost
		 */
    	
    	writePacketToPort(sw, pi, actionsArray, cntx);

		/**
		 * Continue packet processing
		 */
		
		return Command.CONTINUE;
	}


	/*
	* Write a packet out to a specific port 
	*/
	public void writePacketToPort(IOFSwitch sw, OFPacketIn pi, ArrayList<OFAction> actions, FloodlightContext cntx){

		OFPacketOut packetOut = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
		packetOut.setBufferId(pi.getBufferId());
		packetOut.setInPort(pi.getInPort());
		//Calculate the length of actions list
		short length = 0;
		Iterator<OFAction> it = actions.iterator();
		while(it.hasNext())
			length += it.next().getLength();
		packetOut.setActions(actions);
		packetOut.setActionsLength(length);
		if (pi.getBufferId() == 0xffffffff) {
			byte[] packetData = pi.getPacketData();
			packetOut.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH + packetOut.getActionsLength() + packetData.length));
			packetOut.setPacketData(packetData);
		} else {
			packetOut.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH + packetOut.getActionsLength()));
		}
		try {
			sw.write(packetOut, cntx);
		} catch (IOException e) {
			log.error("Failure writing packet to port", e);
		}
	}

	/*
	* Write an ICMP reply packet out that is replying to the packet in ICMP request
	*
	* @param sw
	* @param pi
	* @param dst_ipaddr The destination IP address (as String) the ICMP reply is going to (found from the source IP address of the ICMP request)
	* @param dst_dladdr The destination MAC address (as byte array) this is found from the source MAC address of the IMCP request
	* @param src_ipaddr The source IP address (as String) Note this should be the same IP address associated with the outPort
	* @param src_dladdr The source MAC address (as byte array) Note this should be the same MAC address associate with the outPort
	* @param outPort The port on the OpenFlow switch that the packet will be send out on
	* @param cntx
	*/
	public void writeICMPReplyToPort (IOFSwitch sw, OFPacketIn pi, String dstIP, byte[] dstMAC, String srcIP, byte[] srcMAC, Short outPort,  FloodlightContext cntx) {
		OFPacketOut packetOut = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);

		Ethernet l2 = new Ethernet();
		l2.setSourceMACAddress(srcMAC);
		l2.setDestinationMACAddress(dstMAC);
		l2.setEtherType(Ethernet.TYPE_IPv4);

		IPv4 l3 = new IPv4();
		l3.setSourceAddress(IPv4.toIPv4Address((srcIP)));
		l3.setDestinationAddress(IPv4.toIPv4Address((dstIP)));
		l3.setProtocol(IPv4.PROTOCOL_ICMP);

		ICMP icmp = new ICMP();
		icmp.deserialize(Arrays.copyOfRange(pi.getPacketData(), 34, 98), 0, pi.getTotalLength()-34);
		icmp.setIcmpType((byte) 0x0);//TODO update ICMP_REPLY to constant from ICMP class when using floodlight v1
		icmp.setIcmpCode((byte) 0x0);
	
		l2.setPayload(l3);
		l3.setPayload(icmp);
	
		OFActionOutput action = new OFActionOutput().setPort(outPort);
		packetOut.setActions(Collections.singletonList((OFAction)action));
		packetOut.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
		packetOut.setBufferId(-1);
		byte[] serializedData = l2.serialize();
		packetOut.setPacketData(serializedData);
		packetOut.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH + packetOut.getActionsLength() + serializedData.length));
		try {
			sw.write(packetOut, cntx);
			log.debug("ICMP reply sent");
		} catch (IOException e) {
			log.error("Failure writing packet to port", e);
		}
	}

	/* Install a flow-mod with given parameters */
	private void installFlowMod(IOFSwitch sw, OFPacketIn pi, OFMatch match, ArrayList<OFAction> actions, int idleTimeout, int hardTimeout, int priority, FloodlightContext cntx){
		OFFlowMod flowMod = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		flowMod.setBufferId(-1);
		flowMod.setMatch(match);
		flowMod.setCommand(OFFlowMod.OFPFC_ADD);
		flowMod.setIdleTimeout((short) idleTimeout);
		flowMod.setHardTimeout((short) hardTimeout);
		flowMod.setPriority((short) priority);

		flowMod.setActions(actions);

		//calcualte actions length
		short length = 0;
		Iterator<OFAction> it = actions.iterator();
		while(it.hasNext())
			length += it.next().getLength();
		flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + length));
		
		try{
			sw.write(flowMod, cntx);
		}catch(IOException e){
			log.error("Failure writing Flow-Mod", e);
		}
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
	        // We don't provide any services, return null
		return null;
	}


}
