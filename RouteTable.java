package net.floodlightcontroller.practical;

import java.util.ArrayList;
import java.util.Iterator;

import org.apache.commons.net.util.SubnetUtils;

/**
* A class for managing the route table of the OpenFlow routers for SCC365 Practical 4.
* @author Jamie Bird
* @version 1.0
*/
public class RouteTable{
	
	/*
	*  ____________________________________
	* | Destination | Next hop | Out port |
	* |_____________|__________|__________|
	* | 10.0.1.0/24 | 10.0.3.1 |    3     |
	* |_____________|__________|__________| 
	*/
	private class RouteEntry{
		String 	dst_net, next_hop;
		short 	out_port;	
		public RouteEntry(String dst_net, String next_hop, short out_port){
			this.dst_net 	= dst_net;
			this.next_hop 	= next_hop;
			this.out_port 	= out_port;
		}
	}

	private ArrayList<RouteEntry> route_table;
	
	/**
	* Creates routing table
	*/
	public RouteTable(){
		route_table = new ArrayList<RouteEntry>();
	}
	
	/**
	* Add a newly learnt route to the routing table
	* @param	dst_net		Destination network
	* @param	next_hop	Next hop IP address
	* @param	out_port	Out port of next hop
	*/
	public void addRoute(String dst_net, String next_hop, short out_port){
		route_table.add(new RouteEntry(dst_net, next_hop, out_port));
	}
	
	/**
	* Check if the routing table contains a route to specified IP.
	* @param	ip		Desired destination
	*/
	public boolean hasRoute(String ip){
		Iterator<RouteEntry> it = route_table.iterator();
		while(it.hasNext()){
			RouteEntry r = it.next();
			SubnetUtils.SubnetInfo si = new SubnetUtils(r.dst_net).getInfo();
			if(si.isInRange(ip))
				return true;
		}
		return false;
	}

	/**
	* Get the destination network of the specified IP.
	* @param	ip	Desired destination
	* @return	Destination network if route exists, null otherwise. Recommed using hasRoute prior.
	*/
	public String dstNet(String ip){
		Iterator<RouteEntry> it = route_table.iterator();
		while(it.hasNext()){
			RouteEntry r = it.next();
			SubnetUtils.SubnetInfo si = new SubnetUtils(r.dst_net).getInfo();
			if(si.isInRange(ip))
				return r.dst_net;
		}
		return null;
	}

	/**
	* Get the next hop of the specified IP.
	* @param	ip	Desired destination
	* @return	Next hop if route exists, null otherwise. Recommed using hasRoute prior.
	*/
	public String nextHop(String ip){
		Iterator<RouteEntry> it = route_table.iterator();
		while(it.hasNext()){
			RouteEntry r = it.next();
			SubnetUtils.SubnetInfo si = new SubnetUtils(r.dst_net).getInfo();
			if(si.isInRange(ip))
				return r.next_hop;
		}
		return null;
	}

	/**
	* Get the out port of the specified IP.
	* @param	ip	Desired destination.
	* @return	Out port if route exists, -1 otherwise. Recommend using hasRoute prior.
	*/
	public short outPort(String ip){
		Iterator<RouteEntry> it = route_table.iterator();
		while(it.hasNext()){
			RouteEntry r = it.next();
			SubnetUtils.SubnetInfo si = new SubnetUtils(r.dst_net).getInfo();
			if(si.isInRange(ip))
				return r.out_port;
		}
		return -1;
	}
}
