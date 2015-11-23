package net.floodlightcontroller.practical;

import java.util.ArrayList;
import java.util.Iterator;

/**
* A class for managing the ARP table of the OpenFlow routers for SCC365 Practical 4.
* @author Jamie Bird
* @version 1.0
*/
public class ARPTable{

	/*
	*  ______________________________
	* |    IP    |         MAC       |
	* |__________|___________________|
	* | 10.0.1.1 | 00:00:00:00:00:01 |
	* |__________|___________________|
	*/
	private class ARPEntry{
		String ip, mac;
		public ARPEntry(String ip, String mac){
			this.ip 	= ip;
			this.mac 	= mac;
		}
	}

	private ArrayList<ARPEntry> arp_table;

	/**
	* Create the ARP table.
	*/
	public ARPTable(){
		arp_table = new ArrayList<ARPEntry>();
	}

	/**
	* Add a newly learnt ARP entry.
	* @param	ip	IP address
	* @param	mac	MAC address
	*/
	public void addARP(String ip, String mac){
		arp_table.add(new ARPEntry(ip, mac)); 
	}

	/**
	* Check if the ARP table contains an entry for a specified IP. 
	* @param	ip	IP address
	*/
	public boolean hasARP(String ip){
		Iterator<ARPEntry> it = arp_table.iterator();
		while(it.hasNext()){
			ARPEntry a = it.next();
			if(a.ip.equals(ip))
				return true;
		} 
		return false;
	}

	/**
	* Get the MAC address of the specified IP.
	* @param	ip	IP address
	* @return	MAC address if ARP entry found, null otherwise. Recommed using has ARP prior.
	*/
	public String mac(String ip){
		Iterator<ARPEntry> it = arp_table.iterator();
                while(it.hasNext()){
                        ARPEntry a = it.next();
                        if(a.ip.equals(ip))
                                return a.mac;
                }
                return null;
	}
}
