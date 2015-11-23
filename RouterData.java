package net.floodlightcontroller.practical;

import net.floodlightcontroller.core.IOFSwitch;

import java.util.HashMap;
import java.util.ArrayList;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.FileNotFoundException;

import org.json.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
* A class to manage the sotrage of the per router data required for SCC365 Practical 4.
* Contains routers IP addresses, MAC address, ARP table and routing table. 
* @author Jamie Bird
* @version 1.0
*/
public class RouterData{
	protected static Logger log;
	
	private HashMap<Short, String> mac;
	private HashMap<Short, String> ip;

	private RouteTable 	route_table;
	private ARPTable	arp_table;

	/**
	* Initialises the router data according to the switch ID
	* @param	sw	the OpenFlow switch to be used as the router.		
	* @see		IOFSwitch
	*/
	public RouterData(IOFSwitch sw){
		log = LoggerFactory.getLogger(RouterData.class);

		mac 	= new HashMap<Short, String>();
		ip 	= new HashMap<Short, String>();

		route_table 	= new RouteTable();
		arp_table	= new ARPTable();

		String jsonData = "";
		try(BufferedReader br = new BufferedReader(new FileReader("/home/vagrant/floodlight/src/main/java/net/floodlightcontroller/practical/routers.json"))){
			StringBuilder sb 	= new StringBuilder();
			String line 		= br.readLine();

			while(line != null){
				sb.append(line);
				sb.append(System.lineSeparator());
				line = br.readLine();
			}
			jsonData = sb.toString();
		}catch(FileNotFoundException e){
			log.debug("Failed to read routers.json {}", e.toString());
		}catch(IOException e){
			log.debug("IOException: {}", e.toString());
		}//finally{
		//	br.close();
		//}

		JSONObject json = new JSONObject(jsonData);

		if(!json.has(String.valueOf(sw.getId()))){
			log.debug("No router data for dpid {}", sw.getId());
		}else{
			//router
			JSONObject router = json.getJSONObject(String.valueOf(sw.getId()));

			//add interfaces
			JSONArray interfaces = router.getJSONArray("interfaces");
			for(int i = 0; i < interfaces.length(); i++){
				JSONObject iface = interfaces.getJSONObject(i);
				mac.put((short) iface.getInt("port"), iface.getString("mac"));
				ip.put((short) iface.getInt("port"), iface.getString("net"));
			}

			//add routes
			JSONArray routes = router.getJSONArray("routes");
			for(int i = 0; i < routes.length(); i++){
				JSONObject route = routes.getJSONObject(i);
				route_table.addRoute(route.getString("destination"), route.getString("next_hop"), (short) route.getInt("out_port"));	
			}

			//add arp
			JSONArray arps = router.getJSONArray("arp");
			for(int i = 0; i < arps.length(); i++){
				JSONObject arp = arps.getJSONObject(i);
				arp_table.addARP(arp.getString("ip"), arp.getString("mac"));
			}
			log.debug("Router {} initialised. Interfaces: {} Routes: {} ARP entries: {}", new Object[]{sw.getId(), interfaces.length(), routes.length(), arps.length()});
		}
	}

	/**
	* Get the Route table of the router.
	* @return 	the RouteTable of the router
	* @see		RouteTable	
	*/
	public RouteTable routeTable(){
		return route_table;
	}	

	/**
	* Get the ARP table of the router.
	* @return	the ARPTable of the router
	* @see		ARPTable
	*/
	public ARPTable arpTable(){
		return arp_table;
	}

	/**
	* Get the IP address of the specified port.
	* @param	port	Switch port	
	* @return	IP address
	*/
	public String ip(short port){
		return ip.get(port);
	}

	/**
	* Get all IP addresses of the router
	* @return	an ArrayList of IP addresses
	* @see		ArrayList
	*/
	public ArrayList<String> allIP(){
		return new ArrayList<String>(ip.values());	
	}

	/**
	* Get the MAC addess of the scecified port
	* @param	port	Switch port
	* @return	MAC addess
	*/
	public String mac(short port){
		return mac.get(port);
	}
}
