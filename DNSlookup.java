
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.*;
import java.io.*;

/**
 *
 */

/**
 * @author Donald Acton
 * This example is adapted from Kurose & Ross
 *
 */
public class DNSlookup {


    static final int MIN_PERMITTED_ARGUMENT_COUNT = 2;
    static boolean tracingOn = false;
    static InetAddress rootNameServer;

    static Random rnd = new Random();
    static byte[] queryId = new byte[2];


    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {
        String fqdn;
        boolean error= false;
        DNSResponse response; // Just to force compilation
        int argCount = args.length;

        if (argCount < 2 || argCount > 3) {
            usage();
            return;
        }

        String rootNameServerString = args[0];
        rootNameServer = InetAddress.getByName(rootNameServerString);
        fqdn = args[1];

        if (argCount == 3 && args[2].equals("-t"))
            tracingOn = true;

        // Start adding code here to initiate the lookup

        //send query
        DatagramSocket socket = new DatagramSocket();
        ByteArrayOutputStream sendBuf = encodeNewQuery(fqdn);

        byte[] resBuf = new byte[1024*100];
        byte[] byteArray = sendBuf.toByteArray();
        DatagramPacket queryPacket = new DatagramPacket(byteArray, byteArray.length, rootNameServer, 53);
        socket.send(queryPacket);



        //get response
        DatagramPacket responsePacket = new DatagramPacket(resBuf, resBuf.length);
        socket.receive(responsePacket);

        //display response
        DNSResponse res = new DNSResponse(responsePacket.getData(), responsePacket.getLength());

        ByteBuffer q = ByteBuffer.wrap(queryId);


        int queryVal = q.getShort();
        if (tracingOn) {
			System.out.println("\n");
			System.out.println("Query ID     "+res.getQueryID()+" "+fqdn+" --> "+rootNameServer.getHostAddress());
			res.printDNSResponse();
		}

		ResponseRecord nextRequest = res.getNextRequest();

		String nextFqdn = fqdn;
		String nextAddress = rootNameServerString;
		DNSResponse nextRes = null;

		while (nextRequest != null) {
			String nextType = nextRequest.getType();


			if (nextRequest.isAnswer()) {
				if (!nextType.equals("CN")
						&& !nextType.equals("NS")
						&& (!nextRequest.getName().trim().equals(nextFqdn.trim()) || !nextRequest.getData().trim().equals(nextAddress.trim()))) {
					break;
				}
			}

			if (nextRequest.getName().trim().equals(nextFqdn.trim()) && nextRequest.getData().trim().equals(nextAddress.trim())) {
				nextFqdn = fqdn;
				nextRes = getDNSResponse(nextAddress, nextFqdn);
			} else if (nextType == "A") {
				nextAddress = nextRequest.getData();
				nextRes = getDNSResponse(nextAddress, nextFqdn);
			} else if (nextType == "NS") {
				nextFqdn = nextRequest.getData();
				nextAddress = rootNameServerString;
				nextRes = getDNSResponse(nextAddress, nextFqdn);
			} else if (nextType == "CN") {
				nextAddress = rootNameServerString;
				nextFqdn = nextRequest.getData();
				nextRes = getDNSResponse(nextAddress, nextFqdn);
			}

			if (tracingOn) {
				nextRes.printDNSResponse();
			}

			nextRequest = nextRes.getNextRequest();
		}

		socket.close();
		ResponseRecord finalRR;
		if (nextRes != null) {
			finalRR= nextRes.getFirstAnswer();
		} else {
			finalRR = res.getFirstAnswer();
		}

        long start = System.currentTimeMillis();
        long end = start + 10*1000; // 60 seconds * 1000 ms/sec

        // if server name cannot be retrieved successfully
		if(finalRR.getType().equals("SOA") || res.getRCode()==5){
            // print SOA record
			System.out.println(fqdn + " " + "-4" + " " + "0.0.0.0");
		} else if(res.getRCode()==3 || res.getQueryID() == queryVal){
            // when ip is not found
			System.out.println(fqdn + " " + "-1" + " " + "0.0.0.0");
		} else if(System.currentTimeMillis() >= end){
            //terminate lookup after 60 sec
            System.out.println(fqdn + " " + "-3" + " " + "0.0.0.0");
        }else {

			String finalAddress = finalRR.getData();
			int finalTtl = finalRR.getTtl();
			System.out.println(fqdn + " " + finalTtl + " " + finalAddress);


		}
	}

	private static void usage() {
		System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-t]");
		System.out.println("   where");
		System.out.println("       rootDNS - the IP address (in dotted form) of the root");
		System.out.println("                 DNS server you are to start your search at");
		System.out.println("       name    - fully qualified domain name to lookup");
		System.out.println("       -t      -trace the queries made and responses received");
	}

	private static ByteArrayOutputStream encodeNewQuery(String fqdn) {

		ByteArrayOutputStream sendBuf = new ByteArrayOutputStream();

		// create random query ID and write into byte buffer
		byte[] queryId = new byte[2];
		rnd.nextBytes(queryId);
		sendBuf.write(queryId, 0, 2);

		// write QR, AA, TC, RD, RA, Z, RCODE, and query count into byte buffer
		sendBuf.write(0);
		sendBuf.write(0);
		sendBuf.write(0);
		sendBuf.write(1);

		// write answer count
		sendBuf.write(0);
		sendBuf.write(0);

		//write NSCOUNT
		sendBuf.write(0);
		sendBuf.write(0);

		//write additional record count
		sendBuf.write(0);
		sendBuf.write(0);

		//write fqdn into byte buffer
		String[] substrings = fqdn.split("\\.");
		for (int i = 0; i < substrings.length; i++) {
			sendBuf.write(substrings[i].length());
			byte[] substringByte = substrings[i].getBytes();
			sendBuf.write(substringByte, 0, substringByte.length);
		}
		sendBuf.write(0);

		//write Qtype
		sendBuf.write(0);
		sendBuf.write(1);

		//write Qclass
		sendBuf.write(0);
		sendBuf.write(1);

		return sendBuf;
	}

	public static DNSResponse getDNSResponse(String addressString, String fqdn) throws Exception{
		InetAddress nextAddress = null;
		DatagramPacket nextQueryPacket = null;
		DatagramPacket nextResponsePacket = null;
		DNSResponse nextRes = null;
		ByteArrayOutputStream nextSendBuf = null;
		byte[] nextResBuf = new byte[4096];
		byte[] nextByteArray;

		DatagramSocket socket = new DatagramSocket();

		nextSendBuf = encodeNewQuery(fqdn);
		nextByteArray = nextSendBuf.toByteArray();
		nextAddress = InetAddress.getByName(addressString);

		nextQueryPacket = new DatagramPacket(nextByteArray, nextByteArray.length, nextAddress, 53);
		socket.send(nextQueryPacket);

		nextResponsePacket = new DatagramPacket(nextResBuf, nextResBuf.length);
		socket.receive(nextResponsePacket);
		nextRes = new DNSResponse(nextResponsePacket.getData(), nextResponsePacket.getLength());

		if (tracingOn) {
			System.out.println("\n");
			System.out.println("Query ID     " + nextRes.getQueryID() + " " + fqdn + " --> " + nextAddress.getHostAddress());
		}
		socket.close();

		return nextRes;

	}



}


