
// Lots of the action associated with handling a DNS query is processing
// the response. Although not required you might find the following skeleton of
// a DNSreponse helpful. The class below has bunch of instance data that typically needs to be 
// parsed from the response. If you decide to use this class keep in mind that it is just a 
// suggestion and feel free to add or delete methods to better suit your implementation as 
// well as instance variables.

import java.nio.ByteBuffer;
import java.io.*;
import java.util.*;

public class DNSResponse {
    private byte[] data;
    private int queryID;                    // this is for the response it must match the one in the request
    private int answerCount = 0;            // number of answers
    private int remainingAnswers = 0;       // number of asnwers remaining to be added to answerArray;
    private List<ResponseRecord> answerArray = new LinkedList<ResponseRecord>();    //array of answer responses;
    private boolean decoded = false;        // Was this response successfully decoded
    private int nsCount = 0;                // number of nscount response records
    private List<ResponseRecord> nsArray = new LinkedList<ResponseRecord>();       // array of NS response
    private int additionalCount = 0;        // number of additional (alternate) response records
    private List<ResponseRecord> additionalArray = new LinkedList<ResponseRecord>();   // array of additional response;
    private boolean authoritative = false;  // Is this an authoritative record
    private boolean RD = false;             // see if there is recursive record
    private boolean RA = false;             // see if it is capable of recursive queries
    private int rCode = 0;                  // record code
    private int qCount = 0;                 // number of queryCount response records
    private String QName="";                // query name



    // Note you will almost certainly need some additional instance variables.

    // When in trace mode you probably want to dump out all the relevant information in a response

    void dumpResponse() {



    }

    // The constructor: you may want to add additional parameters, but the two shown are 
    // probably the minimum that you need.

    public DNSResponse (byte[] responseData, int len) {
        int offset;
        this.data = new byte[len];
        System.arraycopy(responseData, 0, data, 0, len);

        ByteBuffer byteBuffer;
        byte targetByte;

        // The following are probably some of the things
        // you will need to do.
        // Extract the query ID
        offset = 0;
        byteBuffer = ByteBuffer.wrap(data, offset, 2);
        queryID = byteBuffer.getShort() & 0xffff;

        // Make sure the message is a query response and determine
        // if it is an authoritative response or note
        offset = 2;
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data, offset, 1);
        targetByte = byteBuffer.get();
        authoritative = getBit(5, targetByte) != 0;
        RD = getBit(7, targetByte) != 0;

        //determine if it is RA
        offset = 3;
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data, offset, 1);
        targetByte = byteBuffer.get();
        RA = getBit(0,targetByte)!=0;
        rCode = targetByte & (byte) Integer.parseInt("00001111", 2);

        // determine query count
        offset = 4;
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data,offset,2);
        qCount=byteBuffer.getShort();

        // determine answer count
        offset = 6;
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data, offset, 2);
        answerCount=byteBuffer.getShort();
        remainingAnswers = answerCount;

        // determine NS Count
        offset = 8;
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data, offset, 2);
        nsCount=byteBuffer.getShort();

        // determine additional record count
        offset = 10;
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data, offset, 2);
        additionalCount=byteBuffer.getShort();

        // Extract list of answers, name server, and additional information response
        // records

        // extract query name
        offset = 12;
        int qoff = 12;          // offset for Qname
        byteBuffer.clear();
        int remainingLength = data.length - offset;
        byteBuffer = ByteBuffer.wrap(data, offset, remainingLength - 1);
        QName = getQueryName(byteBuffer);
        int queryLength = QName.length() + 6 ; //query length is the length of the query plus two byte, one each at the beginning and end

        int newOffset = offset + queryLength;

        //Keep reading the data until the end.
        while (newOffset < data.length) {

            ResponseRecord rr = createResponseRecord(byteBuffer, newOffset, qoff);
            if(rr.getType().equals("NS") ||rr.getType().equals("SOA") ) {
                nsArray.add(rr);
            } else if (rr.getType() == "A" || rr.getType() == "AAAA" || rr.getType() == "CN") {
                if (remainingAnswers > 0) {
                    answerArray.add(rr);
                    remainingAnswers--;
                } else {
                    additionalArray.add(rr);
                }
            }
            newOffset = newOffset + rr.getRecordLength();
        }

    }




    // You will probably want a methods to extract a compressed FQDN, IP address
    // cname, authoritative DNS servers and other values like the query ID etc.


    // You will also want methods to extract the response records and record
    // the important values they are returning. Note that an IPV6 reponse record
    // is of type 28. It probably wouldn't hurt to have a response record class to hold
    // these records.

    //Get the query id of this response
    public int getQueryID(){
        return queryID;
    }

    //Get the bit at the desired location. Count from left to right.
    public int getBit(int position, byte b)
    {
        position = 7 - position;
        return (b >> position) & 1;
    }

    //Get the name
    public String getQueryName(ByteBuffer byteBuffer){
        ByteArrayOutputStream queryBuffer = new ByteArrayOutputStream();
        byte i = byteBuffer.get();                  // index in data
        String domainName = "";
        while(i!= (byte) Integer.parseInt("00", 2) && byteBuffer.hasRemaining()) {

            byteBuffer.mark();
            byte currentByte = byteBuffer.get();
            if (isBytePointer(currentByte)) {
                byteBuffer.reset();
                int address = getPointerAddress(byteBuffer.getShort());
                domainName = getName(address);
                return queryBuffer.toString() + domainName;
            } else {
                queryBuffer.write(currentByte);
            }
            i--;
            if (i == (byte) Integer.parseInt("00", 2)) {
                byteBuffer.mark();
                byte nextByte = byteBuffer.get();
                if (nextByte == (byte) Integer.parseInt("00", 2) && !isBytePointer(nextByte)) {
                    break;
                } else if (isBytePointer(nextByte)){
                    i = 1;
                    queryBuffer.write('.');
                    byteBuffer.reset();
                } else {
                    queryBuffer.write((byte) Integer.parseInt("00101110", 2));
                    i = nextByte;
                }
            }
        }

        return queryBuffer.toString();
    }

    //Get the name, takes in a byte buffer and an int.
    public String getName(ByteBuffer byteBuffer, int qoff){
        int startAddr = getPointerAddress(byteBuffer.getShort());
        String name = getName(startAddr);
        return name;
    }

    //Get the name, takes in an address
    public String getName(int address) {
        ByteBuffer tempBuffer;
        int queryLength = data.length - address;
        tempBuffer = ByteBuffer.wrap(data, address, queryLength);
        return getQueryName(tempBuffer);
    }

    //Get the type
    public String getType(ByteBuffer byteBuffer){
        String ns="";
        switch(byteBuffer.getShort()){
            case 1:
                ns= "A";
                break;
            case 28:
                ns= "AAAA";
                break;
            case 2:
                ns= "NS";
                break;
            case 5:
                ns="CN";
                break;
            case 6:
                ns="SOA";
                break;
            default: ns="";
                break;
        }
        return ns;
    }

    //Get the ttl
    public int getTTL(ByteBuffer byteBuffer){
        return byteBuffer.getInt();
    }

    //Check if this byte is a pointer
    public boolean isBytePointer(byte b) {
        int result = (int) (b & 0b11000000);
        return result == 0b11000000;
    }

    //Get the pointer address
    public int getPointerAddress(short s) {
        int result =(int) (s & 0b0011111111111111);
        return result;
    }

    //Get the IPV4 address
    public String getHostIP4Address(ByteBuffer byteBuffer) {

        String address = "";
        byte currentByte = 0;
        while(byteBuffer.hasRemaining()) {
            currentByte = byteBuffer.get();
            address = address + new String(Integer.toString(currentByte & 0xff));
            address = address + ".";
        }
        address = address.substring(0, address.length() - 1);
        return address;
    }

    //Get the IPV6 address
    public String getHostIP6Address(ByteBuffer byteBuffer){
        String address ="";
        int val = 0;
        while(byteBuffer.hasRemaining()) {
            val = byteBuffer.getShort() & 0xffff;
            address = address + Integer.toHexString(val);
            address = address + ":";
        }
        return address.substring(0,address.length()-2);
    }



    //Create a response record
    public ResponseRecord createResponseRecord(ByteBuffer byteBuffer, int offset, int qoff) {
        // extract authoritative nameserver
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data, offset, 2);
        String name = getName(byteBuffer, qoff);

        // extract server Type
        offset+=2;
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data, offset, 2);
        String type = getType(byteBuffer);

        // extract TTL
        offset+=4;
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data,offset,4);
        int ttl = getTTL(byteBuffer);

        // extract length
        offset+=4;
        byteBuffer.clear();
        byteBuffer = ByteBuffer.wrap(data,offset,2);
        int length = byteBuffer.getShort();

        String stringData = "";
        if (type == "NS") {
            offset+=2;
            byteBuffer.clear();
            byteBuffer = ByteBuffer.wrap(data,offset,length);
            byte b = data[offset];
            stringData = getQueryName(byteBuffer);
        } else if (type =="A") {
            offset+=2;
            byteBuffer.clear();
            byteBuffer = ByteBuffer.wrap(data,offset,length);
            byte b = data[offset];
            stringData = getHostIP4Address(byteBuffer);
        } else if (type == "AAAA") {
            offset+=2;
            byteBuffer.clear();
            byteBuffer = ByteBuffer.wrap(data,offset,length);
            byte b = data[offset];
            stringData = getHostIP6Address(byteBuffer);
        } else if (type == "CN"){
            offset+=2;
            byteBuffer.clear();
            byteBuffer = ByteBuffer.wrap(data,offset,length);
            byte b = data[offset];
            stringData = getQueryName(byteBuffer);
        } else if (type == "SOA") {
            offset+=2;
            byteBuffer.clear();
            byteBuffer = ByteBuffer.wrap(data,offset,length);
            byte b = data[offset];
            stringData = "----";
        }
        ResponseRecord rr = new ResponseRecord(name, type, ttl, length, stringData );
        return rr;
    }

    //Print out this response
    public void printDNSResponse(){
        System.out.println("Response ID: "+ queryID + " Authoritative " + authoritative);
        System.out.println("  Answers ("+answerCount+")");
        for (int i=0;i<answerCount;i++){
            System.out.format("       %-30s %-10d %-4s %s\n", answerArray.get(i).getName(),
                    answerArray.get(i).getTtl(),
                    answerArray.get(i).getType(),
                    answerArray.get(i).getData());
        }
        System.out.println("  Nameservers ("+nsCount+")");
        for (int i=0;i<nsArray.size();i++){
            if(nsArray.get(i).getType().equals("SOA")){
                System.out.format("       %-30s %-10d %-4s %s\n", nsArray.get(i).getName(),
                        nsArray.get(i).getTtl(),
                        "6",
                        nsArray.get(i).getData());
            } else{
                System.out.format("       %-30s %-10d %-4s %s\n", nsArray.get(i).getName(),
                        nsArray.get(i).getTtl(),
                        nsArray.get(i).getType(),
                        nsArray.get(i).getData());
            }

        }
        System.out.println("  Additional Information ("+additionalCount+")");
        for (int i=0;i<additionalArray.size();i++){
            System.out.format("       %-30s %-10d %-4s %s\n", additionalArray.get(i).getName(),
                    additionalArray.get(i).getTtl(),
                    additionalArray.get(i).getType(),
                    additionalArray.get(i).getData());
        }
    }

    public ResponseRecord getNextRequest() {
        ResponseRecord target = null;
        //if we have a list of answers, we check the first answer.
        //If the first answer is not of type A, then we have to look up the first answer
        ResponseRecord tempTarget;
        if (answerCount > 0) {
            tempTarget = answerArray.get(0);
            tempTarget.isAnswer = true;
            return tempTarget;
            //if we don't have an answer, we go to the first additional record, and look it up.
        } else if (additionalCount > 0) {
            target = additionalArray.get(0);
            //if we don't have any additional record, go to name server array
        } else if (nsCount > 0) {
            tempTarget = nsArray.get(0);
            if (tempTarget.getType().equals("SOA")) {
                target = null;
            }else{
                target=tempTarget;
            }
        } else {
            //TODO
        }

        return target;
    }

    public ResponseRecord getFirstAnswer() {
        if(this.answerCount>0){
            return this.answerArray.get(0);
        } else {
            return this.nsArray.get(0);
        }

    }

    public int getAddtionalCount() {
        return this.additionalCount;
    }

    public int getRCode(){
        return this.rCode;
    }
}








