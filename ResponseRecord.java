

public class ResponseRecord {
    private String name;        //name is two byte. if first 2 bits are 11, then rest is a pointer to the actual name, offset from request id.
    private String type;
    private int ttl;
    private int dataLength;
    private String data;
    public Boolean isAnswer = false;

    public ResponseRecord(String name, String type, int ttl, int dataLength, String data) {
        this.name = name;
        this.type = type;
        this.ttl = ttl;
        this.dataLength = dataLength;
        this.data = data;
    }

    public String getName() {
        return this.name;
    }

    public String getType() {
        return this.type;
    }

    public int getTtl() {
        return this.ttl;
    }

    public int getDataLength() {
        return this.dataLength;
    }

    public String getData() {
        return this.data;
    }

    public int getRecordLength() {
        return this.dataLength + 12;
    }

    public boolean isAnswer() {
        return this.isAnswer;
    }
}