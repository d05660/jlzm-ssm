package org.cloud.ssm.common;

public class ResponseMessage {
	private int code;
    private String msg;
    private String token;
    private long timestamp;

    public ResponseMessage(){}

    public ResponseMessage(int code, String msg, String token) {
        super();
        this.code = code;
        this.msg = msg;
        this.token = token;
        this.timestamp = System.currentTimeMillis();
    }

    public ResponseMessage(int code, String msg) {
        super();
        this.code = code;
        this.msg = msg;
        this.token = "";
        this.timestamp = System.currentTimeMillis();
    }
    
    public ResponseMessage(String msg) {
        super();
        this.code = 200;
        this.msg = msg;
        this.token = "";
        this.timestamp = System.currentTimeMillis();
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
}
