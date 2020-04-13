package com.crypto.server.cryptoserver.bean.request;

public class SignBean {
	
	private String type;
	private String pub;
	private String priv;
	private String dataSign;
	private String data;
	
	//getters && setters
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getPub() {
		return pub;
	}
	public void setPub(String pub) {
		this.pub = pub;
	}
	public String getPriv() {
		return priv;
	}
	public void setPriv(String priv) {
		this.priv = priv;
	}
	public String getDataSign() {
		return dataSign;
	}
	public void setDataSign(String dataSign) {
		this.dataSign = dataSign;
	}
	public String getData() {
		return data;
	}
	public void setData(String data) {
		this.data = data;
	}
	
	

}
