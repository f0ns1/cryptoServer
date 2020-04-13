package com.crypto.server.cryptoserver.bean.request;

public class EncryptBean {
	
	private String alg;
	private String data;
	private String pub;
	private String priv;
	private String certificate;
	
	
	//Getters && setters
	public String getCertificate() {
		return certificate;
	}
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	
	public String getAlg() {
		return alg;
	}
	public void setAlg(String alg) {
		this.alg = alg;
	}
	public String getData() {
		return data;
	}
	public void setData(String data) {
		this.data = data;
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
	
	

}
