package com.crypto.server.cryptoserver.bean.request;

public class DecryptBean {
	
	private String alg;
	private String pub;
	private String priv;
	private String data;
	private String certificate;
	
	//getters&& setters 
	public String getAlg() {
		return alg;
	}
	public void setAlg(String alg) {
		this.alg = alg;
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
	public String getData() {
		return data;
	}
	public void setData(String data) {
		this.data = data;
	}
	public String getCertificate() {
		return certificate;
	}
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	

	
	
	
}
