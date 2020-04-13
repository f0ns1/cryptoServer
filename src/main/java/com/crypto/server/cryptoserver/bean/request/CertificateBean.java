package com.crypto.server.cryptoserver.bean.request;

public class CertificateBean {
	
	private String operation;
	private String name;
	private String validity;
	private String size;
	
	//getters && setters
	public String getOperation() {
		return operation;
	}
	public void setOperation(String operation) {
		this.operation = operation;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getValidity() {
		return validity;
	}
	public void setValidity(String validity) {
		this.validity = validity;
	}
	public String getSize() {
		return size;
	}
	public void setSize(String size) {
		this.size = size;
	}

	
	
}
