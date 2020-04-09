package com.crypto.server.cryptoserver.bean.response;

public class ResponseBean {

	private String service;
	private String status;

	public ResponseBean(String service, String data) {

		this.service = service;
		this.status = data;

	}

	public String getService() {
		return service;
	}

	public void setService(String service) {
		this.service = service;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

}
