package com.crypto.server.cryptoserver.controller.actions;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.jboss.logging.Logger;

public class Hash {

	private static final String HEADER = "Hash.";
	private String alg;
	private Logger log = Logger.getLogger(HEADER);
	private String logData;

	public Hash(String alg) {
		this.alg = alg;
		logData = HEADER + "Hash() alg= " + alg;
		log.info(logData);
	}

	public String hashAction(String data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(alg);
		logData = HEADER + "hashAction() input data = " + data;
		return (data != null) ? Base64.getEncoder().encodeToString(md.digest(data.getBytes(StandardCharsets.UTF_8)))
				: "";
	}

}
