package com.crypto.server.cryptoserver.controller.actions;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.logging.Logger;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Encode {

	public static final String HEADER = "";
	private String logData;
	private Logger log = Logger.getLogger(HEADER);
	private String type;

	// operations
	private final String B64 = "B64";
	private final String URL = "URL";
	private final String HEX = "HEX";
	private final String BINARY = "BINARY";
	private final String ENCODE = "encode";
	private final String DECODE = "decode";

	public Encode(String type) {
		this.type = type;
		logData = HEADER + "Encode() operation type = " + type;
	}

	public String encode(String data) {
		logData = HEADER + "encode() input " + data;
		log.info(logData);
		String ret = chooseOperation(data, ENCODE);
		logData = HEADER + "encode() response = " + ret;
		log.info(logData);
		return ret;
	}

	public String decode(String data) {
		logData = HEADER + "decode() input data = " + data;
		log.info(logData);
		String ret = chooseOperation(data, DECODE);
		logData = HEADER + "decode() ret = " + ret;
		log.info(logData);
		return ret;
	}

	private String chooseOperation(String data, String operation) {
		String ret = null;
		switch (type) {
		case B64:
			if (operation != null && operation.equals(ENCODE)) {
				ret = encodeB64(data);
			} else {
				ret = decodeB64(data);
			}
			break;
		case HEX:
			if (operation != null && operation.equals(ENCODE)) {
				ret = encodeHex(data);
			} else {
				try {
					ret = decodeHex(data);
				} catch (DecoderException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			break;
		case URL:
			if (operation != null && operation.equals(ENCODE)) {
				ret = encodeUrl(data);
			} else {
				ret = decodeUrl(data);
			}
			break;
		case BINARY:
			if (operation != null && operation.equals(ENCODE)) {
				ret = encodeBinary(data);
			} else {
				ret = decodeBinary(data);
			}
			break;
		default:
			break;
		}
		logData = HEADER + "chooseOperationç() operation " + type + " type = " + operation + " result = " + ret;
		log.info(logData);
		return ret;
	}

	private String decodeBinary(String data) {
		String s2 = "";
		char nextChar;

		for (int i = 0; i <= data.length() - 8; i += 8) // this is a little tricky. we want [0, 7], [9, 16], etc
														// (increment index by 9 if bytes are space-delimited)
		{
			nextChar = (char) Integer.parseInt(data.substring(i, i + 8), 2);
			s2 += nextChar;
		}
		return s2;
	}

	private String encodeBinary(String data) {
		byte[] bytes = data.getBytes();
		StringBuilder binary = new StringBuilder();
		for (byte b : bytes) {
			int val = b;
			for (int i = 0; i < 8; i++) {
				binary.append((val & 128) == 0 ? 0 : 1);
				val <<= 1;
			}

		}
		return binary.toString();

	}

	private String decodeUrl(String data) {
		return (data != null) ? URLDecoder.decode(data) : "";
	}

	private String encodeUrl(String data) {
		return (data != null) ? URLEncoder.encode(data) : "";
	}

	private String decodeHex(String data) throws DecoderException {
		return (data != null) ? new String(Hex.decodeHex(data)) : "";
	}

	private String encodeHex(String data) {
		return (data != null) ? Hex.encodeHexString(data.getBytes()) : "";
	}

	private String decodeB64(String data) {
		return (data != null) ? new String(Base64.getDecoder().decode(data)) : "";
	}

	private String encodeB64(String data) {
		return (data != null) ? Base64.getEncoder().encodeToString(data.getBytes()) : "";
	}

}
