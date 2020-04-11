package com.crypto.server.cryptoserver.controller;

import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ApplicationController {
	public static final String HEADER = "ApplicationController.";
	private Logger log = Logger.getLogger(HEADER);
	private String logData;
	// Mapping
	private static final String SIGN_MAPPING = "/sign";
	private static final String ENCRYPT_MAPPING = "/encrypt";
	private static final String DECRYPT_MAPPING = "/decrypt";
	private static final String INDEX_MAPPING = "/";
	private static final String CONTACT_MAPPING = "/contact";
	private static final String HASH_MAPPING = "/hash";
	private static final String ENCODE_MAPPING = "/encode";
	private static final String CERTIFICATE_MAPPING = "/certificates";

	@RequestMapping(INDEX_MAPPING)
	public String index(HttpServletRequest request, HttpServletResponse response) {
		logData = HEADER + "index()";
		log.info(logData);
		return "index";
	}

	@RequestMapping(ENCRYPT_MAPPING)
	public String encryptController(HttpServletRequest request, HttpServletResponse response) {
		logData = HEADER + "encryptCOntroller() ";
		log.info(logData);
		return ENCRYPT_MAPPING.replace("/", "");
	}

	@RequestMapping(DECRYPT_MAPPING)
	public String decryptController(HttpServletRequest request, HttpServletResponse response) {
		logData = HEADER + "decryptCOntroller() ";
		log.info(logData);
		return DECRYPT_MAPPING.replace("/", "");
	}

	@RequestMapping(SIGN_MAPPING)
	public String signController(HttpServletRequest request, HttpServletResponse response) {
		logData = HEADER + "signController() ";
		log.info(logData);
		return SIGN_MAPPING.replace("/", "");
	}

	@RequestMapping(CERTIFICATE_MAPPING)
	public String certificatesController(HttpServletRequest request, HttpServletResponse response) {
		logData = HEADER + "certificatesController() ";
		log.info(logData);
		return CERTIFICATE_MAPPING.replace("/", "");
	}

	@RequestMapping(ENCODE_MAPPING)
	public String encodeController(HttpServletRequest request, HttpServletResponse response) {
		logData = HEADER + "encodeMapping()";
		log.info(logData);
		return ENCODE_MAPPING.replace("/", "");
	}

	@RequestMapping(HASH_MAPPING)
	public String hashController(HttpServletRequest request, HttpServletResponse response) {
		logData = HEADER + "hashController() ";
		log.info(logData);
		return HASH_MAPPING.replace("/", "");
	}

	@RequestMapping(CONTACT_MAPPING)
	public String contactController(HttpServletRequest request, HttpServletResponse response) {
		logData = HEADER + "conetctController()";
		log.info(logData);
		return CONTACT_MAPPING.replace("/", "");
	}
}
