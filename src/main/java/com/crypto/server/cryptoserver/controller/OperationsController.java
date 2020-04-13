package com.crypto.server.cryptoserver.controller;

import java.security.Security;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.crypto.server.cryptoserver.bean.request.CertificateBean;
import com.crypto.server.cryptoserver.bean.request.DecryptBean;
import com.crypto.server.cryptoserver.bean.request.EncodeBean;
import com.crypto.server.cryptoserver.bean.request.EncryptBean;
import com.crypto.server.cryptoserver.bean.request.HashBean;
import com.crypto.server.cryptoserver.bean.request.SignBean;
import com.crypto.server.cryptoserver.bean.response.ResponseBean;
import com.crypto.server.cryptoserver.controller.actions.Certificates;
import com.crypto.server.cryptoserver.controller.actions.Decrypt;
import com.crypto.server.cryptoserver.controller.actions.Encode;
import com.crypto.server.cryptoserver.controller.actions.Encrypt;
import com.crypto.server.cryptoserver.controller.actions.Hash;
import com.crypto.server.cryptoserver.controller.actions.Sign;
import com.crypto.server.cryptoserver.utils.Utils;

@RestController
public class OperationsController {
	private static final String HEADER = "OperationsController.";
	Logger log = Logger.getLogger(HEADER);
	private Utils utl;
	private static final String ENCRYPT_MAPPING = "/services/encrypt-jdk-service";
	private static final String DECRYPT_MAPPING = "/services/decrypt-jdk-service";
	private static final String SIGN_MAPPING = "/services/sign-jdk-service";
	private static final String CERTIFICATES_MAPPING = "/services/certificates-jdk-service";
	private static final String ENCRYPT_BC_MAPPING = "/services/encrypt-bc-service";
	private static final String DECRYPT_BC_MAPPING = "/services/decrypt-bc-service";
	private static final String ENCODE_MAPPING = "/services/encode-service";
	private static final String DECODE_MAPPING = "/services/decode-service";
	private static final String HASH_MAPPING = "/services/hash-service";

	// global variables
	private String type;
	private String publicKey;
	private String privateKey;
	private String alg;
	private String dataSign;
	private String data;
	private String certificate;
	private String logData;

	public OperationsController() {
		utl = new Utils();
	}

	@RequestMapping(value = ENCRYPT_MAPPING, method = RequestMethod.POST)
	public ResponseBean encryptServiceJDKController(@RequestBody EncryptBean body, HttpServletResponse response) {
		logData = HEADER + "encryptServiceJDKControler() init method ";
		log.info(logData);
		try {
			type = body.getAlg();
			data = body.getData();
			publicKey = body.getPub();
			privateKey = body.getPriv();
		} catch (Exception e) {
			e.printStackTrace();
		}
		Encrypt enc = new Encrypt(type, privateKey, publicKey);
		String encryptedData = enc.encrypt(data, "B64");
		ResponseBean resp = new ResponseBean(ENCRYPT_MAPPING, encryptedData);
		log.info(HEADER + "encryptServiceJDKController()  output = " + resp.getStatus());
		log.info(HEADER + "encryptServiceJDKController()  service = " + resp.getService());
		return resp;
	}

	@RequestMapping(value = ENCRYPT_BC_MAPPING, method = RequestMethod.POST)
	public ResponseBean encryptServiceBCController(@RequestBody EncryptBean bean, HttpServletResponse response) {
		log.info("crypto application server !!");
		log.info(HEADER + "decryptServiceJDKController() init method ");
		try {
			type = bean.getAlg();
			data = bean.getData();
			publicKey = bean.getPub();
			privateKey = bean.getPriv();
			certificate = bean.getCertificate();
		} catch (Exception e) {
			e.printStackTrace();
		}
		Security.addProvider(new BouncyCastleProvider());
		Encrypt enc = new Encrypt("envelop", privateKey, publicKey, certificate);
		String dataDecrypted = enc.encrypt(data, "B64");
		ResponseBean resp = new ResponseBean(ENCRYPT_BC_MAPPING, dataDecrypted);
		logData = HEADER + "encryptServiceJDKController()  output = " + resp.getStatus();
		log.info(logData);
		logData = HEADER + "encryptServiceJDKController()  output = " + resp.getService();
		log.info(logData);
		return resp;
	}

	@RequestMapping(value = DECRYPT_MAPPING, method = RequestMethod.POST)
	public ResponseBean decryptServiceJDKController(@RequestBody DecryptBean bean, HttpServletResponse response) {
		log.info("crypto application server !!");
		logData = HEADER + "decryptServiceJDKController() init method ";
		log.info(logData);
		try {
			type = bean.getAlg();
			data = bean.getData();
			publicKey = bean.getPub();
			privateKey = bean.getPriv();
		} catch (Exception e) {
			e.printStackTrace();
		}
		Decrypt dec = new Decrypt(type, privateKey, publicKey);
		String dataDecrypted = dec.decrypt(data, "B64");
		ResponseBean resp = new ResponseBean(DECRYPT_MAPPING, dataDecrypted);
		logData = HEADER + "encryptServiceJDKController()  output = " + resp.getStatus();
		log.info(logData);
		logData = HEADER + "encryptServiceJDKController()  service = " + resp.getService();
		log.info(logData);
		return resp;
	}

	@RequestMapping(value = DECRYPT_BC_MAPPING, method = RequestMethod.POST)
	public ResponseBean decryptServiceBCController(@RequestBody DecryptBean bean, HttpServletResponse response) {
		logData = HEADER + "decryptServiceJDKController() init method ";
		log.info(logData);
		try {
			alg = bean.getAlg();
			data = bean.getData();
			publicKey = bean.getPub();
			privateKey = bean.getPriv();
			certificate = bean.getCertificate();
		} catch (Exception e) {
			e.printStackTrace();
		}

		Decrypt dec = new Decrypt("envelop", privateKey, publicKey, certificate, alg);
		String dataDecrypted = dec.decrypt(data, "B64");
		ResponseBean resp = new ResponseBean(DECRYPT_MAPPING, dataDecrypted);
		log.info(HEADER + "encryptServiceJDKController()  output = " + resp.getStatus());
		log.info(HEADER + "encryptServiceJDKController()  service = " + resp.getService());
		return resp;
	}

	@RequestMapping(value = SIGN_MAPPING, method = RequestMethod.POST)
	public ResponseBean signServiceJDKController(@RequestBody SignBean bean, HttpServletResponse response) {
		logData = HEADER + "signServiceController() init method ";
		log.info(logData);
		try {
			type = bean.getType();
			data = bean.getData();
			if (type.equals("sign")) {
				privateKey = bean.getPriv();
			} else {
				publicKey = bean.getPub();
				dataSign = bean.getDataSign();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		Sign sign = new Sign(privateKey, publicKey);
		String resp = null;
		if (type != null && type.equals("sign")) {
			resp = sign.signData(data);
		} else {
			resp = String.valueOf(sign.verifySignData(data, dataSign));
		}
		logData = HEADER + "signServiceJDKController() response data = " + resp;
		log.info(logData);
		ResponseBean respBean = new ResponseBean(SIGN_MAPPING, resp);
		logData = HEADER + "signServiceJDKController() respBean = " + respBean.getService();
		log.info(logData);
		logData = HEADER + "signServiceJdkController() respBean = " + respBean.getStatus();
		log.info(logData);
		return respBean;
	}

	@RequestMapping(value = CERTIFICATES_MAPPING, method = RequestMethod.POST)
	public ResponseBean certificatesController(@RequestBody CertificateBean bean, HttpServletResponse response) {
		logData = HEADER + "certificatesController() init method ";
		log.info(logData);
		JSONObject certificate = null;
		try {
			String operation = bean.getOperation();
			String name = bean.getName();
			String type = "RSA";
			String validity = bean.getValidity();
			String size = bean.getSize();
			Certificates cert = new Certificates(name, type, Integer.parseInt(validity), Integer.parseInt(size));
			if (operation != null && operation.equals("certificate")) {
				certificate = cert.generateCertificate();
			} else if (operation != null && operation.equals("keyPair")) {
				certificate = cert.generateKeyPair();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		ResponseBean beanResp = new ResponseBean(CERTIFICATES_MAPPING, certificate.toString());
		logData = HEADER + "certificatesController() response = " + beanResp.getStatus();
		log.info(logData);
		return beanResp;
	}

	@RequestMapping(value = ENCODE_MAPPING, method = RequestMethod.POST)
	public ResponseBean encodeController(@RequestBody EncodeBean bean, HttpServletResponse response) {
		logData = HEADER + "encondeCOntroller() init method";
		log.info(logData);
		String status = null;
		try {
			String in = bean.getData();
			String type = bean.getAlg();
			Encode encode = new Encode(type);
			status = encode.encode(in);
			logData = HEADER + "encodeServiceController() status = " + status;
			log.info(logData);
		} catch (Exception e) {
			logData = HEADER + "encodeController() exception " + e.getMessage();
			log.severe(logData);
		}
		ResponseBean beanResp = new ResponseBean(ENCODE_MAPPING, status);
		logData = HEADER + "encondeController() response = " + beanResp.getService();
		log.info(logData);
		return beanResp;
	}

	@RequestMapping(value = DECODE_MAPPING, method = RequestMethod.POST)
	public ResponseBean decodeServiceController(@RequestBody EncodeBean bean, HttpServletResponse response) {
		logData = HEADER + "decodeServiceController() init service";
		log.info(logData);
		String status = null;
		try {
			String in = bean.getData();
			String type = bean.getAlg();
			Encode encode = new Encode(type);
			status = encode.decode(in);
			logData = HEADER + "decodeServiceCOntroller() stattus = " + status;
			log.info(logData);
		} catch (Exception e) {
			logData = HEADER + "decodeCOntroller() exception " + e.getMessage();
			log.severe(logData);
		}
		ResponseBean respBean = new ResponseBean(DECODE_MAPPING, status);
		logData = HEADER + "decodeServiceController() response = " + respBean.getStatus();
		log.info(logData);
		return respBean;
	}

	@RequestMapping(value = HASH_MAPPING, method = RequestMethod.POST)
	public ResponseBean hashServiceController(@RequestBody HashBean bean, HttpServletResponse response) {
		logData = HEADER + "hashServiceController() init method ";
		log.info(logData);
		String status = null;
		try {
			String in = bean.getData();
			String type = bean.getAlg();
			Hash hash = new Hash(type);
			status = hash.hashAction(in);
			logData = HEADER + "hashServiceController()  response = " + data;
			log.info(logData);
		} catch (Exception e) {
			logData = HEADER + "decodeCOntroller() exception " + e.getMessage();
			log.severe(logData);
		}
		ResponseBean responseBean = new ResponseBean(HASH_MAPPING, status);
		logData = HEADER + "hashServiceController() response " + responseBean.getStatus();
		log.info(logData);
		return responseBean;
	}

}
