package com.crypto.server.cryptoserver.controller.actions;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.json.JSONObject;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

public class Certificates {
	private String HEADER = "Certificates.";
	private Logger log = Logger.getLogger(HEADER);
	private int validity;
	private String name;
	private String type;
	private int size;

	public Certificates(String name, String type, int validity, int size) {
		this.validity = validity;
		this.name = name;
		this.type = type;
		this.size = size;

	}

	public JSONObject generateCertificate() {
		String cert = null;
		JSONObject obj = new JSONObject();
		try {
		
			CertAndKeyGen keyGen = new CertAndKeyGen(type, "SHA256WithRSA", null);
			keyGen.generate(size);
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = keyGen.getSelfCertificate(new X500Name(name), (long) validity * 24 * 3600);
			log.info(HEADER + "Certificate : " + chain[0].getEncoded());
			cert = Base64.getEncoder().encodeToString(chain[0].getEncoded());
			obj.put("palintext",chain[0].toString());
			obj.put("cert", cert);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return obj;
	}

	public JSONObject generateKeyPair() {
		CertAndKeyGen keyGen = null;
		JSONObject pair = new JSONObject();
		try {
			keyGen = new CertAndKeyGen(type, "SHA256WithRSA", null);
			keyGen.generate(size);
			PrivateKey priv = keyGen.getPrivateKey();
			PublicKey pub = keyGen.getPublicKey();
			log.info(HEADER + "getnerteKeyPair()  priv = " + priv);
			log.info(HEADER + "getnerteKeyPair()  pub = " + pub);

			pair.put("privateKeyB64", Base64.getEncoder().encodeToString(priv.getEncoded()));
			pair.put("publicKeyB64", Base64.getEncoder().encodeToString(pub.getEncoded()));


			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			X509Certificate[] serverChain = new X509Certificate[1];
			X509V3CertificateGenerator serverCertGen = new X509V3CertificateGenerator();
			X500Principal serverSubjectName = new X500Principal("CN=OrganizationName");
			serverCertGen.setSerialNumber(new BigInteger("123456789"));
			// X509Certificate caCert=null;
			serverCertGen.setIssuerDN(serverSubjectName);
			serverCertGen.setNotBefore(new Date());
			serverCertGen.setNotAfter(new Date());
			serverCertGen.setSubjectDN(serverSubjectName);
			serverCertGen.setPublicKey(pub);
			serverCertGen.setSignatureAlgorithm("MD5WithRSA");
			// certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,new
			// AuthorityKeyIdentifierStructure(caCert));
			serverChain[0] = serverCertGen.generateX509Certificate(priv, "BC"); // note: private key of CA
			pair.put("certificateB64", Base64.getEncoder().encodeToString(serverChain[0].getEncoded()));
			//pair.put("certificate", serverChain[0]);
		} catch (Exception e) {
			e.printStackTrace();
		}
		log.info(HEADER + "getnerteKeyPair()  pair = " + pair);
		return pair;
	}

}
