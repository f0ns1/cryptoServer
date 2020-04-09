package com.crypto.server.cryptoserver.controller.actions;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OutputEncryptor;

import com.crypto.server.cryptoserver.utils.ManageKeys;



public class Encrypt {

	private String type;
	private String privateKey;
	private String publicKey;
	private String certificate;
	private ManageKeys mk;

	public Encrypt(String type, String privatekey, String publicKey, String certificate) {
		this.type = type;
		this.privateKey = privatekey;
		this.publicKey = publicKey;
		this.certificate = certificate;
		mk = new ManageKeys();
	}

	public Encrypt(String type, String privatekey, String publicKey) {
		this.type = type;
		this.privateKey = privatekey;
		this.publicKey = publicKey;
		mk = new ManageKeys();
	}

	public String encrypt(String data, String output) {
		String encData = null;
		switch (type) {
		case "3DES":
			encData = encrypt3DES(data, output);
			break;
		case "AES":
			encData = encryptAES(data, output);
			break;
		case "RC2":
			encData = encryptRC2(data, output);
			break;
		case "RC4":
			encData = encryptRC4(data, output);
			break;
		case "Blowfish":
			encData = encryptBlowfish(data, output);
			break;
		case "RSA":
			encData = encryptRSA(data, output);
			break;
		case "envelop":

			try {
				encData = envelopData(data.getBytes("UTF-8"), mk.getCertificate(certificate));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		return encData;
	}

	private String encryptRSA(String data, String output) {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, mk.getPublicKey(publicKey));
			output = Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
		} catch (Exception e) {
			e.printStackTrace();
		}

		return output;
	}

	private String encryptBlowfish(String data, String output) {
		byte[] encData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(mk.getPrivateKey(privateKey).getEncoded());
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] inputBytes = data.getBytes();
			encData = cipher.doFinal(inputBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return outputFormat(encData, output);
	}

	private String encryptRC4(String data, String output) {
		byte[] encData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(mk.getPrivateKey(privateKey).getEncoded());
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "RC4");
			Cipher cipher = Cipher.getInstance("RC4");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] inputBytes = data.getBytes();
			encData = cipher.doFinal(inputBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return outputFormat(encData, output);
	}

	private String encryptRC2(String data, String output) {
		byte[] encData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(mk.getPrivateKey(privateKey).getEncoded());
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "RC2");
			Cipher cipher = Cipher.getInstance("RC2");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] inputBytes = data.getBytes();
			encData = cipher.doFinal(inputBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return outputFormat(encData, output);
	}

	private String encryptAES(String data, String output) {
		byte[] encData = null;
		try {
			byte[] key = mk.getPrivateKey(privateKey).getEncoded();
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			encData = cipher.doFinal(data.getBytes("UTF-8"));
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return outputFormat(encData, output);
	}

	private String encrypt3DES(String data, String output) {
		byte[] encData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(mk.getPrivateKey(privateKey).getEncoded());
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
			final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
			final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			final byte[] plainTextBytes = data.getBytes("utf-8");
			encData = cipher.doFinal(plainTextBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return outputFormat(encData, output);
	}

	public String envelopData(byte[] data, X509Certificate encryptionCertificate) {
		String out = null;
		byte[] encryptedData = null;
		try {
			if (null != data && null != encryptionCertificate) {
				CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
				JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
				cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
				CMSTypedData msg = new CMSProcessableByteArray(data);
				OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC")
						.build();
				CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg, encryptor);
				encryptedData = cmsEnvelopedData.getEncoded();
				out = outputFormat(encryptedData, "B64");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return out;
	}

	private String outputFormat(byte[] data, String output) {
		String out = null;
		switch (output) {
		case "B64":
			out = (data != null) ? Base64.getEncoder().encodeToString(data) : "Void Encryption";
			break;
		case "Hex":
			out = (data != null) ? Hex.encodeHexString(data) : "Void Encryption";
			break;
		default:

			break;
		}
		return out;
	}

}
