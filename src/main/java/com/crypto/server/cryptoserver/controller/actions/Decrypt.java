package com.crypto.server.cryptoserver.controller.actions;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.operator.OutputEncryptor;

import com.crypto.server.cryptoserver.utils.ManageKeys;


public class Decrypt {
	private String type;
	private String privateKey;
	private String publicKey;
	private String certificate;
	private String algEnv; 
	private ManageKeys mk;

	public Decrypt(String type, String privatekey, String publicKey) {
		this.type = type;
		this.privateKey = privatekey;
		this.publicKey = publicKey;
		mk = new ManageKeys();
	}

	public Decrypt(String type, String privateKey, String publicKey, String certificate) {
		this.type = type;
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.certificate = certificate;
		mk = new ManageKeys();
	}

	public Decrypt(String type, String privateKey, String publicKey, String certificate, String alg) {
		this.type = type;
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.certificate = certificate;
		mk = new ManageKeys();
		this.algEnv= alg;
	}

	public String decrypt(String data, String output) {
		String encData = null;

		switch (type) {
		case "3DES":
			encData = decrypt3DES(data, output);
			break;
		case "AES":
			encData = decryptAES(data, output);
			break;
		case "RC2":
			encData = decryptRC2(data, output);
			break;
		case "RC4":
			encData = decryptRC4(data, output);
			break;
		case "Blowfish":
			encData = decryptBlowfish(data, output);
			break;
		case "RSA":
			encData = decryptRSA(data, output);
			break;
		case "envelop":
			try {
			encData = decryptDataEnvelop(Base64.getDecoder().decode(data),mk.getPrivateKey(privateKey));
			}catch(Exception e) {
				e.printStackTrace();
			}
			break;
		}
		return encData;
	}

	private String decryptRSA(String data, String output) {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, mk.getPrivateKey(privateKey));
			output = new String(cipher.doFinal(Base64.getDecoder().decode(data.getBytes())));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return output;
	}

	private String decryptBlowfish(String data, String input) {
		byte[] decData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(mk.getPrivateKey(privateKey).getEncoded());
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, key);
			decData = cipher.doFinal((input.equals("B64") ? Base64.getDecoder().decode(data) : Hex.decodeHex(data)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(decData);
	}

	private String decryptRC4(String data, String input) {
		byte[] decData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(mk.getPrivateKey(privateKey).getEncoded());
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "RC4");
			Cipher cipher = Cipher.getInstance("RC4");
			cipher.init(Cipher.DECRYPT_MODE, key);
			decData = cipher.doFinal((input.equals("B64") ? Base64.getDecoder().decode(data) : Hex.decodeHex(data)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(decData);
	}

	private String decryptRC2(String data, String input) {
		byte[] decData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(mk.getPrivateKey(privateKey).getEncoded());
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "RC2");
			Cipher cipher = Cipher.getInstance("RC2");
			cipher.init(Cipher.DECRYPT_MODE, key);
			decData = cipher.doFinal((input.equals("B64") ? Base64.getDecoder().decode(data) : Hex.decodeHex(data)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(decData);
	}

	private String decryptAES(String data, String input) {
		byte[] decData = null;
		try {
			byte[] key = mk.getPrivateKey(this.privateKey).getEncoded();
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			decData = cipher.doFinal((input.equals("B64") ? Base64.getDecoder().decode(data) : Hex.decodeHex(data)));
		} catch (Exception e) {
			System.out.println("Error while decrypting : " + e.toString());
		}
		return new String(decData);
	}

	private String decrypt3DES(String data, String input) {
		byte[] plainText = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(mk.getPrivateKey(privateKey).getEncoded());
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
			final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
			final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			decipher.init(Cipher.DECRYPT_MODE, key, iv);
			plainText = decipher
					.doFinal((input.equals(("Hex")) ? Hex.decodeHex(data) : Base64.getDecoder().decode(data)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(plainText);
	}

	public  String  decryptDataEnvelop(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException {
		  byte[] decryptedData = null;
		    if (null != encryptedData && null != decryptionKey) {
		        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
		        Collection<RecipientInformation> recipients
		          = envelopedData.getRecipientInfos().getRecipients();
		        KeyTransRecipientInformation recipientInfo 
		          = (KeyTransRecipientInformation) recipients.iterator().next();
		        JceKeyTransRecipient recipient
		          = new JceKeyTransEnvelopedRecipient(decryptionKey);
		        return new String(recipientInfo.getContent(recipient));
		    }
		    return null;
	}

	private ASN1ObjectIdentifier getEnvelopAlg(String algEnv2) {
		ASN1ObjectIdentifier ret =null;
		switch (algEnv2) {
		case "AES":
			ret = CMSAlgorithm.AES128_CBC;
			break;
		case "3DES":
			ret = CMSAlgorithm.DES_EDE3_CBC;
			break;
		case "CASTS":
			ret = CMSAlgorithm.CAST5_CBC;
			break;
		case "CAMELIA":
			ret = CMSAlgorithm.CAMELLIA128_CBC;
			break;
		default:
			ret = CMSAlgorithm.AES128_CBC;
			break;
		}
		System.out.println(" algorithm = "+ret);
		return ret;
	}

}
