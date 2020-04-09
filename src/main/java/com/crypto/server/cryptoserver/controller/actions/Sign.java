package com.crypto.server.cryptoserver.controller.actions;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;

import javax.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import com.crypto.server.cryptoserver.utils.ManageKeys;


public class Sign {
	private static final String HEADER = "";
	private String privateKey;
	private String publicKey;
	Logger log = Logger.getLogger(HEADER);
	private ManageKeys mk;

	public Sign(String privateKey, String publicKey) {

		this.privateKey = privateKey;
		this.publicKey = publicKey;
		mk = new ManageKeys();
	}

	public String signData(String data) {
		String out = null;
		log.info(HEADER + "signData() input  " + data);
		try {
			out = sign(data, mk.getPrivateKey(privateKey));
		} catch (Exception e) {
			e.printStackTrace();
		}
		log.info(HEADER + "signData() output = " + out);
		return out;
	}

	public boolean verifySignData(String data, String dataSign) {
		boolean verify = false;
		log.info(HEADER + "verifySignData() input data = " + data);
		log.info(HEADER + "verifySignData() input data sign =" + dataSign);
		try {
			verify = verify(data, dataSign, mk.getPublicKey(publicKey));
		} catch (Exception e) {
			e.printStackTrace();
		}
		log.info(HEADER + "verifySignData() out = " + verify);
		return verify;
	}

	private String sign(String plainText, PrivateKey privateKey) throws Exception {
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(privateKey);
		privateSignature.update(plainText.getBytes("UTF-8"));
		byte[] signature = privateSignature.sign();
		return Base64.getEncoder().encodeToString(signature);
	}

	private boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
		Signature publicSignature = Signature.getInstance("SHA256withRSA");
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes("UTF-8"));
		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		return publicSignature.verify(signatureBytes);
	}
/*
	public static byte[] signCms(byte[] data, X509Certificate signingCertificate, PrivateKey signingKey)
			throws Exception {

		byte[] signedMessage = null;
		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		CMSTypedData cmsData = new CMSProcessableByteArray(data);
		certList.add(signingCertificate);
		Store certs = new JcaCertStore(certList);

		CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();

		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
		cmsGenerator.addSignerInfoGenerator(
				new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
						.build(contentSigner, signingCertificate));
		cmsGenerator.addCertificates(certs);

		CMSSignedData cms = cmsGenerator.generate(cmsData, true);
		signedMessage = cms.getEncoded();
		return signedMessage;
	}

	public static boolean verifSignedData(byte[] signedData) throws Exception {

		X509Certificate signCert = null;
		ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
		ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
		CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));

		SignerInformationStore signers = ((CMSSignedData) cmsSignedData.getCertificates()).getSignerInfos();
		SignerInformation signer = signers.getSigners().iterator().next();
		Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
		X509CertificateHolder certHolder = certCollection.iterator().next();

		return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
	}
*/
}
