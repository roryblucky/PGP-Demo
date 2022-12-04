package com.pgp.demo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.function.Predicate;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class PgpTest {
    public static void main(String[] args)
            throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
      
        String messagge = "hello";

        String encryptMessage = encryptAdnSignMessage(messagge.getBytes(), true, true);
        System.out.println(encryptMessage);

        String decryptMessage = decryptAndVerifyMessage(encryptMessage);

        System.out.println(decryptMessage);
    }

    private static String decryptAndVerifyMessage(String encryptMessage) throws IOException, PGPException {
        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(IOUtils.toInputStream(encryptMessage, StandardCharsets.UTF_8)));

        Object data = jcaPGPObjectFactory.nextObject();
        PGPEncryptedDataList pgpData = null;
        if (data instanceof PGPEncryptedDataList) {
            pgpData = (PGPEncryptedDataList) data;
        } else {
            pgpData = (PGPEncryptedDataList) jcaPGPObjectFactory.nextObject();
        }

        Iterator<PGPEncryptedData> encryptedDataObjects = pgpData.getEncryptedDataObjects();
        PGPPrivateKey privateKey = null;
		PGPPublicKeyEncryptedData encryptedData = null;
        while(encryptedDataObjects.hasNext()) {
            encryptedData = (PGPPublicKeyEncryptedData) encryptedDataObjects.next();
            PGPSecretKey loadSecretKey = loadSecrectKey(PgpTest.class.getClassLoader().getResourceAsStream("gina-prv.asc"));
            privateKey = loadSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("changeit".toCharArray()));
        }

        if (privateKey == null) {
			throw new IllegalArgumentException("secret key for message not found.");
		}

        InputStream clearDataStream = encryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));;

        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clearDataStream);
        Object message = plainFact.nextObject();

        if (message instanceof PGPCompressedData) {
            plainFact = new JcaPGPObjectFactory(((PGPCompressedData)message).getDataStream());

            message = plainFact.nextObject();
        }
        PGPOnePassSignature pgpOnePassSignature = null;
        if (message instanceof PGPOnePassSignatureList) {
            pgpOnePassSignature = ((PGPOnePassSignatureList) message).get(0);
            long keyID = pgpOnePassSignature.getKeyID();

            PGPPublicKey publicKey = loadPublicKey(PgpTest.class.getClassLoader().getResourceAsStream("rory-pub.asc"), key -> key.getKeyID() == keyID);
            pgpOnePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

            message = plainFact.nextObject();
        }

        byte[] realData = new byte[encryptMessage.getBytes().length];
        if (message instanceof PGPLiteralData) {
            InputStream inputStream = ((PGPLiteralData) message).getInputStream();
            realData = IOUtils.toByteArray(inputStream);

            pgpOnePassSignature.update(realData);
            PGPSignatureList singnatureData = (PGPSignatureList) plainFact.nextObject();
            if (!pgpOnePassSignature.verify(singnatureData.get(0))) {
                throw new PGPException("Signature verification failed!");
            }

            if (encryptedData.isIntegrityProtected()) {
                if (!encryptedData.verify()) {
					throw new PGPException("message failed integrity check");
				}
            }
        }

        return new String(realData);

    }

    public static String encryptAdnSignMessage(byte[] message, boolean withIntegrityCheck, boolean armor) throws IOException, PGPException {
        InputStream publicKeyStream = PgpTest.class.getClassLoader().getResourceAsStream("gina-pub.asc");

        PGPPublicKey publicKey = loadPublicKey(publicKeyStream, key -> key.isEncryptionKey());

        InputStream signedPrivateKeyStream = PgpTest.class.getClassLoader().getResourceAsStream("rory-prv.asc");

        PGPSecretKey secretKey = loadSecrectKey(signedPrivateKeyStream);

        ByteArrayOutputStream result = new ByteArrayOutputStream();;
        OutputStream outputStream = result;
        if (armor) {
            outputStream = new ArmoredOutputStream(outputStream);
        }

        //create encryptor and output stream          
        PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom()).setProvider("BC"));

        pgpEncryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));
        OutputStream encryptdOutStream = pgpEncryptedDataGenerator.open(outputStream, new byte[message.length]);


        //create compressed generator to create compressed output stream based on the aboved encypted output stream.
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream compressedOutStream = compressedDataGenerator.open(encryptdOutStream);

      
        //get private key to sign
        PGPPrivateKey extractPrivateKey = secretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("changeit".toCharArray()));

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA256)
                        .setProvider("BC"));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, extractPrivateKey);

        //use userId to sign
        Iterator<String> userIds = secretKey.getPublicKey().getUserIDs();
        if (userIds.hasNext()) {
            PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
            signatureSubpacketGenerator.addSignerUserID(false, (String) userIds.next());
            signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
        }
        // one pass header
        signatureGenerator.generateOnePassVersion(false).encode(compressedOutStream);

        // create lireral data writer to write the raw content to compressed output stream 
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalDataOutStream = literalDataGenerator.open(compressedOutStream, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, message.length, new Date());
        literalDataOutStream.write(message);

        signatureGenerator.update(message);
        signatureGenerator.generate().encode(compressedOutStream);
        
        literalDataOutStream.close();
        literalDataGenerator.close();
        compressedOutStream.close();
        compressedDataGenerator.close();
        pgpEncryptedDataGenerator.close();
        outputStream.close();
        
        return result.toString();

    }

    public static PGPSecretKey loadSecrectKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSecretKeyRings = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input),
                new JcaKeyFingerprintCalculator());
        Iterator<PGPSecretKeyRing> keyRings = pgpSecretKeyRings.getKeyRings();
        while (keyRings.hasNext()) {
            PGPSecretKeyRing keyRing = keyRings.next();
            Iterator<PGPSecretKey> secretKeys = keyRing.getSecretKeys();
            ;
            while (secretKeys.hasNext()) {
                PGPSecretKey next = secretKeys.next();
                if (next.isSigningKey()) {
                    return next;
                }
            }
        }
        throw new PGPException("Cannot found signing key in private key");

    }

    public static PGPPublicKey loadPublicKey(InputStream input, Predicate<PGPPublicKey> condition) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPublicKeyRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> keyRings = pgpPublicKeyRings.getKeyRings();

        while (keyRings.hasNext()) {
            PGPPublicKeyRing keyRing = keyRings.next();
            Iterator<PGPPublicKey> publicKeys = keyRing.getPublicKeys();
            while (publicKeys.hasNext()) {
                PGPPublicKey next = publicKeys.next();
                if (condition.test(next)) {
                    return next;
                }
            }
        }
        throw new PGPException("Cannot found encryption key in public key");
    }
}
