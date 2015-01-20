package com.skye.securityExample.publicKey.dh;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Java Diffie-Hellman 密鑰交換演算法，密鑰長度預設為 1024 byte。
 * <p>
 * Java6 密鑰長度包含 512 至 1024(64 的倍數) byte。
 * </p>
 * 
 * @author Skye
 */
public class JavaDHExample {
	private final static String ALGORITHM = "DH";

	/**
	 * 密鑰演算法，可選 DES、DESede 及 AES 演算法。
	 */
	private final static String SYMMETRIC_ALGORITHM = "AES";

	/**
	 * 公鑰。
	 */
	private final static String PUBLIC_KEY = "PublicKey";

	/**
	 * 私鑰。
	 */
	private final static String PRIVATE_KEY = "PrivateKey";

	/**
	 * 初始化甲方密鑰。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static Map<String, Key> initKey() throws NoSuchAlgorithmException {
		// 實體化密鑰產生器。
		KeyPairGenerator keyPairGenerator = KeyPairGenerator
				.getInstance(ALGORITHM);

		// 初始化密鑰產生器，預設長度為 1024 byte。
		// keyPairGenerator.initialize(1024);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Map<String, Key> result = new HashMap<String, Key>();
		result.put(PUBLIC_KEY, keyPair.getPublic());
		result.put(PRIVATE_KEY, keyPair.getPrivate());
		return result;
	}

	/**
	 * 初始化乙方密鑰。
	 * 
	 * @param encodedPrivateKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static Map<String, Key> initKey(byte[] encodedPrivateKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidAlgorithmParameterException {
		KeyFactory factory = KeyFactory.getInstance(ALGORITHM);

		// 產生公鑰。
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				encodedPrivateKey);
		PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);

		DHParameterSpec params = ((DHPublicKey) publicKey).getParams();

		// 實體化密鑰產生器。
		KeyPairGenerator keyPairGenerator = KeyPairGenerator
				.getInstance(factory.getAlgorithm());

		// 初始化密鑰產生器。
		keyPairGenerator.initialize(params);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Map<String, Key> result = new HashMap<String, Key>();
		result.put(PUBLIC_KEY, keyPair.getPublic());
		result.put(PRIVATE_KEY, keyPair.getPrivate());
		return result;
	}

	/**
	 * DH 加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// 實體化 AES 密鑰材料。
		SecretKey secretKey = new SecretKeySpec(key, SYMMETRIC_ALGORITHM);

		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());

		// 初始化，設置為加密模式。
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);

		return cipher.doFinal(data);
	}

	/**
	 * DH 解密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decrypt(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// 實體化 AES 密鑰材料。
		SecretKey secretKey = new SecretKeySpec(key, SYMMETRIC_ALGORITHM);

		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, secretKey);

		return cipher.doFinal(data);
	}

	/**
	 * 建構密鑰。
	 * 
	 * @param encodedPublicKey
	 * @param encodedPrivateKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 */
	public static byte[] getSecretKey(byte[] encodedPublicKey,
			byte[] encodedPrivateKey) throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException {
		KeyFactory factory = KeyFactory.getInstance(ALGORITHM);

		// 產生公鑰。
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);

		// 產生私鑰。
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey = factory.generatePrivate(pkcs8EncodedKeySpec);

		// 實體化密鑰產生器。
		KeyAgreement keyAgreement = KeyAgreement.getInstance(factory
				.getAlgorithm());

		// 初始化密鑰產生器。
		keyAgreement.init(privateKey);
		keyAgreement.doPhase(publicKey, true);

		SecretKey secretKey = keyAgreement.generateSecret(SYMMETRIC_ALGORITHM);
		return secretKey.getEncoded();
	}

	/**
	 * 取得私鑰。
	 * 
	 * @param key
	 * @return
	 */
	public static byte[] getPrivateKey(Map<String, Key> keyMap) {
		Key key = keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}

	/**
	 * 取得公鑰。
	 * 
	 * @param key
	 * @return
	 */
	public static byte[] getPublicKey(Map<String, Key> keyMap) {
		Key key = keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
}
