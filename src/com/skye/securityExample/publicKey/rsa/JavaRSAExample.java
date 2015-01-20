package com.skye.securityExample.publicKey.rsa;

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
import javax.crypto.NoSuchPaddingException;

/**
 * Java RSA 典型非對稱式加密演算法，私鑰加密公鑰解密，公鑰加密私鑰解密，基於大數因數分解。
 * <p>
 * Java6 密鑰長度預設為 1024 byte，包含 512 至 65536(64 的倍數) byte，工作模式包含 ECB，填充方式包含
 * NoPadding、PKCS1Padding、OAEPWITHMD5AndMGF1Padding
 * 、OAEPWITHSHA1AndMGF1Padding、OAEPWITHSHA256AndMGF1Padding
 * 、OAEPWITHSHA384AndMGF1Padding 及 OAEPWITHSHA512AndMGF1Padding。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度預設為 2048 byte，包含 512 至 65536(64 的倍數) byte，工作模式包含
 * NONE，填充方式包含 NoPadding、PKCS1Padding、OAEPWITHMD5AndMGF1Padding
 * 、OAEPWITHSHA1AndMGF1Padding、OAEPWITHSHA224AndMGF1Padding
 * 、OAEPWITHSHA256AndMGF1Padding
 * 、OAEPWITHSHA384AndMGF1Padding、OAEPWITHSHA512AndMGF1Padding 及
 * ISO9796-1Padding。
 * </p>
 * 
 * @author Skye
 */
public class JavaRSAExample {
	private final static String ALGORITHM = "RSA";

	/**
	 * 公鑰。
	 */
	private final static String PUBLIC_KEY = "PublicKey";

	/**
	 * 私鑰。
	 */
	private final static String PRIVATE_KEY = "PrivateKey";

	/**
	 * 初始化密鑰。
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
	 * RSA 使用私鑰加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptByPrivateKey(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		// 取得私鑰。
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

		// 初始化，設置為加密模式。
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}

	/**
	 * RSA 使用公鑰加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encryptByPublicKey(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		// 取得公鑰。
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(keySpec);

		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

		// 初始化，設置為加密模式。
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}

	/**
	 * RSA 使用私鑰解密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptByPrivateKey(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		// 取得私鑰。
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

		// 初始化，設置為解密模式。
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}

	/**
	 * RSA 使用公鑰解密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decryptByPublicKey(byte[] data, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		// 取得公鑰。
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(keySpec);

		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

		// 初始化，設置為解密模式。
		cipher.init(Cipher.DECRYPT_MODE, publicKey);

		return cipher.doFinal(data);
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
