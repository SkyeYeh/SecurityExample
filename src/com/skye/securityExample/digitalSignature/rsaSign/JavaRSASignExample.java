package com.skye.securityExample.digitalSignature.rsaSign;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Java RSA Sign 典型數位簽章演算法，私鑰簽章公鑰驗章，基於大數因數分解。
 * <p>
 * Java6 密鑰長度預設為 1024 byte，包含 512 至 65536(64 的倍數) byte，演算法包含
 * MD2withRSA、MD5withRSA 及 SHA1withRSA。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度預設為 2048 byte，包含 512 至 65536(64 的倍數) byte，演算法包含
 * SHA224withRSA、SHA256withRSA、SHA384withRSA、SHA512withRSA 、RIPEMD128withRSA 及
 * RIPEMD160withRSA。
 * </p>
 * 
 * @author Skye
 */
public class JavaRSASignExample {
	private final static String ALGORITHM = "RSA";
	private final static String SIGNATURE_ALGORITHM = "MD5withRSA";

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
	 * RSA 使用私鑰簽章。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] sign(byte[] data, byte[] key)
			throws SignatureException, InvalidKeySpecException,
			NoSuchAlgorithmException, InvalidKeyException {
		// 取得私鑰。
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

		// 初始化 Signature。
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateKey);

		signature.update(data);
		return signature.sign();
	}

	/**
	 * RSA 使用公鑰驗章。
	 * 
	 * @param data
	 * @param key
	 * @param sign
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public static boolean verify(byte[] data, byte[] key, byte[] sign)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidKeyException, SignatureException {
		// 取得公鑰。
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(keySpec);

		// 初始化 Signature。
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicKey);

		signature.update(data);
		return signature.verify(sign);
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
