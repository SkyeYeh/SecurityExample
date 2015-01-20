package com.skye.securityExample.hashFunction.hmacRipeMd;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Bouncy Castle Message Authentication Code RACE Integrity primitives
 * Evaluation Message Digest 訊息摘要演算法，HmacRipeMD128 長度為 128 byte，分為 HmacRipeMD128
 * 及 RipeMD160 兩種。僅 Bouncy Castle 實作。
 * 
 * @author Skye
 */
public class BouncyCastleMACRipeMDExample {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 初始化 HmacRipeMD128 訊息認證碼演算法。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] iniHmacRipeMD128Key() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacRipeMD128");
		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey.getEncoded();
	}

	/**
	 * HmacRipeMD128 訊息認證碼演算法編碼。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeHmacRipeMD128(byte[] data, byte[] key)
			throws InvalidKeyException, NoSuchAlgorithmException {
		SecretKey secretKey = new SecretKeySpec(key, "HmacRipeMD128");
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);
		return mac.doFinal(data);
	}

	/**
	 * HmacRipeMD128 訊息認證碼演算法編碼，回傳 16 進位字串。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeHmacRipeMD128Hex(byte[] data, byte[] key)
			throws InvalidKeyException, NoSuchAlgorithmException {
		byte[] encodeData = encodeHmacRipeMD128(data, key);
		return new String(Hex.encode(encodeData));
	}

	/**
	 * 初始化 HmacRipeMD160 訊息認證碼演算法。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] iniHmacRipeMD160Key() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacRipeMD160");
		SecretKey secretKey = keyGenerator.generateKey();
		return secretKey.getEncoded();
	}

	/**
	 * HmacRipeMD160 訊息認證碼演算法編碼。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeHmacRipeMD160(byte[] data, byte[] key)
			throws InvalidKeyException, NoSuchAlgorithmException {
		SecretKey secretKey = new SecretKeySpec(key, "HmacRipeMD160");
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);
		return mac.doFinal(data);
	}

	/**
	 * HmacRipeMD160 訊息認證碼演算法編碼，回傳 16 進位字串。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeHmacRipeMD160Hex(byte[] data, byte[] key)
			throws InvalidKeyException, NoSuchAlgorithmException {
		byte[] encodeData = encodeHmacRipeMD160(data, key);
		return new String(Hex.encode(encodeData));
	}
}
