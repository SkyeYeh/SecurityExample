package com.skye.securityExample.hashFunction.md;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Bouncy Castle Message Digest 訊息摘要演算法，長度為 128 byte，分為 MD2、MD4 及 MD5 三種。
 * <p>
 * Java6 實作 MD2 及 MD5。
 * </p>
 * <p>
 * Bouncy Castle 實作 MD4。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleMDExample {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * MD4 訊息摘要演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeMD4(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("MD4");
		return messageDigest.digest(data);
	}

	/**
	 * MD4 訊息摘要演算法編碼，回傳 16 進位字串。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeMD4Hex(byte[] data)
			throws NoSuchAlgorithmException {
		byte[] encodeData = encodeMD4(data);
		return new String(Hex.encode(encodeData));
	}
}
