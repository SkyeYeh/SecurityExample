package com.skye.securityExample.hashFunction.md;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Java Message Digest 訊息摘要演算法，長度為 128 byte，分為 MD2、MD4 及 MD5 三種。
 * <p>
 * Java6 實作 MD2 及 MD5。
 * </p>
 * <p>
 * Bouncy Castle 實作 MD4。
 * </p>
 * 
 * @author Skye
 */
public class JavaMDExample {
	/**
	 * MD2 訊息摘要演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeMD2(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("MD2");
		return messageDigest.digest(data);
	}

	/**
	 * MD5 訊息摘要演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeMD5(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("MD5");
		return messageDigest.digest(data);
	}
}
