package com.skye.securityExample.hashFunction.sha;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Bouncy Castle Secure Hash Algorithm 安全雜湊演算法，SHA-1 長度為 160 byte，分為
 * SHA-1、SHA-224、SHA-256、SHA-384 及 SHA-512。
 * <p>
 * Java6 實作 SHA-1、SHA-256、SHA-384 及 SHA-512。
 * </p>
 * <p>
 * Bouncy Castle 實作 SHA-224。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleSHAExample {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * SHA-224 安全雜湊演算法編碼。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] encodeSHA224(byte[] data)
			throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-224");
		return messageDigest.digest(data);
	}

	/**
	 * SHA-224 安全雜湊演算法編碼，回傳 16 進位字串。
	 * 
	 * @param data
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String encodeSHA224Hex(byte[] data)
			throws NoSuchAlgorithmException {
		byte[] encodeData = encodeSHA224(data);
		return new String(Hex.encode(encodeData));
	}
}
