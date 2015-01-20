package com.skye.securityExample.hashFunction.md;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * Commons Codec Message Digest 訊息摘要演算法，長度為 128 byte，分為 MD2、MD4 及 MD5 三種。
 * <p>
 * Java6 實作 MD2 及 MD5。
 * </p>
 * <p>
 * Bouncy Castle 實作 MD4。
 * </p>
 * 
 * @author Skye
 */
public class CommonsCodecMDExample {
	/**
	 * MD5 訊息摘要演算法編碼。
	 * 
	 * @param data
	 * @return
	 */
	public static byte[] encodeMD5(byte[] data) {
		return DigestUtils.md5(data);
	}

	/**
	 * MD5 訊息摘要演算法編碼，回傳 16 進位字串。
	 * 
	 * @param data
	 * @return
	 */
	public static String encodeMD5Hex(byte[] data) {
		return DigestUtils.md5Hex(data);
	}
}
