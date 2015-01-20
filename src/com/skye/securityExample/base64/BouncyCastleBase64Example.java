package com.skye.securityExample.base64;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.UrlBase64;

/**
 * Bouncy Castle Base64 編碼： 長度為 4 的倍數，使用"="補位，每行為 76 個字元，
 * 每行末需添加一個換行符號，含有"+"和"/"符號。Url Base64 省略所有換行符號，"+"替換為"-"；"/"替換為"_"；"="替換為"."。
 * 
 * @author Skye
 */
public class BouncyCastleBase64Example {
	public final static String charsetName = "UTF-8";

	/**
	 * Bouncy Castle Base64 編碼，省略行末換行符號。
	 * 
	 * @param data
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String encode(String data)
			throws UnsupportedEncodingException {
		byte[] bytes = Base64.encode(data.getBytes(charsetName));
		return new String(bytes, charsetName);
	}

	/**
	 * Bouncy Castle Base64 解碼。
	 * 
	 * @param encodeData
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String decode(String encodeData)
			throws UnsupportedEncodingException {
		byte[] bytes = Base64.decode(encodeData.getBytes(charsetName));
		return new String(bytes, charsetName);
	}

	/**
	 * Bouncy Castle Url Base64 編碼，省略所有換行符號，"+"替換為"-"；"/"替換為"_"；"="替換為"."。
	 * 
	 * @param data
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String urlEncode(String data)
			throws UnsupportedEncodingException {
		byte[] bytes = UrlBase64.encode(data.getBytes(charsetName));
		return new String(bytes, charsetName);
	}

	/**
	 * Bouncy Castle Url Base64 解碼。
	 * 
	 * @param encodeData
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String urlDecode(String encodeData)
			throws UnsupportedEncodingException {
		byte[] bytes = UrlBase64.decode(encodeData.getBytes(charsetName));
		return new String(bytes, charsetName);
	}
}
