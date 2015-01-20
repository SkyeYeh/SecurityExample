package com.skye.securityExample.base64;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;

/**
 * Commons Codec Base64 編碼： 長度為 4 的倍數，使用"="補位，每行為 76 個字元，
 * 每行末需添加一個換行符號，含有"+"和"/"符號。Url Base64 省略所有換行符號，"+"替換為"-"；"/"替換為"_"；省略"="。
 * 
 * @author Skye
 */
public class CommonsCodecBase64Example {
	public final static String charsetName = "UTF-8";

	/**
	 * Commons Codec Base64 編碼，省略行末換行符號。
	 * 
	 * @param data
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String encode(String data)
			throws UnsupportedEncodingException {
		byte[] bytes = Base64.encodeBase64(data.getBytes(charsetName));
		return new String(bytes, charsetName);
	}

	/**
	 * Commons Codec Base64 安全編碼。
	 * 
	 * @param data
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String encodeSafe(String data)
			throws UnsupportedEncodingException {
		byte[] bytes = Base64.encodeBase64(data.getBytes(charsetName), true);
		return new String(bytes, charsetName);
	}

	/**
	 * Commons Codec Base64 解碼。
	 * 
	 * @param encodeData
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String decode(String encodeData)
			throws UnsupportedEncodingException {
		byte[] bytes = Base64.decodeBase64(encodeData.getBytes(charsetName));
		return new String(bytes, charsetName);
	}

	/**
	 * Commons Codec Url Base64 編碼，省略所有換行符號，"+"替換為"-"；"/"替換為"_"；省略"="。
	 * 
	 * @param data
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static String urlEncodeSafe(String data)
			throws UnsupportedEncodingException {
		byte[] bytes = Base64.encodeBase64URLSafe(data.getBytes(charsetName));
		return new String(bytes, charsetName);
	}
}
