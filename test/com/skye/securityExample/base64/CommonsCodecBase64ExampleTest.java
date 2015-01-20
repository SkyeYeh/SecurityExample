package com.skye.securityExample.base64;

import java.io.UnsupportedEncodingException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.skye.securityExample.base64.CommonsCodecBase64Example;

/**
 * Commons Codec Base64 編碼： 長度為 4 的倍數，使用"="補位，每行為 76 個字元，
 * 每行末需添加一個換行符號，含有"+"和"/"符號。Url Base64 省略所有換行符號，"+"替換為"-"；"/"替換為"_"；省略"="。
 * 
 * @author Skye
 */
public class CommonsCodecBase64ExampleTest {
	private String data = null;

	@Before
	public void setUp() {
		data = "加解密 Commons Codec Base64 編碼";
	}

	@After
	public void tearDown() {
		data = null;
	}

	/**
	 * Commons Codec Base64 編碼，省略行末換行符號。
	 */
	@Test
	public void testEncode() {
		System.out.println("-- Commons Codec Base64 Start --");
		System.out.println("Data\t：" + data);

		String encodeData = null;
		String decodeData = null;
		try {
			// Commons Codec Base64 編碼，省略行末換行符號。
			encodeData = CommonsCodecBase64Example.encode(data);
			// Commons Codec Base64 解碼。
			decodeData = CommonsCodecBase64Example.decode(encodeData);
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, decodeData);
		// 驗證。
		Assert.assertEquals(data, decodeData);

		System.out.println("-- Commons Codec Base64 End --");
		System.out.println();
	}

	/**
	 * Commons Codec Base64 安全編碼。
	 */
	@Test
	public void testEncodeSafe() {
		System.out.println("-- Commons Codec Base64 Safe Start --");
		System.out.println("Data\t：" + data);

		String encodeData = null;
		String decodeData = null;
		try {
			// Commons Codec Base64 安全編碼。
			encodeData = CommonsCodecBase64Example.encodeSafe(data);
			// Commons Codec Base64 解碼。
			decodeData = CommonsCodecBase64Example.decode(encodeData);
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, decodeData);
		// 驗證。
		Assert.assertEquals(data, decodeData);

		System.out.println("-- Commons Codec Base64 Safe End --");
		System.out.println();
	}

	/**
	 * Commons Codec Url Base64 編碼，省略所有換行符號，"+"替換為"-"；"/"替換為"_"；省略"="。
	 */
	@Test
	public void testUrlEncodeSafe() {
		System.out.println("-- Commons Codec Base64 Url Safe Start --");
		System.out.println("Data\t：" + data);

		String encodeData = null;
		String decodeData = null;
		try {
			// Commons Codec Url Base64 編碼，省略所有換行符號，"+"替換為"-"；"/"替換為"_"；省略"="。
			encodeData = CommonsCodecBase64Example.urlEncodeSafe(data);
			// Commons Codec Base64 解碼。
			decodeData = CommonsCodecBase64Example.decode(encodeData);
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, decodeData);
		// 驗證。
		Assert.assertEquals(data, decodeData);

		System.out.println("-- Commons Codec Base64 Url Safe End --");
		System.out.println();
	}

	/**
	 * 印出結果。
	 * 
	 * @param encodeData
	 * @param decodeData
	 */
	private static void print(String encodeData, String decodeData) {
		System.out.println("Encode\t：" + encodeData);
		System.out.println("Decode\t：" + decodeData);
	}
}
