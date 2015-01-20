package com.skye.securityExample.base64;

import java.io.UnsupportedEncodingException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.skye.securityExample.base64.BouncyCastleBase64Example;

/**
 * Bouncy Castle Base64 編碼： 長度為 4 的倍數，使用"="補位，每行為 76 個字元，
 * 每行末需添加一個換行符號，含有"+"和"/"符號。Url Base64 省略所有換行符號，"+"替換為"-"；"/"替換為"_"；"="替換為"."。
 * 
 * @author Skye
 */
public class BouncyCastleBase64ExampleTest {
	private String data = null;

	@Before
	public void setUp() {
		data = "加解密 Bouncy Castle Base64 ";
	}

	@After
	public void tearDown() {
		data = null;
	}

	/**
	 * Bouncy Castle Base64 編碼，省略行末換行符號。
	 */
	@Test
	public void testEncode() {
		System.out.println("-- Bouncy Castle Base64 Start --");
		System.out.println("Data\t：" + data);

		String encodeData = null;
		String decodeData = null;
		try {
			// Bouncy Castle Base64 編碼，省略行末換行符號。
			encodeData = BouncyCastleBase64Example.encode(data);
			// Bouncy Castle Base64 解碼。
			decodeData = BouncyCastleBase64Example.decode(encodeData);
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}

		// 印出結果。
		print(encodeData, decodeData);
		// 驗證。
		Assert.assertEquals(data, decodeData);

		System.out.println("-- Bouncy Castle Base64 End --");
		System.out.println();
	}

	/**
	 * Bouncy Castle Url Base64 編碼，省略所有換行符號，"+"替換為"-"；"/"替換為"_"；"="替換為"."。
	 */
	@Test
	public void testUrlEncode() {
		System.out.println("-- Bouncy Castle Url Base64 Start --");
		System.out.println("Data\t：" + data);

		String encodeData = null;
		String decodeData = null;
		try {
			// Bouncy Castle Url Base64
			// 編碼，省略所有換行符號，"+"替換為"-"；"/"替換為"_"；"="替換為"."。
			encodeData = BouncyCastleBase64Example.urlEncode(data);
			// Bouncy Castle Url Base64 解碼。
			decodeData = BouncyCastleBase64Example.urlDecode(encodeData);
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}

		// 印出結果。
		print(encodeData, decodeData);
		// 驗證。
		Assert.assertEquals(data, decodeData);

		System.out.println("-- Bouncy Castle Url Base64 End --");
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
