package com.skye.securityExample.hashFunction.sha;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Commons Codec Secure Hash Algorithm 安全雜湊演算法，SHA-1 長度為 160 byte，分為
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
public class CommonsCodecSHAExampleTest {
	private final static String charsetName = "UTF-8";
	private String data = null;
	private String data2 = null;

	@Before
	public void setUp() {
		data = "Hello Commons Codec Secure Hash Algorithm.";
		data2 = "Hello Commons Codec Secure Hash Algorithm.";
	}

	@After
	public void tearDown() {
		data = null;
		data2 = null;
	}

	/**
	 * SHA-1 安全雜湊演算法編碼。
	 */
	@Test
	public void testEncodeSHA() {
		System.out.println("-- Commons Codec SHA-1 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// SHA-1 安全雜湊演算法編碼。
			encodeData = CommonsCodecSHAExample.encodeSHA(data
					.getBytes(charsetName));
			// SHA-1 安全雜湊演算法編碼。
			encodeData2 = CommonsCodecSHAExample.encodeSHA(data2
					.getBytes(charsetName));
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, encodeData2);
		// 校驗。
		Assert.assertEquals(encodeData, encodeData2);

		System.out.println("-- Commons Codec SHA-1 End --");
		System.out.println();
	}

	/**
	 * SHA-256 安全雜湊演算法編碼。
	 */
	@Test
	public void testEncodeSHA256() {
		System.out.println("-- Commons Codec SHA-256 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// SHA-256 安全雜湊演算法編碼。
			encodeData = CommonsCodecSHAExample.encodeSHA256(data
					.getBytes(charsetName));
			// SHA-256 安全雜湊演算法編碼。
			encodeData2 = CommonsCodecSHAExample.encodeSHA256(data2
					.getBytes(charsetName));
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, encodeData2);
		// 校驗。
		Assert.assertEquals(encodeData, encodeData2);

		System.out.println("-- Commons Codec SHA-256 End --");
		System.out.println();
	}

	/**
	 * SHA-384 安全雜湊演算法編碼。
	 */
	@Test
	public void testEncodeSHA384() {
		System.out.println("-- Commons Codec SHA-384 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// SHA-384 安全雜湊演算法編碼。
			encodeData = CommonsCodecSHAExample.encodeSHA384(data
					.getBytes(charsetName));
			// SHA-384 安全雜湊演算法編碼。
			encodeData2 = CommonsCodecSHAExample.encodeSHA384(data2
					.getBytes(charsetName));
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, encodeData2);
		// 校驗。
		Assert.assertEquals(encodeData, encodeData2);

		System.out.println("-- Commons Codec SHA-384 End --");
		System.out.println();
	}

	/**
	 * SHA-512 安全雜湊演算法編碼。
	 */
	@Test
	public void testEncodeSHA512() {
		System.out.println("-- Commons Codec SHA-512 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		String encodeData = null;
		String encodeData2 = null;
		try {
			// SHA-512 安全雜湊演算法編碼。
			encodeData = CommonsCodecSHAExample.encodeSHA512(data
					.getBytes(charsetName));
			// SHA-512 安全雜湊演算法編碼。
			encodeData2 = CommonsCodecSHAExample.encodeSHA512(data2
					.getBytes(charsetName));
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		} catch (UnsupportedEncodingException e) {
			Assert.fail(e.toString());
		}
		// 印出結果。
		print(encodeData, encodeData2);
		// 校驗。
		Assert.assertEquals(encodeData, encodeData2);

		System.out.println("-- Commons Codec SHA-512 End --");
		System.out.println();
	}

	/**
	 * 印出結果。
	 * 
	 * @param encodeData
	 * @param encodeData2
	 */
	private static void print(String encodeData, String encodeData2) {
		System.out.println("EncodeData\t：" + encodeData);
		System.out.println("EncodeData2\t：" + encodeData2);
	}
}
