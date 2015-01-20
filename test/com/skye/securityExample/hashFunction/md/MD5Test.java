package com.skye.securityExample.hashFunction.md;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Message Digest 訊息摘要演算法，長度為 128 byte，分為 MD2、MD4 及 MD5 三種。
 * <p>
 * Java6 實作 MD2 及 MD5。
 * </p>
 * <p>
 * Bouncy Castle 實作 MD4。
 * </p>
 * 
 * @author Skye
 */
public class MD5Test {
	private File file = null;

	@Before
	public void setUp() {
		file = new File(
				"D:\\workspace\\SecurityExample\\WebContent\\apache-maven-3.2.1-bin.zip");
	}

	@After
	public void tearDown() {
		file = null;
	}

	/**
	 * Java MD5 驗證檔案。
	 */
	@Test
	public void testMessageDigest() {
		FileInputStream fileInputStream = null;
		try {
			fileInputStream = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			Assert.fail(e.toString());
		}

		DigestInputStream digestInputStream = null;
		try {
			digestInputStream = new DigestInputStream(fileInputStream,
					MessageDigest.getInstance("MD5"));
		} catch (NoSuchAlgorithmException e) {
			Assert.fail(e.toString());
		}

		int buf = 1024;
		byte[] buffer = new byte[buf];
		int read;
		try {
			read = digestInputStream.read(buffer, 0, buf);
			while (read != -1) {
				read = digestInputStream.read(buffer, 0, buf);
			}
			digestInputStream.close();
		} catch (IOException e) {
			Assert.fail(e.toString());
		}

		MessageDigest messageDigest = digestInputStream.getMessageDigest();
		byte[] encodeData = messageDigest.digest();
		String encodeDataHex = Hex.encodeHexString(encodeData);
		// 校驗。
		Assert.assertEquals("5d86506f17e5ff0b0c83c648f4093abb", encodeDataHex);
	}

	/**
	 * Commons Codec MD5 驗證檔案。
	 */
	@Test
	public void testDigestUtils() {
		FileInputStream fileInputStream = null;
		try {
			fileInputStream = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			Assert.fail(e.toString());
		}

		String encodeDataHex = null;
		try {
			encodeDataHex = DigestUtils.md5Hex(fileInputStream);
		} catch (IOException e) {
			Assert.fail(e.toString());
		}
		// 校驗。
		Assert.assertEquals("5d86506f17e5ff0b0c83c648f4093abb", encodeDataHex);
	}
}
