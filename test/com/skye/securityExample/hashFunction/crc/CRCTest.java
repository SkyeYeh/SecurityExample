package com.skye.securityExample.hashFunction.crc;

import java.util.zip.CRC32;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Java Cyclic Redundancy Check 循環冗餘校驗，長度為 32 byte。CRC-1 為奇偶校驗碼；CRC-32-IEEE
 * 802.3 實作通訊領域的錯誤控制；CRC-32-Adler 也稱為 Adler-32；CRC-128 演變為 MD 演算法；CRC-168 演變為
 * SHA 演算法。
 * 
 * @author Skye
 */
public class CRCTest {
	private String data = null;
	private String data2 = null;

	@Before
	public void setUp() {
		data = "Hello Java Cyclic Redundancy Check.";
		data2 = "Hello Java Cyclic Redundancy Check.";
	}

	@After
	public void tearDown() {
		data = null;
		data2 = null;
	}

	/**
	 * CRC-32 循環冗餘校驗。
	 */
	@Test
	public void testCRC32() {
		System.out.println("-- JAVA CRC-32 Start --");
		System.out.println("Data\t：" + data);
		System.out.println("Data2\t：" + data2);

		CRC32 crc32 = new CRC32();
		crc32.update(data.getBytes());
		String encodeData = Long.toHexString(crc32.getValue());

		CRC32 crc322 = new CRC32();
		crc322.update(data2.getBytes());
		String encodeData2 = Long.toHexString(crc322.getValue());

		// 印出結果。
		print(encodeData, encodeData2);
		// 校驗。
		Assert.assertEquals(encodeData, encodeData2);

		System.out.println("-- JAVA CRC-32 End --");
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
