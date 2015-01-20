package com.skye.securityExample.publicKey.dh;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Java Diffie-Hellman 密鑰交換演算法，密鑰長度預設為 1024 byte。
 * <p>
 * Java6 密鑰長度包含 512 至 1024(64 的倍數) byte。
 * </p>
 * 
 * @author Skye
 */
public class JavaDHExampleTest {
	private String data = null;
	private byte[] publicKey_A = null;
	private byte[] privateKey_A = null;
	private byte[] key_A = null;
	private byte[] publicKey_B = null;
	private byte[] privateKey_B = null;
	private byte[] key_B = null;

	@Before
	public void setUp() throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			InvalidKeyException {
		data = "Hello Java Diffie-Hellman.";
		Map<String, Key> keyMap_A = JavaDHExample.initKey();
		publicKey_A = JavaDHExample.getPublicKey(keyMap_A);
		privateKey_A = JavaDHExample.getPrivateKey(keyMap_A);

		Map<String, Key> keyMap_B = JavaDHExample.initKey(publicKey_A);
		publicKey_B = JavaDHExample.getPublicKey(keyMap_B);
		privateKey_B = JavaDHExample.getPrivateKey(keyMap_B);

		key_A = JavaDHExample.getSecretKey(publicKey_B, privateKey_A);
		key_B = JavaDHExample.getSecretKey(publicKey_A, privateKey_B);
	}

	@After
	public void tearDown() {
		data = null;
	}

	/**
	 * DH 加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 */
	@Test
	public void testEncrypt() {
		System.out.println("-- JAVA DH Start --");
		System.out.println("Data\t：" + data);

		System.out.println("PublicKey A\t："
				+ Base64.encodeBase64String(publicKey_A));
		System.out.println("PrivateKey A\t："
				+ Base64.encodeBase64String(privateKey_A));

		System.out.println("PublicKey B\t："
				+ Base64.encodeBase64String(publicKey_B));
		System.out.println("PrivateKey B\t："
				+ Base64.encodeBase64String(privateKey_B));

		System.out.println("Key A\t：" + Base64.encodeBase64String(key_A));
		System.out.println("Key B\t：" + Base64.encodeBase64String(key_B));

		byte[] encodeData = null;
		byte[] decodeData = null;

		try {
			encodeData = JavaDHExample.encrypt(data.getBytes(), key_A);
			System.out.println("EncodeData\t："
					+ Base64.encodeBase64String(encodeData));

			decodeData = JavaDHExample.decrypt(encodeData, key_B);
			System.out.println("DecodeData\t：" + new String(decodeData));
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.toString());
		}

		// 校驗。
		Assert.assertEquals(data, new String(decodeData));

		System.out.println("-- JAVA DH End --");
		System.out.println();
	}
}
