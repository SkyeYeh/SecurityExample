package com.skye.securityExample.publicKey.rsa;

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
 * Java RSA 典型非對稱式加密演算法，私鑰加密公鑰解密，公鑰加密私鑰解密，基於大數因數分解。
 * <p>
 * Java6 密鑰長度預設為 1024 byte，包含 512 至 65536(64 的倍數) byte，工作模式包含 ECB，填充方式包含
 * NoPadding、PKCS1Padding、OAEPWITHMD5AndMGF1Padding
 * 、OAEPWITHSHA1AndMGF1Padding、OAEPWITHSHA256AndMGF1Padding
 * 、OAEPWITHSHA384AndMGF1Padding 及 OAEPWITHSHA512AndMGF1Padding。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度預設為 2048 byte，包含 512 至 65536(64 的倍數) byte，工作模式包含
 * NONE，填充方式包含 NoPadding、PKCS1Padding、OAEPWITHMD5AndMGF1Padding
 * 、OAEPWITHSHA1AndMGF1Padding、OAEPWITHSHA224AndMGF1Padding
 * 、OAEPWITHSHA256AndMGF1Padding
 * 、OAEPWITHSHA384AndMGF1Padding、OAEPWITHSHA512AndMGF1Padding 及
 * ISO9796-1Padding。
 * </p>
 * 
 * @author Skye
 */
public class JavaRSAExampleTest {
	private String data = null;
	private byte[] publicKey = null;
	private byte[] privateKey = null;

	@Before
	public void setUp() throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			InvalidKeyException {
		System.out.println("-- JAVA RSA Start --");

		data = "Hello Java RSA.";
		Map<String, Key> keyMap = JavaRSAExample.initKey();
		publicKey = JavaRSAExample.getPublicKey(keyMap);
		privateKey = JavaRSAExample.getPrivateKey(keyMap);

		System.out.println("Data\t：" + data);
		System.out.println("PublicKey\t："
				+ Base64.encodeBase64String(publicKey));
		System.out.println("PrivateKey\t："
				+ Base64.encodeBase64String(privateKey));
	}

	@After
	public void tearDown() {
		data = null;
		System.out.println("-- JAVA RSA End --");
		System.out.println();
	}

	/**
	 * RSA 使用私鑰加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 */
	@Test
	public void testEncryptByPrivateKey() {
		byte[] encodeData = null;
		byte[] decodeData = null;

		try {
			encodeData = JavaRSAExample.encryptByPrivateKey(data.getBytes(),
					privateKey);
			System.out.println("EncodeData\t："
					+ Base64.encodeBase64String(encodeData));

			decodeData = JavaRSAExample.decryptByPublicKey(encodeData,
					publicKey);
			System.out.println("DecodeData\t：" + new String(decodeData));
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.toString());
		}

		// 校驗。
		Assert.assertEquals(data, new String(decodeData));
	}

	/**
	 * RSA 使用公鑰加密。
	 * 
	 * @param data
	 * @param key
	 * @return
	 */
	@Test
	public void testEncryptByPublicKey() {
		byte[] encodeData = null;
		byte[] decodeData = null;

		try {
			encodeData = JavaRSAExample.encryptByPublicKey(data.getBytes(),
					publicKey);
			System.out.println("EncodeData\t："
					+ Base64.encodeBase64String(encodeData));

			decodeData = JavaRSAExample.decryptByPrivateKey(encodeData,
					privateKey);
			System.out.println("DecodeData\t：" + new String(decodeData));
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.toString());
		}

		// 校驗。
		Assert.assertEquals(data, new String(decodeData));
	}
}
