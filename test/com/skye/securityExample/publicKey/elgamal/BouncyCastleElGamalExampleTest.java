package com.skye.securityExample.publicKey.elgamal;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Java ElGamal 常用非對稱式加密演算法，公鑰加密私鑰解密，基於離散對數。
 * <p>
 * Bouncy Castle 密鑰長度預設為 1024 byte，包含 160 至 16384(8 的倍數) byte，工作模式包含 ECB 及
 * NONE，填充方式包含 NoPadding、PKCS1Padding、OAEPWITHMD5AndMGF1Padding
 * 、OAEPWITHSHA1AndMGF1Padding、OAEPWITHSHA224AndMGF1Padding
 * 、OAEPWITHSHA256AndMGF1Padding
 * 、OAEPWITHSHA384AndMGF1Padding、OAEPWITHSHA512AndMGF1Padding 及
 * ISO9796-1Padding。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleElGamalExampleTest {
	private String data = null;
	private byte[] publicKey = null;
	private byte[] privateKey = null;

	@Before
	public void setUp() throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			InvalidKeyException, InvalidParameterSpecException {
		System.out.println("-- JAVA ElGamal Start --");

		data = "Hello Java ElGamal.";
		Map<String, Key> keyMap = BouncyCastleElGamalExample.initKey();
		publicKey = BouncyCastleElGamalExample.getPublicKey(keyMap);
		privateKey = BouncyCastleElGamalExample.getPrivateKey(keyMap);

		System.out.println("Data\t：" + data);
		System.out.println("PublicKey\t："
				+ Base64.encodeBase64String(publicKey));
		System.out.println("PrivateKey\t："
				+ Base64.encodeBase64String(privateKey));
	}

	@After
	public void tearDown() {
		data = null;
		System.out.println("-- JAVA ElGamal End --");
		System.out.println();
	}

	/**
	 * ElGamal 使用公鑰加密。
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
			encodeData = BouncyCastleElGamalExample.encryptByPublicKey(
					data.getBytes(), publicKey);
			System.out.println("EncodeData\t："
					+ Base64.encodeBase64String(encodeData));

			decodeData = BouncyCastleElGamalExample.decryptByPrivateKey(
					encodeData, privateKey);
			System.out.println("DecodeData\t：" + new String(decodeData));
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.toString());
		}

		// 校驗。
		Assert.assertEquals(data, new String(decodeData));
	}
}
