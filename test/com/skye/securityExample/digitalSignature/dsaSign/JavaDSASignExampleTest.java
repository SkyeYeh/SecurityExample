package com.skye.securityExample.digitalSignature.dsaSign;

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
 * Java DSA Sign 數位簽章標準演算法，私鑰簽章公鑰驗章。
 * <p>
 * Java6 密鑰長度預設為 1024 byte，包含 512 至 1024(64 的倍數) byte，演算法包含 SHA1withDSA。
 * </p>
 * <p>
 * Bouncy Castle 密鑰長度預設為 1024 byte，包含 512 至 1024(64 的倍數) byte，演算法包含
 * SHA224withDSA、SHA256withDSA、SHA384withDSA 及 SHA512withDSA。
 * </p>
 * 
 * @author Skye
 */
public class JavaDSASignExampleTest {
	private String data = null;
	private byte[] publicKey = null;
	private byte[] privateKey = null;

	@Before
	public void setUp() throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException,
			InvalidKeyException {
		System.out.println("-- JAVA DSA Sign Start --");

		data = "Hello Java DSA Sign.";
		Map<String, Key> keyMap = JavaDSASignExample.initKey();
		publicKey = JavaDSASignExample.getPublicKey(keyMap);
		privateKey = JavaDSASignExample.getPrivateKey(keyMap);

		System.out.println("Data\t：" + data);
		System.out.println("PublicKey\t："
				+ Base64.encodeBase64String(publicKey));
		System.out.println("PrivateKey\t："
				+ Base64.encodeBase64String(privateKey));
	}

	@After
	public void tearDown() {
		data = null;
		System.out.println("-- JAVA DSA Sign End --");
		System.out.println();
	}

	/**
	 * DSA 使用私鑰簽章。DSA 使用公鑰驗章。
	 * 
	 * @param data
	 * @param key
	 * @return
	 */
	@Test
	public void testSign() {
		byte[] sign = null;
		boolean verify = false;

		try {
			sign = JavaDSASignExample.sign(data.getBytes(), privateKey);
			System.out.println("Sign\t：" + Base64.encodeBase64String(sign));

			verify = JavaDSASignExample
					.verify(data.getBytes(), publicKey, sign);
			System.out.println("Verify\t：" + verify);
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.toString());
		}

		// 校驗。
		Assert.assertTrue(verify);
	}
}
