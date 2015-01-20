package com.skye.securityExample.digitalSignature.ecdsaSign;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Java ECDSA Sign 橢圓曲線數位簽章演算法，私鑰簽章公鑰驗章，微軟序號驗證演算法。
 * <p>
 * Bouncy Castle 密鑰長度無限制，演算法包含 NONEwithECDSA
 * 、RIPEMD160withECDSA、SHA1withECDSA、SHA224withECDSA、SHA256withECDSA
 * 、SHA384withECDSA 及 SHA512withECDSA。
 * </p>
 * 
 * @author Skye
 */
public class BouncyCastleECDSASignExample {
	private final static String ALGORITHM = "ECDSA";
	private final static String SIGNATURE_ALGORITHM = "SHA512withECDSA";

	/**
	 * 公鑰。
	 */
	private final static String PUBLIC_KEY = "PublicKey";

	/**
	 * 私鑰。
	 */
	private final static String PRIVATE_KEY = "PrivateKey";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * 初始化密鑰。
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static Map<String, Key> initKey() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		// 初始化 ECDSA 演算法材料
		ECParameterSpec parameterSpec = getECParameterSpec();

		// 實體化密鑰產生器。
		KeyPairGenerator keyPairGenerator = KeyPairGenerator
				.getInstance(ALGORITHM);
		keyPairGenerator.initialize(parameterSpec, new SecureRandom());

		// 初始化密鑰產生器，預設長度為 1024 byte。
		// keyPairGenerator.initialize(1024);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Map<String, Key> result = new HashMap<String, Key>();
		result.put(PUBLIC_KEY, keyPair.getPublic());
		result.put(PRIVATE_KEY, keyPair.getPrivate());
		return result;
	}

	/**
	 * 初始化 ECDSA 演算法材料。
	 * 
	 * @return
	 */
	private static ECParameterSpec getECParameterSpec() {
		// 長度 72。
		BigInteger p = new BigInteger(
				"883423532389192164791648750360308885314476597252960362792450860609699839");
		ECFieldFp field = new ECFieldFp(p);

		// 長度 60。
		BigInteger a = new BigInteger(
				"7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
				16);
		// 長度 60。
		BigInteger b = new BigInteger(
				"6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",
				16);
		EllipticCurve curve = new EllipticCurve(field, a, b);

		// 長度 72。
		BigInteger x = new BigInteger(
				"110282003749548856476348533541186204577905061504881242240149511594420911");
		// 長度 72。
		BigInteger y = new BigInteger(
				"869078407435509378747351873793058868500210384946040694651368759217025454");
		ECPoint g = new ECPoint(x, y);

		// 長度 72。
		BigInteger n = new BigInteger(
				"883423532389192164791648750360308884807550341691627752275345424702807307");
		ECParameterSpec parameterSpec = new ECParameterSpec(curve, g, n, 1);
		return parameterSpec;
	}

	/**
	 * ECDSA 使用私鑰簽章。
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] sign(byte[] data, byte[] key)
			throws SignatureException, InvalidKeySpecException,
			NoSuchAlgorithmException, InvalidKeyException {
		// 取得私鑰。
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

		// 初始化 Signature。
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateKey);

		signature.update(data);
		return signature.sign();
	}

	/**
	 * ECDSA 使用公鑰驗章。
	 * 
	 * @param data
	 * @param key
	 * @param sign
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public static boolean verify(byte[] data, byte[] key, byte[] sign)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			InvalidKeyException, SignatureException {
		// 取得公鑰。
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(keySpec);

		// 初始化 Signature。
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicKey);

		signature.update(data);
		return signature.verify(sign);
	}

	/**
	 * 取得私鑰。
	 * 
	 * @param key
	 * @return
	 */
	public static byte[] getPrivateKey(Map<String, Key> keyMap) {
		Key key = keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}

	/**
	 * 取得公鑰。
	 * 
	 * @param key
	 * @return
	 */
	public static byte[] getPublicKey(Map<String, Key> keyMap) {
		Key key = keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
}
