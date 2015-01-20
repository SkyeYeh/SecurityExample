package com.skye.securityExample.web;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import com.skye.securityExample.digitalSignature.rsaSign.JavaRSASignExample;
import com.skye.securityExample.publicKey.rsa.JavaRSAExample;
import com.skye.securityExample.symmetricKey.aes.JavaAESExample;

/**
 * 接收 Client 端訊息，使用 RSA 私鑰解密得到 AES 金鑰， 使用 AES 加密資料，並使用 RSA 私鑰簽章，傳送給 Client。
 * 
 * @author Skye
 */
public class DataServlet extends HttpServlet {
	private static final long serialVersionUID = 3806088106953701173L;
	private static final String KEY_PARAM = "base64RsaPrivateKey";

	private byte[] rsaPrivateKey;
	private byte[] aesKey;

	@Override
	public void init() {
		try {
			super.init();
		} catch (ServletException e) {
			e.printStackTrace();
		}
		String base64RsaPrivateKey = getInitParameter(KEY_PARAM);
		rsaPrivateKey = Base64.decodeBase64(base64RsaPrivateKey);
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
		doPost(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
		// 取得 AES 金鑰。
		try {
			aesKey = getInputData(req);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 創建輸出。
		byte[] outputData = getOutputData();

		// RSA 使用私鑰簽章。
		byte[] sign = null;
		try {
			sign = JavaRSASignExample.sign(outputData, rsaPrivateKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
		String hexSign = null;
		hexSign = Hex.encodeHexString(sign);

		// 輸出加入簽章值。
		try {
			outputData = outputAddSign(outputData, hexSign.getBytes());
		} catch (IOException e) {
			e.printStackTrace();
		}

		// 使用 AES 加密，並寫入 resp。
		try {
			respWrite(resp, JavaAESExample.encrypt(outputData, aesKey));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 輸出加入簽章值。
	 * 
	 * @param output
	 * @param sign
	 * @return
	 * @throws IOException
	 */
	private byte[] outputAddSign(byte[] output, byte[] sign) throws IOException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		byteArrayOutputStream.write(sign);
		byteArrayOutputStream.write(output);
		output = byteArrayOutputStream.toByteArray();
		byteArrayOutputStream.flush();
		byteArrayOutputStream.close();
		return output;
	}

	/**
	 * 取得 AES 金鑰。
	 * 
	 * @param req
	 * @return
	 * @throws Exception
	 */
	private byte[] getInputData(HttpServletRequest req) throws Exception {
		// 讀取輸入。
		byte[] encryptAesKey = getInput(req);

		byte[] aesKey = null;
		// RSA 使用私鑰解密。
		aesKey = JavaRSAExample.decryptByPrivateKey(encryptAesKey,
				rsaPrivateKey);
		return aesKey;
	}

	/**
	 * 創建輸出。
	 * 
	 * @return
	 */
	private byte[] getOutputData() {
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("RSA");
		return stringBuilder.toString().getBytes();
	}

	/**
	 * 使用 AES 加密，並寫入 resp。
	 * 
	 * @param resp
	 * @param encrypt
	 * @throws IOException
	 */
	private void respWrite(HttpServletResponse resp, byte[] data)
			throws IOException {
		if (data != null) {
			resp.setContentLength(data.length);
			OutputStream out = resp.getOutputStream();
			DataOutputStream dataOutputStream = new DataOutputStream(out);
			dataOutputStream.write(data);
			dataOutputStream.flush();

			out.close();
			dataOutputStream.close();
		}
	}

	/**
	 * 讀取輸入。
	 * 
	 * @param req
	 * @return
	 * @throws IOException
	 */
	private static byte[] getInput(HttpServletRequest req) throws IOException {
		int contentLength = req.getContentLength();
		byte[] result = null;
		if (contentLength > 0) {
			result = new byte[contentLength];
			InputStream in = req.getInputStream();
			DataInputStream dataInputStream = new DataInputStream(in);
			dataInputStream.readFully(result);
			in.close();
			dataInputStream.close();
		}
		return result;
	}
}
