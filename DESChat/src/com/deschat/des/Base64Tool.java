package com.deschat.des;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class Base64Tool {
	public static String base64Encode(String src) {
		try {
			return Base64.getEncoder().encodeToString(src.getBytes("utf-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
			return null;
		}
	}
	public static String base64Decode(String src) {
        byte[] base64decodedBytes = Base64.getDecoder().decode(src);
        try {
			return new String(base64decodedBytes, "utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
			return null;
		}
	}
}
