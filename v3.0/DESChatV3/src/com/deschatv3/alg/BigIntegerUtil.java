package com.deschatv3.alg;

import java.io.UnsupportedEncodingException;
import java.math.*;
import java.util.ArrayList;
import java.util.List;

public class BigIntegerUtil {
	
	/**
	 * 将Byte数组转换成byte数组
	 * @param B 要转换的Byte数组
	 * @return 转换得到的byte数组
	 */
	private static byte[] Byte2byte(Byte[] B) {
		byte[] b=new byte[B.length];
		for(int i=0;i<b.length;i++) {
			b[i]=B[i];
		}
		return b;
	}
	
	/**
	 * 二进制字符串转普通字符串
	 * @param src 要转换的字符串
	 * @return 转换结果
	 */
	public static String binary2String(String src) {
		List<Byte> list=new ArrayList<Byte>();
		for(int i=0;i<src.length();i+=8) {
			list.add((byte)(Integer.parseInt(src.substring(i,i+8),2)));
		}
		byte[] b=Byte2byte(list.toArray(new Byte[list.size()]));
		String s=null;
		try {
			s = new String(b,"utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
		return s;
	}
	
	/**
     * 将一个int数字转换为二进制的字符串形式。
    * @param num 需要转换的int类型数据
    * @param digits 要转换的二进制位数，位数不足则在前面补0
    * @return 二进制的字符串形式
    */
	public static String toBinary(int num, int digits) {
		String s=Integer.toBinaryString(num);
		if(s.length()<digits) {
			String cover = Integer.toBinaryString(1 << digits).substring(1);
		    return cover.substring(s.length()) + s;
		}
		else if(s.length()>digits) {
			return s.substring(s.length() - digits);
		}
		else {
			return s;
		}
	}
	
	/**
	 * 将String的字符串值转为BigInteger值
	 * @param src 输入的字符串
	 * @return 对应的BigInteger值（使用utf-8编码）
	 */
	public static BigInteger string2BigInteger(String src) {
		byte[] b=null;
		try {
			b=src.getBytes("utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < b.length; i++) {
			s.append(toBinary(b[i], 8));
		}
		return new BigInteger(s.toString(), 2);
	}
	
	/**
	 * 将BigInteger的值转为对应的字符串
	 * @param integer
	 * @param bitLen
	 * @return
	 */
	public static String bigInteger2String(BigInteger integer, int bitLen) {
		bitLen = bitLen % 8 == 0 ? bitLen : (bitLen / 8 + 1) * 8;
		String binary = integer.toString(2);
		String zero = "";
		// 如果二进制位长度小于bitLen则在前面补0，否则取最后的bitLen位
		if (binary.length() < bitLen) {
			for (int i = binary.length(); i < bitLen; i++) {
				zero += "0";
			}
			binary = zero + binary;
		}
		else if (binary.length() > bitLen) {
			binary = binary.substring(binary.length() - bitLen);
		}
		return binary2String(binary);
	}

	public static void main(String[] args) {
		// TODO 自动生成的方法存根
		System.out.println(BigIntegerUtil.string2BigInteger("ABCDEFGH").toString(2));
	}

}
