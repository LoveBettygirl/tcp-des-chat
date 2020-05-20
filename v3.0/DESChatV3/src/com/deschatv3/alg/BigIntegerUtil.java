package com.deschatv3.alg;

import java.io.UnsupportedEncodingException;
import java.math.*;
import java.util.ArrayList;
import java.util.List;

public class BigIntegerUtil {
	
	/**
	 * ��Byte����ת����byte����
	 * @param B Ҫת����Byte����
	 * @return ת���õ���byte����
	 */
	private static byte[] Byte2byte(Byte[] B) {
		byte[] b=new byte[B.length];
		for(int i=0;i<b.length;i++) {
			b[i]=B[i];
		}
		return b;
	}
	
	/**
	 * �������ַ���ת��ͨ�ַ���
	 * @param src Ҫת�����ַ���
	 * @return ת�����
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
			// TODO �Զ����ɵ� catch ��
			e.printStackTrace();
		}
		return s;
	}
	
	/**
     * ��һ��int����ת��Ϊ�����Ƶ��ַ�����ʽ��
    * @param num ��Ҫת����int��������
    * @param digits Ҫת���Ķ�����λ����λ����������ǰ�油0
    * @return �����Ƶ��ַ�����ʽ
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
	 * ��String���ַ���ֵתΪBigIntegerֵ
	 * @param src ������ַ���
	 * @return ��Ӧ��BigIntegerֵ��ʹ��utf-8���룩
	 */
	public static BigInteger string2BigInteger(String src) {
		byte[] b=null;
		try {
			b=src.getBytes("utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO �Զ����ɵ� catch ��
			e.printStackTrace();
		}
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < b.length; i++) {
			s.append(toBinary(b[i], 8));
		}
		return new BigInteger(s.toString(), 2);
	}
	
	/**
	 * ��BigInteger��ֵתΪ��Ӧ���ַ���
	 * @param integer
	 * @param bitLen
	 * @return
	 */
	public static String bigInteger2String(BigInteger integer, int bitLen) {
		bitLen = bitLen % 8 == 0 ? bitLen : (bitLen / 8 + 1) * 8;
		String binary = integer.toString(2);
		String zero = "";
		// ���������λ����С��bitLen����ǰ�油0������ȡ����bitLenλ
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
		// TODO �Զ����ɵķ������
		System.out.println(BigIntegerUtil.string2BigInteger("ABCDEFGH").toString(2));
	}

}
