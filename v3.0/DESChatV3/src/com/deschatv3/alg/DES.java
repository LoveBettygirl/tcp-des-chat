package com.deschatv3.alg;

import java.io.UnsupportedEncodingException;
import java.util.*;

public class DES {
	
	/** 初始置换IP */
	private static final byte[] pc_first = { -1,58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
			62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
			57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
			61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7  
	};
	
	/** 逆初始置换IP^{-1} */
	private static final byte[] pc_last = { -1,40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
			38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
			36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
			34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25 
	};
	
	/** 置换运算P */
	private static final byte[] des_P = { -1,16,7,20,21, 29,12,28,17, 1,15,23,26,
			5,18,31,10, 2,8,24,14, 32,27,3,9,
			9,13,30,6, 22,11,4,25 
	}; 
	
	/** 选择扩展运算E盒 */
	private static final byte[] des_E = { -1,32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
			12,13,14,15,16,17,16,17,18,19,20,21,
			20,21,22,23,24,25,24,25,26,27,28,29,
			28,29,30,31,32,1  
	};
	
	/** 选择压缩运算S盒 */
	private static final byte[][] des_S =  {   
			{ -1,0xe,0x0,0x4,0xf,0xd,0x7,0x1,0x4,0x2,0xe,0xf,0x2,0xb,
				0xd,0x8,0x1,0x3,0xa,0xa,0x6,0x6,0xc,0xc,0xb,0x5,0x9,
				0x9,0x5,0x0,0x3,0x7,0x8,0x4,0xf,0x1,0xc,0xe,0x8,0x8,
				0x2,0xd,0x4,0x6,0x9,0x2,0x1,0xb,0x7,0xf,0x5,0xc,0xb,
				0x9,0x3,0x7,0xe,0x3,0xa,0xa,0x0,0x5,0x6,0x0,0xd },//这一部分没用，仅占位
			
			{ -1,0xe,0x0,0x4,0xf,0xd,0x7,0x1,0x4,0x2,0xe,0xf,0x2,0xb,
			0xd,0x8,0x1,0x3,0xa,0xa,0x6,0x6,0xc,0xc,0xb,0x5,0x9,
			0x9,0x5,0x0,0x3,0x7,0x8,0x4,0xf,0x1,0xc,0xe,0x8,0x8,
			0x2,0xd,0x4,0x6,0x9,0x2,0x1,0xb,0x7,0xf,0x5,0xc,0xb,
			0x9,0x3,0x7,0xe,0x3,0xa,0xa,0x0,0x5,0x6,0x0,0xd },
			
			{ -1,0xf,0x3,0x1,0xd,0x8,0x4,0xe,0x7,0x6,0xf,0xb,0x2,0x3,
				0x8,0x4,0xf,0x9,0xc,0x7,0x0,0x2,0x1,0xd,0xa,0xc,0x6,
				0x0,0x9,0x5,0xb,0xa,0x5,0x0,0xd,0xe,0x8,0x7,0xa,0xb,
				0x1,0xa,0x3,0x4,0xf,0xd,0x4,0x1,0x2,0x5,0xb,0x8,0x6,
				0xc,0x7,0x6,0xc,0x9,0x0,0x3,0x5,0x2,0xe,0xf,0x9 },

			{ -1,0xa,0xd,0x0,0x7,0x9,0x0,0xe,0x9,0x6,0x3,0x3,0x4,0xf, 
			0x6,0x5,0xa,0x1,0x2,0xd,0x8,0xc,0x5,0x7,0xe,0xb,0xc,
			0x4,0xb,0x2,0xf,0x8,0x1,0xd,0x1,0x6,0xa,0x4,0xd,0x9,
			0x0,0x8,0x6,0xf,0x9,0x3,0x8,0x0,0x7,0xb,0x4,0x1,0xf,
			0x2,0xe,0xc,0x3,0x5,0xb,0xa,0x5,0xe,0x2,0x7,0xc },

			{ -1,0x7,0xd,0xd,0x8,0xe,0xb,0x3,0x5,0x0,0x6,0x6,0xf,0x9,
			0x0,0xa,0x3,0x1,0x4,0x2,0x7,0x8,0x2,0x5,0xc,0xb,0x1,
			0xc,0xa,0x4,0xe,0xf,0x9,0xa,0x3,0x6,0xf,0x9,0x0,0x0,
			0x6,0xc,0xa,0xb,0xa,0x7,0xd,0xd,0x8,0xf,0x9,0x1,0x4,
			0x3,0x5,0xe,0xb,0x5,0xc,0x2,0x7,0x8,0x2,0x4,0xe },

			{ -1,0x2,0xe,0xc,0xb,0x4,0x2,0x1,0xc,0x7,0x4,0xa,0x7,0xb,
			0xd,0x6,0x1,0x8,0x5,0x5,0x0,0x3,0xf,0xf,0xa,0xd,0x3,
			0x0,0x9,0xe,0x8,0x9,0x6,0x4,0xb,0x2,0x8,0x1,0xc,0xb,
			0x7,0xa,0x1,0xd,0xe,0x7,0x2,0x8,0xd,0xf,0x6,0x9,0xf,
			0xc,0x0,0x5,0x9,0x6,0xa,0x3,0x4,0x0,0x5,0xe,0x3 },

			{ -1,0xc,0xa,0x1,0xf,0xa,0x4,0xf,0x2,0x9,0x7,0x2,0xc,0x6,
			0x9,0x8,0x5,0x0,0x6,0xd,0x1,0x3,0xd,0x4,0xe,0xe,0x0,
			0x7,0xb,0x5,0x3,0xb,0x8,0x9,0x4,0xe,0x3,0xf,0x2,0x5,
			0xc,0x2,0x9,0x8,0x5,0xc,0xf,0x3,0xa,0x7,0xb,0x0,0xe,
			0x4,0x1,0xa,0x7,0x1,0x6,0xd,0x0,0xb,0x8,0x6,0xd },

			{ -1,0x4,0xd,0xb,0x0,0x2,0xb,0xe,0x7,0xf,0x4,0x0,0x9,0x8,
			0x1,0xd,0xa,0x3,0xe,0xc,0x3,0x9,0x5,0x7,0xc,0x5,0x2,
			0xa,0xf,0x6,0x8,0x1,0x6,0x1,0x6,0x4,0xb,0xb,0xd,0xd,
			0x8,0xc,0x1,0x3,0x4,0x7,0xa,0xe,0x7,0xa,0x9,0xf,0x5,
			0x6,0x0,0x8,0xf,0x0,0xe,0x5,0x2,0x9,0x3,0x2,0xc },

			{ -1,0xd,0x1,0x2,0xf,0x8,0xd,0x4,0x8,0x6,0xa,0xf,0x3,0xb,
			0x7,0x1,0x4,0xa,0xc,0x9,0x5,0x3,0x6,0xe,0xb,0x5,0x0,
			0x0,0xe,0xc,0x9,0x7,0x2,0x7,0x2,0xb,0x1,0x4,0xe,0x1,
			0x7,0x9,0x4,0xc,0xa,0xe,0x8,0x2,0xd,0x0,0xf,0x6,0xc,
			0xa,0x9,0xd,0x0,0xf,0x3,0x3,0x5,0x5,0x6,0x8,0xb }  
			
	};
	
	/** 等分密钥PC-1 */
	private static final byte[] keyleftright =  { 
			-1,57,49,41,33,25,17,9,1,58,50,42,34,26,18,
			10,2,59,51,43,35,27,19,11,3,60,52,44,36,
			63,55,47,39,31,23,15,7,62,54,46,38,30,22,
			14,6,61,53,45,37,29,21,13,5,28,20,12,4 
	};
	
	/** 密钥循环左移 */
	private static final byte[] lefttable = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	
	/** 密钥选取PC-2 */
	private static final byte[] keychoose = {
			-1,14,17,11,24,1,5,3,28,15,6,21,10,
			23,19,12,4,26,8,16,7,27,20,13,2,
			41,52,31,37,47,55,30,40,51,45,33,48,
			44,49,39,56,34,53,46,42,50,36,29,32 
	};
	
	/** 要加密的明文 */
	private String plaintext;
	
	/** 要解密的密文 */
	private String ciphertext;
	
	/** 初始密钥 */
	private String srcKey;
	
	/** 供16轮迭代的子密钥 */
	private String[] keys=new String[16];
	
	/** 模式选择，true为加密，false为解密 */
	private boolean mode;
	
	/**
	 * 构造方法
	 * @param k 初始密钥（限8个字符）
	 * @throws DESException 当密钥的字符个数不为8时，抛出此异常
	 */
	public DES(String k)  throws DESException {
		try {
			//统一使用utf-8编解码是为了避免可能出现的乱码情况
			if(k.getBytes("utf-8").length!=8) {
				throw new DESException("The length of cipher key is not 8 !");
			}
		} catch (UnsupportedEncodingException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
		srcKey=k;
		genKey();//在这里生成16个子密钥
	}
	
	/**
	 * 获取加密或解密的结果
	 * @param text 源文本，加密的源文本为本来的字符串，解密的源文本为加密生成的二进制字符串
	 * @param m 模式选择，true为加密，false为解密
	 * @return 加密或解密的结果
	 */
	public String getResult(String text,boolean m) {
		mode=m;
		if(mode==true) {
			plaintext=text;
			encry();
			return ciphertext;
		}
		else {
			ciphertext=text;
			decry();
			return plaintext;
		}
	}
	
	
	/**
	 * 二进制字符串异或
	 * @param s1 操作数1
	 * @param s2 操作数2
	 * @return s1和s2异或的结果
	 */
	private static String strxor(String s1,String s2) {
		int len= s1.length()>s2.length()?s1.length():s2.length();
		StringBuilder s=new StringBuilder();
		for(int i=0;i<len;i++) {
			if(i>=s1.length()||i>=s2.length()) {
				s.append("0");
			}
			else {
				if(s1.charAt(i)==s2.charAt(i)) {
					s.append("0");
				}
				else {
					s.append("1");
				}
			}
		}
		return s.toString();
	}
	
	/**
	 * 生成二进制文本字符串
	 * @param src 要转换的字符串
	 * @return 转换结果
	 */
	private static String genBinaryMsg(String src) {
		byte[] b=null;
		try {
			b=src.getBytes("utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
		StringBuilder s=new StringBuilder();
		for(int i=0;i<b.length;i++) {
			s.append(BigIntegerUtil.toBinary(b[i],8));
		}
		return s.toString();
	}
	
	/**
	 * 检查二进制字符串的长度是否是64位
	 * @param src 要转换的字符串
	 * @return 生成的64位字符串
	 */
	private static String check64(String src) {
		if(src.length()==64)
			return src;
		if(src.length()>64)//大于64位则取前64位
			return src.substring(0,64);
		StringBuilder s=new StringBuilder();
		s.append(src);
		int len=64-src.length();
		for(int i=0;i<len;i++) {
			s.append("0");//小于64位则在末尾补0
		}
		return s.toString();
	}
	
	/**
	 * 将一个int数字转换为二进制的字符串形式，最后一位为奇校验码
	 * @param num 需要转换的int类型数据
	 * @return 二进制的字符串形式
	 * @throws DESException 当密钥的字符吧不为ASCII码时，抛出此异常
	 */
	public static String toCheckedBinary(int num) throws DESException {
		String s=Integer.toBinaryString(num);
		if(s.length()>7) {
			throw new DESException("The cipher key must be ASCII !");
		}
		int count1=0;
		for(int i=0;i<s.length();i++) {
			if(s.charAt(i)=='1') {
				count1++;
			}
		}
		if(count1%2==0) {
			return s+"1";
		}
		else {
			return s+"0";
		}
	}

	/**
	 * 生成二进制密钥字符串
	 * @param src 要转换的字符串
	 * @param len 指定位数
	 * @return 转换结果
	 */
	private static String genBinaryKey(String src, int len) {
		StringBuilder s=new StringBuilder();
		for(int i=0;i<len;i++) {
			s.append(toCheckedBinary(src.charAt(i)));
		}
		return s.toString();
	}
	
	/**
	 * 二进制字符串转普通字符串
	 * @param src 要转换的字符串
	 * @return 转换结果
	 */
	private String binary2String(String src) {
		String s=BigIntegerUtil.binary2String(src);
		if(mode==true) {
			return s;
		}
		else { //如果是解密，则必须去掉尾部用于凑整64位的\0，Java是把\0算作字符串长度的
			return s.replaceAll("\0+$", "");
		}
	}
	
	/**
	 * 初始置换IP
	 * @param src 待转换的对应源文本的二进制字符串
	 * @return 转换结果，作为16次迭代的初始值
	 */
	private String firstIP(String src) {
		src="0"+src;
		StringBuilder s=new StringBuilder();
		for(int i=1;i<=64;i++) {
			s.append(src.charAt(pc_first[i]));
		}
		return s.toString();
	}
	
	/**
	 * 逆初始置换IP^{-1}
	 * @param src 待转换的二进制字符串
	 * @return 转换结果，之后转为普通字符串作为加密或解密的结果
	 */
	private String lastIP(String src) {
		src="0"+src;
		StringBuilder s=new StringBuilder();
		for(int i=1;i<=64;i++) {
			s.append(src.charAt(pc_last[i]));
		}
		return s.toString();
	}
	
	/**
	 * 选择扩展运算E
	 * @param right 迭代中间结果的右半部分
	 * @return 转换结果，之后和子密钥进行异或运算
	 */
	private String ope_E(String right) {
		String r="0"+right;
		StringBuilder s=new StringBuilder();
		for(int i=1;i<=48;i++) {
			s.append(r.charAt(des_E[i]));
		}
		return s.toString();
	}
	
	/**
	 * 选择压缩运算S，将48位的二进制字符串压缩成32位
	 * @param right 迭代中间结果的右半部分和子密钥异或的结果
	 * @return 32位的转换结果，作为P运算的输入
	 */
	private String ope_S(String right) {
		String r="0"+right;
		StringBuilder s=new StringBuilder();
		int j=1;
		for(int i=1;i<=48;i+=6) {
			String temp=r.substring(i,i+6);
			s.append(BigIntegerUtil.toBinary(des_S[j][Integer.parseInt(temp,2)],4));
			j++;
		}
		return s.toString();
	}
	
	/**
	 * 置换运算P
	 * @param right 进行S运算的结果
	 * @return 转换结果，作为16次迭代中下一次迭代的初始值
	 */
	private String ope_P(String right) {
		String r="0"+right;
		StringBuilder s=new StringBuilder();
		for(int i=1;i<=32;i++) {
			s.append(r.charAt(des_P[i]));
		}
		return s.toString();
	}
	
	/**
	 * 16次迭代的f函数，包括E运算、和子密钥的异或运算、S运算、P运算
	 * @param right 本次迭代的右半部分原值
	 * @param key 本次迭代的子密钥
	 * @return 转换结果，之后和本次迭代的左半部分进行异或作为下一次迭代的右半部分
	 */
	private String f(String right,String key) {
		String addResult=strxor(ope_E(right),key);
		return ope_P(ope_S(addResult));
	}
	
	/**
	 * 16次迭代
	 * @param left 初始置换IP产生的左半部分
	 * @param right 初始置换IP产生的右半部分
	 * @return 16次迭代之后左右部分交换再拼接的结果，作为逆初始置换IP^{-1}的输入
	 */
	private String itra16(String left,String right) {
		if(mode==true) {
			for(int i=0;i<16;i++) {
				String copyLeft=left;
				left=right;
				right=strxor(copyLeft,f(right,keys[i]));
			}
		}
		else {
			for(int i=15;i>=0;i--) {
				String copyLeft=left;
				left=right;
				right=strxor(copyLeft,f(right,keys[i]));
			}
		}
		return right+left; //注意16次迭代完了要交换左右两部分再拼接
	}
	
	/**
	 * 使用初始64位密钥进行置换选择PC-1运算
	 * @return 56位有效位输出，result[0]是左半部分，result[1]是右半部分，输出结果之后将进行循环左移生成16次迭代左密钥的过程
	 */
	private String[] ope_pc_1() {
		String[] result=new String[2];
		String src="0"+genBinaryKey(srcKey,8);
		StringBuilder s=new StringBuilder();
		//生成初始密钥对应的二进制字符串：初始密钥的每个字符8 bit，第8个bit为奇校验码
		//即使每8 bit出现的1的个数为奇数
		for(int i=1;i<=56;i++) {
			s.append(src.charAt(keyleftright[i]));
		}
		//将56位密钥拆分成左右两部分
		result[0]=s.toString().substring(0,28);
		result[1]=s.toString().substring(28);
		return result;
	}
	
	/**
	 * 密钥循环左移运算
	 * @param src 要循环左移的二进制字符串
	 * @param index 循环左移的位数
	 * @return 循环左移的结果
	 */
	private String ope_shift(String src,int index) {
		return src.substring(index)+src.substring(0,index);
	}
	
	/**
	 * 密钥置换选择PC-2运算，生成48位子密钥
	 * @param src 循环左移运算之后两部分拼接的结果
	 * @return 48位子密钥
	 */
	private String ope_pc_2(String src) {
		src="0"+src;
		StringBuilder s=new StringBuilder();
		for(int i=1;i<=48;i++) {
			s.append(src.charAt(keychoose[i]));
		}
		return s.toString();
	}
	
	/**
	 * 生成16次迭代所使用的子密钥
	 */
	private void genKey() {
		String[] temp=ope_pc_1();
		for(int i=0;i<16;i++) {
			temp[0]=ope_shift(temp[0],lefttable[i]);
			temp[1]=ope_shift(temp[1],lefttable[i]);
			keys[i]=ope_pc_2(temp[0]+temp[1]);//左右两部分拼接，进行密钥置换选择PC-2运算
		}
	}
	
	/**
	 * 加密生成二进制字符串，每8个字节进行一次加密
	 */
	private void encry() {
		String temp="";
		String binary=genBinaryMsg(plaintext);//将明文转为二进制字符串，使用utf-8编码
		for(int i=0;i<binary.length();i+=64) {
			String s=firstIP(check64(binary.substring(i)));
			temp+=lastIP(itra16(s.substring(0,32),s.substring(32)));//初始IP置换后的结果拆成左右两部分
		}
		ciphertext=temp;//加密产生结果输出为二进制字符串
	}
	
	/**
	 * 解密二进制字符串生成明文，每8个字节进行一次解密
	 */
	private void decry() {
		String temp="";
		String binary=ciphertext;
		//先检查输入的密文是不是二进制字符串
		for(int i=0;i<binary.length();i++) {
			if(binary.charAt(i)!='0'&&binary.charAt(i)!='1')
				throw new DESException("The ciphertext must be binary string !");
		}
		for(int i=0;i<binary.length();i+=64) {
			String s=firstIP(check64(binary.substring(i)));
			temp+=lastIP(itra16(s.substring(0,32),s.substring(32)));//初始IP置换后的结果拆成左右两部分
		}
		plaintext=binary2String(temp); //将解密生成的二进制字符串转为普通字符串，按照utf-8编码转换
	}

	public static void main(String[] args) {
		// TODO 自动生成的方法存根
	}

}
