package com.deschatv3.alg;

import java.io.UnsupportedEncodingException;
import java.util.*;

public class DES {
	
	/** ��ʼ�û�IP */
	private static final byte[] pc_first = { -1,58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
			62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
			57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
			61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7  
	};
	
	/** ���ʼ�û�IP^{-1} */
	private static final byte[] pc_last = { -1,40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
			38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
			36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
			34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25 
	};
	
	/** �û�����P */
	private static final byte[] des_P = { -1,16,7,20,21, 29,12,28,17, 1,15,23,26,
			5,18,31,10, 2,8,24,14, 32,27,3,9,
			9,13,30,6, 22,11,4,25 
	}; 
	
	/** ѡ����չ����E�� */
	private static final byte[] des_E = { -1,32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
			12,13,14,15,16,17,16,17,18,19,20,21,
			20,21,22,23,24,25,24,25,26,27,28,29,
			28,29,30,31,32,1  
	};
	
	/** ѡ��ѹ������S�� */
	private static final byte[][] des_S =  {   
			{ -1,0xe,0x0,0x4,0xf,0xd,0x7,0x1,0x4,0x2,0xe,0xf,0x2,0xb,
				0xd,0x8,0x1,0x3,0xa,0xa,0x6,0x6,0xc,0xc,0xb,0x5,0x9,
				0x9,0x5,0x0,0x3,0x7,0x8,0x4,0xf,0x1,0xc,0xe,0x8,0x8,
				0x2,0xd,0x4,0x6,0x9,0x2,0x1,0xb,0x7,0xf,0x5,0xc,0xb,
				0x9,0x3,0x7,0xe,0x3,0xa,0xa,0x0,0x5,0x6,0x0,0xd },//��һ����û�ã���ռλ
			
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
	
	/** �ȷ���ԿPC-1 */
	private static final byte[] keyleftright =  { 
			-1,57,49,41,33,25,17,9,1,58,50,42,34,26,18,
			10,2,59,51,43,35,27,19,11,3,60,52,44,36,
			63,55,47,39,31,23,15,7,62,54,46,38,30,22,
			14,6,61,53,45,37,29,21,13,5,28,20,12,4 
	};
	
	/** ��Կѭ������ */
	private static final byte[] lefttable = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	
	/** ��ԿѡȡPC-2 */
	private static final byte[] keychoose = {
			-1,14,17,11,24,1,5,3,28,15,6,21,10,
			23,19,12,4,26,8,16,7,27,20,13,2,
			41,52,31,37,47,55,30,40,51,45,33,48,
			44,49,39,56,34,53,46,42,50,36,29,32 
	};
	
	/** Ҫ���ܵ����� */
	private String plaintext;
	
	/** Ҫ���ܵ����� */
	private String ciphertext;
	
	/** ��ʼ��Կ */
	private String srcKey;
	
	/** ��16�ֵ���������Կ */
	private String[] keys=new String[16];
	
	/** ģʽѡ��trueΪ���ܣ�falseΪ���� */
	private boolean mode;
	
	/**
	 * ���췽��
	 * @param k ��ʼ��Կ����8���ַ���
	 * @throws DESException ����Կ���ַ�������Ϊ8ʱ���׳����쳣
	 */
	public DES(String k)  throws DESException {
		try {
			//ͳһʹ��utf-8�������Ϊ�˱�����ܳ��ֵ��������
			if(k.getBytes("utf-8").length!=8) {
				throw new DESException("The length of cipher key is not 8 !");
			}
		} catch (UnsupportedEncodingException e) {
			// TODO �Զ����ɵ� catch ��
			e.printStackTrace();
		}
		srcKey=k;
		genKey();//����������16������Կ
	}
	
	/**
	 * ��ȡ���ܻ���ܵĽ��
	 * @param text Դ�ı������ܵ�Դ�ı�Ϊ�������ַ��������ܵ�Դ�ı�Ϊ�������ɵĶ������ַ���
	 * @param m ģʽѡ��trueΪ���ܣ�falseΪ����
	 * @return ���ܻ���ܵĽ��
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
	 * �������ַ������
	 * @param s1 ������1
	 * @param s2 ������2
	 * @return s1��s2���Ľ��
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
	 * ���ɶ������ı��ַ���
	 * @param src Ҫת�����ַ���
	 * @return ת�����
	 */
	private static String genBinaryMsg(String src) {
		byte[] b=null;
		try {
			b=src.getBytes("utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO �Զ����ɵ� catch ��
			e.printStackTrace();
		}
		StringBuilder s=new StringBuilder();
		for(int i=0;i<b.length;i++) {
			s.append(BigIntegerUtil.toBinary(b[i],8));
		}
		return s.toString();
	}
	
	/**
	 * ���������ַ����ĳ����Ƿ���64λ
	 * @param src Ҫת�����ַ���
	 * @return ���ɵ�64λ�ַ���
	 */
	private static String check64(String src) {
		if(src.length()==64)
			return src;
		if(src.length()>64)//����64λ��ȡǰ64λ
			return src.substring(0,64);
		StringBuilder s=new StringBuilder();
		s.append(src);
		int len=64-src.length();
		for(int i=0;i<len;i++) {
			s.append("0");//С��64λ����ĩβ��0
		}
		return s.toString();
	}
	
	/**
	 * ��һ��int����ת��Ϊ�����Ƶ��ַ�����ʽ�����һλΪ��У����
	 * @param num ��Ҫת����int��������
	 * @return �����Ƶ��ַ�����ʽ
	 * @throws DESException ����Կ���ַ��ɲ�ΪASCII��ʱ���׳����쳣
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
	 * ���ɶ�������Կ�ַ���
	 * @param src Ҫת�����ַ���
	 * @param len ָ��λ��
	 * @return ת�����
	 */
	private static String genBinaryKey(String src, int len) {
		StringBuilder s=new StringBuilder();
		for(int i=0;i<len;i++) {
			s.append(toCheckedBinary(src.charAt(i)));
		}
		return s.toString();
	}
	
	/**
	 * �������ַ���ת��ͨ�ַ���
	 * @param src Ҫת�����ַ���
	 * @return ת�����
	 */
	private String binary2String(String src) {
		String s=BigIntegerUtil.binary2String(src);
		if(mode==true) {
			return s;
		}
		else { //����ǽ��ܣ������ȥ��β�����ڴ���64λ��\0��Java�ǰ�\0�����ַ������ȵ�
			return s.replaceAll("\0+$", "");
		}
	}
	
	/**
	 * ��ʼ�û�IP
	 * @param src ��ת���Ķ�ӦԴ�ı��Ķ������ַ���
	 * @return ת���������Ϊ16�ε����ĳ�ʼֵ
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
	 * ���ʼ�û�IP^{-1}
	 * @param src ��ת���Ķ������ַ���
	 * @return ת�������֮��תΪ��ͨ�ַ�����Ϊ���ܻ���ܵĽ��
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
	 * ѡ����չ����E
	 * @param right �����м������Ұ벿��
	 * @return ת�������֮�������Կ�����������
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
	 * ѡ��ѹ������S����48λ�Ķ������ַ���ѹ����32λ
	 * @param right �����м������Ұ벿�ֺ�����Կ���Ľ��
	 * @return 32λ��ת���������ΪP���������
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
	 * �û�����P
	 * @param right ����S����Ľ��
	 * @return ת���������Ϊ16�ε�������һ�ε����ĳ�ʼֵ
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
	 * 16�ε�����f����������E���㡢������Կ��������㡢S���㡢P����
	 * @param right ���ε������Ұ벿��ԭֵ
	 * @param key ���ε���������Կ
	 * @return ת�������֮��ͱ��ε�������벿�ֽ��������Ϊ��һ�ε������Ұ벿��
	 */
	private String f(String right,String key) {
		String addResult=strxor(ope_E(right),key);
		return ope_P(ope_S(addResult));
	}
	
	/**
	 * 16�ε���
	 * @param left ��ʼ�û�IP��������벿��
	 * @param right ��ʼ�û�IP�������Ұ벿��
	 * @return 16�ε���֮�����Ҳ��ֽ�����ƴ�ӵĽ������Ϊ���ʼ�û�IP^{-1}������
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
		return right+left; //ע��16�ε�������Ҫ����������������ƴ��
	}
	
	/**
	 * ʹ�ó�ʼ64λ��Կ�����û�ѡ��PC-1����
	 * @return 56λ��Чλ�����result[0]����벿�֣�result[1]���Ұ벿�֣�������֮�󽫽���ѭ����������16�ε�������Կ�Ĺ���
	 */
	private String[] ope_pc_1() {
		String[] result=new String[2];
		String src="0"+genBinaryKey(srcKey,8);
		StringBuilder s=new StringBuilder();
		//���ɳ�ʼ��Կ��Ӧ�Ķ������ַ�������ʼ��Կ��ÿ���ַ�8 bit����8��bitΪ��У����
		//��ʹÿ8 bit���ֵ�1�ĸ���Ϊ����
		for(int i=1;i<=56;i++) {
			s.append(src.charAt(keyleftright[i]));
		}
		//��56λ��Կ��ֳ�����������
		result[0]=s.toString().substring(0,28);
		result[1]=s.toString().substring(28);
		return result;
	}
	
	/**
	 * ��Կѭ����������
	 * @param src Ҫѭ�����ƵĶ������ַ���
	 * @param index ѭ�����Ƶ�λ��
	 * @return ѭ�����ƵĽ��
	 */
	private String ope_shift(String src,int index) {
		return src.substring(index)+src.substring(0,index);
	}
	
	/**
	 * ��Կ�û�ѡ��PC-2���㣬����48λ����Կ
	 * @param src ѭ����������֮��������ƴ�ӵĽ��
	 * @return 48λ����Կ
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
	 * ����16�ε�����ʹ�õ�����Կ
	 */
	private void genKey() {
		String[] temp=ope_pc_1();
		for(int i=0;i<16;i++) {
			temp[0]=ope_shift(temp[0],lefttable[i]);
			temp[1]=ope_shift(temp[1],lefttable[i]);
			keys[i]=ope_pc_2(temp[0]+temp[1]);//����������ƴ�ӣ�������Կ�û�ѡ��PC-2����
		}
	}
	
	/**
	 * �������ɶ������ַ�����ÿ8���ֽڽ���һ�μ���
	 */
	private void encry() {
		String temp="";
		String binary=genBinaryMsg(plaintext);//������תΪ�������ַ�����ʹ��utf-8����
		for(int i=0;i<binary.length();i+=64) {
			String s=firstIP(check64(binary.substring(i)));
			temp+=lastIP(itra16(s.substring(0,32),s.substring(32)));//��ʼIP�û���Ľ���������������
		}
		ciphertext=temp;//���ܲ���������Ϊ�������ַ���
	}
	
	/**
	 * ���ܶ������ַ����������ģ�ÿ8���ֽڽ���һ�ν���
	 */
	private void decry() {
		String temp="";
		String binary=ciphertext;
		//�ȼ������������ǲ��Ƕ������ַ���
		for(int i=0;i<binary.length();i++) {
			if(binary.charAt(i)!='0'&&binary.charAt(i)!='1')
				throw new DESException("The ciphertext must be binary string !");
		}
		for(int i=0;i<binary.length();i+=64) {
			String s=firstIP(check64(binary.substring(i)));
			temp+=lastIP(itra16(s.substring(0,32),s.substring(32)));//��ʼIP�û���Ľ���������������
		}
		plaintext=binary2String(temp); //���������ɵĶ������ַ���תΪ��ͨ�ַ���������utf-8����ת��
	}

	public static void main(String[] args) {
		// TODO �Զ����ɵķ������
	}

}
