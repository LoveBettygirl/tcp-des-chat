package com.deschatv3.alg;

import java.util.*;
import java.math.*;
import java.security.SecureRandom;

public class RSA {
	
	private BigInteger p;
	private BigInteger q;
	private BigInteger n;
	private BigInteger euler; // ŷ��������(n)
	private BigInteger e;
	private BigInteger d;
	private int bitLen; // p��q�ĳ���
	private BigInteger x, y; // ����exgcd����ʱ����
	private RSAPublicKey publicKey;
	private RSAPrivateKey privateKey;
	private static Random r = new SecureRandom();
	
	/**
	 * ���췽��
	 * @param bitLen p��q�ĳ���
	 */
	public RSA(int bitLen) {
		this.bitLen = bitLen;
		p = randomPrime();
		q = randomPrime();
		n = p.multiply(q);
		euler = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		do {
			e = genRandom(BigInteger.ONE, euler);
		} while(gcd(e, euler).compareTo(BigInteger.ONE) != 0);
		// ��e��euler����Ԫd
		d = calculateD(e, euler);
		publicKey = new RSAPublicKey(e, n);
		privateKey = new RSAPrivateKey(d, n);
	}
	
	/**
	 * ��ȡ������RSA��Կ
	 * @return RSA��Կ
	 */
	public RSAPublicKey getRSAPublicKey() {
		return publicKey;
	}
	
	/**
	 * ��ȡ������RSA˽Կ
	 * @return RSA˽Կ
	 */
	public RSAPrivateKey getRSAPrivateKey() {
		return privateKey;
	}
	
	/**
	 * �����Ľ���һ�μ���
	 * @param src Ҫ���ܵ�����
	 * @param k ����ʹ�õĹ�Կ
	 * @return ���ܵõ������ĵ�ʮ�����Ʊ�ʾ
	 */
	public static String encry(String src, RSAPublicKey k) {
		BigInteger integer = BigIntegerUtil.string2BigInteger(src);
		if (integer.compareTo(k.getN()) >= 0)
			throw new RSAException("Data must not be larger than n");
		integer = modPow(integer, k.getE(), k.getN());
		return integer.toString(16);
	}
	
	/**
	 * �����Ľ���һ�ν���
	 * @param src Ҫ���ܵ����ĵ�ʮ�����Ʊ�ʾ
	 * @param k ����ʹ�õ�˽Կ
	 * @return ���ܵõ�������
	 */
	public static String decry(String src, RSAPrivateKey k) {
		BigInteger integer = new BigInteger(src, 16);
		integer = modPow(integer, k.getD(), k.getN());
		return BigIntegerUtil.bigInteger2String(integer, integer.bitLength());
	} 
	
	/**
	 * ����BigInteger���͵������������Χ��(min, max)
	 * @param min ��������½�
	 * @param max ��������Ͻ�
	 * @return ���ɵ��������
	 */
	private BigInteger genRandom(BigInteger min, BigInteger max) {
		BigInteger b;
        do {
            b = new BigInteger(max.bitLength(), r);
        } while (b.compareTo(min) <= 0 || b.compareTo(max) >= 0);
        return b;
	}
	
	/**
	 * ŷ�������չ�㷨
	 * @param a ������
	 * @param b ����
	 * @return ���Լ��
	 */
	private BigInteger exgcd(BigInteger a, BigInteger b){
		if(b.compareTo(BigInteger.ZERO) == 0) {
			x = new BigInteger("1");
			y = new BigInteger("0");
			return a;
		}
		BigInteger result = exgcd(b,a.mod(b));
		BigInteger temp = x;
		x = y;
		y = temp.subtract(a.divide(b).multiply(y));
		return result;
	}
	
	/**
	 * ��e�ķ�ģd���ҵ���չŷ������㷨�������С��������x��
	 * @param a ��Ӧe
	 * @param k ��Ӧŷ������euler
	 * @return e�ķ�ģd
	 */
	private BigInteger calculateD(BigInteger a, BigInteger k){
		BigInteger d = exgcd(a, k);
		// �ж����Լ���Ƿ�Ϊ1�������޽�
	    if(d.compareTo(BigInteger.ONE) == 0) {
	    	return x.mod(k.abs()); // �����x����Ϊ������ҪתΪ��С��������
	    }
	    else
	        return new BigInteger("-1");
	}
	
	/**
	 * ͨ��Miller-Rabin�㷨����һ���������ǲ������������и���Ϊ1/4��
	 * @param n Ҫ���Ե�������
	 * @return true��n����Ϊ������������Ϊ����
	 */
	private boolean millerRabin(BigInteger n) {
		if (!n.testBit(0))
			throw new RSAException("n must > 0 and must be an odd number");
		// ����Ҫ�ҳ�q��kʹ��n-1=2^k*q
		BigInteger q = n.subtract(BigInteger.ONE), k = new BigInteger("0");
		// q���ϳ���2������1�Σ�ֱ�����Ϊ������
		// ���ƵĴ�������k
		while (!q.testBit(0)) {
			k = k.add(BigInteger.ONE);
			q = q.shiftRight(BigInteger.ONE.intValue());
		}
		// ���ѡȡ��a > 1 �� a < n - 1
		/*BigInteger a = new BigDecimal(Math.random()).multiply(new BigDecimal(n.subtract(new BigInteger("3"))))
				.toBigInteger().add(BigInteger.TWO);*/
		BigInteger a = genRandom(BigInteger.ONE, n.subtract(BigInteger.ONE));
		// ����a^q%n��ֵ�Ƿ�Ϊ1��Ϊ1��������
		if (modPow(a, q, n).compareTo(BigInteger.ONE) == 0)
			return true;
		// ���� a^(2^j*q)%n��ֵ�Ƿ�Ϊn-1��j>=1&&j<=k-1������һ��������Ϊ������
		for (BigInteger j = new BigInteger("1"); j.compareTo(k) < 0; j = j.add(BigInteger.ONE)) {
			q = q.shiftLeft(BigInteger.ONE.intValue());
			if (modPow(a, q, n).compareTo(n.subtract(BigInteger.ONE)) == 0)
				return true;
		}
		return false;
	}
	
	/**
	 * ��ȡ��ͬbitLen��Ӧ��Ӧִ��Miller-Rabin�㷨�Ĵ���
	 * @return Ӧִ��Miller-Rabin�㷨�Ĵ���
	 */
	private int getLoop() {
		int rounds;
        if (bitLen < 100) {
            rounds = 50;
        } else if (bitLen < 256) {
            rounds = 27;
        } else if (bitLen < 512) {
            rounds = 15;
        } else if (bitLen < 768) {
            rounds = 8;
        } else if (bitLen < 1024) {
            rounds = 4;
        } else {
            rounds = 2;
        }
        return rounds;
	}
	
	/**
	 * ���ִ��Miller-Rabin�㷨����һ���������ǲ�������
	 * @param n Ҫ���Ե�������
	 * @return true��n����Ϊ������������Ϊ����
	 */
	private boolean testPrime(BigInteger n) {
		int loop = getLoop();
		for (int i = 0; i < loop; i++) {
			if (!millerRabin(n))
				return false;
		}
		return true;
	}
	
	/**
	 * ������ɴ�����
	 * @return ������ɵĴ�����
	 */
	private BigInteger randomPrime() {
		BigInteger random;
		do {
			random = new BigInteger(bitLen, r);
			random.setBit(bitLen - 1); // �������ɵ���������λΪ1����֤�㹻��
			if (!random.testBit(0)) { // ��֤�����Ϊ����
	            random = random.setBit(0);
	        }
		} while(!testPrime(random));
		return random;
	}
	
	/**
	 * շת����������Լ��
	 * @param a ������
	 * @param b ����
	 * @return ���Լ��
	 */
	private BigInteger gcd(BigInteger a, BigInteger b) {
		if (b.compareTo(BigInteger.ZERO) == 0)
			return a;
		BigInteger mod = a.mod(b);
		while (mod.compareTo(BigInteger.ZERO) != 0) {
			a = b;
			b = mod;
			mod = a.mod(b);
		}
		return b;
	}
	
	/**
	 * ����ģ������
	 * @param base ����������
	 * @param index ������ָ��
	 * @param mod ����
	 * @return ģ��������
	 */
	private static BigInteger modPow(BigInteger base, BigInteger index, BigInteger mod) {
		String indexBinary = index.toString(2);
		BigInteger result = new BigInteger(base.toString(10), 10);
		for (int i = 1 ; i < indexBinary.length(); i++) {
			result = result.multiply(result).mod(mod);
			if (indexBinary.charAt(i) == '1')
				result = result.multiply(base).mod(mod);
		}
		return result;
	}
	
	public static void main(String[] args) {
		// TODO �Զ����ɵķ������
		/*RSA rsa = new RSA();
		System.out.println(rsa.genRandom(BigInteger.TWO, new BigInteger("4")));
		for (int i = 1; i < 13; i++) {
			System.out.println(i + " " + rsa.powMod(BigInteger.valueOf(2), BigInteger.valueOf(i), BigInteger.valueOf(13)));
		}*/
		RSA rsa = new RSA(512);
		String a = "AAAAAAAA";
		System.out.println(rsa.getRSAPublicKey());
		System.out.println(rsa.getRSAPrivateKey());
		/*BigInteger temp = RSA.encry(BigIntegerUtil.string2BigInteger(a), rsa.getRSAPublicKey());
		temp = RSA.decry(temp, rsa.getRSAPrivateKey());
		System.out.println(temp.toString(2));
		System.out.println(BigIntegerUtil.bigInteger2String(temp, 64));*/
		String temp = RSA.encry(a, rsa.getRSAPublicKey());
		System.out.println(temp);
		temp = RSA.decry(temp, rsa.getRSAPrivateKey());
		System.out.println(temp);
		System.out.println(temp.length());
	}

}
