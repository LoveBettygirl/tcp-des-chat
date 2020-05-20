package com.deschatv3.alg;

import java.util.*;
import java.math.*;
import java.security.SecureRandom;

public class RSA {
	
	private BigInteger p;
	private BigInteger q;
	private BigInteger n;
	private BigInteger euler; // 欧拉函数φ(n)
	private BigInteger e;
	private BigInteger d;
	private int bitLen; // p和q的长度
	private BigInteger x, y; // 计算exgcd的临时变量
	private RSAPublicKey publicKey;
	private RSAPrivateKey privateKey;
	private static Random r = new SecureRandom();
	
	/**
	 * 构造方法
	 * @param bitLen p和q的长度
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
		// 求e对euler的逆元d
		d = calculateD(e, euler);
		publicKey = new RSAPublicKey(e, n);
		privateKey = new RSAPrivateKey(d, n);
	}
	
	/**
	 * 获取产生的RSA公钥
	 * @return RSA公钥
	 */
	public RSAPublicKey getRSAPublicKey() {
		return publicKey;
	}
	
	/**
	 * 获取产生的RSA私钥
	 * @return RSA私钥
	 */
	public RSAPrivateKey getRSAPrivateKey() {
		return privateKey;
	}
	
	/**
	 * 对明文进行一次加密
	 * @param src 要加密的明文
	 * @param k 加密使用的公钥
	 * @return 加密得到的密文的十六进制表示
	 */
	public static String encry(String src, RSAPublicKey k) {
		BigInteger integer = BigIntegerUtil.string2BigInteger(src);
		if (integer.compareTo(k.getN()) >= 0)
			throw new RSAException("Data must not be larger than n");
		integer = modPow(integer, k.getE(), k.getN());
		return integer.toString(16);
	}
	
	/**
	 * 对密文进行一次解密
	 * @param src 要解密的密文的十六进制表示
	 * @param k 解密使用的私钥
	 * @return 解密得到的明文
	 */
	public static String decry(String src, RSAPrivateKey k) {
		BigInteger integer = new BigInteger(src, 16);
		integer = modPow(integer, k.getD(), k.getN());
		return BigIntegerUtil.bigInteger2String(integer, integer.bitLength());
	} 
	
	/**
	 * 生成BigInteger类型的随机整数，范围：(min, max)
	 * @param min 随机整数下界
	 * @param max 随机整数上界
	 * @return 生成的随机整数
	 */
	private BigInteger genRandom(BigInteger min, BigInteger max) {
		BigInteger b;
        do {
            b = new BigInteger(max.bitLength(), r);
        } while (b.compareTo(min) <= 0 || b.compareTo(max) >= 0);
        return b;
	}
	
	/**
	 * 欧几里得扩展算法
	 * @param a 被除数
	 * @param b 除数
	 * @return 最大公约数
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
	 * 求e的反模d（找到扩展欧几里得算法求出的最小正整数解x）
	 * @param a 对应e
	 * @param k 对应欧拉函数euler
	 * @return e的反模d
	 */
	private BigInteger calculateD(BigInteger a, BigInteger k){
		BigInteger d = exgcd(a, k);
		// 判断最大公约数是否为1，否则无解
	    if(d.compareTo(BigInteger.ONE) == 0) {
	    	return x.mod(k.abs()); // 求出的x可能为负，需要转为最小正整数解
	    }
	    else
	        return new BigInteger("-1");
	}
	
	/**
	 * 通过Miller-Rabin算法测试一个正奇数是不是素数（误判概率为1/4）
	 * @param n 要测试的正奇数
	 * @return true则n被认为是素数，否则为合数
	 */
	private boolean millerRabin(BigInteger n) {
		if (!n.testBit(0))
			throw new RSAException("n must > 0 and must be an odd number");
		// 首先要找出q和k使得n-1=2^k*q
		BigInteger q = n.subtract(BigInteger.ONE), k = new BigInteger("0");
		// q不断除以2（右移1次）直到结果为奇数，
		// 右移的次数就是k
		while (!q.testBit(0)) {
			k = k.add(BigInteger.ONE);
			q = q.shiftRight(BigInteger.ONE.intValue());
		}
		// 随机选取的a > 1 且 a < n - 1
		/*BigInteger a = new BigDecimal(Math.random()).multiply(new BigDecimal(n.subtract(new BigInteger("3"))))
				.toBigInteger().add(BigInteger.TWO);*/
		BigInteger a = genRandom(BigInteger.ONE, n.subtract(BigInteger.ONE));
		// 测试a^q%n的值是否为1，为1则是素数
		if (modPow(a, q, n).compareTo(BigInteger.ONE) == 0)
			return true;
		// 测试 a^(2^j*q)%n的值是否为n-1（j>=1&&j<=k-1），有一个是则认为是素数
		for (BigInteger j = new BigInteger("1"); j.compareTo(k) < 0; j = j.add(BigInteger.ONE)) {
			q = q.shiftLeft(BigInteger.ONE.intValue());
			if (modPow(a, q, n).compareTo(n.subtract(BigInteger.ONE)) == 0)
				return true;
		}
		return false;
	}
	
	/**
	 * 获取不同bitLen对应的应执行Miller-Rabin算法的次数
	 * @return 应执行Miller-Rabin算法的次数
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
	 * 多次执行Miller-Rabin算法测试一个正奇数是不是素数
	 * @param n 要测试的正奇数
	 * @return true则n被认为是素数，否则为合数
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
	 * 随机生成大素数
	 * @return 随机生成的大素数
	 */
	private BigInteger randomPrime() {
		BigInteger random;
		do {
			random = new BigInteger(bitLen, r);
			random.setBit(bitLen - 1); // 设置生成的随机数最高位为1，保证足够大
			if (!random.testBit(0)) { // 保证这个数为奇数
	            random = random.setBit(0);
	        }
		} while(!testPrime(random));
		return random;
	}
	
	/**
	 * 辗转相除法求最大公约数
	 * @param a 被除数
	 * @param b 除数
	 * @return 最大公约数
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
	 * 快速模幂运算
	 * @param base 被除数底数
	 * @param index 被除数指数
	 * @param mod 除数
	 * @return 模除运算结果
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
		// TODO 自动生成的方法存根
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
