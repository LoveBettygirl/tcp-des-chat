package com.deschatv2.alg;

import java.io.Serializable;
import java.math.BigInteger;

public class RSAPublicKey implements Serializable {

	private static final long serialVersionUID = -2071297560602018291L;
	private BigInteger e;
	private BigInteger n;
	
	public RSAPublicKey(BigInteger e, BigInteger n) {
		this.e = e;
		this.n = n;
	}
	
	public BigInteger getE() {
		return e;
	}
	
	public BigInteger getN() {
		return n;
	}
	
	@Override
	public String toString() {
		return "(" + e + ", " + n + ")";
	}
}
