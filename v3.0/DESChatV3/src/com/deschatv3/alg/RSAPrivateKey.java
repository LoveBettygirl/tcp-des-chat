package com.deschatv3.alg;

import java.io.Serializable;
import java.math.*;

public class RSAPrivateKey implements Serializable {

	private static final long serialVersionUID = -7021466273660477038L;
	private BigInteger d;
	private BigInteger n;
	
	public RSAPrivateKey(BigInteger d, BigInteger n) {
		this.d = d;
		this.n = n;
	}
	
	public BigInteger getD() {
		return d;
	}
	
	public BigInteger getN() {
		return n;
	}
	
	@Override
	public String toString() {
		return "(" + d + ", " + n + ")";
	}
}
