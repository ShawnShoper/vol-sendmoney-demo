package com.example.demo.vol;

import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class Convert {

	private Convert() {
	} // never

	public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final char ENCODED_ZERO = ALPHABET[0];
    private static final int[] INDEXES = new int[128];
    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

	public static byte[] parseHexString(String hex) {
		if (hex == null)
			return null;
		try {
			if (hex.length() % 2 != 0) {
				hex = hex.substring(0, hex.length() - 1);
			}
			return Hex.decode(hex);
		} catch (DecoderException e) {
			throw new RuntimeException("Could not parse hex string " + hex, e);
		}
	}

	public static String toHexString(byte[] bytes) {
		if (bytes == null)
			return null;
		return Hex.toHexString(bytes);
	}

	public static String toUnsignedLong(long objectId) {
		return Long.toUnsignedString(objectId);
	}

	public static long parseAccountId(String account) {
		if (account == null) {
			return 0;
		}
		account = account.toUpperCase();
		if (account.startsWith("VOL-")) {
			return Crypto.rsDecode(account.substring(4));
		} else {
			return parseUnsignedLong(account);
		}
	}

    public static long parseUnsignedLong(String number) {
		if (number == null) {
			return 0;
		}
		return Long.parseUnsignedLong(number);
	}


	public static String rsAccount(long accountId) {
		return "VOL-" + Crypto.rsEncode(accountId);
	}

	public static long fullHashToId(byte[] hash) {
		int heightByte = 19; // 8 for v1, 32 for v2 userID
		if (hash == null || hash.length < heightByte) {
		  throw new IllegalArgumentException("Invalid hash: " + Arrays.toString(hash));
		}
		long result = 0;
		for (int i = 0; i < 8; i++) {
		  result <<= 8;
		  result |= (hash[heightByte-1-i] & 0xFF);
		}
		return result;
	}

	public static long fullHashToId(String hash) {
		if (hash == null) {
			return 0;
		}
		return fullHashToId(Convert.parseHexString(hash));
	}

	public static byte[] toBytes(String s) {
		return s.getBytes(StandardCharsets.UTF_8);
	}

	public static String toString(byte[] bytes) {
		return new String(bytes, StandardCharsets.UTF_8);
	}
}
