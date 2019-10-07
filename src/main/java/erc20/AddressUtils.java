package erc20;

import org.bouncycastle.jcajce.provider.digest.Keccak;

import java.security.cert.Certificate;

import static java.nio.charset.StandardCharsets.UTF_8;

class AddressUtils {

    static boolean isValidAddress(String address) {
        if (address == null || address.length() != 42) {
            return false;
        }
        String checksum = checksum(address.replace("0x", "").toLowerCase());
        return checksum.equals(address);
    }

    static String getAddressFor(Certificate certificate) {
        return getAddressFor(certificate.getPublicKey().getEncoded());
    }

    static String getAddressFor(byte[] pubKey) {
        String pubKeyHash = sha3String(pubKey);
        String shortPubKeyHash = pubKeyHash.substring(pubKeyHash.length() - 40); // keep last 20 bytes
        return checksum(shortPubKeyHash);
    }

    private static byte[] sha3(byte[] input) {
        Keccak.Digest256 kecc = new Keccak.Digest256();
        kecc.update(input, 0, input.length);
        return kecc.digest();
    }

    private static String sha3String(String input) {
        return sha3String(input.getBytes(UTF_8));
    }

    private static String sha3String(byte[] input) {
        return toHex(sha3(input));
    }

    private static String toHex(byte[] input) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : input) {
            stringBuilder.append(String.format("%02x", b & 0xFF));
        }
        return stringBuilder.toString();
    }

    private static String checksum(String lowercaseHashWithoutPrefix) {
        String inputHash = sha3String(lowercaseHashWithoutPrefix);
        StringBuilder result = new StringBuilder();
        result.append("0x");

        for (int i = 0; i < lowercaseHashWithoutPrefix.length(); i++) {
            if (Integer.parseInt(String.valueOf(inputHash.charAt(i)), 16) >= 8) {
                result.append(String.valueOf(lowercaseHashWithoutPrefix.charAt(i)).toUpperCase());
            } else {
                result.append(lowercaseHashWithoutPrefix.charAt(i));
            }
        }

        return result.toString();
    }
}