package erc20;

import com.google.protobuf.ByteString;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.util.io.pem.PemReader;
import org.hyperledger.fabric.contract.ClientIdentity;
import org.hyperledger.fabric.protos.msp.Identities.SerializedIdentity;
import org.hyperledger.fabric.shim.ChaincodeBase;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ResponseUtils;

import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.netty.util.internal.StringUtil.isNullOrEmpty;
import static java.math.BigDecimal.ZERO;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Optional.ofNullable;

public class ERC20 extends ChaincodeBase {

    private static final Log LOG = LogFactory.getLog(ERC20.class);

    private static final String symbolKey = "symbol";
    private static final String nameKey = "name";
    private static final String totalSupplyKey = "totalSupply";
    private static final String balanceKey = "balances";
    private static final String allowedKey = "allowed";

    private final ThreadLocal<ChaincodeStub> chaincodeStub = new ThreadLocal<>();

    @Override
    public Response init(ChaincodeStub stub) {
        try {
            chaincodeStub.set(stub);
            if (!stub.getFunction().equals("init")) {
                return ResponseUtils.newErrorResponse("Function other than init is not supported");
            }
            if (totalSupply().compareTo(ZERO) != 0) {
                LOG.info("Upgrading " + name() + " chaincode...");
                return ResponseUtils.newSuccessResponse();
            }

            String symbol = "ERC";
            String name = "Java ERC20 chaincode on Fabric";
            BigDecimal supply = BigDecimal.valueOf(21_000_000);

            LOG.info("Initializing " + name + " (" + symbol + ") with a total supply of " + supply.toPlainString());

            Map<String, BigDecimal> balances = getBalances();
            balances.put(getMyAddress(), supply);
            putState(symbolKey, symbol);
            putState(nameKey, name);
            putState(totalSupplyKey, supply);
            putState(balanceKey, balances);

            postTransferEvent("0x0000000000000000000000000000000000000000", getMyAddress(), supply);

            LOG.info("Balance of " + getMyAddress() + ": " + supply.toPlainString());

            return ResponseUtils.newSuccessResponse();
        } catch (Throwable e) {
            return ResponseUtils.newErrorResponse(e.getMessage());
        }
    }

    @Override
    public Response invoke(ChaincodeStub stub) {
        try {
            chaincodeStub.set(stub);
            LOG.debug("Invocation by " + getMyAddress() + " : (" +
                      "x509::" + getMyCertificate().getSubjectDN().getName() + "::" + getMyCertificate().getIssuerDN().getName());

            String func = stub.getFunction();
            List<String> params = stub.getParameters();
            String response;

            switch (func) {
                case "symbol":
                    if (params != null && !params.isEmpty()) {
                        throw new IllegalArgumentException("No arguments expected");
                    }
                    response = symbol();
                    break;
                case "name":
                    if (params != null && !params.isEmpty()) {
                        throw new IllegalArgumentException("No arguments expected");
                    }
                    response = name();
                    break;
                case "totalSupply":
                    if (params != null && !params.isEmpty()) {
                        throw new IllegalArgumentException("No arguments expected");
                    }
                    response = totalSupply().toPlainString();
                    break;
                case "myAddress":
                    if (params != null && !params.isEmpty()) {
                        throw new IllegalArgumentException("No arguments expected");
                    }
                    response = getMyAddress();
                    break;
                case "addressOf":
                    if (params.size() != 1 || isNullOrEmpty(params.get(0))) {
                        throw new IllegalArgumentException("Argument must be exactly 1 non-empty string representing" +
                                                           " an EC 256 X.509 public key such as 3059301306072A8648CE" +
                                                           "3D020106082A8648CE3D0301070342000439BEA51E9882186AD7AFF8" +
                                                           "EF1B7433C33B3E97AF70103800052188327B640171500537E5789BA5" +
                                                           "B9636357BEC16355DA2D6E1779008F88D3618A7A4AD0FB8588");
                    }
                    byte[] bytes;
                    try {
                        bytes = new BigInteger(params.get(0), 16).toByteArray();
                    } catch (Exception e) {
                        throw new IllegalArgumentException("Failed to decode the public key. It must represent" +
                                                           " an EC 256 X.509 public key such as 3059301306072A8648CE" +
                                                           "3D020106082A8648CE3D0301070342000439BEA51E9882186AD7AFF8" +
                                                           "EF1B7433C33B3E97AF70103800052188327B640171500537E5789BA5" +
                                                           "B9636357BEC16355DA2D6E1779008F88D3618A7A4AD0FB8588");
                    }
                    response = getAddressOf(bytes);
                    break;
                case "balanceOf":
                    if (params.size() != 1 || isNullOrEmpty(params.get(0))) {
                        throw new IllegalArgumentException("Argument must be exactly 1 non-empty string");
                    }
                    if (!AddressUtils.isValidAddress(params.get(0))) {
                        throw new IllegalArgumentException("Invalid address provided");
                    }
                    response = balanceOf(params.get(0)).toPlainString();
                    break;
                case "allowance":
                    if (params.size() != 2 || isNullOrEmpty(params.get(0)) || isNullOrEmpty(params.get(1))) {
                        throw new IllegalArgumentException("Arguments must be exactly 2 non-empty strings");
                    }
                    if (!AddressUtils.isValidAddress(params.get(0))) {
                        throw new IllegalArgumentException("First argument is an invalid address");
                    }
                    if (!AddressUtils.isValidAddress(params.get(1))) {
                        throw new IllegalArgumentException("Second argument is an invalid address");
                    }
                    response = allowance(params.get(0), params.get(1)).toPlainString();
                    break;
                case "transfer":
                    if (params.size() != 2 || isNullOrEmpty(params.get(0)) || isNullOrEmpty(params.get(1))) {
                        throw new IllegalArgumentException("Arguments must be exactly 2 non-empty strings");
                    }
                    if (!AddressUtils.isValidAddress(params.get(0))) {
                        throw new IllegalArgumentException("First argument is an invalid address");
                    }
                    try {
                        new BigDecimal(params.get(1));
                    } catch (NumberFormatException nfe) {
                        throw new IllegalArgumentException("Second argument must be number");
                    }
                    response = transfer(params.get(0), new BigDecimal(params.get(1))).toString();
                    break;
                case "approve":
                    if (params.size() != 2 || isNullOrEmpty(params.get(0)) || isNullOrEmpty(params.get(1))) {
                        throw new IllegalArgumentException("Arguments must be exactly 2 non-empty strings");
                    }
                    if (!AddressUtils.isValidAddress(params.get(0))) {
                        throw new IllegalArgumentException("First argument is an invalid address");
                    }
                    try {
                        new BigDecimal(params.get(1));
                    } catch (NumberFormatException nfe) {
                        throw new IllegalArgumentException("Second argument must be number");
                    }
                    response = approve(params.get(0), new BigDecimal(params.get(1))).toString();
                    break;
                case "transferFrom":
                    if (params.size() != 3 || isNullOrEmpty(params.get(0)) || isNullOrEmpty(params.get(1)) || isNullOrEmpty(params.get(2))) {
                        throw new IllegalArgumentException("Arguments must be exactly 3 non-empty strings");
                    }
                    if (!AddressUtils.isValidAddress(params.get(0))) {
                        throw new IllegalArgumentException("First argument is an invalid address");
                    }
                    if (!AddressUtils.isValidAddress(params.get(1))) {
                        throw new IllegalArgumentException("Second argument is an invalid address");
                    }
                    try {
                        new BigDecimal(params.get(2));
                    } catch (NumberFormatException nfe) {
                        throw new IllegalArgumentException("Third argument must be number");
                    }
                    response = transferFrom(params.get(0), params.get(1), new BigDecimal(params.get(2))).toString();
                    break;
                default:
                    return ResponseUtils.newErrorResponse("Invalid invoke function name. Expecting one of: [\"symbol\", \"name\", \"totalSupply\", \"myAddress\", \"addressOf\", \"balanceOf\", \"allowance\", \"transfer\", \"approve\", \"transferFrom\"]");
            }

            return ResponseUtils.newSuccessResponse(ByteString.copyFromUtf8(response).toByteArray());
        } catch (Throwable e) {
            LOG.error(e);
            return ResponseUtils.newErrorResponse(e.getMessage());
        }
    }

    private String symbol() {
        return getStringState(symbolKey).orElse(null);
    }

    private String name() {
        return getStringState(nameKey).orElse(null);
    }

    private BigDecimal totalSupply() {
        return getState(totalSupplyKey).map(BigInteger::new)
                                       .map(bi -> new BigDecimal(bi, 0))
                                       .orElse(ZERO);
    }

    private BigDecimal balanceOf(String address) {
        return ofNullable(getBalances().get(address)).orElse(ZERO);
    }

    private BigDecimal allowance(String ownerAddress, String spenderAddress) {
        Map<String, HashMap<String, BigDecimal>> allowed = getAllowed();
        HashMap<String, BigDecimal> ownerAllowed = ofNullable(allowed.get(ownerAddress)).orElse(new HashMap<>());
        return ofNullable(ownerAllowed.get(spenderAddress)).orElse(ZERO);
    }

    private Boolean transfer(String address, BigDecimal value) {
        BigDecimal myBalance = balanceOf(getMyAddress());
        BigDecimal toBalance = balanceOf(address);
        if (myBalance.compareTo(value) < 0) {
            throw new RuntimeException("Insufficient funds");
        }
        Map<String, BigDecimal> balances = getBalances();
        balances.put(getMyAddress(), myBalance.subtract(value));
        balances.put(address, toBalance.add(value));
        putState(balanceKey, balances);

        postTransferEvent(getMyAddress(), address, value);

        return true;
    }

    private Boolean approve(String address, BigDecimal value) {
        Map<String, HashMap<String, BigDecimal>> allowed = getAllowed();
        HashMap<String, BigDecimal> myAllowed = ofNullable(allowed.get(getMyAddress())).orElse(new HashMap<>());
        myAllowed.put(address, value);
        allowed.put(getMyAddress(), myAllowed);
        putState(allowedKey, allowed);

        postApprovalEvent(getMyAddress(), address, value);

        return true;
    }

    private Boolean transferFrom(String fromAddress, String toAddress, BigDecimal value) {
        BigDecimal allowance = allowance(fromAddress, getMyAddress());
        if (allowance.compareTo(value) < 0) {
            throw new RuntimeException("Insufficient allowance");
        }
        Map<String, HashMap<String, BigDecimal>> allowed = getAllowed();
        HashMap<String, BigDecimal> fromAllowed = ofNullable(allowed.get(fromAddress)).orElse(new HashMap<>());
        fromAllowed.put(getMyAddress(), allowance.subtract(value));
        allowed.put(fromAddress, fromAllowed);
        putState(allowedKey, allowed);

        BigDecimal fromBalance = balanceOf(fromAddress);
        BigDecimal toBalance = balanceOf(toAddress);
        if (fromBalance.compareTo(value) < 0) {
            throw new RuntimeException("Insufficient funds");
        }
        Map<String, BigDecimal> balances = getBalances();
        balances.put(fromAddress, fromBalance.subtract(value));
        balances.put(toAddress, toBalance.add(value));
        putState(balanceKey, balances);

        postTransferEvent(fromAddress, toAddress, value);

        return true;
    }

    private void postTransferEvent(String from, String to, BigDecimal value) {
        String message = String.format("From %s to %s: %s", from, to, value.toPlainString());
        ofNullable(chaincodeStub.get()).ifPresent(stub -> stub.setEvent("Transfer",
                                                                        ByteString.copyFromUtf8(message).toByteArray()));
    }

    private void postApprovalEvent(String owner, String spender, BigDecimal value) {
        String message = String.format("Owner %s allows spender %s: %s", owner, spender, value.toPlainString());
        ofNullable(chaincodeStub.get()).ifPresent(stub -> stub.setEvent("Approval",
                                                                        ByteString.copyFromUtf8(message).toByteArray()));
    }

    private String getAddressOf(byte[] publicKey) {
        return AddressUtils.getAddressFor(publicKey);
    }

    private String getMyAddress() {
        return AddressUtils.getAddressFor(getMyCertificate());
    }

    private X509Certificate getMyCertificate() {
        try {
            SerializedIdentity identity = SerializedIdentity.parseFrom(chaincodeStub.get().getCreator());
            StringReader reader = new StringReader(identity.getIdBytes().toStringUtf8());
            PemReader pr = new PemReader(reader);
            byte[] x509Data = pr.readPemObject().getContent();
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(x509Data));
        } catch (IOException | CertificateException e) {
            throw new ChaincodeException("Failed to retrieve certificate of invoking identity", e);
        }
    }

    private Optional<String> getStringState(String key) {
        return ofNullable(chaincodeStub.get()).map(stub -> stub.getStringState(key));
    }

    private Optional<byte[]> getState(String key) {
        return ofNullable(chaincodeStub.get()).map(stub -> stub.getState(key)).filter(array -> array.length > 0);
    }

    private Map<String, BigDecimal> getBalances() {
        return getState(balanceKey).map(ByteArrayInputStream::new).map(inputStream -> {
            try {
                return new ObjectInputStream(inputStream).readObject();
            } catch (IOException | ClassNotFoundException e) {
                throw new RuntimeException("Failed to retrieve and deserialize balances", e);
            }
        }).map(obj -> (HashMap<String, BigDecimal>) obj).orElse(new HashMap<>());
    }

    private Map<String, HashMap<String, BigDecimal>> getAllowed() {
        return getState(allowedKey).map(ByteArrayInputStream::new).map(inputStream -> {
            try {
                return new ObjectInputStream(inputStream).readObject();
            } catch (IOException | ClassNotFoundException e) {
                throw new RuntimeException("Failed to retrieve and deserialize balances", e);
            }
        }).map(obj -> (HashMap<String, HashMap<String, BigDecimal>>) obj).orElse(new HashMap<>());
    }

    private void putState(String key, String state) {
        ofNullable(chaincodeStub.get()).ifPresent(stub -> stub.putStringState(key, ofNullable(state).orElse("null")));
    }

    private void putState(String key, BigDecimal state) {
        ofNullable(chaincodeStub.get()).ifPresent(stub -> stub.putState(key, ofNullable(state).orElse(ZERO)
                                                                                              .unscaledValue()
                                                                                              .toByteArray()));
    }

    private void putState(String key, Map<String, ? extends Serializable> state) {
        try {
            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            new ObjectOutputStream(bytesOut).writeObject(ofNullable(state).orElse(new HashMap<>()));
            ofNullable(chaincodeStub.get()).ifPresent(stub -> stub.putState(key, bytesOut.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException("Failed to put map state");
        }
    }

    public static void main(String[] args) {
        new ERC20().start(args);
    }
}