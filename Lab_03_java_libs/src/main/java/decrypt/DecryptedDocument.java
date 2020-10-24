package decrypt;

/**
 * The DecryptedDocument serves to hold various information about decrypted
 * documents for informational reasons.
 */
public class DecryptedDocument {

    private byte[] document;
    private byte[] secretKey;
    private byte[] iv;
    private String cipherName;
    private String macName;
    private HybridDecryption.MACState macState;
    private byte[] macDoc;
    private byte[] macComp;

    public String getCipherName() {
        return cipherName;
    }

    public void setCipherName(String cipherName) {
        this.cipherName = cipherName;
    }

    public String getMACName() {
        return macName;
    }

    public void setMACName(String macName) {
        this.macName = macName;
    }

    public byte[] getDocument() {
        return document;
    }

    public void setDocument(byte[] document) {
        this.document = document;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(byte[] sessionKey) {
        this.secretKey = sessionKey;
    }

    public HybridDecryption.MACState getMacState() {
        return macState;
    }

    public void setMacState(HybridDecryption.MACState macState) {
        this.macState = macState;
    }

    public byte[] getMacDoc() {
        return macDoc;
    }

    public void setMacDoc(byte[] macDoc) {
        this.macDoc = macDoc;
    }

    public byte[] getMacComp() {
        return macComp;
    }

    public void setMacComp(byte[] macComp) {
        this.macComp = macComp;
    }
}
