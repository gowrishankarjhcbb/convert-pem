package com.example.Cloud.HSM.Sample;

import java.io.File;
import java.io.FileReader;
import java.io.StringWriter;
import java.security.cert.CertificateEncodingException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class Main {

    public static void main(String[] args) throws Exception {
        String keyAlias = args[0];
        String keyStorePath= args[1];
        String password = args[2];
        String dn = args[3];
        String pub = args[4];
        KeyStore ks = KeyStore.getInstance("PKCS12");

        ks.load(new FileInputStream(keyStorePath), password.toCharArray());

        Key ssoSigningKey = ks.getKey(keyAlias, password.toCharArray());
        Certificate google = ks.getCertificate(keyAlias);

        PublicKey publicKey = readX509PublicKey(new File(pub));

        CSR.csr((RSAPrivateKey) ssoSigningKey, (RSAPublicKey) publicKey, dn );

//        CSR.getSelfSignedCert();
        final var x500subject = getSubject();
        final var x509Cert    = CSR.getSelfSignedCert(publicKey,(RSAPrivateKey)ssoSigningKey, x500subject, CSR.Validity.ofYears(100), "SHA256WithRSA");
//        System.out.println(x509Cert.toString());
        String s = encodePEM(x509Cert);
        System.out.println(s);
        String s1 = encodePEM(x509Cert.getPublicKey());
        System.out.println(s1);

    }
    private static  X500Name getSubject() {

        return  new X500Name(new RDN[] {new RDN (
            new AttributeTypeAndValue[] {

                new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String("Common Name")),
                new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String("Organisational Unit name")),
                new AttributeTypeAndValue(BCStyle.O,  new DERUTF8String("Organisation")),
                new AttributeTypeAndValue(BCStyle.L,  new DERUTF8String("Locality name")),
                new AttributeTypeAndValue(BCStyle.ST, new DERUTF8String("State or Province name")),
                new AttributeTypeAndValue(BCStyle.C,  new DERUTF8String("uk"))
            }) });
    }

    public static RSAPublicKey readX509PublicKey(File file) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(file);
            PemReader pemReader = new PemReader(keyReader)) {

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            return (RSAPublicKey) factory.generatePublic(pubKeySpec);
        }
    }

    public static String encodePEM(Certificate certificate) {
        try {
            return toPEM("CERTIFICATE", certificate.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    public static String encodePEM(PrivateKey privateKey) throws IOException {
        return toPEM("PRIVATE KEY", privateKey.getEncoded());
    }
    public static String encodePEM(PublicKey publicKey) throws IOException {
        return toPEM("PUBLIC KEY", publicKey.getEncoded());
    }
    /**
     * Converts byte array to PEM
     */
    public static String toPEM(String type, byte[] data) throws IOException {
        final PemObject pemObject = new PemObject(type, data);
        final StringWriter sw = new StringWriter();
        try (final PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(pemObject);
        }
        return sw.toString();
    }
}
