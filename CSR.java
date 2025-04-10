package com.example.Cloud.HSM.Sample;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

public class CSR {

    private static final Provider BC_PROVIDER = new BouncyCastleProvider();
    private static final SecureRandom PRNG        = new SecureRandom();

    public static void csr(RSAPrivateKey privateKey, RSAPublicKey publicKey, String dn) throws OperatorCreationException,
            OperatorCreationException, IOException {
        X500Principal var12 = new X500Principal(dn);
        JcaPKCS10CertificationRequestBuilder var13 = new JcaPKCS10CertificationRequestBuilder(var12, publicKey);
        PKCS10CertificationRequest var14 = var13.build((new JcaContentSignerBuilder("SHA256withRSA"))
                .build((RSAPrivateKey)privateKey));
        byte[] var15 = Base64.encode(var14.getEncoded());
        String var16 = new String(var15);
        System.out.println("\n-----BEGIN NEW CERTIFICATE REQUEST-----");

        for(int var17 = 0; var17 <= var15.length / 64; ++var17) {
            if (64 * var17 + 64 >= var16.length()) {
                System.out.println(var16.substring(64 * var17));
            } else {
                System.out.println(var16.substring(64 * var17, 64 * var17 + 64));
            }
        }

        System.out.println("-----END NEW CERTIFICATE REQUEST-----");
    }

    public static X509Certificate getSelfSignedCert(final PublicKey publicKey, final PrivateKey privateKey, final X500Name subject, final Validity validity, final String signatureAlgorithm) throws Exception {

        final var sn               = new BigInteger(Long.SIZE, PRNG);

        final var issuer           = subject;


        final var keyPublicEncoded = publicKey.getEncoded();
        final var keyPublicInfo    = SubjectPublicKeyInfo.getInstance(keyPublicEncoded);
        /*
         * First, some fiendish trickery to generate the Subject (Public-) Key Identifier...
         */
        try(final var ist = new ByteArrayInputStream(keyPublicEncoded);
            final var ais = new ASN1InputStream(ist))
        {
            final var asn1Sequence         = (ASN1Sequence) ais.readObject();

            final var subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1Sequence);
            final var subjectPublicKeyId   = new BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo);

            /*
             * Now build the Certificate, add some Extensions & sign it with our own Private Key...
             */
            final var certBuilder          = new X509v3CertificateBuilder(issuer, sn, validity.notBefore, validity.notAfter, subject, keyPublicInfo);
            final var contentSigner        = new  JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
            /*
             * BasicConstraints instantiated with "CA=true"
             * The BasicConstraints Extension is usually marked "critical=true"
             *
             * The Subject Key Identifier extension identifies the public key certified by this certificate.
             * This extension provides a way of distinguishing public keys if more than one is available for
             * a given subject name.
             */
            final var certHolder           = certBuilder
                .addExtension(Extension.basicConstraints,     true,  new BasicConstraints(true))
                .addExtension(Extension.subjectKeyIdentifier, false, subjectPublicKeyId)
                .build(contentSigner);

            return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);
        }
    }

    public static final record Validity(Date notBefore, Date notAfter) {

        static Validity ofYears(final int count) {

            final var zdtNotBefore = ZonedDateTime.now();
            final var zdtNotAfter  = zdtNotBefore.plusYears(count);

            return              of(zdtNotBefore.toInstant(), zdtNotAfter.toInstant());
        }
        public static Validity of(final Instant notBefore,  final Instant notAfter) {
            return new Validity   (Date.from    (notBefore), Date.from    (notAfter));
        }
    }


}
