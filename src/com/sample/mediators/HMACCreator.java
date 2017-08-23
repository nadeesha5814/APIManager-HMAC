package com.sample.mediators;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Logger;

/**
 * Created by Nadeesha on 26-Jul-17.
 */
public class HMACCreator {

    private static final Logger log = Logger.getLogger( CustomHMAC.class.getName() );
    static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    static final String SHA256_ALGORITHM = "SHA-256";
    static final String AUTHORIZATION_HEADER = "Authorization";
    static final String DATE_HEADER = "Date";
    private String clientId="";
    private String clientSecret= "";

    public void config(String clientId, String clientSecret ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    private static String base64(byte[] b) {
         return new String(Base64.getEncoder().encode(b));
    }

    private static String hash(String text, String secret) {
        try {
            SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(), HMAC_SHA256_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            return base64(mac.doFinal(text.getBytes()));

        }
        catch (Throwable t) {
            log.info("Error in hashing the message");
            t.printStackTrace();
            return text;
        }
    }

    // Method to hash the body
    private static String hashMsgBody(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA256_ALGORITHM);
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return base64(hash);

        }
        catch (Throwable t) {
            log.info("Error in hashing the message");
            t.printStackTrace();
            return text;
        }
    }

    private static String createContentDigest(String body) {
        if (!body.isEmpty()){
            log.info("Message body found and digested");
            return hashMsgBody(body);
        }

        log.info("No body content found hence nothing was digested");
        return "";
    }

    public String createHMACDigestPOST(String method, String contentType, String path, String body, String date) {
        log.info("HMAC Creation for a POST request");
        StringBuilder sb = new StringBuilder();

        // HTTP Method
        sb.append(method.toUpperCase()).append("\n");

         //Date
        sb.append(date).append("\n");

        // Path
        sb.append(path).append("\n");

        // content-type
        sb.append(contentType).append("\n");

        // body
        sb.append(createContentDigest(body));

        log.info("Hashing "+sb.toString());
        return hash(sb.toString(), clientSecret);
    }

    public String createHMACDigestGET(String method,String path, String date) {
        log.info("HMAC Creation for a GET request");

        StringBuilder sb = new StringBuilder();

        // HTTP Method
        sb.append(method.toUpperCase()).append("\n");

        //Date
        sb.append(date).append("\n");

        // Path
        sb.append(path);
        log.info("Hashing "+sb.toString());
        return hash(sb.toString(), clientSecret);
    }

    public static String getRFC1123Date(Date date) {
        SimpleDateFormat df = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z");
        df.setTimeZone(TimeZone.getTimeZone("GMT"));
        return df.format(date);
    }

    public Map<String,String> setHeaders(String method, String path, String body, String contentType) {


        Map<String, String> headers = new HashMap<String, String>();

        // Set Date
        String date = getRFC1123Date(new Date());
        headers.put(DATE_HEADER,date);

        String hmacDigest = "";
        if(method.equals(CustomHMAC.POST)){
            // Generate HMAC
            hmacDigest = createHMACDigestPOST(method,contentType,path,body,date);
        } else if (method.equals(CustomHMAC.GET)){
            hmacDigest = createHMACDigestGET(method,path,date);
        } else {
            log.info("HMAC generation for this HTTP Method is not configured");
        }


        //set Authorization Header
        headers.put(AUTHORIZATION_HEADER,this.clientId+":"+hmacDigest);
        log.info(AUTHORIZATION_HEADER+":"+headers.get(AUTHORIZATION_HEADER));
        return headers;
    }






}
