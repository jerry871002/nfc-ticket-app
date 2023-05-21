package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You will
 * need to change the keys, design and implement functions to issue and validate tickets. Keep your
 * code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();


    private static final byte[] authenticationKey = TicketActivity.outer.getString(R.string.my_auth_key).getBytes(); // 16-byte key
    private static final byte[] hmacKey = TicketActivity.outer.getString(R.string.my_hmac_key).getBytes(); // 16-byte key

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private static byte[] uid = new byte[8];

    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryTime = 0;
    private static int lastUsedTime = 0;
    private int counter = 0;
    private int initCounter = 0;
    private int maxCounterValue = 0;
    private byte[] cardHMAC = new byte[4];

    private static String infoToShow = "-"; // Use this to show messages

    /**
     * Data Structure
     */
    private static final int UID_PAGE = 0;

    private static final int BOUND_PAGE = 4;
    private static final int INIT_COUNTER_PAGE = 5;
    private static final int EXPIRE_TIME_PAGE = 6;
    private static final int HMAC_PAGE = 7;
    private static final int COUNTER_PAGE = 41;
    private static final int AUTH0_PAGE = 42;
    private static final int AUTH1_PAGE = 43;
    private static final int PASSWD_PAGE = 44;

    /**
     * APP Settings
     */
    private static final int RIDES_PER_ISSUE = 2;

    // EXPIRE_TIME in seconds
    private static final int EXPIRE_TIME = 300;
    private static final int KEY_LENGTH = 16;


    /**
     * Create a new ticket
     */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }

    private byte[] getUID() {
        byte[] UID = new byte[8];
        try {
            utils.readPages(UID_PAGE, 2, UID, 0);
            System.arraycopy(UID, 4, UID, 3, 4); // Eliminate BCC0
            UID[7] = 0;
        } catch (Exception e) {
            Utilities.log("getUID error", true);
        }
        return UID;
    }

    private byte[] generateKey(byte[] uid) {
        byte[] key = new byte[KEY_LENGTH];
        PBEKeySpec spec = new PBEKeySpec(new String(authenticationKey).toCharArray(), uid, 1000, 256);
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = keyFactory.generateSecret(spec).getEncoded();
            key = new byte[KEY_LENGTH];
            System.arraycopy(hash, 0, key, 0, KEY_LENGTH);
        } catch (Exception e) {
            Utilities.log("getKey error", true);
        }
        return key;
    }

    private byte[] generateHMACKey(byte[] uid) {
        byte[] key = new byte[KEY_LENGTH];
        PBEKeySpec spec = new PBEKeySpec(new String(hmacKey).toCharArray(), uid, 1000, 256);
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = keyFactory.generateSecret(spec).getEncoded();
            key = new byte[KEY_LENGTH];
            System.arraycopy(hash, 0, key, 0, KEY_LENGTH);
        } catch (Exception e) {
            Utilities.log("getKey error", true);
        }
        return key;
    }

    private void initBlankCard(byte[] key) {
        try {
            // change auth key
            utils.writePages(key, 0, PASSWD_PAGE, 4);
            // set auth0 and auth1
            utils.writePages(new byte[]{48, 0, 0, 0}, 0, AUTH0_PAGE, 1);
            utils.writePages(new byte[]{3, 0, 0, 0}, 0, AUTH1_PAGE, 1);
        } catch (Exception e) {
            Utilities.log("initBlankCard error", true);
        }
    }

    byte[] toByteArr(int i) {
        return new byte[]{
                (byte) i,
                (byte) (i >> 8),
                (byte) (i >> 16),
                (byte) (i >> 24)
        };
    }

    private boolean addToCounter() {
        byte[] one = {1, 0, 0, 0};
        boolean res = utils.writePages(one, 0, COUNTER_PAGE, 1);
        return res;
    }

    int pageToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) | ((bytes[1] & 0xFF) << 8) | ((bytes[2] & 0xFF) << 16) | ((bytes[3] & 0xFF) << 24);
    }

    private boolean getCounter() {
        byte[] counterArr = new byte[4];
        try {
            utils.readPages(COUNTER_PAGE, 1, counterArr, 0);
            counter = pageToInt(counterArr);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    private boolean getTicketData() {
        byte[] maxCounterValueArr = new byte[4];
        byte[] expiryTimeArr = new byte[4];
        try {
            utils.readPages(BOUND_PAGE, 1, maxCounterValueArr, 0);
            utils.readPages(EXPIRE_TIME_PAGE, 1, expiryTimeArr, 0);
            utils.readPages(HMAC_PAGE, 1, cardHMAC, 0);
        } catch (Exception e) {
            Utilities.log("getTicketData, read pages error", true);
            return false;
        }
        try {
            maxCounterValue = pageToInt(maxCounterValueArr);
            expiryTime = pageToInt(expiryTimeArr);
        } catch (Exception e) {
            Utilities.log("getTicketData, convert to int error", true);
            return false;
        }
        return true;
    }

    private byte[] computeHMAC() {
        byte[] maxCounterValueArr = toByteArr(maxCounterValue);
        byte[] expiryTimeArr = toByteArr(expiryTime);
        byte[] initCounterArr = toByteArr(initCounter);

        ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
        try {
            dataStream.write(uid);
            dataStream.write(maxCounterValueArr);
            dataStream.write(expiryTimeArr);
            dataStream.write(initCounterArr);
        } catch (Exception e) {
            Utilities.log("writeTicketData, compute HMAC value error", true);
            return new byte[20];
        }
        return macAlgorithm.generateMac(dataStream.toByteArray());
    }

    private boolean writeTicketData(boolean maxCounterFlag, boolean expiryTimeFlag, boolean initCounterFlag, boolean HMACFlag) {
        boolean res = true;
        byte[] maxCounterValueArr = toByteArr(maxCounterValue);
        byte[] expiryTimeArr = toByteArr(expiryTime);
        byte[] initCounterArr = toByteArr(initCounter);
        byte[] writeHMAC = Arrays.copyOfRange(computeHMAC(), 0, 4);
        try {
            if(maxCounterFlag) res &= utils.writePages(maxCounterValueArr, 0, BOUND_PAGE, 1);
            if(initCounterFlag) res &= utils.writePages(initCounterArr, 0, INIT_COUNTER_PAGE, 1);
            if(expiryTimeFlag) res &= utils.writePages(expiryTimeArr, 0, EXPIRE_TIME_PAGE, 1);
            if(HMACFlag) res &= utils.writePages(writeHMAC, 0, HMAC_PAGE, 1);
        } catch (Exception e) {
            Utilities.log("write data error", true);
        }
        return res;
    }

    /**
     * Issue new tickets
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {

        byte[] uid = getUID();
        byte[] authKey = generateKey(uid);
        byte[] hmacKey = generateHMACKey(uid);
        macAlgorithm.setKey(hmacKey);

        boolean blank = utils.authenticate(defaultAuthenticationKey);
        boolean authState = utils.authenticate(authKey) | blank;

        // fetch NFC card data
        getCounter();
        getTicketData();

        if (blank) {
            initBlankCard(authKey);
            maxCounterValue = counter + RIDES_PER_ISSUE;
            initCounter = counter;
            if(!writeTicketData(true, false, true, true)) {
                infoToShow = "Failed to issue ticket. Move too fast.";
                return false;
            }
            infoToShow = "Blank card.\n" + RIDES_PER_ISSUE + " tickets have been issued.\nTotal: 2 rides";
            return true;
        }

        if (!authState) {
            infoToShow = "Authentication failed or move too fast.";
            isValid = false;
            return false;
        }

        // check HMAC (Integrity)
        byte[] computedHMAC = Arrays.copyOfRange(computeHMAC(), 0, 4);
        boolean integrity = Arrays.equals(cardHMAC, computedHMAC);
        if(!integrity) {
            infoToShow = "Card is broken.";
            return false;
        }

        if (lastUsedTime > System.currentTimeMillis() / 1000 - 3) {
            Utilities.log("Too fast, please wait and use card again", true);
            infoToShow = "Please wait and issue card again.";
            return false;
        }

        // check if the issued rides have expired or used up
        if (maxCounterValue == counter || expiryTime < (int) (System.currentTimeMillis() / 1000) && expiryTime != 0) {
            expiryTime = 0;
            maxCounterValue = counter + RIDES_PER_ISSUE;
            initCounter = counter;
            if(!writeTicketData(true, true, true, true)) {
                infoToShow = "Failed to issue ticket. Move too fast.";
                return false;
            }
            infoToShow = "Card used up / expired.\n" + RIDES_PER_ISSUE + " new tickets have been issued.";
            return true;
        }

        maxCounterValue += RIDES_PER_ISSUE;
        remainingUses = maxCounterValue - counter;

        /** Preparations all done, issue ticket*/
        if(!writeTicketData(true, false, false, true)) {
            infoToShow = "Failed to issue ticket. Move too fast.";
            return false;
        }

        lastUsedTime = (int) (System.currentTimeMillis() / 1000);

        infoToShow = "Card in use.\n" + RIDES_PER_ISSUE + " more tickets have been issued.\nTotal: " + remainingUses + " rides";
        return true;
    }

    /**
     * Use ticket once
     */
    public boolean use() throws GeneralSecurityException {
        byte[] uid = getUID();
        byte[] authKey = generateKey(uid);
        byte[] hmacKey = generateHMACKey(uid);
        macAlgorithm.setKey(hmacKey);

        boolean blank = utils.authenticate(defaultAuthenticationKey);
        if(blank) {
            infoToShow = "Blank card found. Please goto issue.";
            return false;
        }

        boolean authState = utils.authenticate(authKey);
        if(!authState) {
            infoToShow = "Authentication failed or move too fast.";
            return false;
        }

        // fetch NFC card data
        getCounter();
        getTicketData();

        // check HMAC (Integrity)
        byte[] computedHMAC = Arrays.copyOfRange(computeHMAC(), 0, 4);
        boolean integrity = Arrays.equals(cardHMAC, computedHMAC);
        if(!integrity) {
            infoToShow = "Card is broken.";
            return false;
        }

        SimpleDateFormat format = new SimpleDateFormat("dd/MM/yyyy' 'HH:mm:ss");
        Timestamp expiryTimeStamp = new Timestamp((long) expiryTime * 1000);

        if (counter >= maxCounterValue) {
            Utilities.log("No more tickets, please goto issue", true);
            infoToShow = "No more tickets, please goto issue";
            return false;
        }

        if (expiryTime != 0 && (int)(System.currentTimeMillis() / 1000) > expiryTime) {
            Utilities.log("Ticket expired on " + format.format(expiryTimeStamp), true);
            infoToShow = "Ticket expired on " + format.format(expiryTimeStamp);
            return false;
        }

        if (lastUsedTime > System.currentTimeMillis() / 1000 - 2) {
            Utilities.log("Too fast, please wait and use card again", true);
            infoToShow = "Too fast, please wait and use card again";
            return false;
        }

        remainingUses = maxCounterValue - counter - 1;
        lastUsedTime = (int) (System.currentTimeMillis() / 1000);
        if (expiryTime == 0) {
            if (initCounter == counter) {
                expiryTime = lastUsedTime + EXPIRE_TIME;
                if(!writeTicketData(false, true, false, true)) {
                    infoToShow = "Failed to issue ticket. Move too fast.";
                    return false;
                }
            } else {
                infoToShow = "Failed to use ticket. Rollback detected.";
                return false;
            }
        }

        /** Preparations all done, use ticket*/
        if(!addToCounter()) {
            infoToShow = "Failed to use ticket. Move too fast.";
            return false;
        }

        lastUsedTime = (int) (System.currentTimeMillis() / 1000);

        expiryTimeStamp = new Timestamp((long) expiryTime * 1000);
        infoToShow = "Ticket Used.\n" + remainingUses + " rides remain.\n"+ "Expire on " + format.format(expiryTimeStamp);
        return true;
    }
}