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
    private int lastUsedTime = 0;

    private int counter = 0;
    private int lastCounter = 0;
    private int upperBound = 0;
    private byte[] cardHMAC = new byte[20];

    private static String infoToShow = "-"; // Use this to show messages

    /**
     * Data Structure
     */
    private static final int UID_PAGE = 0;
    private static final int[] BOUND_PAGE = {4, 13};
    private static final int[] LAST_COUNTER_PAGE = {5, 14};
    private static final int[] LAST_USE_TIME_PAGE = {6, 15};
    private static final int[] EXPIRE_TIME_PAGE = {7, 16};
    private static final int[] HMAC_PAGE = {8, 17};
    private static final int TRANSACTION_PAGE = 22;
    private static final int COUNTER_PAGE = 41;
    private static final int AUTH0_PAGE = 42;
    private static final int AUTH1_PAGE = 43;
    private static final int PASSWD_PAGE = 44;

    /**
     * APP Settings
     */
    private static final int RIDES_ONE_ISSUE = 2;
    private static final int EXPIRE_TIME = 300;


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
        byte[] key = new byte[16];
        PBEKeySpec spec = new PBEKeySpec(new String(authenticationKey).toCharArray(), uid, 1000, 256);
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = keyFactory.generateSecret(spec).getEncoded();
            key = new byte[16];
            System.arraycopy(hash, 0, key, 0, 16);
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
        return utils.writePages(one, 0, COUNTER_PAGE, 1);
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

    private boolean getTicketData(int block) {
        byte[] upperBoundArr = new byte[4];
        byte[] lastCounterArr = new byte[4];
        byte[] lastUsedTimeArr = new byte[4];
        byte[] expiryTimeArr = new byte[4];

        System.out.println("block:" + block);
        try {
            utils.readPages(BOUND_PAGE[block], 1, upperBoundArr, 0);
            utils.readPages(LAST_COUNTER_PAGE[block], 1, lastCounterArr, 0);
            utils.readPages(LAST_USE_TIME_PAGE[block], 1, lastUsedTimeArr, 0);
            utils.readPages(EXPIRE_TIME_PAGE[block], 1, expiryTimeArr, 0);
            utils.readPages(HMAC_PAGE[block], 5, cardHMAC, 0);
        } catch (Exception e) {
            Utilities.log("getTicketData, read pages error", true);
            return false;
        }
        try {
            upperBound = pageToInt(upperBoundArr);
            lastCounter = pageToInt(lastCounterArr);
            lastUsedTime = pageToInt(lastUsedTimeArr);
            expiryTime = pageToInt(expiryTimeArr);
        } catch (Exception e) {
            Utilities.log("getTicketData, convert to int error", true);
            return false;
        }
        return true;
    }

    private byte[] computeHMAC() {
        byte[] upperBoundArr = toByteArr(upperBound);
        byte[] lastCounterArr = toByteArr(lastCounter);
        byte[] lastUsedTimeArr = toByteArr(lastUsedTime);
        byte[] expiryTimeArr = toByteArr(expiryTime);

        ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
        try {
            dataStream.write(uid);
            dataStream.write(upperBoundArr);
            dataStream.write(lastCounterArr);
            dataStream.write(lastUsedTimeArr);
            dataStream.write(expiryTimeArr);
        } catch (Exception e) {
            Utilities.log("writeTicketData, compute HMAC value error", true);
            return new byte[20];
        }
        return macAlgorithm.generateMac(dataStream.toByteArray());
    }

    private boolean writeTicketData(boolean use) {
        int block = counter % 2;
        byte[] upperBoundArr = toByteArr(upperBound);
        byte[] lastCounterArr = toByteArr(lastCounter);
        byte[] lastUsedTimeArr = toByteArr(lastUsedTime);
        byte[] expiryTimeArr = toByteArr(expiryTime);
        byte[] writeHMAC = computeHMAC();

        // Transaction Begins, set TRANSACTION_PAGE to 1
        try {
            utils.writePages(new byte[]{1, 0, 0, 0}, 0, TRANSACTION_PAGE, 1);
        } catch (Exception e) {
            Utilities.log("Transaction begin error", true);
        }

        // Write data to card
        try {
            utils.writePages(upperBoundArr, 0, BOUND_PAGE[block], 1);
            utils.writePages(lastCounterArr, 0, LAST_COUNTER_PAGE[block], 1);
            utils.writePages(lastUsedTimeArr, 0, LAST_USE_TIME_PAGE[block], 1);
            utils.writePages(expiryTimeArr, 0, EXPIRE_TIME_PAGE[block], 1);
            utils.writePages(writeHMAC, 0, HMAC_PAGE[block], 5);
            if (use) {
                addToCounter();
            }
        } catch (Exception e) {
            Utilities.log("Transaction data writing actions error", true);
        }

        // Transaction Ends, set TRANSACTION_PAGE back to 0
        try {
            utils.writePages(new byte[]{0, 0, 0, 0}, 0, TRANSACTION_PAGE, 1);
        } catch (Exception e) {
            Utilities.log("Transaction end error", true);
        }

        return true;
    }

    /**
     * Issue new tickets
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {

        byte[] uid = getUID();
        byte[] key = generateKey(uid);
        boolean blank = utils.authenticate(defaultAuthenticationKey);
        boolean authState = utils.authenticate(key) | blank;

        if (blank) {
            initBlankCard(key);
            upperBound = counter + RIDES_ONE_ISSUE;
            lastCounter = counter;
            lastUsedTime = 0;
            expiryTime = 0;
            writeTicketData(false);
            return true;
        }

        if (!authState) {
            infoToShow = "Authentication failed";
            isValid = false;
            return false;
        }

        // fetch NFC card data
        getCounter();
        getTicketData(counter % 2);

        // check HMAC (Integrity)
        byte[] computedHMAC = computeHMAC();
        boolean integrity = Arrays.equals(cardHMAC, computedHMAC);

        // check Transaction value
        byte[] transaction = new byte[4];
        utils.readPages(TRANSACTION_PAGE, 1, transaction, 0);
        int transactionNotDone = transaction[0];

        boolean resetCard = false;

        // if data is broken in one block, caused by crashed write, check the other block
        if (transactionNotDone == 1 && !integrity) {
            Utilities.log("Current Block Broken", true);
            getTicketData((counter + 1) % 2);
            computedHMAC = computeHMAC();
            integrity = Arrays.equals(cardHMAC, computedHMAC);
            // check if data in the other block is valid
            if (integrity) {
                Utilities.log("Restore data from another block", true);
                // check if counter has been updated, not that possible cuz it's sequential in use()
                if (counter == lastCounter + 1) {
                    upperBound += 1;
                }
                lastCounter = counter;
            } else {
                // two blocks are both broken
                Utilities.log("Both two blocks have been broken", true);
                resetCard = true;
            }
        }
        // data has been successfully updated, but last time *ticket use* failed
        else if (transactionNotDone == 1 && counter == lastCounter + 1) {
            upperBound += 1;
        }
        // card has been modified
        else if (!integrity) {
            Utilities.log("Card is invalid", true);
            resetCard = true;
        }

        if (resetCard) {
            upperBound = counter;
            lastCounter = counter;
            lastUsedTime = 0;
            expiryTime = 0;
        }

        // check if the issued rides have expired
        if (expiryTime < (int) (System.currentTimeMillis() / 1000) && expiryTime != 0) {
            expiryTime = 0;
            upperBound = counter;
        }

        upperBound += RIDES_ONE_ISSUE;
        remainingUses = upperBound - counter;

        if (expiryTime != 0) {
            expiryTime += EXPIRE_TIME; // 120 Seconds
        }

        /** Preparations all done, issue ticket*/
        writeTicketData(false);

        infoToShow = "Card in use.\n" + RIDES_ONE_ISSUE + " more tickets have been issued.\nTotal: " + remainingUses + " rides";
        if (blank) {
            infoToShow = "Blank card.\n" + RIDES_ONE_ISSUE + " tickets have been issued.\nTotal: " + remainingUses + " rides";
        }
        return true;
    }

    /**
     * Use ticket once
     */
    public boolean use() throws GeneralSecurityException {
        byte[] uid = getUID();
        byte[] key = generateKey(uid);

        // fetch NFC card data
        getCounter();
        getTicketData(counter % 2);

        // check HMAC (Integrity)
        byte[] computedHMAC = computeHMAC();
        boolean integrity = Arrays.equals(cardHMAC, computedHMAC);

        // check Transaction value
        byte[] transaction = new byte[4];
        utils.readPages(TRANSACTION_PAGE, 1, transaction, 0);
        int transactionNotDone = transaction[0];

        // if data is broken in one block, caused by crashed write, check the other block
        if (transactionNotDone == 1 && !integrity) {
            Utilities.log("Current Block Broken", true);
            getTicketData((counter + 1) % 2);
            computedHMAC = computeHMAC();
            integrity = Arrays.equals(cardHMAC, computedHMAC);
            // check if data in the other block is valid
            if (integrity) {
                Utilities.log("Restore data from another block", true);
                // check if counter has been updated, not that possible cuz it's sequential
                if (counter == lastCounter + 1) {
                    upperBound += 1;
                }
                lastCounter = counter;
            } else {
                // two blocks are both broken
                Utilities.log("Both two blocks have been broken", true);
                return false;
            }
        }
        // data has been successfully updated, but last time *ticket use* failed
        else if (transactionNotDone == 1 && counter == lastCounter + 1) {
            upperBound += 1;
        }
        // card has been modified
        else if (!integrity) {
            Utilities.log("Card is invalid", true);
            infoToShow = "Card is invalid";
        }

        SimpleDateFormat format = new SimpleDateFormat("dd/MM/yyyy' 'HH:mm:ss");
        Timestamp expiryTimeStamp = new Timestamp((long) expiryTime * 1000);

        if (counter >= upperBound) {
            Utilities.log("No more tickets, please goto issue", true);
            infoToShow = "No more tickets, please goto issue";
            return false;
        }

        if (expiryTime != 0 && (int)(System.currentTimeMillis() / 1000) > expiryTime) {
            Utilities.log("Ticket expired on " + format.format(expiryTimeStamp), true);
            infoToShow = "Ticket expired on " + format.format(expiryTimeStamp);
            return false;
        }

        if (lastUsedTime > System.currentTimeMillis() / 1000 - 5) {
            Utilities.log("Too fast, please wait and use card again", true);
            infoToShow = "Too fast, please wait and use card again";
            return false;
        }

        lastCounter = counter;
        remainingUses = upperBound - counter - 1;
        lastUsedTime = (int) (System.currentTimeMillis() / 1000);
        if (expiryTime == 0) {
            expiryTime = lastUsedTime + EXPIRE_TIME;
        }
        counter++;
        /** Preparations all done, use ticket*/
        writeTicketData(true);

        expiryTimeStamp = new Timestamp((long) expiryTime * 1000);
        infoToShow = "Ticket Used.\n" + remainingUses + " rides remain.\n"+ "Expire on " + format.format(expiryTimeStamp);
        return true;
    }
}