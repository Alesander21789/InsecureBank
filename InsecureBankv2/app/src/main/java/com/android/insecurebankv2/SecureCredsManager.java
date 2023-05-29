package com.android.insecurebankv2;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class SecureCredsManager {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "SecureCredsKey";
    private static final String MYPREFS = "MyPrefs";
    private static final String ENCRYPTED_USERNAME = "EncryptedUsername";
    private static final String ENCRYPTED_PASSWORD = "EncryptedPassword";
    private static final String IV = "IV";

    private Context context;
    private SharedPreferences sharedPreferences;

    public SecureCredsManager(Context context) {
        this.context = context;
        this.sharedPreferences = context.getSharedPreferences(MYPREFS, Context.MODE_PRIVATE);
    }

    public void saveCreds(String username, String password) throws GeneralSecurityException, IOException {
        SecretKey secretKey = getOrCreateSecretKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedUsername = cipher.doFinal(username.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedPassword = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();

        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(ENCRYPTED_USERNAME, Base64.encodeToString(encryptedUsername, Base64.DEFAULT));
        editor.putString(ENCRYPTED_PASSWORD, Base64.encodeToString(encryptedPassword, Base64.DEFAULT));
        editor.putString(IV, Base64.encodeToString(iv, Base64.DEFAULT));
        editor.apply();
    }

    private SecretKey getOrCreateSecretKey() throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        if (keyStore.containsAlias(KEY_ALIAS)) {
            return ((KeyStore.SecretKeyEntry) keyStore.getEntry(KEY_ALIAS, null)).getSecretKey();
        } else {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
            AlgorithmParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .setKeySize(256)
                    .build();
            keyGenerator.init(spec);
            return keyGenerator.generateKey();
        }
    }
}




