package pena.digital;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class EncodeDecode {

    public static void main(String[] args) throws GeneralSecurityException {
        if (args.length < 2) {
            System.out.println("Мало аргументов -decode|-encode fileName");
            return;
        }
        EncodeDecode encodeDecode = new EncodeDecode();
        if (args[0].equals("-decode")) {
            encodeDecode.doDecode(args[1]);
        }
        if (args[0].equals("-encode")) {
            encodeDecode.doEncode(args[1]);
        }
    }

    public SecretKey getKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    private String getKeyFromFileName(String fileName) {
        String[] splitFileName = fileName.split(".");
        int length = splitFileName.length;
        if (splitFileName[length - 1].equals("key")) {
            return splitFileName[length];
        } else {
            return null;
        }
    }

    public void doEncode(String fileName) throws GeneralSecurityException {

        byte[] fileToEncode = readFile(fileName);

        SecretKey key = getKey();

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encodedContent = cipher.doFinal(fileToEncode);

        String encodedFileName = String.format("%s.encodedBy.%s", fileName, key.getAlgorithm());
        saveDataToFile(encodedContent, encodedFileName);
        System.out.println("Файл зашифрован имя файла = " + encodedFileName);
        String fileNameKey = encodedFileName + ".key";
        saveKeyToFile(key, fileNameKey);
        System.out.println("Ключ сохранен имя файла = " + fileNameKey);

    }

    public void saveKeyToFile(SecretKey secretKey, String fileName) {
        saveDataToFile(secretKey.getEncoded(), fileName);
    }

    public String doDecode(String fileName) throws GeneralSecurityException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] bytes = readFile(fileName);
        byte[] bytesKey = readFile(fileName + ".key");

        SecretKeySpec key = new SecretKeySpec(bytesKey, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedContent = cipher.doFinal(bytes);

        String decodedFileName = fileName.replace("encodedBy.AES", "decodedBy.AES.in.") + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HH-mm-ss"));
        saveDataToFile(decryptedContent, decodedFileName);
        System.out.println("Файл декодирован имя = " + decodedFileName);
        return decodedFileName;
    }

    private void saveDataToFile(byte[] fileData, String fileName) {
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(fileName);
            fileOutputStream.write(fileData);
            fileOutputStream.close();
        } catch (FileNotFoundException e) {
            System.out.println("Не создать файл");
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] readFile(String fileName) {
        File file = new File(fileName);
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            System.out.println("Файл не найден");
            throw new RuntimeException(e);
        }
        byte[] fileContent = new byte[(int) file.length()];

        try {
            fis.read(fileContent);
            fis.close();
        } catch (IOException e) {
            System.out.println("Не могу прочиать файл");
            throw new RuntimeException(e);
        }
        return fileContent;
    }
}
