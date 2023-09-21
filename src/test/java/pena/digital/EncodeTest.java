package pena.digital;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class EncodeTest {
    private static String calculateFileHash(String fileName) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        EncodeDecode encodeDecode = new EncodeDecode();
        byte[] bytes = md.digest(encodeDecode.readFile(fileName));

        StringBuilder stringBuilder = new StringBuilder();

        for (byte b : md.digest(bytes)) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    @Test
    @DisplayName("Кодирование файла и сохранение ключа")
    @Order(1)
    public void doEncodeFileTest() throws GeneralSecurityException {
        EncodeDecode encode = new EncodeDecode();
        encode.doEncode("src/test/resources/fathers-0.png");
    }

    @Test
    @DisplayName("Декодирование файла и проверка хеш суммы")
    @Order(2)
    public void doEncodeFileWithKeyFile()  throws GeneralSecurityException {
        EncodeDecode encode = new EncodeDecode();
        String encodedFileName = "src/test/resources/fathers-0.png.encodedBy.AES";
        String decodedFileName = encode.doDecode(encodedFileName);
        org.assertj.core.api.Assertions.assertThat(calculateFileHash("src/test/resources/fathers-0.png")).isEqualTo(calculateFileHash(decodedFileName)) ;
    }


}