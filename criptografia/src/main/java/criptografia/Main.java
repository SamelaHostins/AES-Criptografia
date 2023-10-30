package criptografia;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.Security;
import java.util.List;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    private static final String ALGORITHM = "AES/ECB/PKCS7Padding"; // Usando o modo ECB

    public static void main(String[] args) throws Exception {
        ValidarEntradas validarEntradas = new ValidarEntradas();
        ExpansaoDeChave ex = new ExpansaoDeChave();
        CriptografarArquivo criptografarArquivo = new CriptografarArquivo();
        Chave chaveExpansao = new Chave();
        Scanner scanner = new Scanner(System.in);

        // 20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248
        String chave = validarEntradas.getChaveValida(scanner);
        // processo da expansão da chave
        // System.out.println("Chave: " + chave);
        System.out.println("");
        String chaveHexadecimal = chaveExpansao.transformarChaveParaHexadecimal(chave);
        String[][] matrizDaChave = chaveExpansao.organizarChaveEmMatriz4x4(chaveHexadecimal);
        List<String[][]> listaDeRoundKey = ex.gerarMatrizes(11, 4, 4, matrizDaChave);

        // C:/Users/Acer/OneDrive/Documentos/teste.txt
        String arquivoDeEntrada = validarEntradas.obterCaminhoArquivoValido(scanner);
        System.out.println("");

        String arquivoDeSaida = validarEntradas.obterNomeDoArquivoValido(scanner);
        System.out.println("");

        try {
            criptografarArquivo.criptografaArquivo(arquivoDeEntrada, arquivoDeSaida, listaDeRoundKey);
        } catch (Exception e1) {
            // Lide com a exceção aqui
            e1.printStackTrace(); // ou qualquer tratamento de erro específico que você desejar
        }

        Security.addProvider(new BouncyCastleProvider());

        // Defina sua senha como uma string de bytes separados por vírgula
        String passwordBytes = "20,1,94,33,127,0,48,9,31,94,112,40,59,30,100,248";
        String[] byteStrings = passwordBytes.split(",");
        byte[] password = new byte[16]; // Chave de 128 bits (16 bytes)

        for (int i = 0; i < byteStrings.length; i++) {
            int byteValue = Integer.parseInt(byteStrings[i].trim());
            if (byteValue < 0 || byteValue > 255) {
                throw new IllegalArgumentException("Valores inválidos de byte na chave.");
            }
            password[i] = (byte) byteValue;
        }

        // Crie a chave a partir dos bytes da chave
        Key key = new SecretKeySpec(password, "AES");

        // Criptografar o arquivo
        encryptFile(key, "C:/Users/Acer/OneDrive/Documentos/teste2.txt", "arquivoCriptografado");

        decryptFile(key, "arquivoCriptografado", "arquivoDescriptografado");

        System.out.println("Operações de criptografia e descriptografia concluídas com sucesso!");

    }

    public static void encryptFile(Key key, String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outputFile);
        byte[] input = new byte[64];
        int bytesRead;
        while ((bytesRead = fis.read(input)) != -1) {
            byte[] output = cipher.update(input, 0, bytesRead);
            if (output != null) {
                fos.write(output);
            }
        }
        byte[] output = cipher.doFinal();
        if (output != null) {
            fos.write(output);
        }
        fos.close();
        fis.close();
    }

    public static void decryptFile(Key key, String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(outputFile);
        byte[] input = new byte[64];
        int bytesRead;
        while ((bytesRead = fis.read(input)) != -1) {
            byte[] output = cipher.update(input, 0, bytesRead);
            if (output != null) {
                fos.write(output);
            }
        }
        byte[] output = cipher.doFinal();
        if (output != null) {
            fos.write(output);
        }
        fos.close();
        fis.close();
    }
}