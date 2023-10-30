package criptografia;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CriptografarArquivo extends ECBPadding {

    public byte[] lerArquivoSemSinal(String arquivoDeEntrada) {
        try {
            Path path = Paths.get(arquivoDeEntrada);
            byte[] arquivoEmBytes = Files.readAllBytes(path);
            byte[] arquivoSemSinal = new byte[arquivoEmBytes.length];

            for (int i = 0; i < arquivoEmBytes.length; i++) {
                arquivoSemSinal[i] = (byte) (arquivoEmBytes[i] & 0xFF);
            }

            return arquivoSemSinal;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void criptografarComAES(String arquivoDeEntrada, String arquivoDeSaida, List<String[][]> listaDeRoundKey)
            throws Exception {

        byte[] arquivoEmBytes = lerArquivoSemSinal(arquivoDeEntrada);
        byte[][] matriz = divideEmBlocosDe16Bytes(arquivoEmBytes);
        String[][] matrizEmHex = converteMatrizParaHex(matriz);
        List<String[][]> listaDeBlocos = organizarBlocos4x4(matrizEmHex);

        List<String[][]> cifragem = cifragemAES(listaDeRoundKey, listaDeBlocos);
        try (FileOutputStream fos = new FileOutputStream(arquivoDeSaida)) {
            // Converter a cifragem em uma representação de bytes
            for (String[][] matrizToConvert : cifragem) {
                for (String[] linha : matrizToConvert) {
                    for (String elemento : linha) {
                        // Converter cada valor hexadecimal para um byte
                        int valorByte = (int) Integer.parseInt(elemento, 16);
                        fos.write(valorByte);
                        fos.flush();
                    }
                }
            }
        }
    }

    // Criptografa arquivo
    public void criptografaArquivo(String entrada, String saida, List<String[][]> listaDeRoundKey) throws Exception {
        criptografarComAES(entrada, saida, listaDeRoundKey);
        System.out.println("Arquivo criptografado com sucesso.");
    }

    // dps pode excluir são métodos para testar a criptografia usando uma lib
    public void encryptFileTeste(String arquivoDeEntrada, String arquivoDeSaida, String chave) {
        try {
            // Lê o conteúdo do arquivo de entrada
            byte[] bytesDoArquivo = Files.readAllBytes(Paths.get(arquivoDeEntrada));

            // Divide a string da chave e converte os valores em inteiros
            String[] chaveArray = chave.split(",");
            int[] chaveInteiros = new int[chaveArray.length];
            for (int i = 0; i < chaveArray.length; i++) {
                chaveInteiros[i] = Integer.parseInt(chaveArray[i]);
            }

            // Converte os inteiros em bytes
            byte[] chaveBytes = new byte[chaveInteiros.length];
            for (int i = 0; i < chaveInteiros.length; i++) {
                chaveBytes[i] = (byte) chaveInteiros[i];
            }

            // Cria a chave AES
            SecretKey chaveAES = new SecretKeySpec(chaveBytes, "AES");

            // Cria um objeto Cipher para criptografia AES no modo ECB
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, chaveAES);

            // Cifra o conteúdo do arquivo
            byte[] dadosCifrados = cipher.doFinal(bytesDoArquivo);

            // Grava os dados cifrados em um novo arquivo
            Files.write(Paths.get(arquivoDeSaida), dadosCifrados);
            System.out.println("Arquivo cifrado gerado com sucesso.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void decryptFile(String arquivoCifrado, String arquivoDescriptografado, String chave) {
        try {
            // Converte a chave em bytes
            String[] chaveArray = chave.split(",");
            int[] chaveInteiros = new int[chaveArray.length];
            for (int i = 0; i < chaveArray.length; i++) {
                chaveInteiros[i] = Integer.parseInt(chaveArray[i]);
            }

            byte[] chaveBytes = new byte[chaveInteiros.length];
            for (int i = 0; i < chaveInteiros.length; i++) {
                chaveBytes[i] = (byte) chaveInteiros[i];
            }

            SecretKey chaveAES = new SecretKeySpec(chaveBytes, "AES");

            // Cria um objeto Cipher para descriptografia AES no modo ECB
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, chaveAES);

            // Lê os dados cifrados do arquivo
            byte[] dadosCifrados = Files.readAllBytes(Paths.get(arquivoCifrado));

            // Realiza a descriptografia
            byte[] dadosDescriptografados = cipher.doFinal(dadosCifrados);

            // Grava os dados descriptografados em um novo arquivo
            Files.write(Paths.get(arquivoDescriptografado), dadosDescriptografados);
            System.out.println("Arquivo descriptografado gerado com sucesso.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
