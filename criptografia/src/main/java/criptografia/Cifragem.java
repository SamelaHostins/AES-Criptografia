package criptografia;

import java.util.ArrayList;
import java.util.List;

// Autoras: Karoline, Maria Eduarda e Sâmela
// Autoras: Karoline, Maria Eduarda e Sâmela
public class Cifragem {

    public String[][] converteMatrizParaHex(byte[][] matriz) {
        int numRows = matriz.length;
        int numCols = matriz[0].length;
        String[][] hexMatrix = new String[numRows][numCols];

        for (int i = 0; i < numRows; i++) {
            for (int j = 0; j < numCols; j++) {
                hexMatrix[i][j] = String.format("%02X", matriz[i][j] & 0xFF);
            }
        }

        return hexMatrix;
    }

    // Isso porque o AES pede que os blocos sejam organizados em matrizes 4x4
    public List<String[][]> organizarBlocos4x4(String[][] blocos) {
        List<String[][]> ListaBlocos = new ArrayList<>();

        for (String[] bloco : blocos) {
            String[][] matriz = new String[4][4];
            for (int col = 0; col < 4; col++) {
                for (int linha = 0; linha < 4; linha++) {
                    matriz[linha][col] = bloco[col * 4 + linha];
                }
            }
            ListaBlocos.add(matriz);
        }

        return ListaBlocos;
    }

    // Para ver a lista de matrizes ex: ListaBlocos[0]
    public void imprimirMatrizes4x4(List<String[][]> listaMatrizes) {
        for (int i = 0; i < listaMatrizes.size(); i++) {
            System.out.println("");
            System.out.println("Matriz " + i + ":");
            String[][] matriz = listaMatrizes.get(i);
            for (int linha = 0; linha < 4; linha++) {
                for (int col = 0; col < 4; col++) {
                    System.out.print(matriz[linha][col] + " ");
                }
                System.out.println();
            }
        }
    }

    public List<String[][]> cifragemAES(List<String[][]> roundKeys, List<String[][]> blocos) {
        List<String[][]> blocosCifrados = new ArrayList<>();

        for (String[][] bloco : blocos) {
            String[][] matrizResultado = XorComRoundKey(roundKeys.get(0), bloco);

            for (int roundKey = 1; roundKey <= 9; roundKey++) {
                substituirElementos(matrizResultado);
                shiftRows(matrizResultado);
                int[][] matrizColumn = mixColumns(matrizResultado);
                matrizResultado = XorMixColumnComRoundKey(roundKeys.get(roundKey), matrizColumn);
            }

            substituirElementos(matrizResultado);
            shiftRows(matrizResultado);
            matrizResultado = XorComRoundKey(roundKeys.get(10), matrizResultado);

            blocosCifrados.add(matrizResultado);
        }

        return blocosCifrados;
    }

    // 1) XOR com a roundKey
    public String[][] XorComRoundKey(String[][] roundKey, String[][] bloco) {
        String[][] resultado = new String[4][4];

        for (int linha = 0; linha < 4; linha++) {
            for (int col = 0; col < 4; col++) {
                int valorRoundKey = Integer.parseInt(roundKey[linha][col], 16);
                int valorBloco = Integer.parseInt(bloco[linha][col], 16);
                int resultadoXOR = valorRoundKey ^ valorBloco;

                // Converte o resultado para hexadecimal
                String resultadoHex = Integer.toHexString(resultadoXOR);

                // Garante que o resultado tenha dois caracteres (0-padded)
                if (resultadoHex.length() == 1) {
                    resultadoHex = "0" + resultadoHex;
                }

                resultado[linha][col] = resultadoHex;
            }
        }

        return resultado;
    }

    // 2) SubBytes
    private void substituirElementos(String[][] matriz) {
        String[][] sBox = {
                { "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b",
                        "fe", "d7", "ab", "76" },
                { "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af",
                        "9c", "a4", "72", "c0" },
                { "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1",
                        "71", "d8", "31", "15" },
                { "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2",
                        "eb", "27", "b2", "75" },
                { "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3",
                        "29", "e3", "2f", "84" },
                { "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39",
                        "4a", "4c", "58", "cf" },
                { "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f",
                        "50", "3c", "9f", "a8" },
                { "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21",
                        "10", "ff", "f3", "d2" },
                { "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d",
                        "64", "5d", "19", "73" },
                { "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14",
                        "de", "5e", "0b", "db" },
                { "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62",
                        "91", "95", "e4", "79" },
                { "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea",
                        "65", "7a", "ae", "08" },
                { "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f",
                        "4b", "bd", "8b", "8a" },
                { "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9",
                        "86", "c1", "1d", "9e" },
                { "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9",
                        "ce", "55", "28", "df" },
                { "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f",
                        "b0", "54", "bb", "16" }
        };

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                String elemento = matriz[i][j];

                if (elemento.length() == 2) {
                    int linha = 0;
                    int coluna;

                    char primeiroCaractere = Character.toLowerCase(elemento.charAt(0));

                    if (Character.isDigit(primeiroCaractere)) {
                        linha = Integer.parseInt(elemento.substring(0, 1));
                    } else {
                        if (primeiroCaractere >= 'a' && primeiroCaractere <= 'z') {
                            linha = primeiroCaractere - 'a' + 10;
                        }
                    }

                    char segundoCaractere = Character.toLowerCase(elemento.charAt(1));
                    if (Character.isDigit(segundoCaractere)) {
                        coluna = Integer.parseInt(elemento.substring(1, 2));
                    } else {
                        coluna = segundoCaractere - 'a' + 10;
                    }

                    matriz[i][j] = sBox[linha][coluna];
                }
            }
        }
    }

    // 3) Embaralhando matriz para o proximo passo
    public void shiftRows(String[][] matriz) {
        String[][] newMatriz = new String[matriz.length][matriz.length];
        for (int li = 0; li < matriz.length; li++) {
            for (int col = 0; col < matriz.length; col++) {
                // caso seja maior que zero a linha, deve-se embaralhar os bytes
                if (li > 0) {
                    // se eu estiver na primeira posição e não estiver na última coluna
                    if (li == 1 && col != matriz.length - 1) {
                        // li 1
                        // col 0
                        if (col == 0) {
                            // o resultado da linha 1 coluna 0 deve estar na última coluna
                            // da matriz
                            newMatriz[li][matriz.length - 1] = matriz[li][col];
                        }
                        // 1;0
                        // 1:1
                        newMatriz[li][col] = matriz[li][col + 1];
                    }
                    if (li == 2) {
                        if (col == 0) {
                            // o resultado da linha 2 coluna 0 deve estar na penúltima
                            // coluna da matriz
                            newMatriz[li][matriz.length - 2] = matriz[li][col];
                            newMatriz[li][col] = matriz[li][col + 2];
                        }
                        if (col == 1) {
                            newMatriz[li][matriz.length - 1] = matriz[li][col];
                        }
                        if (col == 3) {
                            // o que tiver na posição 2,3 ficará na posição 2,1
                            newMatriz[li][matriz.length - 3] = matriz[li][col];
                        }
                    }
                    if (li == 3) {
                        if (col == 0) {
                            // o resultado da linha 3 coluna 0 deve estar na antepenúltima
                            // coluna da matriz
                            newMatriz[li][matriz.length - 3] = matriz[li][col];
                            newMatriz[li][col] = matriz[li][col + 3];
                        }
                        if (col == 1) {
                            newMatriz[li][matriz.length - 2] = matriz[li][col];
                        }
                        if (col == 2) {
                            newMatriz[li][matriz.length - 1] = matriz[li][col];
                        }
                    }
                } else {
                    // na linha 0 mantêm-se os valores como são
                    newMatriz[li][col] = matriz[li][col];
                }
            }
        }

        // Atualiza a matriz original com os valores embaralhados
        for (int li = 0; li < matriz.length; li++) {
            for (int col = 0; col < matriz.length; col++) {
                matriz[li][col] = newMatriz[li][col];
            }
        }
    }

    // 4) Gerando RoundConstant - MixColumns
    private int[][] mixColumns(String[][] matriz) {

        // precisará transformar a matriz para int para que seja
        // possível fazer as validações
        int[][] bloco = converterMatrizHexParaInt(matriz);
        int[][] matrizResultante = new int[4][4];

        for (int c = 0; c < 4; c++) {
            // primeira linha da matriz de multiplicação
            // 2,3,1,1
            matrizResultante[0][c] = xor(
                    verificacao(bloco[0][c], "02"), verificacao(bloco[1][c], "03"),
                    verificaSeEhZero(bloco[2][c]), verificaSeEhZero(bloco[3][c]));
            // segunda linha da matriz de multiplicação
            // 1,2,3,1
            matrizResultante[1][c] = xor(
                    verificaSeEhZero(bloco[0][c]), verificacao(bloco[1][c], "02"),
                    verificacao(bloco[2][c], "03"), verificaSeEhZero(bloco[3][c]));
            // terceira linha da matriz de multiplicação
            // 1,1,2,3
            matrizResultante[2][c] = xor(
                    verificaSeEhZero(bloco[0][c]), verificaSeEhZero(bloco[1][c]),
                    verificacao(bloco[2][c], "02"), verificacao(bloco[3][c], "03"));
            // quarta linha da matriz de multiplicação
            // 3,1,1,2
            matrizResultante[3][c] = xor(
                    verificacao(bloco[0][c], "03"), verificaSeEhZero(bloco[1][c]),
                    verificaSeEhZero(bloco[2][c]), verificacao(bloco[3][c], "02"));
        }
        return matrizResultante;

    }

    public int[][] converterMatrizHexParaInt(String[][] matrizString) {
        int linhas = matrizString.length;
        int colunas = matrizString[0].length;
        int[][] matrizInt = new int[linhas][colunas];

        for (int i = 0; i < linhas; i++) {
            for (int j = 0; j < colunas; j++) {
                matrizInt[i][j] = Integer.parseInt(matrizString[i][j], 16);
            }
        }

        return matrizInt;
    }

    private int xor(int a, int b, int c, int d) {
        int resultado = a ^ b;
        resultado = resultado ^ c;
        resultado = resultado ^ d;
        return resultado;
    }

    private int verificaSeEhZero(int elemento) {
        if (elemento == 0) {
            return 0;
        } else {
            return elemento;
        }

    }

    private int verificacao(int elemento, String valorMultiplicacao) {
        if (elemento == 0) {
            return 0;
        } else if (elemento == 1) {
            return Integer.parseInt(valorMultiplicacao);
        } else {
            return this.galoi(elemento, valorMultiplicacao);
        }
    }

    private int galoi(int elemento, String valorMultiplicacao) {

        String numeroHexadecimal = Integer.toHexString(elemento);
        int elementoPosTabelaL = Integer.parseInt(this.susbtituicaoTabelaL(numeroHexadecimal), 16);
        int valorPosTabelaL = Integer.parseInt(this.susbtituicaoTabelaL(valorMultiplicacao), 16);

        int soma = elementoPosTabelaL + valorPosTabelaL;
        // verificação para que se o numero for maior que 255
        if (soma > 255) {
            soma = soma % 255;
        }
        String resultadoHex = Integer.toHexString(soma);
        int elementoFinal = Integer.parseInt(this.susbtituicaoTabelaE(resultadoHex), 16);
        return elementoFinal;
    }

    private String susbtituicaoTabelaL(String elemento) {
        String[][] tabelaL = {
                { "00", "00", "19", "01", "32", "02", "1a", "c6", "4b", "c7", "1b", "68",
                        "33", "ee", "df", "03" },
                { "64", "04", "e0", "0e", "34", "8d", "81", "ef", "4c", "71", "08", "c8",
                        "f8", "69", "1c", "c1" },
                { "7d", "c2", "1d", "b5", "f9", "b9", "27", "6a", "4d", "e4", "a6", "72",
                        "9a", "c9", "09", "78" },
                { "65", "2f", "8a", "05", "21", "0f", "e1", "24", "12", "f0", "82", "45",
                        "35", "93", "da", "8e" },
                { "96", "8f", "db", "bd", "36", "d0", "ce", "94", "13", "5c", "d2", "f1",
                        "40", "46", "83", "38" },
                { "66", "dd", "fd", "30", "bf", "06", "8b", "62", "b3", "25", "e2", "98",
                        "22", "88", "91", "10" },
                { "7e", "6e", "48", "c3", "a3", "b6", "1e", "42", "3a", "6b", "28", "54",
                        "fa", "85", "3d", "ba" },
                { "2b", "79", "0a", "15", "9b", "9f", "5e", "ca", "4e", "d4", "ac", "e5",
                        "f3", "73", "a7", "57" },
                { "af", "58", "a8", "50", "f4", "ea", "d6", "74", "4f", "ae", "e9", "d5",
                        "e7", "e6", "ad", "e8" },
                { "2c", "d7", "75", "7a", "eb", "16", "0b", "f5", "59", "cb", "5f", "b0",
                        "9c", "a9", "51", "a0" },
                { "7f", "0c", "f6", "6f", "17", "c4", "49", "ec", "d8", "43", "1f", "2d",
                        "a4", "76", "7b", "b7" },
                { "cc", "bb", "3e", "5a", "fb", "60", "b1", "86", "3b", "52", "a1", "6c",
                        "aa", "55", "29", "9d" },
                { "97", "b2", "87", "90", "61", "be", "dc", "fc", "bc", "95", "cf", "cd",
                        "37", "3f", "5b", "d1" },
                { "53", "39", "84", "3c", "41", "a2", "6d", "47", "14", "2a", "9e", "5d",
                        "56", "f2", "d3", "ab" },
                { "44", "11", "92", "d9", "23", "20", "2e", "89", "b4", "7c", "b8", "26",
                        "77", "99", "e3", "a5" },
                { "67", "4a", "ed", "de", "c5", "31", "fe", "18", "0d", "63", "8c", "80",
                        "c0", "f7", "70", "07" }
        };

        int linha, coluna;

        if (elemento.length() == 1) {
            // Se o elemento tiver apenas 1 caractere, mantenha o valor original
            elemento = 0 + elemento;
        }

        char primeiroCaractere = Character.toLowerCase(elemento.charAt(0));
        if (Character.isDigit(primeiroCaractere)) {
            linha = Integer.parseInt(elemento.substring(0, 1), 16);
        } else {
            linha = primeiroCaractere - 'a' + 10;
        }

        char segundoCaractere = Character.toLowerCase(elemento.charAt(1));
        if (Character.isDigit(segundoCaractere)) {
            coluna = Integer.parseInt(elemento.substring(1, 2), 16);
        } else {
            coluna = segundoCaractere - 'a' + 10;
        }

        return tabelaL[linha][coluna];
    }

    private String susbtituicaoTabelaE(String elemento) {
        String[][] tabelaE = {
                { "01", "03", "05", "0f", "11", "33", "55", "ff", "1a", "2e", "72", "96",
                        "a1", "f8", "13", "35" },
                { "5f", "e1", "38", "48", "d8", "73", "95", "a4", "f7", "02", "06", "0a",
                        "1e", "22", "66", "aa" },
                { "e5", "34", "5c", "e4", "37", "59", "eb", "26", "6a", "be", "d9", "70",
                        "90", "ab", "e6", "31" },
                { "53", "f5", "04", "0c", "14", "3c", "44", "cc", "4f", "d1", "68", "b8",
                        "d3", "6e", "b2", "cd" },
                { "4c", "d4", "67", "a9", "e0", "3b", "4d", "d7", "62", "a6", "f1", "08",
                        "18", "28", "78", "88" },
                { "83", "9e", "b9", "d0", "6b", "bd", "dc", "7f", "81", "98", "b3", "ce",
                        "49", "db", "76", "9a" },
                { "b5", "c4", "57", "f9", "10", "30", "50", "f0", "0b", "1d", "27", "69",
                        "bb", "d6", "61", "a3" },
                { "fe", "19", "2b", "7d", "87", "92", "ad", "ec", "2f", "71", "93", "ae",
                        "e9", "20", "60", "a0" },
                { "fb", "16", "3a", "4e", "d2", "6d", "b7", "c2", "5d", "e7", "32", "56",
                        "fa", "15", "3f", "41" },
                { "c3", "5e", "e2", "3d", "47", "c9", "40", "c0", "5b", "ed", "2c", "74",
                        "9c", "bf", "da", "75" },
                { "9f", "ba", "d5", "64", "ac", "ef", "2a", "7e", "82", "9d", "bc", "df",
                        "7a", "8e", "89", "80" },
                { "9b", "b6", "c1", "58", "e8", "23", "65", "af", "ea", "25", "6f", "b1",
                        "c8", "43", "c5", "54" },
                { "fc", "1f", "21", "63", "a5", "f4", "07", "09", "1b", "2d", "77", "99",
                        "b0", "cb", "46", "ca" },
                { "45", "cf", "4a", "de", "79", "8b", "86", "91", "a8", "e3", "3e", "42",
                        "c6", "51", "f3", "0e" },
                { "12", "36", "5a", "ee", "29", "7b", "8d", "8c", "8f", "8a", "85", "94",
                        "a7", "f2", "0d", "17" },
                { "39", "4b", "dd", "7c", "84", "97", "a2", "fd", "1c", "24", "6c", "b4",
                        "c7", "52", "f6", "01" }
        };

        int linha, coluna;

        if (elemento.length() == 1) {
            // Se o elemento tiver apenas 1 caractere, mantenha o valor original
            elemento = 0 + elemento;
        }

        char primeiroCaractere = Character.toLowerCase(elemento.charAt(0));
        if (Character.isDigit(primeiroCaractere)) {
            linha = Integer.parseInt(elemento.substring(0, 1), 16);
        } else {
            linha = primeiroCaractere - 'a' + 10;
        }

        char segundoCaractere = Character.toLowerCase(elemento.charAt(1));
        if (Character.isDigit(segundoCaractere)) {
            coluna = Integer.parseInt(elemento.substring(1, 2), 16);
        } else {
            coluna = segundoCaractere - 'a' + 10;
        }

        return tabelaE[linha][coluna];
    }

    // etapa 5
    public String[][] XorMixColumnComRoundKey(String[][] roundKey, int[][] bloco) {
        String[][] resultado = new String[4][4];

        for (int linha = 0; linha < 4; linha++) {
            for (int col = 0; col < 4; col++) {
                int valorRoundKey = Integer.parseInt(roundKey[linha][col], 16);
                int valorBloco = bloco[linha][col];
                int resultadoXOR = valorRoundKey ^ valorBloco;

                // Converte o resultado para hexadecimal
                String resultadoHex = Integer.toHexString(resultadoXOR);

                // Garante que o resultado tenha dois caracteres (0-padded)
                if (resultadoHex.length() == 1) {
                    resultadoHex = "0" + resultadoHex;
                }

                resultado[linha][col] = resultadoHex;
            }
        }

        return resultado;
    }

    public void imprimirMatriz(int[][] matriz) {
        for (int i = 0; i < matriz.length; i++) {
            for (int j = 0; j < matriz[i].length; j++) {
                System.out.print(matriz[i][j] + " ");
            }
            System.out.println();
        }
    }

    public static void main(String[] args) {
        Cifragem cifragem = new Cifragem();
        ExpansaoDeChave expansao = new ExpansaoDeChave();
        int numMatrizes = 11;
        int numLinhas = 4;
        int numColunas = 4;

        // // Fornecer a matriz que será adicionada como o primeiro elemento
        String[][] primeiraMatriz = {
                { "41", "45", "49", "4d" },
                { "42", "46", "4a", "4e" },
                { "43", "47", "4b", "4f" },
                { "44", "48", "4c", "50" }
        };

        List<String[][]> ListaDeMatrizes = expansao.gerarMatrizes(numMatrizes,
                numLinhas, numColunas,
                primeiraMatriz);

        // Criar um bloco com os valores fornecidos
        String[][] bloco = {
                { "44", "4e", "56", "4e" },
                { "45", "56", "49", "54" },
                { "53", "4f", "4d", "4f" },
                { "45", "4c", "45", "21" }
        };

        List<String[][]> roundKeys = ListaDeMatrizes;
        List<String[][]> blocos = new ArrayList<>();
        blocos.add(bloco);

        List<String[][]> blocosCifrados = cifragem.cifragemAES(roundKeys, blocos);

        for (String[][] blocoCifrado : blocosCifrados) {
            // Itere pelas linhas do bloco cifrado
            for (int linha = 0; linha < blocoCifrado.length; linha++) {
                // Itere pelas colunas do bloco cifrado
                for (int coluna = 0; coluna < blocoCifrado[linha].length; coluna++) {
                    System.out.print(blocoCifrado[linha][coluna] + " ");
                }
                System.out.println();
            }
            System.out.println();
        }
    }
}