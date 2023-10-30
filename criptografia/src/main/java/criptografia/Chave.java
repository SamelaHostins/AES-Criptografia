package criptografia;

public class Chave {
    public String transformarChaveParaHexadecimal(String sequencia) {
        String[] numeros = sequencia.split(",");
        StringBuilder hexadecimal = new StringBuilder();

        for (String numero : numeros) {
            int valorEmDecimal = Integer.parseInt(numero);
            hexadecimal.append(String.format("%02X", valorEmDecimal));
            hexadecimal.append(",");
        }

        // Remova a vírgula extra no final, se houver
        if (hexadecimal.length() > 0 && hexadecimal.charAt(hexadecimal.length() - 1) == ',') {
            hexadecimal.setLength(hexadecimal.length() - 1);
        }

        return hexadecimal.toString();
    }

    public String[][] organizarChaveEmMatriz4x4(String chave) {
        String[] hexStrings = chave.split(",");
        String[][] matriz4x4 = new String[4][4];
        int hexIndex = 0;
        for (int col = 0; col < 4; col++) {
            for (int linha = 0; linha < 4; linha++) {
                matriz4x4[linha][col] = hexStrings[hexIndex++];
            }
        }
        return matriz4x4;
    }

    public void imprimirMatrizDaChave(String[][] matriz4x4) {
        for (int linha = 0; linha < 4; linha++) {
            for (int col = 0; col < 4; col++) {
                System.out.print(matriz4x4[linha][col] + " ");
            }
            System.out.println();
        }
    }
}
