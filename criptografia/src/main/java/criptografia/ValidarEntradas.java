package criptografia;

import java.io.File;
import java.util.Scanner;

// Autoras: Karoline, Maria Eduarda e Sâmela
public class ValidarEntradas {

    // Verifica se o file passado existe
    public boolean isFileValido(String nomeArquivo) {
        File file = new File(nomeArquivo);
        return file.exists() && file.isFile();
    }

    public String obterCaminhoArquivoValido(Scanner scanner) {
        String arquivo;

        while (true) {
            System.out.println("Informe o caminho do arquivo: ");
            arquivo = scanner.nextLine();

            if (isFileValido(arquivo)) {
                return arquivo;
            } else {
                System.out.println("Caminho de arquivo inválido. Tente novamente.");
            }
        }
    }

    public String obterNomeDoArquivoValido(Scanner scanner) {
        String arquivo;

        while (true) {
            System.out.println("Informe o nome do arquivo de destino a ser gerado: ");
            arquivo = scanner.nextLine();

            if (arquivo != null && !arquivo.trim().isEmpty()) {
                return arquivo;
            } else {
                System.out.println("Nome do arquivo de destino inválido. Tente novamente.");
            }
        }
    }

    // Valida se a chave foi escrita corretamente pelo usuário
    public String validarChave(String chave) {
        if (!chave.matches("^\\d{1,3}(,\\d{1,3}){15}$")) {
            return "A chave fornecida não está no formato correto.";
        }
        return null; // A chave é válida
    }

    // pede a chave pro usuário e chama o método de validar
    public String getChaveValida(Scanner scanner) {
        String chave = "";
        boolean chaveValida = false;

        while (!chaveValida) {
            System.out.println("Informe a chave de criptografia:");
            chave = scanner.nextLine();

            String erro = validarChave(chave);
            if (erro == null) {
                chaveValida = true;
            } else {
                System.out.println(erro);
            }
        }

        return chave;
    }

}
