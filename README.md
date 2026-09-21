# Casulo


<img width="840" height="554" alt="casulogui" src="https://github.com/user-attachments/assets/59e204e3-0f68-453b-932c-3800a80adfd9" />



Casulo é um empacotador e protetor de binários para **Windows** e **Linux**, desenvolvido principalmente em **Free Pascal/Lazarus** e **Rust**.

O projeto cria um container autenticado para a aplicação original, aplica compressão e criptografia por build e utiliza um stub específico para cada plataforma para validar, reconstruir e iniciar o executável protegido.

> **Uso responsável:** o Casulo foi desenvolvido para proteção, distribuição e estudo de software próprio ou autorizado. Não use o projeto para ocultar código malicioso, burlar controles de segurança ou empacotar software sem autorização.

## Principais recursos

* suporte a executáveis **Windows PE64** e **Linux ELF64**;
* compressão com **Zstandard** ou **Brotli**;
* criptografia **AES-256-CBC**;
* derivação de chaves com **HKDF-SHA256**;
* autenticação de metadados e chunks com **HMAC-SHA256**;
* container fragmentado com valores, identificadores e parâmetros diversificados a cada build;
* **VM interna diversificada por build**, utilizada na derivação de material criptográfico e no controle das etapas finais de execução;
* opcodes, constantes, programas internos e parâmetros da VM regenerados durante o empacotamento;
* Stub Windows desenvolvido em **Rust**;
* Stub Linux desenvolvido em **Rust `no_std`**, sem dependência da libc;
* recursos **RCDATA** para armazenamento fragmentado do container no executável Windows;
* execução em memória no Windows quando o PE é compatível com o mapper;
* suporte a relocations, resolução de imports, proteções de memória e tabelas de unwind no mapper PE64;
* **demand paging opcional no Windows**, mantendo páginas executáveis protegidas e disponibilizando-as sob demanda durante a execução;
* fallback convencional em disco para executáveis Windows que utilizam recursos não suportados pelo mapper;
* execução Linux utilizando **`memfd` + `execveat`**, evitando a necessidade de criar um executável permanente em disco;
* limpeza de buffers contendo material criptográfico e payloads intermediários após o uso;
* suporte a metadados de versão e ícone no executável Windows;
* opções de otimização do compilador Rust configuráveis pelo packer.


## Estrutura do projeto

A estrutura utilizada pelo projeto é:

```text
Casulo/
├── bin/                  # executável compilado do Casulo (não versionado)
├── src/                  # aplicação/packer em Free Pascal/Lazarus
│   └── assets/           # imagens e recursos usados pela interface
├── stub_linux/           # templates e código da Stub Linux
├── stub_windows/         # templates e código da Stub Windows
├── tools/                # utilitários auxiliares
├── README.md
├── LICENSE
└── .gitignore
```

O executável principal é compilado em `bin/`. Em tempo de execução, o Casulo resolve os caminhos das stubs a partir da raiz do projeto, portanto `stub_linux/` e `stub_windows/` permanecem ao lado de `bin/` e `src/`.

Os arquivos `*.in` das stubs são **templates**. Durante o empacotamento, o Casulo substitui marcadores `@@...@@` por valores específicos daquela build.

Arquivos Rust gerados a partir desses templates, recursos `RCDATA`, segredos temporários, diretórios `target/` e demais artefatos de compilação não devem ser versionados.

## Fluxo geral

```text
Executável original
        │
        ▼
   Compressão
 Zstd / Brotli
        │
        ▼
Container autenticado
 AES-256-CBC
 HKDF-SHA256
 HMAC-SHA256
        │
        ▼
 Fragmentação
        │
   ┌────┴────┐
   ▼         ▼
Windows     Linux
RCDATA      dados anexados
   │         │
   ▼         ▼
Stub Rust específico
da plataforma
```

## Requisitos de desenvolvimento

O ambiente principal de desenvolvimento é Linux.

Requisitos gerais:

- Free Pascal / Lazarus;
- biblioteca **Dcrypt** para o código Lazarus/Free Pascal do Casulo;
- Rust **1.96 ou superior**;
- Cargo;
- Git;
- toolchain de compilação C/C++;
- `cargo-xwin` para a Stub Windows quando compilada a partir do Linux.

No Fedora, uma base de desenvolvimento pode ser instalada com:

```bash
sudo dnf install git curl gcc gcc-c++ make lazarus fpc
```

Rust pode ser instalado pelo `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Para builds Windows a partir do Linux:

```bash
cargo install cargo-xwin
```

> Os nomes dos pacotes podem variar entre versões do Fedora.

## Stubs

### Windows

A Stub Windows trabalha com PE64/x86-64.

Dependendo das características do executável, o packer seleciona o modo apropriado de execução. O mapper em memória é utilizado apenas quando a imagem é compatível com os requisitos implementados pelo loader.

O diretório da Stub deve manter no Git apenas os templates e módulos fonte, por exemplo:

```text
stub_windows/
├── Cargo.toml.in
├── build.rs.in
├── src/
│   ├── main.rs.in
│   ├── exec_vm.rs.in
│   ├── loader.rs
│   ├── paging.rs
│   └── exec_signal.rs
└── assets/
    └── icon.ico
```

### Linux

A Stub Linux é escrita em Rust `no_std` e utiliza uma entrada `_start` própria.

Arquivos esperados no repositório:

```text
stub_linux/
├── Cargo.toml.in
├── build.rs
└── src/
    ├── main.rs.in
    └── exec_vm.rs.in
```

## Detector

O repositório pode incluir o utilitário:

```text
tools/casulo_detect.py
```

Ele analisa PE/ELF e procura características estruturais do formato Casulo, além de apresentar informações do binário.

Exemplo:

```bash
python3 tools/casulo_detect.py programa.exe
```

Para informações PE mais completas:

```bash
pip install pefile
```

Para ELF:

```bash
pip install pyelftools
```

## Estado do projeto

O Casulo ainda está em desenvolvimento. Mudanças no formato do container, compatibilidade dos loaders e templates das stubs podem ocorrer entre versões.

## Licença

Casulo é distribuído sob a **MIT License**.

Você pode usar, copiar, modificar, mesclar, publicar, distribuir, sublicenciar e utilizar o código em projetos pessoais, open source ou comerciais, inclusive em software proprietário, nos termos da licença.

Consulte o arquivo `LICENSE` para os detalhes completos.
